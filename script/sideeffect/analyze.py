#!/usr/bin/env python3
"""Side-effect analysis for bug-transplant FuzzBench experiments.

Derives per-(fuzzer, trial, bug) reach/trigger timings inline by calling into
``fuzzbench_triage`` — does NOT consume ``triage_results_survival_long.csv``.
Inputs are the FuzzBench experiment directory (containing local.db and
coverage/crash archives) and the bug_metadata.json emitted by
``fuzzbench_generate.py``.

See ``script/sideeffect/AGENTS.md`` for the analysis design.
"""

from __future__ import annotations

import argparse
import csv
import logging
import sqlite3
import sys
import tarfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fuzzbench_triage import (  # noqa: E402
    _bug_targets_from_metadata,
    _match_bug_ids_in_stacktrace,
    load_bug_metadata,
    resolve_local_db_path,
    scan_coverage_for_bugs,
    scan_crash_dirs,
)

logger = logging.getLogger(__name__)

STRATUM_GATED = "gated"
STRATUM_ALWAYS = "always_active"
DEFAULT_CENSOR_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class BugInfo:
    bug_id: str
    dispatch_value: int
    stratum: str
    crash_file: str | None
    crash_line: int | None

    @property
    def bit_index(self) -> int | None:
        if self.dispatch_value <= 0:
            return None
        dv = self.dispatch_value
        if dv & (dv - 1) != 0:
            return None
        return dv.bit_length() - 1


def build_bug_index(bug_metadata: dict) -> dict[str, BugInfo]:
    bugs: dict[str, BugInfo] = {}
    for bug_id, info in bug_metadata["bugs"].items():
        dv = int(info.get("dispatch_value", 0))
        bugs[bug_id] = BugInfo(
            bug_id=bug_id,
            dispatch_value=dv,
            stratum=STRATUM_GATED if dv > 0 else STRATUM_ALWAYS,
            crash_file=info.get("crash_file"),
            crash_line=info.get("crash_line"),
        )
    return bugs


# ---------------------------------------------------------------------------
# Build the survival matrix directly from local.db + coverage snapshots.
# ---------------------------------------------------------------------------


def load_trial_inventory(db_path: Path, benchmark: str
                         ) -> tuple[dict[str, list[str]], int]:
    """Return ({fuzzer: [trial_id, ...]}, censor_seconds from snapshot max)."""
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        trials = cur.execute(
            "select fuzzer, id from trial where preempted = 0 and benchmark = ? "
            "order by fuzzer, id",
            (benchmark,),
        ).fetchall()
        max_snap = cur.execute(
            "select max(snapshot.time) from snapshot "
            "join trial on snapshot.trial_id = trial.id "
            "where trial.preempted = 0 and trial.benchmark = ?",
            (benchmark,),
        ).fetchone()
    finally:
        conn.close()

    by_fuzzer: dict[str, list[str]] = defaultdict(list)
    for fuzzer, tid in trials:
        by_fuzzer[fuzzer].append(str(tid))
    censor = int(max_snap[0]) if max_snap and max_snap[0] else DEFAULT_CENSOR_SECONDS
    return dict(by_fuzzer), censor


def build_pivot(trials_by_fuzzer: dict[str, list[str]],
                bug_ids: list[str],
                crash_results: dict,
                coverage_results: dict | None,
                censor: int) -> dict[tuple[str, str, str], dict]:
    """Produce one entry per (fuzzer, trial, bug) with observed events.

    When ``coverage_results`` is None (no coverage archives on disk), reach
    is left unobserved. When coverage scan did run, reach_time is taken from
    the coverage snapshot; if the scan skipped a bug because it already
    crashed in that trial, we fall back to trig_t — triggering tautologically
    implies reach. This matches ``fuzzbench_triage.merge_results``.
    """
    pivot: dict[tuple[str, str, str], dict] = {}
    for fuzzer, trial_ids in trials_by_fuzzer.items():
        for trial_id in trial_ids:
            for bug_id in bug_ids:
                key = (fuzzer, trial_id, bug_id)
                trig_t = crash_results.get(key)
                cov_t = None if coverage_results is None else coverage_results.get(key)
                if coverage_results is not None and cov_t is None and trig_t is not None:
                    reach_t = trig_t
                else:
                    reach_t = cov_t
                pivot[key] = {
                    "fuzzer": fuzzer,
                    "trial": trial_id,
                    "bug_id": bug_id,
                    "reached_time": reach_t,
                    "reached_observed": 1 if reach_t is not None else 0,
                    "triggered_time": trig_t,
                    "triggered_observed": 1 if trig_t is not None else 0,
                    "censor": censor,
                }
    return pivot


def sorted_missing_coverage(experiment_dir: Path, benchmark: str) -> list[str]:
    """Return the trial directory paths whose coverage subdir is missing/empty."""
    exp_folders = experiment_dir / "experiment-folders"
    if not exp_folders.exists():
        return []
    missing = []
    prefix = benchmark + "-"
    for fuzzer_dir in sorted(exp_folders.iterdir()):
        if not fuzzer_dir.is_dir() or not fuzzer_dir.name.startswith(prefix):
            continue
        for trial_dir in sorted(fuzzer_dir.iterdir()):
            if not trial_dir.is_dir():
                continue
            coverage_dir = trial_dir / "coverage"
            if not coverage_dir.exists():
                missing.append(f"{trial_dir} (no coverage/ subdir)")
                continue
            archives = [p for p in coverage_dir.iterdir()
                        if p.name.endswith(".json.gz") and p.stat().st_size > 0]
            if not archives:
                missing.append(f"{coverage_dir} (empty)")
    return missing


# ---------------------------------------------------------------------------
# Kaplan-Meier median
# ---------------------------------------------------------------------------


def km_median(times: list[int], events: list[int]) -> int | None:
    if not times:
        return None
    by_time: dict[int, list[int]] = defaultdict(list)
    for t, e in zip(times, events):
        by_time[t].append(e)
    n_at_risk = len(times)
    surv = 1.0
    for t in sorted(by_time):
        events_at_t = sum(by_time[t])
        n_at_t = len(by_time[t])
        if events_at_t > 0 and n_at_risk > 0:
            surv *= (1 - events_at_t / n_at_risk)
            if surv <= 0.5:
                return t
        n_at_risk -= n_at_t
    return None


# ---------------------------------------------------------------------------
# Stratum / per-bug aggregations
# ---------------------------------------------------------------------------


def compute_stratum_summary(pivot: dict, bugs: dict[str, BugInfo],
                            all_fuzzers: list[str]) -> list[dict]:
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for entry in pivot.values():
        bug = bugs.get(entry["bug_id"])
        if bug is None:
            continue
        groups[(entry["fuzzer"], bug.stratum)].append(entry)

    rows = []
    for fuzzer in all_fuzzers:
        for stratum in (STRATUM_GATED, STRATUM_ALWAYS):
            entries = groups.get((fuzzer, stratum), [])
            if not entries:
                rows.append({"fuzzer": fuzzer, "stratum": stratum,
                             "n_trial_bug_pairs": 0})
                continue
            n = len(entries)
            trig_obs = sum(e["triggered_observed"] for e in entries)
            reach_obs = sum(e["reached_observed"] for e in entries)
            reach_only = sum(
                1 for e in entries
                if e["reached_observed"] and not e["triggered_observed"]
            )
            trig_times = [e["triggered_time"] or e["censor"] for e in entries]
            trig_events = [e["triggered_observed"] for e in entries]
            reach_times = [e["reached_time"] or e["censor"] for e in entries]
            reach_events = [e["reached_observed"] for e in entries]
            rows.append({
                "fuzzer": fuzzer,
                "stratum": stratum,
                "n_trial_bug_pairs": n,
                "triggered_frac": round(trig_obs / n, 4),
                "reached_frac": round(reach_obs / n, 4),
                "reached_only_frac_of_reached":
                    round(reach_only / reach_obs, 4) if reach_obs else 0.0,
                "km_median_trigger_seconds": km_median(trig_times, trig_events),
                "km_median_reach_seconds": km_median(reach_times, reach_events),
            })
    return rows


def compute_per_bug_stratum(pivot: dict, bugs: dict[str, BugInfo]) -> list[dict]:
    per_bug: dict[str, list[dict]] = defaultdict(list)
    for entry in pivot.values():
        per_bug[entry["bug_id"]].append(entry)

    rows = []
    for bug_id, info in sorted(bugs.items()):
        entries = per_bug.get(bug_id, [])
        n = len(entries)
        trig_obs = sum(e["triggered_observed"] for e in entries)
        reach_obs = sum(e["reached_observed"] for e in entries)
        reach_only = sum(
            1 for e in entries
            if e["reached_observed"] and not e["triggered_observed"]
        )
        trig_times = [e["triggered_time"] or e["censor"] for e in entries] if entries else []
        trig_events = [e["triggered_observed"] for e in entries] if entries else []
        reach_times = [e["reached_time"] or e["censor"] for e in entries] if entries else []
        reach_events = [e["reached_observed"] for e in entries] if entries else []
        rows.append({
            "bug_id": bug_id,
            "stratum": info.stratum,
            "dispatch_value": info.dispatch_value,
            "bit_index": info.bit_index if info.bit_index is not None else "",
            "crash_file": info.crash_file or "",
            "crash_line": info.crash_line if info.crash_line is not None else "",
            "n_trials": n,
            "triggered_trials": trig_obs,
            "reached_trials": reach_obs,
            "reached_not_triggered": reach_only,
            "reached_only_frac_of_reached":
                round(reach_only / reach_obs, 4) if reach_obs else 0.0,
            "km_median_trigger_seconds": km_median(trig_times, trig_events),
            "km_median_reach_seconds": km_median(reach_times, reach_events),
        })
    return rows


def compute_reached_vs_triggered(pivot: dict, bugs: dict[str, BugInfo]) -> list[dict]:
    per_key: dict[tuple[str, str, str, str], dict] = defaultdict(
        lambda: {"reached": 0, "triggered": 0, "reached_not_triggered": 0, "n": 0}
    )
    for entry in pivot.values():
        bug = bugs.get(entry["bug_id"])
        if bug is None:
            continue
        k = (entry["fuzzer"], bug.stratum, entry["bug_id"], str(bug.dispatch_value))
        acc = per_key[k]
        acc["n"] += 1
        acc["reached"] += entry["reached_observed"]
        acc["triggered"] += entry["triggered_observed"]
        if entry["reached_observed"] and not entry["triggered_observed"]:
            acc["reached_not_triggered"] += 1

    rows = []
    for (fuzzer, stratum, bug_id, dv), acc in sorted(per_key.items()):
        rows.append({
            "fuzzer": fuzzer,
            "stratum": stratum,
            "bug_id": bug_id,
            "dispatch_value": int(dv),
            "trials": acc["n"],
            "reached": acc["reached"],
            "triggered": acc["triggered"],
            "reached_not_triggered": acc["reached_not_triggered"],
        })
    return rows


# ---------------------------------------------------------------------------
# Crash bit inference — reuses fuzzbench_triage stack matching
# ---------------------------------------------------------------------------


def infer_bits_from_crashes(db_path: Path, bug_metadata: dict,
                            bugs: dict[str, BugInfo], benchmark: str
                            ) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """Classify every crash in local.db against our target bugs.

    Returns (per_crash, per_fuzzer_bit, unmatched_by_key, unmatched_by_fuzzer).
    """
    bug_targets = _bug_targets_from_metadata(bug_metadata)
    if not bug_targets:
        return [], [], [], []

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        rows = cur.execute(
            "select trial.fuzzer, trial.id, crash.time, crash.crash_stacktrace, "
            "       crash.crash_key, crash.crash_type, crash.crash_state "
            "from crash join trial on crash.trial_id = trial.id "
            "where trial.preempted = 0 and trial.benchmark = ? "
            "order by trial.id, crash.time",
            (benchmark,),
        ).fetchall()
    finally:
        conn.close()

    per_crash = []
    per_fuzzer_bit_counter: dict[tuple[str, int], int] = defaultdict(int)
    per_fuzzer_total_gated: dict[str, int] = defaultdict(int)
    per_fuzzer_total_always: dict[str, int] = defaultdict(int)
    per_fuzzer_total_unmatched: dict[str, int] = defaultdict(int)
    per_fuzzer_total_all: dict[str, int] = defaultdict(int)
    unmatched_by_key_acc: dict[tuple[str, str], dict] = {}
    unmatched_trials_by_key: dict[tuple[str, str], set] = defaultdict(set)

    for fuzzer, trial_id, crash_time, stacktrace, crash_key, crash_type, crash_state in rows:
        per_fuzzer_total_all[fuzzer] += 1
        matched = _match_bug_ids_in_stacktrace(stacktrace or "", bug_targets)
        matched_bugs = [bugs[m] for m in matched if m in bugs]
        gated_matched = [b for b in matched_bugs if b.stratum == STRATUM_GATED]
        always_matched = [b for b in matched_bugs if b.stratum == STRATUM_ALWAYS]
        if gated_matched:
            per_fuzzer_total_gated[fuzzer] += 1
            for bug in gated_matched:
                if bug.bit_index is not None:
                    per_fuzzer_bit_counter[(fuzzer, bug.bit_index)] += 1
        elif always_matched:
            per_fuzzer_total_always[fuzzer] += 1
        else:
            per_fuzzer_total_unmatched[fuzzer] += 1
            key = (fuzzer, crash_key or "")
            # Trim newlines in crash_type / crash_state for CSV readability.
            ctype = (crash_type or "").replace("\n", " | ").strip()
            cstate = (crash_state or "").replace("\n", " | ").strip()
            if key not in unmatched_by_key_acc:
                unmatched_by_key_acc[key] = {
                    "fuzzer": fuzzer,
                    "crash_key": (crash_key or "").replace("\n", " | ").strip(),
                    "crash_type": ctype,
                    "top_state": cstate.split(" | ")[0] if cstate else "",
                    "count": 0,
                    "first_time": int(crash_time),
                }
            acc = unmatched_by_key_acc[key]
            acc["count"] += 1
            acc["first_time"] = min(acc["first_time"], int(crash_time))
            unmatched_trials_by_key[key].add(str(trial_id))

        per_crash.append({
            "fuzzer": fuzzer,
            "trial": str(trial_id),
            "crash_time": int(crash_time),
            "matched_bugs": ";".join(sorted(b.bug_id for b in matched_bugs)),
            "matched_strata": ";".join(sorted({b.stratum for b in matched_bugs})),
            "inferred_bits_set": ";".join(
                str(b.bit_index)
                for b in sorted(gated_matched, key=lambda x: x.bit_index or -1)
                if b.bit_index is not None
            ),
            "crash_key": (crash_key or "").replace("\n", " | ").strip(),
            "crash_type": (crash_type or "").replace("\n", " | ").strip(),
            "is_unmatched": int(not matched_bugs),
        })

    max_bit = max(
        (b.bit_index for b in bugs.values() if b.bit_index is not None),
        default=-1,
    )
    per_fuzzer_bit_rows = []
    fuzzers = sorted(set(per_fuzzer_total_gated) | set(per_fuzzer_total_always)
                     | set(per_fuzzer_total_unmatched))
    for fuzzer in fuzzers:
        total_gated = per_fuzzer_total_gated.get(fuzzer, 0)
        total_always = per_fuzzer_total_always.get(fuzzer, 0)
        for bit in range(max_bit + 1):
            c = per_fuzzer_bit_counter.get((fuzzer, bit), 0)
            per_fuzzer_bit_rows.append({
                "fuzzer": fuzzer,
                "bit": bit,
                "crashes_implying_bit_set": c,
                "gated_crashes_total": total_gated,
                "always_active_crashes_total": total_always,
                "fraction_of_gated_crashes":
                    round(c / total_gated, 4) if total_gated else 0.0,
            })

    unmatched_by_key = []
    for key, acc in sorted(unmatched_by_key_acc.items(),
                           key=lambda kv: (-kv[1]["count"], kv[0])):
        unmatched_by_key.append({
            "fuzzer": acc["fuzzer"],
            "crash_key": acc["crash_key"],
            "crash_type": acc["crash_type"],
            "top_state_frame": acc["top_state"],
            "occurrences": acc["count"],
            "trials_seen": len(unmatched_trials_by_key[key]),
            "first_crash_time_seconds": acc["first_time"],
        })

    unmatched_by_fuzzer = []
    for fuzzer in fuzzers:
        all_count = per_fuzzer_total_all.get(fuzzer, 0)
        matched_count = (per_fuzzer_total_gated.get(fuzzer, 0)
                         + per_fuzzer_total_always.get(fuzzer, 0))
        unmatched_count = per_fuzzer_total_unmatched.get(fuzzer, 0)
        unique_keys = sum(1 for (fz, _ck) in unmatched_by_key_acc if fz == fuzzer)
        unmatched_by_fuzzer.append({
            "fuzzer": fuzzer,
            "total_crashes": all_count,
            "matched_crashes": matched_count,
            "unmatched_crashes": unmatched_count,
            "matched_frac": round(matched_count / all_count, 4) if all_count else 0.0,
            "unmatched_unique_crash_keys": unique_keys,
        })

    return per_crash, per_fuzzer_bit_rows, unmatched_by_key, unmatched_by_fuzzer


# ---------------------------------------------------------------------------
# Optional raw crash byte extraction
# ---------------------------------------------------------------------------


def extract_crash_bytes(experiment_dir: Path, benchmark: str,
                        bug_metadata: dict,
                        bugs: dict[str, BugInfo]) -> list[dict]:
    n_dispatch = int(bug_metadata.get("dispatch_bytes", 1))
    rows = []
    exp_folders = experiment_dir / "experiment-folders"
    if not exp_folders.exists():
        return rows
    for fuzzer_dir in sorted(exp_folders.iterdir()):
        if not fuzzer_dir.is_dir() or not fuzzer_dir.name.startswith(benchmark + "-"):
            continue
        fuzzer = fuzzer_dir.name[len(benchmark) + 1:]
        for trial_dir in sorted(fuzzer_dir.iterdir()):
            if not trial_dir.is_dir():
                continue
            crashes_dir = trial_dir / "crashes"
            if not crashes_dir.exists():
                continue
            trial_id = trial_dir.name.split("-")[-1]
            for archive in sorted(crashes_dir.iterdir()):
                if not archive.name.endswith(".tar.gz") or archive.stat().st_size == 0:
                    continue
                try:
                    with tarfile.open(archive, "r:gz") as tf:
                        for member in tf.getmembers():
                            if not member.isfile():
                                continue
                            f = tf.extractfile(member)
                            if f is None:
                                continue
                            data = f.read(n_dispatch)
                            if len(data) < n_dispatch:
                                continue
                            dispatch_int = 0
                            for i in range(n_dispatch):
                                dispatch_int |= data[i] << (8 * i)
                            bit_flags = [
                                bug.bit_index for bug in bugs.values()
                                if bug.dispatch_value
                                and (dispatch_int & bug.dispatch_value)
                                and bug.bit_index is not None
                            ]
                            rows.append({
                                "fuzzer": fuzzer,
                                "trial": trial_id,
                                "archive": archive.name,
                                "filename": member.name,
                                "dispatch_hex": data.hex(),
                                "bits_set": ";".join(
                                    str(b) for b in sorted(bit_flags)),
                            })
                except (tarfile.TarError, OSError) as e:
                    logger.debug("Skip %s: %s", archive, e)
    return rows


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------


def write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def _fmt_seconds(value) -> str:
    if value in (None, ""):
        return "-"
    try:
        v = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f"{v/3600:.2f}h"


def write_markdown(out_dir: Path, stratum_rows: list[dict],
                   per_bug_rows: list[dict], bit_rows: list[dict],
                   reached_rows: list[dict], crash_count: int,
                   raw_crash_sample: int, benchmark: str,
                   coverage_available: bool,
                   missing_coverage_paths: list[str],
                   unmatched_by_key: list[dict],
                   unmatched_by_fuzzer: list[dict]) -> None:
    lines = ["# Transplant side-effect analysis", ""]
    lines.append(f"Benchmark: `{benchmark}`  ")
    lines.append(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%MZ')}"
    )
    lines.append("")
    lines.append(
        "Survival data is derived by calling `fuzzbench_triage`'s "
        "`scan_crash_dirs` (trigger times) and `scan_coverage_for_bugs` "
        "(reach times) on the experiment's `local.db` + per-trial coverage "
        "JSON snapshots."
    )
    lines.append("")
    if coverage_available:
        lines.append(
            "Reach data: live `scan_coverage_for_bugs` over "
            "`experiment-folders/*/trial-*/coverage/*.json.gz`."
        )
    else:
        lines.append(
            "> **Reach data is empty.** No usable per-trial coverage JSON "
            "snapshots were found under "
            "`experiment-folders/*/trial-*/coverage/*.json.gz`. No fallback "
            "is applied — `reached_frac` and `reached_only` columns below "
            "are all zero because the reach event was never observed."
        )
        if missing_coverage_paths:
            lines.append("")
            lines.append("<details><summary>Trial directories missing coverage data "
                         f"({len(missing_coverage_paths)})</summary>")
            lines.append("")
            lines.append("```")
            for p in missing_coverage_paths[:40]:
                lines.append(p)
            if len(missing_coverage_paths) > 40:
                lines.append(f"... and {len(missing_coverage_paths) - 40} more")
            lines.append("```")
            lines.append("</details>")
    lines.append("")

    lines.append("## §3.1 Gated vs. always-active — stratum summary")
    lines.append("")
    lines.append(
        "| fuzzer | stratum | trial×bug pairs | triggered frac | "
        "reached frac | reach-only / reached | KM median trigger | KM median reach |"
    )
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for r in stratum_rows:
        if r["n_trial_bug_pairs"] == 0:
            continue
        lines.append(
            "| {fuzzer} | {stratum} | {n} | {tf:.2%} | {rf:.2%} | {ro:.2%} | {kmt} | {kmr} |".format(
                fuzzer=r["fuzzer"],
                stratum=r["stratum"],
                n=r["n_trial_bug_pairs"],
                tf=r["triggered_frac"],
                rf=r["reached_frac"],
                ro=r["reached_only_frac_of_reached"],
                kmt=_fmt_seconds(r.get("km_median_trigger_seconds")),
                kmr=_fmt_seconds(r.get("km_median_reach_seconds")),
            )
        )
    lines.append("")
    lines.append(
        "`reach-only / reached` is the share of reached bugs that were never "
        "triggered — for gated bugs this is direct dispatch-cost evidence; "
        "for always-active bugs it is intrinsic difficulty. KM median is the "
        "nonparametric median time across the stratum; `-` means >50% still "
        "censored at the right-censor horizon."
    )
    lines.append("")

    lines.append("## Per-bug detail (sorted by stratum, then trigger count)")
    lines.append("")
    lines.append(
        "| bug | stratum | bit | trials | reached | triggered | reached_only | "
        "reach-only / reached | KM median trigger |"
    )
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for r in sorted(
            per_bug_rows,
            key=lambda r: (r["stratum"], -int(r["triggered_trials"] or 0), r["bug_id"])):
        lines.append(
            "| {b} | {s} | {bit} | {n} | {r_} | {t} | {ro} | {rof:.2%} | {kmt} |".format(
                b=r["bug_id"],
                s=r["stratum"],
                bit=r["bit_index"] if r["bit_index"] != "" else "-",
                n=r["n_trials"],
                r_=r["reached_trials"],
                t=r["triggered_trials"],
                ro=r["reached_not_triggered"],
                rof=r["reached_only_frac_of_reached"],
                kmt=_fmt_seconds(r.get("km_median_trigger_seconds")),
            )
        )
    lines.append("")

    if bit_rows:
        lines.append("## Crash bit inference (lower bound on dispatch bits set at crash time)")
        lines.append("")
        lines.append(
            f"Crashes analyzed: {crash_count}. Each row is a (fuzzer, "
            "dispatch bit) pair. `fraction_of_gated_crashes` is the share of "
            "that fuzzer's gated-bug crashes that imply this bit was set; "
            "multiple bits can be set at once, so fractions do not sum to 1."
        )
        lines.append("")
        lines.append(
            "| fuzzer | bit | crashes_implying_set | gated_crashes_total | fraction |"
        )
        lines.append("| --- | ---: | ---: | ---: | ---: |")
        for r in bit_rows:
            lines.append(
                "| {f} | {b} | {c} | {tg} | {fr:.2%} |".format(
                    f=r["fuzzer"], b=r["bit"],
                    c=r["crashes_implying_bit_set"],
                    tg=r["gated_crashes_total"],
                    fr=r["fraction_of_gated_crashes"],
                )
            )
        lines.append("")

    if raw_crash_sample:
        lines.append(
            f"Raw dispatch-byte extraction: {raw_crash_sample} crash inputs "
            "sampled. See `crash_bytes.csv`."
        )
    else:
        lines.append(
            "Raw dispatch-byte extraction skipped: crash archives under "
            "`experiment-folders/*/crashes/` are zero-size or missing."
        )
    lines.append("")

    lines.append("## Reached-but-not-triggered asymmetry")
    lines.append("")
    stratum_counts: dict[str, dict[str, int]] = {
        STRATUM_GATED: {"reached": 0, "triggered": 0, "reached_only": 0, "n": 0},
        STRATUM_ALWAYS: {"reached": 0, "triggered": 0, "reached_only": 0, "n": 0},
    }
    for r in reached_rows:
        bucket = stratum_counts[r["stratum"]]
        bucket["reached"] += r["reached"]
        bucket["triggered"] += r["triggered"]
        bucket["reached_only"] += r["reached_not_triggered"]
        bucket["n"] += r["trials"]
    lines.append(
        "| stratum | trial×bug pairs | reached | triggered | reached_only | reached_only share |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for stratum in (STRATUM_GATED, STRATUM_ALWAYS):
        b = stratum_counts[stratum]
        share = b["reached_only"] / b["reached"] if b["reached"] else 0.0
        lines.append(
            f"| {stratum} | {b['n']} | {b['reached']} | {b['triggered']} | "
            f"{b['reached_only']} | {share:.2%} |"
        )
    lines.append("")

    # Unmatched crashes — crashes whose stacktrace did not match any of our
    # target bugs. Useful for catching bugs outside the transplant set,
    # dispatch-induced noise, or harness issues.
    lines.append("## Unmatched crashes (outside target bug set)")
    lines.append("")
    lines.append(
        "Crashes whose stacktrace did not match any transplanted bug's "
        "crash_file:crash_line (and, when applicable, sanitizer signature). "
        "These are bugs the fuzzer found that we didn't transplant — could be "
        "unrelated real bugs, harness/infrastructure crashes, or dispatch-"
        "mechanism-induced crashes. Full per-crash rows in `bit_inference.csv` "
        "with `is_unmatched=1`."
    )
    lines.append("")
    if unmatched_by_fuzzer:
        lines.append(
            "| fuzzer | total crashes | matched | unmatched | matched frac | unique unmatched crash_keys |"
        )
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
        for r in unmatched_by_fuzzer:
            lines.append(
                f"| {r['fuzzer']} | {r['total_crashes']} | "
                f"{r['matched_crashes']} | {r['unmatched_crashes']} | "
                f"{r['matched_frac']:.2%} | {r['unmatched_unique_crash_keys']} |"
            )
        lines.append("")
        if unmatched_by_key:
            lines.append("### Top unmatched crash signatures (highest occurrence)")
            lines.append("")
            lines.append(
                "| fuzzer | crash_type | top_state_frame | occurrences | trials_seen |"
            )
            lines.append("| --- | --- | --- | ---: | ---: |")
            for r in unmatched_by_key[:30]:
                ctype_short = (r["crash_type"] or "").split(" | ")[0]
                lines.append(
                    f"| {r['fuzzer']} | `{ctype_short}` | "
                    f"`{r['top_state_frame']}` | {r['occurrences']} | "
                    f"{r['trials_seen']} |"
                )
            if len(unmatched_by_key) > 30:
                lines.append("")
                lines.append(f"… and {len(unmatched_by_key) - 30} more. "
                             "See `unmatched_crashes_by_key.csv`.")
            lines.append("")
    else:
        lines.append("No crashes, or all crashes matched a target bug.")
        lines.append("")

    (out_dir / "side_effect_summary.md").write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def auto_detect_benchmark(experiment_dir: Path,
                          bug_metadata: dict) -> str:
    default = f"{bug_metadata['project']}_transplant"
    exp_folders = experiment_dir / "experiment-folders"
    if not exp_folders.exists():
        return default
    prefixes: set[str] = set()
    for d in exp_folders.iterdir():
        if not d.is_dir():
            continue
        idx = d.name.rfind("-")
        if idx > 0:
            prefixes.add(d.name[:idx])
    if len(prefixes) == 1:
        return prefixes.pop()
    return default


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-dir", required=True, type=Path,
                        help="FuzzBench experiment dir containing local.db "
                             "and experiment-folders/")
    parser.add_argument("--bug-metadata", required=True, type=Path,
                        help="Path to bug_metadata.json")
    parser.add_argument("--benchmark",
                        help="Benchmark name (auto-detected when a single "
                             "benchmark is present)")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)

    bug_metadata = load_bug_metadata(args.bug_metadata)
    bugs = build_bug_index(bug_metadata)
    n_gated = sum(1 for b in bugs.values() if b.stratum == STRATUM_GATED)
    n_always = sum(1 for b in bugs.values() if b.stratum == STRATUM_ALWAYS)
    logger.info("Bugs: %d gated, %d always-active (total %d)",
                n_gated, n_always, len(bugs))

    benchmark = args.benchmark or auto_detect_benchmark(args.experiment_dir, bug_metadata)
    logger.info("Benchmark: %s", benchmark)

    db_path = resolve_local_db_path(args.experiment_dir)
    if db_path is None:
        logger.error("local.db not found under %s", args.experiment_dir)
        sys.exit(1)

    trials_by_fuzzer, censor = load_trial_inventory(db_path, benchmark)
    logger.info("Found %d fuzzers, %d trials; right-censor at %ds (%.1fh)",
                len(trials_by_fuzzer),
                sum(len(t) for t in trials_by_fuzzer.values()),
                censor, censor / 3600)

    logger.info("scan_crash_dirs: matching crashes to bugs via stacktrace")
    crash_results = scan_crash_dirs(args.experiment_dir, benchmark, bug_metadata)
    logger.info("  %d (fuzzer, trial, bug) crash entries", len(crash_results))

    logger.info("scan_coverage_for_bugs: checking crash-line coverage")
    coverage_results = scan_coverage_for_bugs(
        args.experiment_dir, benchmark, bug_metadata, None, crash_results)
    logger.info("  %d (fuzzer, trial, bug) coverage-reached entries",
                len(coverage_results))
    coverage_available = bool(coverage_results)
    missing_coverage_paths: list[str] = []
    if not coverage_available:
        missing_coverage_paths = sorted_missing_coverage(
            args.experiment_dir, benchmark)
        logger.warning(
            "No per-trial coverage archives found (checked %d trial dirs). "
            "Reach data will be left empty.", len(missing_coverage_paths),
        )

    pivot = build_pivot(
        trials_by_fuzzer, sorted(bugs), crash_results,
        coverage_results if coverage_available else None, censor,
    )
    all_fuzzers = sorted(trials_by_fuzzer)
    logger.info("Pivot: %d (fuzzer, trial, bug) tuples", len(pivot))

    stratum_rows = compute_stratum_summary(pivot, bugs, all_fuzzers)
    write_csv(args.output_dir / "stratum_summary.csv",
              ["fuzzer", "stratum", "n_trial_bug_pairs", "triggered_frac",
               "reached_frac", "reached_only_frac_of_reached",
               "km_median_trigger_seconds", "km_median_reach_seconds"],
              stratum_rows)

    per_bug_rows = compute_per_bug_stratum(pivot, bugs)
    write_csv(args.output_dir / "per_bug_stratum.csv",
              ["bug_id", "stratum", "dispatch_value", "bit_index",
               "crash_file", "crash_line", "n_trials",
               "triggered_trials", "reached_trials",
               "reached_not_triggered", "reached_only_frac_of_reached",
               "km_median_trigger_seconds", "km_median_reach_seconds"],
              per_bug_rows)

    reached_rows = compute_reached_vs_triggered(pivot, bugs)
    write_csv(args.output_dir / "reached_vs_triggered.csv",
              ["fuzzer", "stratum", "bug_id", "dispatch_value", "trials",
               "reached", "triggered", "reached_not_triggered"],
              reached_rows)

    per_crash_rows, bit_rows, unmatched_by_key, unmatched_by_fuzzer = \
        infer_bits_from_crashes(db_path, bug_metadata, bugs, benchmark)
    write_csv(args.output_dir / "bit_inference.csv",
              ["fuzzer", "trial", "crash_time", "matched_bugs",
               "matched_strata", "inferred_bits_set",
               "crash_key", "crash_type", "is_unmatched"],
              per_crash_rows)
    write_csv(args.output_dir / "bit_frequency_by_fuzzer.csv",
              ["fuzzer", "bit", "crashes_implying_bit_set",
               "gated_crashes_total", "always_active_crashes_total",
               "fraction_of_gated_crashes"],
              bit_rows)
    write_csv(args.output_dir / "unmatched_crashes_by_key.csv",
              ["fuzzer", "crash_key", "crash_type", "top_state_frame",
               "occurrences", "trials_seen", "first_crash_time_seconds"],
              unmatched_by_key)
    write_csv(args.output_dir / "unmatched_crashes_by_fuzzer.csv",
              ["fuzzer", "total_crashes", "matched_crashes",
               "unmatched_crashes", "matched_frac",
               "unmatched_unique_crash_keys"],
              unmatched_by_fuzzer)
    unmatched_total = sum(r["unmatched_crashes"] for r in unmatched_by_fuzzer)
    logger.info(
        "Crash classification: %d total, %d matched to target bugs, %d unmatched (%d unique crash_keys)",
        len(per_crash_rows),
        sum(r["matched_crashes"] for r in unmatched_by_fuzzer),
        unmatched_total,
        len(unmatched_by_key),
    )

    raw_rows = extract_crash_bytes(args.experiment_dir, benchmark,
                                   bug_metadata, bugs)
    if raw_rows:
        write_csv(args.output_dir / "crash_bytes.csv",
                  ["fuzzer", "trial", "archive", "filename",
                   "dispatch_hex", "bits_set"], raw_rows)
        logger.info("Raw crash-byte extraction: %d inputs sampled",
                    len(raw_rows))

    write_markdown(args.output_dir, stratum_rows, per_bug_rows, bit_rows,
                   reached_rows, len(per_crash_rows), len(raw_rows), benchmark,
                   coverage_available, missing_coverage_paths,
                   unmatched_by_key, unmatched_by_fuzzer)
    logger.info("Wrote outputs to %s", args.output_dir)


if __name__ == "__main__":
    main()
