#!/usr/bin/env python3
"""Analyze crash/bug duplication at three levels for a transplant benchmark.

Level 1  Inter-bug duplication inside the transplanted set.  Different OSV IDs
         may have identical (file, line, function) crash locations, or
         near-identical top-N stack frames — the transplant workflow takes
         them as separate bugs but they are the same issue.

Level 2  "Unmatched" fuzz crashes that are actually the same bug as one of
         the transplanted targets.  Our stacktrace matcher misses them when
         the reported line differs due to macro expansion, inlining, or
         compiler version, even though top-N frames are the same.

Level 3  Duplication within the unmatched fuzz crash set itself.  Hundreds of
         distinct ``crash_key`` values collapse onto a much smaller number of
         underlying bugs once you fingerprint on top-N frames.

Usage:
    python3 script/sideeffect/duplication_report.py \
        --benchmark-dir fuzzbench/benchmarks/c-blosc2_transplant_decompress_frame_fuzzer \
        --experiment-db /mnt/.../local.db \
        --sideeffect-dir /mnt/.../sideeffect \
        --output /mnt/.../duplication_analysis.md
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fuzzbench_triage import (  # noqa: E402
    _bug_targets_from_metadata,
    _match_bug_ids_in_stacktrace,
    load_bug_metadata as load_bug_metadata_with_refs,
)

FRAME_RE = re.compile(
    r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+(/src/[^:\n]+)(?::(\d+))?",
    re.MULTILINE,
)
ERROR_LINE_RE = re.compile(r"==ERROR:\s*AddressSanitizer:\s*(.+?)(?=\s+on|\s+address|\s*$)",
                           re.MULTILINE)

PROJECT_FILE_PREFIX = "/src/"


def extract_frames(stacktrace: str) -> list[tuple[str, str, int | None]]:
    """Return list of (function, file, line) from ASAN frames, project source only."""
    frames: list[tuple[str, str, int | None]] = []
    for m in FRAME_RE.finditer(stacktrace or ""):
        func = m.group(1).strip()
        filepath = m.group(2).strip()
        line = int(m.group(3)) if m.group(3) else None
        if not filepath.startswith(PROJECT_FILE_PREFIX):
            continue
        rel = "/".join(filepath.split("/")[3:])  # strip "/src/<proj>/"
        frames.append((func, rel, line))
    return frames


def extract_error_class(stacktrace: str) -> str:
    m = ERROR_LINE_RE.search(stacktrace or "")
    if not m:
        return "?"
    return m.group(1).strip().split("\n")[0]


def _frames_ff(frames):
    """Drop line numbers — produce (function, file) tuples for loose fingerprinting."""
    return [(f, p) for f, p, _ in frames]


def fingerprint(frames, depth: int = 3, with_line: bool = False) -> tuple:
    """Top-N fingerprint. If ``with_line`` is False (default), drop line numbers."""
    if with_line:
        return tuple(frames[:depth])
    return tuple(_frames_ff(frames)[:depth])


def load_bug_crashes(benchmark_dir: Path) -> dict[str, dict]:
    """Read crashes/<bug_id>.txt reference crashes and fingerprint each.

    Stores two top-3 fingerprints per bug — one with line numbers (strict)
    and one without (loose, (function, file) only).
    """
    bugs_dir = benchmark_dir / "crashes"
    out: dict[str, dict] = {}
    if not bugs_dir.exists():
        return out
    for txt in sorted(bugs_dir.glob("*.txt")):
        bug_id = txt.stem
        text = txt.read_text(errors="replace")
        frames = extract_frames(text)
        out[bug_id] = {
            "frames": frames,
            "fingerprint_ff": fingerprint(frames, 3, with_line=False),
            "fingerprint_ffl": fingerprint(frames, 3, with_line=True),
            "error_class": extract_error_class(text),
        }
    return out


def load_bug_metadata(benchmark_dir: Path) -> dict:
    path = benchmark_dir / "bug_metadata.json"
    with open(path) as f:
        return json.load(f)


def group_bugs_by_location(metadata: dict) -> tuple[list[tuple[tuple, list[str]]], list[str]]:
    """Group bugs by (crash_file, crash_line, crash_function).

    Bugs that lack all three fields (no reference crash was captured) are not
    grouped — those are returned as a flat list so the report does not count
    them as one big duplicate cluster.
    """
    by_loc: dict[tuple, list[str]] = defaultdict(list)
    no_location: list[str] = []
    for bug_id, info in metadata["bugs"].items():
        f = info.get("crash_file") or ""
        ln = info.get("crash_line")
        fn = info.get("crash_function") or ""
        if not f and ln is None and not fn:
            no_location.append(bug_id)
            continue
        by_loc[(f, ln, fn)].append(bug_id)
    groups = sorted(
        [(k, sorted(v)) for k, v in by_loc.items()],
        key=lambda kv: (-len(kv[1]), kv[0]),
    )
    return groups, sorted(no_location)


def group_bugs_by_fingerprint(bug_crashes: dict, depth: int = 3,
                               with_line: bool = False
                               ) -> list[tuple[tuple, list[str]]]:
    """Group bugs whose reference crashes share top-N frames.

    ``with_line`` toggles between the loose (function, file) key and the
    strict (function, file, line) key.
    """
    by_fp: dict[tuple, list[str]] = defaultdict(list)
    for bug_id, info in bug_crashes.items():
        fp = fingerprint(info["frames"], depth, with_line=with_line)
        if not fp:
            continue
        by_fp[fp].append(bug_id)
    return sorted(
        [(k, sorted(v)) for k, v in by_fp.items()],
        key=lambda kv: (-len(kv[1]), kv[0]),
    )


def load_unmatched_crashes(db_path: Path, benchmark: str) -> list[dict]:
    """For each unique (fuzzer, crash_key) unmatched crash, pull one full stack."""
    # First, find matched bug_ids for each crash per our existing matcher to
    # classify unmatched — but we'd double the work; instead, rely on the
    # fact that the side-effect output already exported unmatched_crashes_by_key.csv.
    # Here we just pull every distinct (crash_type, crash_state) and a sample
    # stacktrace for each.
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        rows = cur.execute(
            "select trial.fuzzer, crash.crash_key, crash.crash_type, "
            "       crash.crash_state, crash.crash_stacktrace, count(*) "
            "from crash join trial on crash.trial_id = trial.id "
            "where trial.preempted = 0 and trial.benchmark = ? "
            "group by trial.fuzzer, crash.crash_key, crash.crash_type, "
            "         crash.crash_state "
            "order by count(*) desc",
            (benchmark,),
        ).fetchall()
    finally:
        conn.close()
    out = []
    for fuzzer, key, ctype, cstate, stack, count in rows:
        out.append({
            "fuzzer": fuzzer,
            "crash_key": key or "",
            "crash_type": (ctype or "").replace("\n", " | "),
            "crash_state": (cstate or "").replace("\n", " | ").strip(),
            "stacktrace": stack or "",
            "count": count,
        })
    return out


def normalize_crash_key(key: str) -> str:
    """Canonical form for a crash_key regardless of storage format.

    Collapses both `\\n` and `|` frame separators to spaces, trims trailing
    separator punctuation, and canonicalizes whitespace.
    """
    s = (key or "").replace("|", "\n")
    s = re.sub(r"\s+", " ", s)
    return s.strip(" \t|")


def load_unmatched_keys(sideeffect_dir: Path) -> set[tuple[str, str]]:
    """Read which (fuzzer, crash_key) the triage flagged as unmatched."""
    path = sideeffect_dir / "unmatched_crashes_by_key.csv"
    out: set[tuple[str, str]] = set()
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            out.add((r["fuzzer"], normalize_crash_key(r["crash_key"])))
    return out


def fingerprint_unmatched(unmatched_rows: list[dict],
                          unmatched_keys: set[tuple[str, str]]
                          ) -> list[dict]:
    """Attach both loose and strict top-3 frame fingerprints to unmatched crashes."""
    out = []
    for r in unmatched_rows:
        key = (r["fuzzer"], normalize_crash_key(r["crash_key"]))
        if key not in unmatched_keys:
            continue
        frames = extract_frames(r["stacktrace"])
        out.append({
            **r,
            "frames": frames,
            "fingerprint_ff": fingerprint(frames, 3, with_line=False),
            "fingerprint_ffl": fingerprint(frames, 3, with_line=True),
            "top_function": frames[0][0] if frames else "",
        })
    return out


def fingerprint_all(rows: list[dict]) -> list[dict]:
    """Attach top-3 and full-stack frame fingerprints to every crash row.

    * ``fingerprint_ff`` / ``fingerprint_ffl`` — top-3 (function, file)
      and (function, file, line) — used for Level 1 and the loose
      bug-matcher.
    * ``fingerprint_full`` — *every* project frame as `(func, file, line)`,
      used for the B column in the Crashes A/B/C table.  Two crashes
      share a B fingerprint only when their full stack is identical.
    """
    out = []
    for r in rows:
        frames = extract_frames(r["stacktrace"])
        out.append({
            **r,
            "frames": frames,
            "fingerprint_ff": fingerprint(frames, 3, with_line=False),
            "fingerprint_ffl": fingerprint(frames, 3, with_line=True),
            "fingerprint_full": tuple(frames),
            "top_function": frames[0][0] if frames else "",
        })
    return out


_SANITIZER_PATH_MARKERS = (
    "compiler-rt/lib/asan/",
    "compiler-rt/lib/tsan/",
    "compiler-rt/lib/msan/",
    "compiler-rt/lib/ubsan/",
    "compiler-rt/lib/hwasan/",
)


def _project_top3_funcs(frames) -> tuple[str, ...]:
    """Top-3 function names with sanitizer interceptor frames skipped.

    Matches FuzzBench clusterfuzz `crash_state`, which strips ASAN/TSAN/
    MSAN/UBSAN interceptor frames before taking the top 3.
    """
    filtered = [
        f for f in frames
        if not any(marker in f[1] for marker in _SANITIZER_PATH_MARKERS)
    ]
    return tuple(f[0] for f in filtered[:3])


def _bug_state_map(bug_crashes: dict) -> dict[tuple[str, ...], set[str]]:
    """Map each bug's sanitizer-stripped top-3 function names → bug_ids."""
    out: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for bug_id, info in bug_crashes.items():
        top3 = _project_top3_funcs(info.get("frames", []))
        if top3:
            out[top3].add(bug_id)
    return out


def _crash_state_top3(crash_state: str) -> tuple[str, ...]:
    """Parse a DB `crash_state` value into the top-3 function names tuple.

    `crash_state` comes from FuzzBench clusterfuzz triage; in the DB it's
    newline-separated, and we flatten it to `' | '`-separated when loading.
    """
    state = (crash_state or "").replace("\n", " | ")
    parts = [s.strip() for s in state.split("|") if s.strip()]
    return tuple(parts[:3])


def compute_overview(all_crashes: list[dict],
                     bug_targets: list,
                     bug_crashes: dict) -> dict:
    """Compute A/B/C headline + per-level bug overlap.

    A/B/C are dedup keys; each level has a matching rule against the
    canonical bug set in ``crashes/``:
    * **A** — individual crash occurrence.  Matches a bug when its
      stacktrace triages to one via
      ``fuzzbench_triage._match_bug_ids_in_stacktrace``.
    * **B** — full-stack `(func, file, line)` tuple as the dedup key;
      the match rule is the same full-stack-aware
      ``fuzzbench_triage._match_bug_ids_in_stacktrace`` (looks for any
      frame whose ``(crash_file, crash_line)`` matches a bug, with
      reference-stack and sanitizer-signature tie-breaking).  A B
      fingerprint counts as matched when any crash sharing it triages
      to a bug.
    * **C** — FuzzBench ``crash_key`` as the dedup key; the match rule
      is ``crash_state`` (sanitizer-stripped top-3 function names)
      equality with a bug reference stack.  ``crash_type`` isn't
      compared because FuzzBench's normalized types don't line up with
      the raw ASAN summary strings in the reference crashes.

    The union of B and C hits per row forms the candidate set; each
    row's candidates are emitted in the rendered markdown for a manual
    pass.
    """
    bug_c_map = _bug_state_map(bug_crashes)

    a_total = 0
    a_matched = 0
    b_fps: set[tuple] = set()
    b_matched_fps: set[tuple] = set()
    c_keys: set[str] = set()
    c_matched_keys: set[str] = set()
    candidates: dict[str, dict] = {}

    for r in all_crashes:
        count = r["count"]
        a_total += count

        full = r.get("fingerprint_full")
        key = normalize_crash_key(r.get("crash_key") or "")
        top3 = _crash_state_top3(r.get("crash_state") or "")

        if full:
            b_fps.add(full)
        if key:
            c_keys.add(key)

        b_hits = _match_bug_ids_in_stacktrace(
            r.get("stacktrace") or "", bug_targets)
        c_hits = bug_c_map.get(top3, set()) if top3 else set()
        hits = b_hits | c_hits
        if not hits:
            continue

        a_matched += count
        if full and b_hits:
            b_matched_fps.add(full)
        if key and c_hits:
            c_matched_keys.add(key)

        if key:
            slot = candidates.setdefault(key, {
                "crash_key": key,
                "bug_ids": set(),
                "occurrences": 0,
            })
            slot["bug_ids"].update(hits)
            slot["occurrences"] += count

    candidate_list = sorted(
        (
            {**v, "bug_ids": sorted(v["bug_ids"])}
            for v in candidates.values()
        ),
        key=lambda x: x["crash_key"],
    )
    candidate_bugs: set[str] = set()
    for v in candidates.values():
        candidate_bugs.update(v["bug_ids"])

    return {
        "A": a_total,
        "B": len(b_fps),
        "C": len(c_keys),
        "A_matched": a_matched,
        "B_matched": len(b_matched_fps),
        "C_matched": len(c_matched_keys),
        "bugs_total": len(bug_targets),
        "bug_state_clusters": len(bug_c_map),
        "candidate_C": len(candidate_list),
        "candidate_bugs": len(candidate_bugs),
        "candidates": candidate_list,
    }


def cluster_by_fingerprint(unmatched: list[dict],
                            key: str = "fingerprint_ff") -> list[dict]:
    """Cluster unmatched crashes by a precomputed fingerprint key.

    ``key`` is either ``"fingerprint_ff"`` (top-3 function+file, no line) or
    ``"fingerprint_ffl"`` (top-3 function+file+line).
    """
    clusters: dict[tuple, dict] = {}
    for r in unmatched:
        fp = r.get(key)
        if not fp:
            fp = ("(no project frames)",)
        c = clusters.setdefault(fp, {
            "fingerprint": fp,
            "signature_count": 0,
            "occurrences": 0,
            "fuzzers": set(),
            "crash_types": Counter(),
            "example_state": "",
        })
        c["signature_count"] += 1
        c["occurrences"] += r["count"]
        c["fuzzers"].add(r["fuzzer"])
        c["crash_types"][r["crash_type"].split(" | ")[0]] += 1
        if not c["example_state"]:
            c["example_state"] = r["crash_state"][:120]
    out = []
    for fp, c in clusters.items():
        out.append({
            **c,
            "fuzzers": sorted(c["fuzzers"]),
            "top_crash_type": c["crash_types"].most_common(1)[0][0] if c["crash_types"] else "",
        })
    out.sort(key=lambda x: -x["occurrences"])
    return out


def match_unmatched_to_bugs(unmatched: list[dict],
                            bug_crashes: dict) -> list[dict]:
    """Flag unmatched crashes whose loose top-3 fingerprint matches a bug's."""
    bug_fps = {bid: info["fingerprint_ff"] for bid, info in bug_crashes.items()}
    results = []
    for r in unmatched:
        fp = r["fingerprint_ff"]
        if not fp:
            continue
        hits = [bid for bid, bfp in bug_fps.items() if bfp == fp]
        if hits:
            results.append({**r, "matching_bug_ids": sorted(hits)})
    return results


def fmt_frames(frames, depth: int = 5) -> str:
    lines = []
    for i, frame in enumerate(frames[:depth]):
        func, f = frame[0], frame[1]
        line = frame[2] if len(frame) > 2 and frame[2] is not None else None
        suffix = f":{line}" if line is not None else ""
        lines.append(f"  #{i} `{func}` in `{f}{suffix}`")
    if not lines:
        lines.append("  (no project frames)")
    return "\n".join(lines)


def render_markdown(benchmark_name: str, bug_metadata: dict,
                    bug_crashes: dict,
                    bug_ff_groups: list, bug_ffl_groups: list,
                    unmatched: list[dict],
                    ff_clusters: list[dict], ffl_clusters: list[dict],
                    unmatched_matches_bug: list[dict],
                    ghostscript_example: dict | None,
                    fuzz_data_available: bool = True,
                    no_location_bugs: list[str] | None = None,
                    overview: dict | None = None) -> str:
    """Render a duplication report with the new two-table layout.

    Level 1 collapses transplanted bugs at three progressively-loose keys.
    The crashes section merges the old L2 + L3 into one table, dedup'd the
    same way.
    """
    no_location_bugs = no_location_bugs or []
    lines: list[str] = []
    lines.append(f"# Bug-and-crash duplication analysis — {benchmark_name}")
    lines.append("")
    lines.append(
        "The bug set below is the **merge output** for this benchmark — "
        "local bugs (already triggering at the target commit) and "
        "transplanted bugs combined — not only the transplanted subset."
    )
    lines.append("")
    lines.append(
        "Three sections: the headline A/B/C table (all fuzz crashes, "
        "three dedup keys, plus overlap with the bug set); Level 1 shows "
        "duplication inside the merge bug set; the Crashes table drills into "
        "the **unmatched** fuzz crashes — how FuzzBench's native `crash_key`s "
        "collapse when we apply the same fingerprint keys used for Level 1."
    )
    lines.append("")

    # ---- Headline: A/B/C over ALL fuzz crashes + per-level bug overlap
    if fuzz_data_available and overview:
        lines.append("## Headline — all crashes (A/B/C)")
        lines.append("")
        lines.append(
            "Scope: **every** crash recorded in `local.db` for this "
            "benchmark (all fuzzers and trials).  Three dedup keys "
            "applied globally.  The *matched to bug* row counts how "
            "many of those dedup'd items appear in the canonical bug "
            "set at `crashes/<OSV>.txt`:"
        )
        lines.append("")
        lines.append(
            "* **A match** — a crash occurrence whose B or C matches a bug."
        )
        lines.append(
            "* **B match** — the fuzz crash triages to a bug via "
            "`fuzzbench_triage._match_bug_ids_in_stacktrace`: any "
            "frame's `(crash_file, crash_line)` matches a bug's, with "
            "reference-stack and sanitizer-signature tie-breaking.  "
            "The B column counts distinct full-stack `(func, file, "
            "line)` fingerprints that triage to a bug."
        )
        lines.append(
            "* **C match** — the fuzz crash's `crash_state` (sanitizer-"
            "stripped top-3 function names — the function-name portion "
            "of the FuzzBench `crash_key`) equals a bug's `crash_state`.  "
            "`crash_type` isn't compared: FuzzBench's normalized types "
            "(`Heap-buffer-overflow`, `UNKNOWN READ`, …) don't line up "
            "with the raw ASAN summaries in the reference crashes."
        )
        lines.append("")
        lines.append(
            "| | A — all crashes (occurrences) | B — unique full-stack `(func, file, line)` | C — unique FuzzBench `crash_key` |"
        )
        lines.append("| --- | ---: | ---: | ---: |")
        lines.append(
            f"| total | {overview['A']:,} | {overview['B']} | {overview['C']} |"
        )
        lines.append(
            f"| matched to bug | {overview['A_matched']:,} / {overview['A']:,} | "
            f"{overview['B_matched']} / {overview['B']} | "
            f"{overview['C_matched']} / {overview['C']} |"
        )
        lines.append("")

        # ---- Candidate crash_key → bug_ids mapping (pre-manual-verification)
        lines.append("## Bug-set overlap — candidates")
        lines.append("")
        lines.append(
            f"The {overview['candidate_C']} crash_keys below are the C-"
            f"matched (or B-matched) ones from the headline — each "
            f"touches at least one OSV id from the merge set.  The "
            f"union covers **{overview['candidate_bugs']} distinct "
            f"bugs**.  Each row still needs a manual verdict to "
            f"confirm the root cause matches; see the verified section "
            f"below."
        )
        lines.append("")
        lines.append(
            "| # | `crash_key` (type : top-3 functions) | occurrences | candidate OSV ids |"
        )
        lines.append("| ---: | --- | ---: | --- |")
        for i, v in enumerate(overview["candidates"]):
            lines.append(
                f"| {i} | `{v['crash_key']}` | {v['occurrences']:,} | "
                f"{', '.join(v['bug_ids'])} |"
            )
        lines.append("")
        lines.append(
            f"Automated candidate totals (upper bound): "
            f"**{overview['candidate_C']} / {overview['C']} crash_keys** "
            f"touch at least one bug; **{overview['candidate_bugs']} / "
            f"{overview['bugs_total']} bugs** are touched."
        )
        lines.append("")

    # ---- Level 1: three dedup keys applied to the merge bug set
    lines.append("## Level 1 — duplication inside the merge bug set (local + transplanted)")
    lines.append("")
    total_bugs = len(bug_metadata["bugs"])
    # no_location bugs are opaque — each counts as its own "cluster" under any key.
    ff_bug_clusters = len(bug_ff_groups) + len(no_location_bugs)
    ffl_bug_clusters = len(bug_ffl_groups) + len(no_location_bugs)
    lines.append(
        "| raw OSV ids | top-3 `(func, file)` clusters | top-3 `(func, file, line)` clusters |"
    )
    lines.append("| ---: | ---: | ---: |")
    lines.append(
        f"| {total_bugs} | {ff_bug_clusters} | {ffl_bug_clusters} |"
    )
    lines.append("")
    if no_location_bugs:
        lines.append(
            f"> **{len(no_location_bugs)} bug(s)** have no crash location in "
            f"`bug_metadata.json` (no reference crash extracted).  They can't "
            f"be fingerprinted, so they are counted as distinct under every "
            f"key — inflating the `clusters` columns above by "
            f"`{len(no_location_bugs)}` each."
        )
        lines.append("")

    # Duplicate groups at each key
    dup_ff = [g for g in bug_ff_groups if len(g[1]) > 1]
    dup_ffl = [g for g in bug_ffl_groups if len(g[1]) > 1]
    if dup_ff:
        lines.append("### Bugs that share a top-3 `(function, file)` fingerprint")
        lines.append("")
        lines.append("| top-3 (func → func → func) | OSV ids | count |")
        lines.append("| --- | --- | ---: |")
        for fp, ids in dup_ff:
            chain = " → ".join(f[0] for f in fp)
            lines.append(f"| `{chain}` | {', '.join(ids)} | {len(ids)} |")
        lines.append("")
    if dup_ffl:
        lines.append("### Bugs that share a top-3 `(function, file, line)` fingerprint")
        lines.append("")
        lines.append(
            "Strict key: every frame must agree on its line number, not just "
            "`(function, file)`.  If this group is smaller than the previous "
            "one, some bugs share a call chain but differ on a line — usually "
            "from inlining/macro-expansion drift between commits."
        )
        lines.append("")
        lines.append("| top-3 (func → func → func, with lines) | OSV ids | count |")
        lines.append("| --- | --- | ---: |")
        for fp, ids in dup_ffl:
            parts = []
            for frame in fp:
                func, f, ln = frame[0], frame[1], frame[2] if len(frame) > 2 else None
                parts.append(f"{func}:{ln}" if ln is not None else func)
            lines.append(
                f"| `{' → '.join(parts)}` | {', '.join(ids)} | {len(ids)} |"
            )
        lines.append("")

    if ghostscript_example:
        lines.append("### Illustration — ghostscript OSV-2022-121 / OSV-2022-54")
        lines.append("")
        lines.append(
            "User-provided example: these two OSV ids both crash via the same "
            "`s_hex_process → s_exD_process → sreadbuf → …` chain, so the "
            "loose top-3 `(func, file)` key collapses them into one.  The "
            "strict `(func, file, line)` key keeps them apart (lines drift "
            "across commits because of inlining).  Trigger scope from "
            "`gstoraster_fuzzer.csv` shows disjoint commit windows, "
            "indicating they are actually sequential regressions, not a "
            "single bug — stack alone is therefore insufficient to decide."
        )
        lines.append("")

    # ---- Crashes section (merged L2 + L3)
    if not fuzz_data_available:
        lines.append("## Crashes (merged L2 + L3) — skipped")
        lines.append("")
        lines.append(
            "No `--experiment-db` / `--sideeffect-dir` provided.  "
            "Fuzz-crash clustering requires FuzzBench's `local.db` and the "
            "`unmatched_crashes_by_key.csv` emitted by "
            "`script/sideeffect/analyze.py`."
        )
        lines.append("")
        return "\n".join(lines) + "\n"

    total_sigs = len(unmatched)
    total_occ = sum(r["count"] for r in unmatched)
    lines.append("## Unmatched crashes — unified L2 + L3 table")
    lines.append("")
    lines.append(
        "Scope: **only** the fuzz crashes that FuzzBench's strict "
        "`(crash_file, crash_line)` triage flagged as unmatched.  Starts "
        "from FuzzBench's native `crash_key` (type + top-3 function names) "
        "for every such crash, then progressively collapses with the same "
        "top-3 fingerprint keys used above."
    )
    lines.append("")
    lines.append(
        "| unique FuzzBench `crash_key`s | top-3 `(func, file)` clusters | top-3 `(func, file, line)` clusters | fingerprint-matches a transplanted bug |"
    )
    lines.append("| ---: | ---: | ---: | ---: |")
    lines.append(
        f"| {total_sigs} | {len(ff_clusters)} | {len(ffl_clusters)} | "
        f"{len(unmatched_matches_bug)} |"
    )
    lines.append("")
    lines.append(
        f"For context, those `{total_sigs}` crash_keys represent **{total_occ:,} "
        f"total unmatched crash occurrences** across all fuzzers and trials.  "
        f"The last column re-uses the loose `(func, file)` key and counts "
        f"how many unmatched signatures land on the same fingerprint as a "
        f"bug from the Level 1 table — i.e. were mislabeled as unmatched by "
        f"the strict `(crash_file, crash_line)` matcher."
    )
    lines.append("")

    if unmatched_matches_bug:
        lines.append("### Unmatched signatures that fingerprint-match a transplanted bug")
        lines.append("")
        lines.append(
            "| matching OSV id(s) | unmatched top frame | crash type | occurrences | fuzzer |"
        )
        lines.append("| --- | --- | --- | ---: | --- |")
        for r in unmatched_matches_bug[:20]:
            ctype_short = r["crash_type"].split(" | ")[0]
            lines.append(
                f"| {', '.join(r['matching_bug_ids'])} | "
                f"`{(r['frames'][0][0] if r['frames'] else '?')}` | "
                f"`{ctype_short}` | {r['count']:,} | {r['fuzzer']} |"
            )
        if len(unmatched_matches_bug) > 20:
            lines.append("")
            lines.append(f"…and {len(unmatched_matches_bug) - 20} more.")
        lines.append("")

    lines.append("### Top clusters after top-3 `(func, file)` collapse")
    lines.append("")
    lines.append(
        "| top-3 (func → func → func) | unique signatures | total occurrences | fuzzers | top crash_type |"
    )
    lines.append("| --- | ---: | ---: | ---: | --- |")
    for c in ff_clusters[:15]:
        fp = c["fingerprint"]
        chain = (" → ".join(f[0] for f in fp)
                 if fp and isinstance(fp[0], tuple) else str(fp))
        lines.append(
            f"| `{chain}` | {c['signature_count']} | {c['occurrences']:,} | "
            f"{len(c['fuzzers'])} | `{c['top_crash_type']}` |"
        )
    lines.append("")

    # ---- Summary
    lines.append("## Summary")
    lines.append("")
    if overview:
        lines.append(
            f"* **All fuzz crashes (A/B/C):** {overview['A']:,} occurrences → "
            f"{overview['B']} unique full-stack `(func, file, line)` → "
            f"{overview['C']} unique FuzzBench `crash_key`s."
        )
        lines.append(
            f"* **Bug overlap at each A/B/C level:** "
            f"A {overview['A_matched']:,} / {overview['A']:,}, "
            f"B {overview['B_matched']} / {overview['B']}, "
            f"C {overview['C_matched']} / {overview['C']}.  "
            f"Candidate bugs (union of B and C matches): "
            f"{overview['candidate_bugs']} / {overview['bugs_total']}."
        )
    lines.append(
        f"* **Merge bug set (local + transplanted):** {total_bugs} raw OSV ids → "
        f"{ff_bug_clusters} loose clusters → {ffl_bug_clusters} strict "
        f"clusters."
    )
    lines.append(
        f"* **Unmatched fuzz crashes:** {total_sigs} FuzzBench crash_keys → "
        f"{len(ff_clusters)} loose clusters → {len(ffl_clusters)} strict "
        f"clusters.  {len(unmatched_matches_bug)} unmatched signatures are "
        f"actually hits on a bug in the merge set once line numbers are "
        f"ignored."
    )
    lines.append("")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-dir", required=True, type=Path,
                        help="FuzzBench benchmark dir with crashes/ and bug_metadata.json")
    parser.add_argument("--experiment-db", type=Path,
                        help="FuzzBench local.db for the experiment. If "
                             "omitted, only Level 1 analysis is produced.")
    parser.add_argument("--benchmark-name",
                        help="benchmark key in local.db (auto-detected)")
    parser.add_argument("--sideeffect-dir", type=Path,
                        help="Output dir from script/sideeffect/analyze.py "
                             "(required unless --experiment-db is also omitted).")
    parser.add_argument("--ghostscript-example", action="store_true",
                        help="Include the user-provided ghostscript OSV-2022-121 / OSV-2022-54 illustration")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    metadata = load_bug_metadata(args.benchmark_dir)
    bug_crashes = load_bug_crashes(args.benchmark_dir)
    metadata_with_refs = load_bug_metadata_with_refs(
        args.benchmark_dir / "bug_metadata.json")
    bug_targets = _bug_targets_from_metadata(metadata_with_refs)
    benchmark_name = args.benchmark_name or args.benchmark_dir.name

    db_bench = args.benchmark_name or benchmark_name
    if args.experiment_db:
        conn = sqlite3.connect(args.experiment_db)
        try:
            rows = conn.execute("select distinct benchmark from trial").fetchall()
        finally:
            conn.close()
        db_benchmarks = [r[0] for r in rows]
        if args.benchmark_name:
            db_bench = args.benchmark_name
        elif len(db_benchmarks) == 1:
            db_bench = db_benchmarks[0]
        elif benchmark_name in db_benchmarks:
            db_bench = benchmark_name
        else:
            raise SystemExit(
                f"Ambiguous benchmark in DB: {db_benchmarks}; pass --benchmark-name"
            )

    _, no_location_bugs = group_bugs_by_location(metadata)
    bug_ff_groups = group_bugs_by_fingerprint(bug_crashes, 3, with_line=False)
    bug_ffl_groups = group_bugs_by_fingerprint(bug_crashes, 3, with_line=True)

    unmatched: list[dict] = []
    ff_clusters: list[dict] = []
    ffl_clusters: list[dict] = []
    unmatched_matches_bug: list[dict] = []
    overview: dict | None = None
    if args.experiment_db and args.sideeffect_dir:
        unmatched_keys = load_unmatched_keys(args.sideeffect_dir)
        raw_rows = load_unmatched_crashes(args.experiment_db, db_bench)
        all_crashes = fingerprint_all(raw_rows)
        overview = compute_overview(all_crashes, bug_targets, bug_crashes)
        unmatched = fingerprint_unmatched(raw_rows, unmatched_keys)
        ff_clusters = cluster_by_fingerprint(unmatched, key="fingerprint_ff")
        ffl_clusters = cluster_by_fingerprint(unmatched, key="fingerprint_ffl")
        unmatched_matches_bug = match_unmatched_to_bugs(unmatched, bug_crashes)

    ghostscript_example = {} if args.ghostscript_example else None

    md = render_markdown(benchmark_name, metadata, bug_crashes,
                        bug_ff_groups, bug_ffl_groups,
                        unmatched, ff_clusters, ffl_clusters,
                        unmatched_matches_bug,
                        ghostscript_example,
                        fuzz_data_available=bool(args.experiment_db and args.sideeffect_dir),
                        no_location_bugs=no_location_bugs,
                        overview=overview)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(md)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
