#!/usr/bin/env python3
"""Cross-benchmark classification of unmatched crashes.

Reads ``unmatched_crashes_by_key.csv`` from each side-effect output directory
and produces a single markdown report classifying the signatures by crash
type, dispatch-mechanism relevance, and (where applicable) source file.

Usage:
    python3 script/sideeffect/unmatched_report.py \
        --bench "c-blosc2=/path/to/c-blosc2/sideeffect" \
        --bench "htslib=/path/to/htslib/sideeffect" \
        --output /path/to/unmatched_analysis.md
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path


# Top-frame patterns that identify dispatch-mechanism / transplant-added code.
DISPATCH_FRAME_RE = re.compile(r"__bug_dispatch|bug_dispatch_link")

# Categorization rules. Order matters: first matching rule wins.
CRASH_TYPE_RULES = [
    ("resource/oom",       re.compile(r"(?i)\b(out-of-memory|oom|Rss-limit)")),
    ("resource/timeout",   re.compile(r"(?i)\b(timeout|deadly\-signal\-abrt)")),
    ("abort/assert",       re.compile(r"(?i)\b(abrt|abort|assert|unreachable)")),
    ("stack-overflow",     re.compile(r"(?i)stack[- ]overflow")),
    ("stack-buffer",       re.compile(r"(?i)stack-buffer")),
    ("heap-overflow",      re.compile(r"(?i)heap-buffer")),
    ("heap-use-after-free", re.compile(r"(?i)heap-use-after-free")),
    ("use-after-scope",    re.compile(r"(?i)(stack|heap)-use-after")),
    ("double-free",        re.compile(r"(?i)double-free")),
    ("null-deref",         re.compile(r"(?i)null-deref")),
    ("segv/unknown",       re.compile(r"(?i)\b(SEGV|UNKNOWN|deadlysignal)")),
    ("integer-overflow",   re.compile(r"(?i)integer-overflow")),
    ("undefined-behavior", re.compile(r"(?i)undefined")),
]


def classify_crash_type(crash_type: str) -> str:
    for name, pat in CRASH_TYPE_RULES:
        if pat.search(crash_type or ""):
            return name
    return "other"


def is_dispatch_frame(top_frame: str) -> bool:
    return bool(DISPATCH_FRAME_RE.search(top_frame or ""))


def read_unmatched(path: Path) -> list[dict]:
    rows = []
    with open(path, newline="") as f:
        for raw in csv.DictReader(f):
            rows.append({
                "fuzzer": raw["fuzzer"],
                "crash_key": raw["crash_key"],
                "crash_type": raw["crash_type"],
                "top_frame": raw["top_state_frame"],
                "occurrences": int(raw["occurrences"]),
                "trials_seen": int(raw["trials_seen"]),
                "first_time": int(raw["first_crash_time_seconds"]),
            })
    return rows


def summarize(rows: list[dict]) -> dict:
    """Aggregate unmatched rows into classification buckets."""
    total_occurrences = sum(r["occurrences"] for r in rows)
    total_keys = len(rows)

    by_bucket: dict[str, dict] = defaultdict(lambda: {"occ": 0, "keys": 0})
    dispatch_occ = 0
    dispatch_keys = 0
    for r in rows:
        bucket = classify_crash_type(r["crash_type"])
        by_bucket[bucket]["occ"] += r["occurrences"]
        by_bucket[bucket]["keys"] += 1
        if is_dispatch_frame(r["top_frame"]):
            dispatch_occ += r["occurrences"]
            dispatch_keys += 1

    # Top frames across all fuzzers (aggregated)
    frame_occ: Counter = Counter()
    frame_keys: Counter = Counter()
    for r in rows:
        frame_occ[r["top_frame"]] += r["occurrences"]
        frame_keys[r["top_frame"]] += 1

    # Top signatures (unique crash_key) by occurrence
    top_signatures = sorted(rows, key=lambda r: -r["occurrences"])[:10]

    # Per-fuzzer breakdown
    fuzzer_stats: dict[str, dict] = defaultdict(lambda: {"occ": 0, "keys": 0})
    for r in rows:
        fuzzer_stats[r["fuzzer"]]["occ"] += r["occurrences"]
        fuzzer_stats[r["fuzzer"]]["keys"] += 1

    return {
        "total_occurrences": total_occurrences,
        "total_keys": total_keys,
        "by_bucket": dict(by_bucket),
        "dispatch_occurrences": dispatch_occ,
        "dispatch_keys": dispatch_keys,
        "top_frames": frame_occ.most_common(10),
        "frame_key_counts": dict(frame_keys),
        "top_signatures": top_signatures,
        "fuzzer_stats": dict(fuzzer_stats),
    }


def render_markdown(summaries: dict[str, dict]) -> str:
    lines: list[str] = []
    lines.append("# Unmatched-crash analysis across transplant benchmarks")
    lines.append("")
    lines.append(
        "For each benchmark this report breaks down the crashes whose "
        "stacktrace did NOT match any transplanted bug target. Source data: "
        "`unmatched_crashes_by_key.csv` from each benchmark's `sideeffect/` "
        "output. Total counts reflect `occurrences` (sum over fuzzers and "
        "trials) — not the number of unique crash signatures."
    )
    lines.append("")

    # ------------------------------------------------------------------ Overview
    lines.append("## Overview")
    lines.append("")
    lines.append(
        "| benchmark | unmatched crashes | unique signatures | dispatch-frame occurrences | dispatch-frame unique sigs |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for name, s in summaries.items():
        lines.append(
            f"| {name} | {s['total_occurrences']:,} | {s['total_keys']:,} | "
            f"{s['dispatch_occurrences']:,} | {s['dispatch_keys']:,} |"
        )
    lines.append("")
    lines.append(
        "`dispatch-frame occurrences` counts crashes whose top frame is in "
        "`__bug_dispatch*` / `bug_dispatch_link*` — strong evidence of "
        "dispatch-mechanism-induced crashes (not real project bugs)."
    )
    lines.append("")

    # ---------------------------------------------------- Per-category breakdown
    lines.append("## Crash-type buckets per benchmark")
    lines.append("")
    all_buckets: set[str] = set()
    for s in summaries.values():
        all_buckets.update(s["by_bucket"].keys())
    ordered = [
        "heap-overflow", "stack-buffer", "heap-use-after-free", "use-after-scope",
        "double-free", "null-deref", "stack-overflow", "abort/assert",
        "segv/unknown", "integer-overflow", "undefined-behavior",
        "resource/oom", "resource/timeout", "other",
    ]
    ordered_present = [b for b in ordered if b in all_buckets] + [
        b for b in sorted(all_buckets) if b not in ordered
    ]
    header = "| benchmark | " + " | ".join(ordered_present) + " |"
    lines.append(header)
    lines.append("| --- | " + " | ".join("---:" for _ in ordered_present) + " |")
    for name, s in summaries.items():
        cells: list[str] = []
        for bucket in ordered_present:
            occ = s["by_bucket"].get(bucket, {"occ": 0, "keys": 0})["occ"]
            keys = s["by_bucket"].get(bucket, {"occ": 0, "keys": 0})["keys"]
            if occ == 0 and keys == 0:
                cells.append("-")
            else:
                cells.append(f"{occ:,} ({keys})")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    lines.append("")
    lines.append(
        "Cells show `occurrences (unique signatures)`. Buckets are assigned by "
        "crash_type regex in priority order: resource > assert > stack "
        "overflow > buffer overflows > UAF > null-deref > SEGV-generic."
    )
    lines.append("")

    # -------------------------------------------------- Per-benchmark detail
    for name, s in summaries.items():
        lines.append(f"## {name}")
        lines.append("")
        lines.append(
            f"Total unmatched crashes: **{s['total_occurrences']:,}** across "
            f"**{s['total_keys']:,}** unique `crash_key`s, from "
            f"{len(s['fuzzer_stats'])} fuzzers."
        )
        lines.append("")

        # Per-fuzzer breakdown
        lines.append("### Per-fuzzer unmatched volume")
        lines.append("")
        lines.append("| fuzzer | unmatched crashes | unique signatures |")
        lines.append("| --- | ---: | ---: |")
        for fuzzer in sorted(s["fuzzer_stats"]):
            st = s["fuzzer_stats"][fuzzer]
            lines.append(f"| {fuzzer} | {st['occ']:,} | {st['keys']} |")
        lines.append("")

        # Top frames
        lines.append("### Top crash frames (aggregated across fuzzers)")
        lines.append("")
        lines.append(
            "| top frame | occurrences | unique crash_keys |"
        )
        lines.append("| --- | ---: | ---: |")
        for frame, occ in s["top_frames"]:
            keys = s["frame_key_counts"].get(frame, 0)
            lines.append(
                f"| `{frame or '(unknown)'}` | {occ:,} | {keys} |"
            )
        lines.append("")

        # Top signatures (full context)
        lines.append("### Top 10 unique signatures by occurrence")
        lines.append("")
        lines.append(
            "| fuzzer | crash_type | top frame | occurrences | trials | first-seen (s) | dispatch? |"
        )
        lines.append(
            "| --- | --- | --- | ---: | ---: | ---: | :---: |"
        )
        for r in s["top_signatures"]:
            ctype_short = (r["crash_type"] or "").split(" | ")[0]
            disp = "yes" if is_dispatch_frame(r["top_frame"]) else ""
            lines.append(
                f"| {r['fuzzer']} | `{ctype_short}` | `{r['top_frame'] or '(unknown)'}` | "
                f"{r['occurrences']:,} | {r['trials_seen']} | {r['first_time']} | {disp} |"
            )
        lines.append("")

    # --------------------------------------------- Cross-benchmark takeaways
    lines.append("## Observations")
    lines.append("")
    lines.append(
        "Interpret unmatched crashes along three axes:"
    )
    lines.append("")
    lines.append(
        "1. **Real unpatched bugs at target commit** — real bugs in source code "
        "that we did not transplant. These are legitimate fuzzer finds the "
        "benchmark happens to exclude. Their top frames are in project source "
        "(not in `__bug_dispatch*`), and the crash_type is usually "
        "`heap-overflow`, `stack-buffer-overflow`, or `use-after-free`."
    )
    lines.append(
        "2. **Dispatch-mechanism artifacts** — crashes whose top frame is in "
        "`__bug_dispatch*` / `bug_dispatch_link*` helpers, or in code paths "
        "that only exist because of transplant patches. The `dispatch-frame` "
        "column in the overview isolates the first category; second category "
        "requires per-signature review."
    )
    lines.append(
        "3. **Harness / infrastructure noise** — timeouts, OOMs, libfuzzer "
        "internal aborts. See the `resource/*` and `abort/assert` buckets."
    )
    lines.append("")
    lines.append(
        "For each benchmark, a high matched fraction (see the main side-effect "
        "reports) and low dispatch-frame count indicates the benchmark is "
        "measuring what we intended — transplanted bug discovery — with little "
        "extra noise. A high unmatched fraction with top frames in project "
        "source points to unpatched bugs worth investigating or transplanting."
    )
    lines.append("")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench", action="append", required=True,
                        help='Entry in the form name=<path_to_sideeffect_dir>, '
                             'may repeat')
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    summaries: dict[str, dict] = {}
    for entry in args.bench:
        if "=" not in entry:
            raise SystemExit(f"--bench expects name=<path>, got {entry}")
        name, path = entry.split("=", 1)
        p = Path(path) / "unmatched_crashes_by_key.csv"
        if not p.exists():
            raise SystemExit(f"No unmatched_crashes_by_key.csv at {p}")
        summaries[name] = summarize(read_unmatched(p))

    md = render_markdown(summaries)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(md)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
