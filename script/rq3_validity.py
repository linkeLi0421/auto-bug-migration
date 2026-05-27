#!/usr/bin/env python3
"""Classify transplanted-bug validity for RQ3.

For each (benchmark, bug) pair, compare the canonical OSV crash log in
``original-crashes/<bug>.txt`` against the post-transplant crash log in
``crashes/<bug>.txt``. Produce a three-tier verdict matching the
``ndss2027_paper_structure_plan.md`` RQ3 definition:

* ``exact``    — same sanitizer class + same top project frame
                 + same top-3 (function, file) fingerprint.
* ``partial``  — same sanitizer class + non-empty project-frame or
                 source-file overlap (but not exact). The "vulnerable
                 code path is shared even if line numbers / files
                 drifted across commits" case.
* ``rejected`` — different sanitizer class, OR no project-frame and no
                 file overlap. Likely an agent-introduced confounder
                 rather than the historical bug.
* ``no_data``  — one or both crash logs missing a usable stack /
                 sanitizer SUMMARY. Excluded from rate denominators.

All comparison primitives are imported from existing modules
(``bug_verify``, ``sideeffect.duplication_report``); this script is
pure glue.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from bug_verify import extract_sanitizer_class  # noqa: E402
from sideeffect.duplication_report import extract_frames  # noqa: E402

logger = logging.getLogger(__name__)

VERDICTS = ("exact", "partial", "rejected", "no_data")


# Frames whose function name OR file path looks like sanitizer / libFuzzer /
# libc infrastructure rather than project code. Stack traces in
# UBSAN/ASAN/libFuzzer paths can stack 5-10 of these on top of the real
# project frame, fooling top-frame comparison.
_INFRA_FUNC_RE = re.compile(
    r"^("
    r"__asan_|__msan_|__tsan_|__sanitizer|__interceptor_|__ubsan_"
    r"|fuzzer::|asan_thread_start|_start$|start_thread$|__clone$"
    r"|__libc_|raise$|abort$|__assert_fail$|__GI___|sigsetjmp"
    r")"
)
_INFRA_PATH_RE = re.compile(
    r"^(/src/llvm-project/|/lib/x86_64-linux-gnu/|/usr/lib/)"
)
# Dispatch wrapping renames bug-gated functions like
# `ndpi_search_kerberos_osv_2020_1715` (the wrapped/gated variant) and
# `ndpi_search_kerberos_original` (the unwrapped fallback when the dispatch
# bit is 0). Strip both so the cleaned name matches the original's
# `ndpi_search_kerberos`.
_DISPATCH_SUFFIX_RE = re.compile(r"(_osv_\d+_\d+|_original)(?=$|\W)")

# Harness entry-point frames that appear in /src/<proj>/fuzz/* and so are
# not filtered by _INFRA_PATH_RE; treat as non-vulnerability code for the
# drift tier's overlap count.
_HARNESS_FUNCS = {"LLVMFuzzerTestOneInput"}


def _clean_func(name: str) -> str:
    """Strip dispatch-wrapping bug-ID suffix from a function name."""
    return _DISPATCH_SUFFIX_RE.sub("", name)


def _is_infra(func: str, path: str) -> bool:
    return bool(_INFRA_FUNC_RE.match(func)) or bool(_INFRA_PATH_RE.match(path))


def _clean_project_frames(text: str) -> list[tuple[str, str, int | None]]:
    """All real project frames (cleaned func name; relpath + line preserved)."""
    out: list[tuple[str, str, int | None]] = []
    # extract_frames returns frames in /src/ with paths relative to /src/<proj>/.
    # We need the full path again to apply _INFRA_PATH_RE; re-extract from raw.
    for m in re.finditer(
        r"#\d+\s+\S+\s+in\s+(.+?)\s+(/\S+?):(\d+)(?::\d+)?\s*$",
        text or "", re.MULTILINE,
    ):
        func = m.group(1).strip()
        path = m.group(2).strip()
        line = int(m.group(3))
        if _is_infra(func, path):
            continue
        # Keep relative-to-project path for portable comparison.
        rel = "/".join(path.split("/")[3:]) if path.startswith("/src/") else path
        out.append((_clean_func(func), rel, line))
    return out


def _first_top(frames: list[tuple[str, str, int | None]]) -> str:
    return frames[0][0] if frames else ""


def _top3_fingerprint(frames: list[tuple[str, str, int | None]]) -> tuple:
    """Top-3 (function, file) tuples; ignores line numbers (drift across commits)."""
    return tuple((f, p) for f, p, _ in frames[:3])


def _file_set(frames: list[tuple[str, str, int | None]]) -> set[str]:
    return {p.split("/")[-1] for _, p, _ in frames}


def _func_set(frames: list[tuple[str, str, int | None]]) -> set[str]:
    return {f for f, _, _ in frames}


def classify(orig_text: str, post_text: str) -> tuple[str, dict]:
    """Apply the 3-tier RQ3 rule using cleaned project frames.

    Cleaning steps (both sides):
      * Drop sanitizer / libFuzzer / libc infrastructure frames.
      * Strip dispatch-wrapping `_osv_\\d+_\\d+` suffix from function names.

    Verdict:
      * **exact**    — same sanitizer class + same first cleaned project
                       frame + same top-3 (function, file) fingerprint.
      * **partial**  — same first cleaned project frame (regardless of
                       sanitizer class — UBSAN catching what ASan would
                       have surfaced as SEGV is the same bug), OR same
                       sanitizer class with non-empty stack overlap, OR
                       *drift*: different sanitizer class AND different
                       top frame but >=2 shared non-harness project funcs.
                       The drift tier catches cases where heap-layout
                       changes on the merged binary shift which ASAN
                       check fires first while the vulnerable code area
                       is unchanged (e.g. SEGV in restore_space ↔
                       heap-UAF in ptr_struct_mark, both inside the
                       same GC traversal).
      * **rejected** — none of the above: different top, different
                       class, and no/only-harness overlap.
      * **no_data**  — at least one log lacks a sanitizer SUMMARY.
    """
    orig_class, orig_dir = extract_sanitizer_class(orig_text)
    post_class, post_dir = extract_sanitizer_class(post_text)
    orig_frames = _clean_project_frames(orig_text)
    post_frames = _clean_project_frames(post_text)
    orig_top = _first_top(orig_frames)
    post_top = _first_top(post_frames)
    orig_fp = _top3_fingerprint(orig_frames)
    post_fp = _top3_fingerprint(post_frames)
    orig_files = _file_set(orig_frames)
    post_files = _file_set(post_frames)
    orig_funcs = _func_set(orig_frames)
    post_funcs = _func_set(post_frames)

    details = {
        "orig_class": orig_class or "",
        "orig_dir": orig_dir or "",
        "orig_top": orig_top,
        "orig_top3": "|".join(f"{f}@{p}" for f, p in orig_fp),
        "post_class": post_class or "",
        "post_dir": post_dir or "",
        "post_top": post_top,
        "post_top3": "|".join(f"{f}@{p}" for f, p in post_fp),
        "shared_funcs": len(orig_funcs & post_funcs),
        "shared_files": len(orig_files & post_files),
    }

    if not orig_class or not post_class:
        return "no_data", details

    same_top = bool(orig_top and post_top and orig_top == post_top)
    same_fp3 = bool(orig_fp and post_fp and orig_fp == post_fp)
    if orig_class == post_class and same_top and same_fp3:
        return "exact", details
    if same_top:
        return "partial", details
    if orig_class == post_class and ((orig_funcs & post_funcs) or (orig_files & post_files)):
        return "partial", details

    # Drift tier: same vulnerable code area, different sanitizer class.
    # Heap-layout differences on the merged binary commonly shift which
    # ASAN check fires first while the underlying vulnerability is the
    # same. Require >=2 shared non-harness project funcs to avoid
    # accepting "harness-frame only" coincidences (e.g. ndpi cases
    # where the sole shared frame is LLVMFuzzerTestOneInput).
    nontrivial_funcs = (orig_funcs & post_funcs) - _HARNESS_FUNCS
    if len(nontrivial_funcs) >= 2:
        details["note"] = (
            f"sanitizer-class drift: {orig_class} -> {post_class} "
            f"with {len(nontrivial_funcs)} shared non-harness funcs"
        )
        return "partial", details

    return "rejected", details


def find_benchmark_dirs(root: Path) -> list[Path]:
    """All ``*_transplant_*`` benchmark dirs under ``root``."""
    out = []
    for d in sorted(root.iterdir()):
        if d.is_dir() and "_transplant_" in d.name and (d / "bug_metadata.json").is_file():
            out.append(d)
    return out


def analyze_benchmark(bench_dir: Path) -> list[dict]:
    """One row per bug. Skips bugs lacking either crash log."""
    meta = json.loads((bench_dir / "bug_metadata.json").read_text())
    rows = []
    for bug_id, info in meta["bugs"].items():
        orig = bench_dir / "original-crashes" / f"{bug_id}.txt"
        post = bench_dir / "crashes" / f"{bug_id}.txt"
        if not orig.is_file() or not post.is_file():
            verdict, details = "no_data", {}
            details["note"] = "missing_log"
        else:
            verdict, details = classify(
                orig.read_text(errors="replace"),
                post.read_text(errors="replace"),
            )
        rows.append({
            "benchmark": bench_dir.name,
            "bug_id": bug_id,
            "dispatch_value": info.get("dispatch_value"),
            "triggered": info.get("triggered"),
            "verdict": verdict,
            **details,
        })
    return rows


def summarize(rows: list[dict]) -> dict[str, Counter]:
    by_bench: dict[str, Counter] = {}
    for r in rows:
        by_bench.setdefault(r["benchmark"], Counter())[r["verdict"]] += 1
    by_bench["__overall__"] = Counter(r["verdict"] for r in rows)
    return by_bench


def render_markdown(summary: dict[str, Counter]) -> str:
    overall = summary["__overall__"]
    benches = sorted(k for k in summary if k != "__overall__")

    def _pct(num: int, den: int) -> str:
        return f"{num/den*100:.1f}%" if den else "—"

    lines = ["# RQ3: Transplanted-bug validity", ""]
    lines.append(
        "For each transplanted bug, compare `original-crashes/<bug>.txt` "
        "(canonical OSV reference, collected at the buggy commit / native "
        "target commit) against `crashes/<bug>.txt` (post-transplant log "
        "from the merged benchmark binary). Verdicts follow the "
        "`ndss2027_paper_structure_plan.md` definition:"
    )
    lines.append("")
    lines.append("- **exact** — same sanitizer class + same top project frame + same top-3 (function, file) fingerprint.")
    lines.append("- **partial** — same sanitizer class + non-empty project-frame or source-file overlap (line/file drift across commits is OK).")
    lines.append("- **rejected** — different sanitizer class, or no overlap.")
    lines.append("- **no_data** — at least one log lacks a usable sanitizer SUMMARY; excluded from rate denominators.")
    lines.append("")
    lines.append("## Overall")
    lines.append("")
    classified = sum(overall[v] for v in ("exact", "partial", "rejected"))
    total = sum(overall.values())
    lines.append(f"- Total bugs analyzed: **{total}** ({classified} classified, {overall['no_data']} no_data)")
    for v in ("exact", "partial", "rejected"):
        lines.append(f"- **{v}**: {overall[v]} ({_pct(overall[v], classified)} of classified)")
    lines.append("")
    lines.append("## Per benchmark")
    lines.append("")
    lines.append("| benchmark | total | exact | partial | rejected | no_data |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for b in benches:
        c = summary[b]
        tot = sum(c.values())
        lines.append(
            f"| {b} | {tot} | {c['exact']} | {c['partial']} | {c['rejected']} | {c['no_data']} |"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    # Stable field order regardless of dict insertion order.
    fields = [
        "benchmark", "bug_id", "dispatch_value", "triggered", "verdict",
        "orig_class", "orig_dir", "orig_top", "orig_top3",
        "post_class", "post_dir", "post_top", "post_top3",
        "shared_funcs", "shared_files", "note",
    ]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="RQ3 transplant validity classifier (uses existing primitives).",
    )
    parser.add_argument(
        "--benchmarks-root", default=str(PROJECT_ROOT / "fuzzbench" / "benchmarks"),
        help="Root containing <project>_transplant_<target>/ benchmark dirs.",
    )
    parser.add_argument(
        "--benchmark", action="append", default=None,
        help="Restrict to specific benchmark dir name(s); can be repeated.",
    )
    parser.add_argument(
        "--output-dir", default=str(PROJECT_ROOT / "data"),
        help="Where to write rq3_validity.csv and rq3_validity_summary.md.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    benchmarks_root = Path(args.benchmarks_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    dirs = find_benchmark_dirs(benchmarks_root)
    if args.benchmark:
        wanted = set(args.benchmark)
        dirs = [d for d in dirs if d.name in wanted]
    if not dirs:
        logger.error("No benchmark directories found under %s", benchmarks_root)
        return 2

    all_rows: list[dict] = []
    for d in dirs:
        logger.info("Analyzing %s ...", d.name)
        all_rows.extend(analyze_benchmark(d))

    summary = summarize(all_rows)

    csv_path = output_dir / "rq3_validity.csv"
    md_path = output_dir / "rq3_validity_summary.md"
    write_csv(csv_path, all_rows)
    md_path.write_text(render_markdown(summary))

    overall = summary["__overall__"]
    classified = sum(overall[v] for v in ("exact", "partial", "rejected"))
    logger.info("")
    logger.info("=== RQ3 validity summary ===")
    logger.info("benchmarks: %d   bugs analyzed: %d   classified: %d   no_data: %d",
                len(dirs), sum(overall.values()), classified, overall["no_data"])
    for v in ("exact", "partial", "rejected"):
        pct = (overall[v] / classified * 100) if classified else 0.0
        logger.info("  %-10s %3d  (%.1f%% of classified)", v, overall[v], pct)
    logger.info("")
    logger.info("CSV:      %s", csv_path)
    logger.info("Markdown: %s", md_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
