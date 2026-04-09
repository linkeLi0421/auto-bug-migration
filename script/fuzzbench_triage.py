#!/usr/bin/env python3
"""Post-experiment triage for FuzzBench bug transplant experiments.

Analyzes FuzzBench experiment results to determine which transplanted bugs
were triggered by each fuzzer. Uses two data sources:

1. Crash inputs from FuzzBench crash directories — reads dispatch bytes to
   identify which bug was active when the crash occurred ("triggered").
2. Coverage snapshots — checks if bug crash lines were covered ("reached").

Outputs a CSV with per-bug discovery timeline for survival analysis.

Usage:
    python3 script/fuzzbench_triage.py \
        --experiment-dir /tmp/fuzzbench-data/transplant-cblosc2-24h \
        --bug-metadata benchmarks/c-blosc2_transplant/bug_metadata.json \
        --output results.csv
"""

import argparse
import csv
import gzip
import json
import logging
import os
import struct
import sys
import tarfile
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)


def load_bug_metadata(metadata_path: Path) -> dict:
    with open(metadata_path) as f:
        return json.load(f)


def dispatch_bytes_to_bug_ids(dispatch_bytes_data: bytes, bug_metadata: dict) -> list:
    """Decode dispatch bytes from a crash input to determine which bugs are active.

    The dispatch mechanism uses N bytes where each bit corresponds to a bug.
    Bit 0 of byte 0 = bug with dispatch_value 1
    Bit 1 of byte 0 = bug with dispatch_value 2
    Bit 0 of byte 1 = bug with dispatch_value 256
    etc.
    """
    n_dispatch = bug_metadata["dispatch_bytes"]
    if len(dispatch_bytes_data) < n_dispatch:
        return []

    # Reconstruct the dispatch value as a single integer
    dispatch_value = 0
    for i in range(n_dispatch):
        dispatch_value |= dispatch_bytes_data[i] << (8 * i)

    triggered_bugs = []
    for bug_id, info in bug_metadata["bugs"].items():
        bv = info["dispatch_value"]
        if bv == 0:
            # Local bugs (dispatch_value=0) are always active
            triggered_bugs.append(bug_id)
        elif dispatch_value & bv:
            triggered_bugs.append(bug_id)

    return triggered_bugs


def _find_fuzzer_dirs(experiment_dir: Path, benchmark: str) -> list:
    """Find fuzzer directories, handling both FuzzBench layouts.

    Layout 1 (nested):  experiment-folders/{benchmark}/{fuzzer}/trial-{id}/
    Layout 2 (flat):    experiment-folders/{benchmark}-{fuzzer}/trial-{id}/

    Returns list of (fuzzer_name, fuzzer_path) tuples.
    """
    exp_folders = experiment_dir / "experiment-folders"
    if not exp_folders.exists():
        logger.error("experiment-folders not found at %s. "
                     "Check your --experiment-dir path.", exp_folders)
        return []

    # Try nested layout first
    benchmark_dir = exp_folders / benchmark
    if benchmark_dir.exists():
        return [(d.name, d) for d in sorted(benchmark_dir.iterdir()) if d.is_dir()]

    # Try flat layout: {benchmark}-{fuzzer}
    prefix = benchmark + "-"
    fuzzer_dirs = []
    for d in sorted(exp_folders.iterdir()):
        if d.is_dir() and d.name.startswith(prefix):
            fuzzer_name = d.name[len(prefix):]
            fuzzer_dirs.append((fuzzer_name, d))

    if not fuzzer_dirs:
        candidates = [d.name for d in exp_folders.iterdir() if d.is_dir()]
        logger.warning("No dirs matching benchmark %s found. Available: %s",
                       benchmark, candidates)

    return fuzzer_dirs


def scan_corpus_snapshots(experiment_dir: Path, benchmark: str,
                          bug_metadata: dict) -> dict:
    """Scan FuzzBench corpus snapshots for dispatch byte matches.

    Returns:
        dict: {(fuzzer, trial_id, bug_id): earliest_timestamp_seconds}
    """
    results = {}
    fuzzer_dirs = _find_fuzzer_dirs(experiment_dir, benchmark)
    if not fuzzer_dirs:
        return results

    n_dispatch = bug_metadata["dispatch_bytes"]

    for fuzzer_name, fuzzer_path in fuzzer_dirs:
        for trial_dir in sorted(fuzzer_path.iterdir()):
            if not trial_dir.is_dir():
                continue
            trial_id = trial_dir.name.split("-")[-1] if "-" in trial_dir.name else trial_dir.name

            corpus_dir = trial_dir / "corpus"
            if not corpus_dir.exists():
                continue

            for entry in sorted(corpus_dir.iterdir()):
                # Handle tar.gz corpus archives (FuzzBench default)
                if entry.is_file() and entry.name.endswith(".tar.gz"):
                    snapshot_time = int(entry.stat().st_mtime)
                    try:
                        with tarfile.open(entry, "r:gz") as tf:
                            for member in tf.getmembers():
                                if not member.isfile():
                                    continue
                                f = tf.extractfile(member)
                                if f is None:
                                    continue
                                data = f.read()
                                if len(data) < n_dispatch:
                                    continue
                                active_bugs = dispatch_bytes_to_bug_ids(
                                    data[:n_dispatch], bug_metadata)
                                for bug_id in active_bugs:
                                    key = (fuzzer_name, trial_id, bug_id)
                                    if key not in results or snapshot_time < results[key]:
                                        results[key] = snapshot_time
                    except (tarfile.TarError, OSError) as e:
                        logger.debug("Skipping corrupt archive %s: %s", entry, e)
                    continue

                # Handle plain directories (extracted snapshots)
                if not entry.is_dir():
                    continue
                try:
                    snapshot_time = int(entry.name)
                except ValueError:
                    snapshot_time = int(entry.stat().st_mtime)

                for input_file in entry.iterdir():
                    if not input_file.is_file():
                        continue
                    try:
                        data = input_file.read_bytes()
                    except OSError:
                        continue

                    if len(data) < n_dispatch:
                        continue

                    active_bugs = dispatch_bytes_to_bug_ids(
                        data[:n_dispatch], bug_metadata)

                    for bug_id in active_bugs:
                        key = (fuzzer_name, trial_id, bug_id)
                        if key not in results or snapshot_time < results[key]:
                            results[key] = snapshot_time

    return results


def scan_crash_dirs(experiment_dir: Path, benchmark: str,
                    bug_metadata: dict) -> dict:
    """Scan FuzzBench crash directories for triggered bugs.

    Returns:
        dict: {(fuzzer, trial_id, bug_id): earliest_timestamp_seconds}
    """
    results = {}
    fuzzer_dirs = _find_fuzzer_dirs(experiment_dir, benchmark)
    if not fuzzer_dirs:
        return results

    n_dispatch = bug_metadata["dispatch_bytes"]

    for fuzzer_name, fuzzer_path in fuzzer_dirs:
        for trial_dir in sorted(fuzzer_path.iterdir()):
            if not trial_dir.is_dir():
                continue
            trial_id = trial_dir.name.split("-")[-1] if "-" in trial_dir.name else trial_dir.name

            crashes_dir = trial_dir / "crashes"
            if not crashes_dir.exists():
                continue

            for crash_file in sorted(crashes_dir.iterdir()):
                if not crash_file.is_file():
                    continue
                try:
                    data = crash_file.read_bytes()
                except OSError:
                    continue

                if len(data) < n_dispatch:
                    continue

                crash_time = int(crash_file.stat().st_mtime)

                active_bugs = dispatch_bytes_to_bug_ids(
                    data[:n_dispatch], bug_metadata)

                for bug_id in active_bugs:
                    key = (fuzzer_name, trial_id, bug_id)
                    if key not in results or crash_time < results[key]:
                        results[key] = crash_time

    return results


def _parse_llvm_coverage(coverage_path: Path) -> dict:
    """Parse LLVM coverage JSON (gzipped) into {file: {line: count}} dict."""
    with gzip.open(coverage_path, "rt") as f:
        data = json.load(f)

    file_coverage = {}
    for file_entry in data["data"][0]["files"]:
        filename = file_entry["filename"]
        lines = {}
        # LLVM segments: [line, col, count, hasCount, isRegionEntry, isGapRegion]
        # A segment marks the start of a region; count applies until next segment
        segments = file_entry.get("segments", [])
        for seg in segments:
            line, col, count, has_count = seg[0], seg[1], seg[2], seg[3]
            if has_count and count > 0:
                lines[line] = max(lines.get(line, 0), count)
        if lines:
            file_coverage[filename] = lines

    return file_coverage


def scan_coverage_for_bugs(experiment_dir: Path, benchmark: str,
                           bug_metadata: dict) -> dict:
    """Scan FuzzBench coverage snapshots to determine when bug crash lines were reached.

    Uses crash_file/crash_line from bug_metadata to check if the bug's crash
    location was covered in each coverage snapshot.

    Returns:
        dict: {(fuzzer, trial_id, bug_id): earliest_timestamp_seconds}
    """
    results = {}

    # Build lookup: normalize file paths and collect bugs with crash line info
    bug_crash_lines = {}  # bug_id -> (file_suffix, line)
    for bug_id, info in bug_metadata["bugs"].items():
        crash_file = info.get("crash_file")
        crash_line = info.get("crash_line")
        if crash_file and crash_line:
            bug_crash_lines[bug_id] = (crash_file, crash_line)

    if not bug_crash_lines:
        logger.info("No bugs have crash line info; skipping coverage scan")
        return results

    logger.info("Checking coverage for %d bugs with crash lines", len(bug_crash_lines))

    fuzzer_dirs = _find_fuzzer_dirs(experiment_dir, benchmark)
    if not fuzzer_dirs:
        return results

    for fuzzer_name, fuzzer_path in fuzzer_dirs:
        for trial_dir in sorted(fuzzer_path.iterdir()):
            if not trial_dir.is_dir():
                continue
            trial_id = trial_dir.name.split("-")[-1] if "-" in trial_dir.name else trial_dir.name

            coverage_dir = trial_dir / "coverage"
            if not coverage_dir.exists():
                continue

            for cov_file in sorted(coverage_dir.iterdir()):
                if not cov_file.name.endswith(".json.gz"):
                    continue

                snapshot_time = int(cov_file.stat().st_mtime)

                try:
                    file_coverage = _parse_llvm_coverage(cov_file)
                except (json.JSONDecodeError, OSError, KeyError) as e:
                    logger.debug("Skipping %s: %s", cov_file, e)
                    continue

                for bug_id, (crash_file, crash_line) in bug_crash_lines.items():
                    key = (fuzzer_name, trial_id, bug_id)
                    if key in results:
                        continue  # already found earlier

                    # Match file path: coverage uses full /src/ paths
                    for cov_filename, line_counts in file_coverage.items():
                        if cov_filename.endswith(crash_file) or crash_file.endswith(cov_filename) or \
                           cov_filename == crash_file:
                            if crash_line in line_counts:
                                results[key] = snapshot_time
                            break

    return results


def merge_results(crash_results: dict, corpus_results: dict,
                  coverage_results: dict, bug_metadata: dict) -> list:
    """Merge all data sources into a unified timeline.

    Returns list of dicts with columns:
        fuzzer, trial, bug_id, time_first_reached, time_first_triggered
    """
    all_keys = set()
    all_keys.update(crash_results.keys())
    all_keys.update(corpus_results.keys())
    all_keys.update(coverage_results.keys())

    rows = []
    for key in sorted(all_keys):
        fuzzer, trial, bug_id = key

        # Triggered: crash with matching dispatch bytes
        triggered_time = None
        if key in crash_results:
            triggered_time = crash_results[key]

        # Reached: crash line covered in coverage snapshot
        reached_time = None
        if key in coverage_results:
            reached_time = coverage_results[key]

        # If no coverage data but we have triggered, reached <= triggered
        if reached_time is None and triggered_time is not None:
            reached_time = triggered_time

        rows.append({
            "fuzzer": fuzzer,
            "trial": trial,
            "bug_id": bug_id,
            "time_first_reached": reached_time,
            "time_first_triggered": triggered_time,
        })

    return rows


def write_csv(rows: list, output_path: Path):
    fieldnames = ["fuzzer", "trial", "bug_id", "time_first_reached", "time_first_triggered"]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_bug_report(rows: list, bug_metadata: dict, output_path: Path):
    """Write a detailed per-bug JSON report with crash line info and discovery status."""
    # Aggregate across all fuzzers/trials: best result per bug
    bug_status = {}
    for bug_id, info in bug_metadata["bugs"].items():
        bug_status[bug_id] = {
            "crash_file": info.get("crash_file"),
            "crash_line": info.get("crash_line"),
            "crash_function": info.get("crash_function"),
            "dispatch_value": info.get("dispatch_value"),
            "reached_by": [],   # list of {fuzzer, trial, time}
            "triggered_by": [], # list of {fuzzer, trial, time}
        }

    for row in rows:
        bug_id = row["bug_id"]
        if bug_id not in bug_status:
            continue
        if row["time_first_reached"] is not None:
            bug_status[bug_id]["reached_by"].append({
                "fuzzer": row["fuzzer"],
                "trial": row["trial"],
                "time": row["time_first_reached"],
            })
        if row["time_first_triggered"] is not None:
            bug_status[bug_id]["triggered_by"].append({
                "fuzzer": row["fuzzer"],
                "trial": row["trial"],
                "time": row["time_first_triggered"],
            })

    # Summary counts
    total = len(bug_status)
    has_crash_line = sum(1 for b in bug_status.values() if b["crash_line"] is not None)
    reached = sum(1 for b in bug_status.values() if b["reached_by"])
    triggered = sum(1 for b in bug_status.values() if b["triggered_by"])

    report = {
        "summary": {
            "total_bugs": total,
            "bugs_with_crash_line": has_crash_line,
            "bugs_reached": reached,
            "bugs_triggered": triggered,
        },
        "bugs": bug_status,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Wrote bug report to %s", output_path)

    # Also write a human-readable text summary
    txt_path = output_path.with_suffix(".txt")
    with open(txt_path, "w") as f:
        f.write(f"Bug Triage Report\n{'='*60}\n\n")
        f.write(f"Total bugs: {total}\n")
        f.write(f"Bugs with crash line info: {has_crash_line}\n")
        f.write(f"Bugs reached (crash line covered): {reached}\n")
        f.write(f"Bugs triggered (crash found): {triggered}\n\n")

        f.write(f"{'Bug ID':<20} {'Crash Location':<50} {'Reached':>8} {'Triggered':>10}\n")
        f.write(f"{'-'*20} {'-'*50} {'-'*8} {'-'*10}\n")
        for bug_id in sorted(bug_status):
            b = bug_status[bug_id]
            loc = f"{b['crash_file']}:{b['crash_line']}" if b["crash_line"] else "(no crash line)"
            # Truncate long paths — keep filename:line
            if len(loc) > 50:
                loc = "..." + loc[-(50-3):]
            r = "yes" if b["reached_by"] else "no"
            t = "yes" if b["triggered_by"] else "no"
            f.write(f"{bug_id:<20} {loc:<50} {r:>8} {t:>10}\n")

    logger.info("Wrote readable summary to %s", txt_path)


def print_summary(rows: list, bug_metadata: dict):
    """Print a human-readable summary of bug discovery."""
    total_bugs = len(bug_metadata["bugs"])

    # Group by fuzzer
    by_fuzzer_triggered = defaultdict(lambda: defaultdict(set))
    by_fuzzer_reached = defaultdict(lambda: defaultdict(set))
    for row in rows:
        if row["time_first_triggered"] is not None:
            by_fuzzer_triggered[row["fuzzer"]][row["trial"]].add(row["bug_id"])
        if row["time_first_reached"] is not None:
            by_fuzzer_reached[row["fuzzer"]][row["trial"]].add(row["bug_id"])

    print(f"\n{'='*60}")
    print(f"Bug Discovery Summary ({total_bugs} total bugs)")
    print(f"{'='*60}")

    all_fuzzers = sorted(set(list(by_fuzzer_triggered.keys()) + list(by_fuzzer_reached.keys())))
    for fuzzer in all_fuzzers:
        triggered_trials = by_fuzzer_triggered.get(fuzzer, {})
        reached_trials = by_fuzzer_reached.get(fuzzer, {})

        triggered_counts = [len(bugs) for bugs in triggered_trials.values()]
        reached_counts = [len(bugs) for bugs in reached_trials.values()]
        mean_triggered = sum(triggered_counts) / len(triggered_counts) if triggered_counts else 0
        mean_reached = sum(reached_counts) / len(reached_counts) if reached_counts else 0

        all_triggered = set()
        for bugs in triggered_trials.values():
            all_triggered.update(bugs)
        all_reached = set()
        for bugs in reached_trials.values():
            all_reached.update(bugs)

        n_trials = max(len(triggered_trials), len(reached_trials))
        print(f"\n{fuzzer}:")
        print(f"  Trials: {n_trials}")
        print(f"  Mean bugs reached: {mean_reached:.1f}")
        print(f"  Mean bugs triggered: {mean_triggered:.1f}")
        print(f"  Unique bugs reached (any trial): {len(all_reached)}/{total_bugs}")
        print(f"  Unique bugs triggered (any trial): {len(all_triggered)}/{total_bugs}")

    # Bugs never found
    all_found = set()
    for row in rows:
        if row["time_first_triggered"] is not None:
            all_found.add(row["bug_id"])
    never_found = set(bug_metadata["bugs"].keys()) - all_found
    if never_found:
        print(f"\nBugs never triggered: {sorted(never_found)}")


def main():
    parser = argparse.ArgumentParser(
        description="Triage FuzzBench experiment results for bug transplant evaluation",
    )
    parser.add_argument("--experiment-dir", required=True,
                        help="FuzzBench experiment filestore path")
    parser.add_argument("--bug-metadata", required=True,
                        help="Path to bug_metadata.json from fuzzbench_generate.py")
    parser.add_argument("--benchmark",
                        help="Benchmark name (auto-detected from bug_metadata if omitted)")
    parser.add_argument("--output", required=True,
                        help="Output CSV path")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    experiment_dir = Path(args.experiment_dir)
    bug_metadata = load_bug_metadata(Path(args.bug_metadata))

    project = bug_metadata["project"]
    if args.benchmark:
        benchmark = args.benchmark
    else:
        # Auto-detect benchmark name from experiment directory
        exp_folders = experiment_dir / "experiment-folders"
        benchmark = f"{project}_transplant"
        if exp_folders.exists():
            candidates = [d.name for d in exp_folders.iterdir() if d.is_dir()]
            # Find common prefix among candidate dirs (strip fuzzer suffix)
            prefixes = set()
            for c in candidates:
                # FuzzBench flat layout: {benchmark}-{fuzzer}
                for sep_pos in range(len(c) - 1, 0, -1):
                    if c[sep_pos] == '-':
                        prefixes.add(c[:sep_pos])
                        break
            if len(prefixes) == 1:
                benchmark = prefixes.pop()
                logger.info("Auto-detected benchmark: %s", benchmark)

    logger.info("Experiment: %s", experiment_dir)
    logger.info("Benchmark: %s", benchmark)
    logger.info("Total bugs: %d", len(bug_metadata["bugs"]))

    # Scan data sources
    logger.info("Scanning crash directories...")
    crash_results = scan_crash_dirs(experiment_dir, benchmark, bug_metadata)
    logger.info("  Found %d (fuzzer, trial, bug) crash entries", len(crash_results))

    logger.info("Scanning coverage snapshots for bug crash lines...")
    coverage_results = scan_coverage_for_bugs(experiment_dir, benchmark, bug_metadata)
    logger.info("  Found %d (fuzzer, trial, bug) coverage-reached entries", len(coverage_results))

    # Merge and output
    rows = merge_results(crash_results, {}, coverage_results, bug_metadata)
    output_path = Path(args.output)
    write_csv(rows, output_path)
    logger.info("Wrote %d rows to %s", len(rows), output_path)

    # Write detailed bug report (JSON + readable text)
    report_path = output_path.with_name(output_path.stem + "_bug_report.json")
    write_bug_report(rows, bug_metadata, report_path)

    print_summary(rows, bug_metadata)


if __name__ == "__main__":
    main()
