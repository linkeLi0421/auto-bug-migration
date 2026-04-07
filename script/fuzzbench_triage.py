#!/usr/bin/env python3
"""Post-experiment triage for FuzzBench bug transplant experiments.

Analyzes FuzzBench experiment results to determine which transplanted bugs
were triggered by each fuzzer. Combines two data sources:

1. Crash inputs from FuzzBench corpus snapshots — reads dispatch bytes to
   identify which bug was active when the crash occurred ("triggered").
2. Canary monitor logs (if available) — reads shared-memory polling CSV
   to get "reached" timestamps.

Outputs a CSV with per-bug discovery timeline for survival analysis.

Usage:
    python3 script/fuzzbench_triage.py \
        --experiment-dir /tmp/fuzzbench-data/transplant-cblosc2-24h \
        --bug-metadata benchmarks/c-blosc2_transplant/bug_metadata.json \
        --output results.csv
"""

import argparse
import csv
import json
import logging
import os
import struct
import sys
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


def scan_corpus_snapshots(experiment_dir: Path, benchmark: str,
                          bug_metadata: dict) -> dict:
    """Scan FuzzBench corpus snapshots for crash inputs and extract dispatch bytes.

    FuzzBench stores corpus snapshots in:
      experiment_dir/experiment-folders/{benchmark}/{fuzzer}/trial-{id}/corpus/

    Returns:
        dict: {(fuzzer, trial_id, bug_id): earliest_timestamp_seconds}
    """
    results = {}  # (fuzzer, trial, bug_id) -> earliest_time
    exp_folders = experiment_dir / "experiment-folders"

    if not exp_folders.exists():
        logger.warning("No experiment-folders found in %s", experiment_dir)
        return results

    benchmark_dir = exp_folders / benchmark
    if not benchmark_dir.exists():
        # Try without exact match
        candidates = [d for d in exp_folders.iterdir() if d.is_dir()]
        logger.warning("Benchmark dir %s not found. Available: %s",
                       benchmark, [c.name for c in candidates])
        return results

    n_dispatch = bug_metadata["dispatch_bytes"]

    for fuzzer_dir in sorted(benchmark_dir.iterdir()):
        if not fuzzer_dir.is_dir():
            continue
        fuzzer_name = fuzzer_dir.name

        for trial_dir in sorted(fuzzer_dir.iterdir()):
            if not trial_dir.is_dir():
                continue
            trial_match = trial_dir.name  # e.g. "trial-1"
            trial_id = trial_match.split("-")[-1] if "-" in trial_match else trial_match

            # Scan corpus archive directories (numbered by snapshot cycle)
            corpus_dir = trial_dir / "corpus"
            if not corpus_dir.exists():
                continue

            for snapshot_dir in sorted(corpus_dir.iterdir()):
                if not snapshot_dir.is_dir():
                    continue

                # Try to extract timestamp from directory name or use mtime
                try:
                    snapshot_time = int(snapshot_dir.name)
                except ValueError:
                    snapshot_time = int(snapshot_dir.stat().st_mtime)

                for input_file in snapshot_dir.iterdir():
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

    FuzzBench stores crashes in:
      experiment_dir/experiment-folders/{benchmark}/{fuzzer}/trial-{id}/crashes/

    Returns:
        dict: {(fuzzer, trial_id, bug_id): earliest_timestamp_seconds}
    """
    results = {}
    exp_folders = experiment_dir / "experiment-folders"
    if not exp_folders.exists():
        return results

    benchmark_dir = exp_folders / benchmark
    if not benchmark_dir.exists():
        return results

    n_dispatch = bug_metadata["dispatch_bytes"]

    for fuzzer_dir in sorted(benchmark_dir.iterdir()):
        if not fuzzer_dir.is_dir():
            continue
        fuzzer_name = fuzzer_dir.name

        for trial_dir in sorted(fuzzer_dir.iterdir()):
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

                # Use file mtime as crash discovery time
                crash_time = int(crash_file.stat().st_mtime)

                active_bugs = dispatch_bytes_to_bug_ids(
                    data[:n_dispatch], bug_metadata)

                for bug_id in active_bugs:
                    key = (fuzzer_name, trial_id, bug_id)
                    if key not in results or crash_time < results[key]:
                        results[key] = crash_time

    return results


def scan_canary_logs(experiment_dir: Path, benchmark: str) -> dict:
    """Scan canary monitor CSV logs for reached/triggered timestamps.

    Expected log format:
        timestamp_ms, bug_id, reached_count, triggered_count

    Returns:
        dict: {(fuzzer, trial_id, bug_id): {
            "first_reached_ms": int, "first_triggered_ms": int
        }}
    """
    results = {}
    exp_folders = experiment_dir / "experiment-folders"
    if not exp_folders.exists():
        return results

    benchmark_dir = exp_folders / benchmark
    if not benchmark_dir.exists():
        return results

    for fuzzer_dir in sorted(benchmark_dir.iterdir()):
        if not fuzzer_dir.is_dir():
            continue
        fuzzer_name = fuzzer_dir.name

        for trial_dir in sorted(fuzzer_dir.iterdir()):
            if not trial_dir.is_dir():
                continue
            trial_id = trial_dir.name.split("-")[-1] if "-" in trial_dir.name else trial_dir.name

            canary_log = trial_dir / "canary_log.csv"
            if not canary_log.exists():
                continue

            with open(canary_log) as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) < 4:
                        continue
                    try:
                        ts_ms = int(row[0])
                        bug_id = row[1].strip()
                        reached = int(row[2])
                        triggered = int(row[3])
                    except (ValueError, IndexError):
                        continue

                    key = (fuzzer_name, trial_id, bug_id)
                    if key not in results:
                        results[key] = {
                            "first_reached_ms": None,
                            "first_triggered_ms": None,
                        }

                    if reached > 0 and results[key]["first_reached_ms"] is None:
                        results[key]["first_reached_ms"] = ts_ms

                    if triggered > 0 and results[key]["first_triggered_ms"] is None:
                        results[key]["first_triggered_ms"] = ts_ms

    return results


def merge_results(crash_results: dict, corpus_results: dict,
                  canary_results: dict, bug_metadata: dict) -> list:
    """Merge all data sources into a unified timeline.

    Returns list of dicts with columns:
        fuzzer, trial, bug_id, time_first_reached, time_first_triggered
    """
    all_keys = set()
    all_keys.update(crash_results.keys())
    all_keys.update(corpus_results.keys())
    all_keys.update(canary_results.keys())

    rows = []
    for key in sorted(all_keys):
        fuzzer, trial, bug_id = key

        # Triggered time: earliest from crash or corpus scan
        triggered_time = None
        if key in crash_results:
            triggered_time = crash_results[key]
        if key in corpus_results:
            ct = corpus_results[key]
            if triggered_time is None or ct < triggered_time:
                triggered_time = ct

        # Reached time: from canary if available, else same as triggered
        reached_time = None
        if key in canary_results:
            cr = canary_results[key]
            if cr["first_reached_ms"] is not None:
                reached_time = cr["first_reached_ms"] / 1000.0  # ms to seconds
            if cr["first_triggered_ms"] is not None:
                canary_triggered = cr["first_triggered_ms"] / 1000.0
                if triggered_time is None or canary_triggered < triggered_time:
                    triggered_time = canary_triggered

        # If no canary but we have triggered, reached <= triggered
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


def print_summary(rows: list, bug_metadata: dict):
    """Print a human-readable summary of bug discovery."""
    total_bugs = len(bug_metadata["bugs"])

    # Group by fuzzer
    by_fuzzer = defaultdict(lambda: defaultdict(set))
    for row in rows:
        if row["time_first_triggered"] is not None:
            by_fuzzer[row["fuzzer"]][row["trial"]].add(row["bug_id"])

    print(f"\n{'='*60}")
    print(f"Bug Discovery Summary ({total_bugs} total bugs)")
    print(f"{'='*60}")

    for fuzzer in sorted(by_fuzzer):
        trials = by_fuzzer[fuzzer]
        bug_counts = [len(bugs) for bugs in trials.values()]
        mean_bugs = sum(bug_counts) / len(bug_counts) if bug_counts else 0
        all_bugs = set()
        for bugs in trials.values():
            all_bugs.update(bugs)
        print(f"\n{fuzzer}:")
        print(f"  Trials: {len(trials)}")
        print(f"  Mean bugs triggered: {mean_bugs:.1f}")
        print(f"  Unique bugs found (any trial): {len(all_bugs)}/{total_bugs}")

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
    benchmark = args.benchmark or f"{project}_transplant"

    logger.info("Experiment: %s", experiment_dir)
    logger.info("Benchmark: %s", benchmark)
    logger.info("Total bugs: %d", len(bug_metadata["bugs"]))

    # Scan all data sources
    logger.info("Scanning crash directories...")
    crash_results = scan_crash_dirs(experiment_dir, benchmark, bug_metadata)
    logger.info("  Found %d (fuzzer, trial, bug) crash entries", len(crash_results))

    logger.info("Scanning corpus snapshots...")
    corpus_results = scan_corpus_snapshots(experiment_dir, benchmark, bug_metadata)
    logger.info("  Found %d (fuzzer, trial, bug) corpus entries", len(corpus_results))

    logger.info("Scanning canary logs...")
    canary_results = scan_canary_logs(experiment_dir, benchmark)
    logger.info("  Found %d (fuzzer, trial, bug) canary entries", len(canary_results))

    # Merge and output
    rows = merge_results(crash_results, corpus_results, canary_results, bug_metadata)
    output_path = Path(args.output)
    write_csv(rows, output_path)
    logger.info("Wrote %d rows to %s", len(rows), output_path)

    print_summary(rows, bug_metadata)


if __name__ == "__main__":
    main()
