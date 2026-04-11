#!/usr/bin/env python3
"""Render FuzzBench triage output into human-readable per-fuzzer summaries."""

import argparse
import csv
import json
import logging
import os
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def _parse_optional_int(value):
    if value in (None, "", "None"):
        return None
    return int(value)


def _format_location(crash_file: str | None, crash_line: int | None) -> str:
    if not crash_file:
        return "-"
    if crash_line is None:
        return crash_file
    return f"{crash_file}:{crash_line}"


def load_rows_from_csv(path: Path) -> tuple[list[dict], int | None, dict[str, str]]:
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                "fuzzer": row["fuzzer"],
                "trial": str(row["trial"]),
                "bug_id": row["bug_id"],
                "time_first_reached": _parse_optional_int(row.get("time_first_reached")),
                "time_first_triggered": _parse_optional_int(row.get("time_first_triggered")),
            })
    return rows, None, {}


def load_rows_from_bug_report_json(path: Path) -> tuple[list[dict], int | None, dict[str, str]]:
    with open(path) as f:
        data = json.load(f)

    rows_by_key = {}
    bug_locations = {}
    for bug_id, info in data["bugs"].items():
        bug_locations[bug_id] = _format_location(info.get("crash_file"), info.get("crash_line"))
        for event in info.get("reached_by", []):
            key = (event["fuzzer"], str(event["trial"]), bug_id)
            row = rows_by_key.setdefault(key, {
                "fuzzer": event["fuzzer"],
                "trial": str(event["trial"]),
                "bug_id": bug_id,
                "time_first_reached": None,
                "time_first_triggered": None,
            })
            event_time = _parse_optional_int(event.get("time"))
            if row["time_first_reached"] is None or (
                    event_time is not None and event_time < row["time_first_reached"]):
                row["time_first_reached"] = event_time
        for event in info.get("triggered_by", []):
            key = (event["fuzzer"], str(event["trial"]), bug_id)
            row = rows_by_key.setdefault(key, {
                "fuzzer": event["fuzzer"],
                "trial": str(event["trial"]),
                "bug_id": bug_id,
                "time_first_reached": None,
                "time_first_triggered": None,
            })
            event_time = _parse_optional_int(event.get("time"))
            if row["time_first_triggered"] is None or (
                    event_time is not None and event_time < row["time_first_triggered"]):
                row["time_first_triggered"] = event_time

    total_bugs = data.get("summary", {}).get("total_bugs")
    return sorted(rows_by_key.values(), key=lambda row: (row["fuzzer"], row["trial"], row["bug_id"])), \
        total_bugs, bug_locations


def load_bug_metadata(path: Path) -> dict[str, str]:
    with open(path) as f:
        data = json.load(f)
    return {
        bug_id: _format_location(info.get("crash_file"), info.get("crash_line"))
        for bug_id, info in data["bugs"].items()
    }


def read_experiment_start(db_path: Path | None) -> float | None:
    if db_path is None or not db_path.exists():
        return None

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        row = cur.execute("select time_created from experiment limit 1").fetchone()
    finally:
        conn.close()

    if not row or not row[0]:
        return None

    try:
        dt = datetime.fromisoformat(row[0])
    except ValueError:
        logger.warning("Could not parse experiment start time from %s", db_path)
        return None
    return dt.replace(tzinfo=timezone.utc).timestamp()


def read_trial_ids_by_fuzzer(db_path: Path | None) -> dict[str, set[str]]:
    if db_path is None or not db_path.exists():
        return {}

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        rows = cur.execute("select fuzzer, id from trial").fetchall()
    finally:
        conn.close()

    result = defaultdict(set)
    for fuzzer, trial_id in rows:
        result[fuzzer].add(str(trial_id))
    return dict(result)


def detect_time_mode(rows: list[dict]) -> str:
    values = [
        value
        for row in rows
        for value in (row["time_first_reached"], row["time_first_triggered"])
        if value is not None
    ]
    if values and max(values) < 1_000_000_000:
        return "relative"
    return "epoch"


def _format_timestamp(timestamp: int | None, time_mode: str) -> str:
    if timestamp is None:
        return "-"
    if time_mode == "relative":
        return f"{timestamp}s"
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _format_hours(timestamp: int | None, experiment_start_epoch: float | None,
                  time_mode: str) -> str:
    if timestamp is None:
        return "-"
    if time_mode == "relative":
        return f"{timestamp / 3600:.2f}"
    if experiment_start_epoch is None:
        return "-"
    return f"{(timestamp - experiment_start_epoch) / 3600:.2f}"


def _format_hours_cell(timestamp: int | None, experiment_start_epoch: float | None,
                       time_mode: str) -> str:
    value = _format_hours(timestamp, experiment_start_epoch, time_mode)
    if value == "-":
        return value
    return f"{value}h"


def build_summaries(rows: list[dict], all_bug_ids: set[str],
                    trial_ids_by_fuzzer: dict[str, set[str]] | None = None) -> tuple[list[dict], list[dict]]:
    fuzzers = sorted({row["fuzzer"] for row in rows})

    fuzzer_summaries = []
    bug_fuzzer_rows = []
    for fuzzer in fuzzers:
        fuzzer_rows = [row for row in rows if row["fuzzer"] == fuzzer]
        observed_trials = {row["trial"] for row in fuzzer_rows}
        if trial_ids_by_fuzzer and fuzzer in trial_ids_by_fuzzer:
            trials = sorted(trial_ids_by_fuzzer[fuzzer], key=int)
        else:
            trials = sorted(observed_trials, key=int)

        reached_by_trial = defaultdict(set)
        triggered_by_trial = defaultdict(set)
        reached_by_bug = defaultdict(list)
        triggered_by_bug = defaultdict(list)

        for row in fuzzer_rows:
            if row["time_first_reached"] is not None:
                reached_by_trial[row["trial"]].add(row["bug_id"])
                reached_by_bug[row["bug_id"]].append(row["time_first_reached"])
            if row["time_first_triggered"] is not None:
                triggered_by_trial[row["trial"]].add(row["bug_id"])
                triggered_by_bug[row["bug_id"]].append(row["time_first_triggered"])

        reached_counts = [len(reached_by_trial[trial]) for trial in trials] if trials else []
        triggered_counts = [len(triggered_by_trial[trial]) for trial in trials] if trials else []
        unique_reached = set(reached_by_bug)
        unique_triggered = set(triggered_by_bug)
        reached_trial_count = sum(1 for trial in trials if reached_by_trial[trial])
        triggered_trial_count = sum(1 for trial in trials if triggered_by_trial[trial])

        fuzzer_summaries.append({
            "fuzzer": fuzzer,
            "trial_count": len(trials),
            "reached_trial_count": reached_trial_count,
            "triggered_trial_count": triggered_trial_count,
            "unique_reached": len(unique_reached),
            "unique_triggered": len(unique_triggered),
            "mean_reached_per_trial": (sum(reached_counts) / len(reached_counts)) if reached_counts else 0.0,
            "mean_triggered_per_trial": (sum(triggered_counts) / len(triggered_counts)) if triggered_counts else 0.0,
            "best_reached_count": max(reached_counts) if reached_counts else 0,
            "best_triggered_count": max(triggered_counts) if triggered_counts else 0,
            "first_reached_time": min((min(times) for times in reached_by_bug.values()), default=None),
            "first_triggered_time": min((min(times) for times in triggered_by_bug.values()), default=None),
            "bugs_reached_all_trials": sum(1 for bug_id in all_bug_ids if len(reached_by_bug.get(bug_id, [])) == len(trials)),
            "bugs_triggered_all_trials": sum(1 for bug_id in all_bug_ids if len(triggered_by_bug.get(bug_id, [])) == len(trials)),
            "missing_reached": sorted(all_bug_ids - unique_reached),
            "missing_triggered": sorted(all_bug_ids - unique_triggered),
        })

        for bug_id in sorted(all_bug_ids):
            reached_times = reached_by_bug.get(bug_id, [])
            triggered_times = triggered_by_bug.get(bug_id, [])
            bug_fuzzer_rows.append({
                "bug_id": bug_id,
                "fuzzer": fuzzer,
                "reached_trial_count": len(reached_times),
                "triggered_trial_count": len(triggered_times),
                "best_reached_time": min(reached_times) if reached_times else None,
                "best_triggered_time": min(triggered_times) if triggered_times else None,
            })

    return fuzzer_summaries, bug_fuzzer_rows


def write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, input_path: Path, db_path: Path | None,
                   experiment_start_epoch: float | None, total_bugs: int,
                   bug_locations: dict[str, str], fuzzer_summaries: list[dict],
                   bug_fuzzer_rows: list[dict], time_mode: str) -> None:
    lines = [
        "# FuzzBench Triage Summary",
        "",
        f"Input: `{input_path}`",
    ]
    if db_path and db_path.exists():
        lines.append(f"Experiment DB: `{db_path}`")
    if experiment_start_epoch is not None:
        lines.append(
            "Experiment start (UTC): "
            + datetime.fromtimestamp(experiment_start_epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        )
    lines.extend([
        "",
        "## By Fuzzer",
        "",
        "| Fuzzer | Trials | Unique Triggered | Unique Reached | Mean Triggered/Trial | Mean Reached/Trial | Bugs Triggered In All Trials | First Trigger |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ])
    for summary in fuzzer_summaries:
        lines.append(
            "| "
            f"{summary['fuzzer']} | "
            f"{summary['triggered_trial_count']}/{summary['trial_count']} | "
            f"{summary['unique_triggered']}/{total_bugs} | "
            f"{summary['unique_reached']}/{total_bugs} | "
            f"{summary['mean_triggered_per_trial']:.1f} | "
            f"{summary['mean_reached_per_trial']:.1f} | "
            f"{summary['bugs_triggered_all_trials']} | "
            f"{_format_hours_cell(summary['first_triggered_time'], experiment_start_epoch, time_mode)} |"
        )

    bug_rows_by_fuzzer = defaultdict(list)
    for row in bug_fuzzer_rows:
        bug_rows_by_fuzzer[row["fuzzer"]].append(row)

    for summary in fuzzer_summaries:
        fuzzer = summary["fuzzer"]
        lines.extend([
            "",
            f"## {fuzzer}",
            "",
            f"Triggered `{summary['unique_triggered']}/{total_bugs}` bugs and reached "
            f"`{summary['unique_reached']}/{total_bugs}` bugs across "
            f"`{summary['triggered_trial_count']}/{summary['trial_count']}` trials with crashes.",
            "",
        ])
        if summary["missing_triggered"]:
            lines.append("Missing triggered bugs: " + ", ".join(summary["missing_triggered"]))
            lines.append("")

        lines.extend([
            "| Bug ID | Crash Location | Triggered Trials | Reached Trials | Best Trigger | Best Reach |",
            "| --- | --- | ---: | ---: | --- | --- |",
        ])
        for row in sorted(
                bug_rows_by_fuzzer[fuzzer],
                key=lambda item: (
                    -item["triggered_trial_count"],
                    -item["reached_trial_count"],
                    item["best_triggered_time"] if item["best_triggered_time"] is not None else 1 << 60,
                    item["bug_id"],
                )):
            if row["triggered_trial_count"] == 0 and row["reached_trial_count"] == 0:
                continue
            lines.append(
                "| "
                f"{row['bug_id']} | "
                f"{bug_locations.get(row['bug_id'], '-')} | "
                f"{row['triggered_trial_count']} | "
                f"{row['reached_trial_count']} | "
                f"{_format_hours_cell(row['best_triggered_time'], experiment_start_epoch, time_mode)} | "
                f"{_format_hours_cell(row['best_reached_time'], experiment_start_epoch, time_mode)} |"
            )

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def default_output_dir(input_path: Path) -> Path:
    if os.access(input_path.parent, os.W_OK):
        return input_path.parent
    return Path.cwd() / "triage-reports" / input_path.parent.name


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create human-readable summaries from FuzzBench triage output",
    )
    parser.add_argument("--input", required=True,
                        help="Path to triage_results.csv or *_bug_report.json")
    parser.add_argument("--bug-metadata",
                        help="Optional bug_metadata.json for crash locations and total bug count")
    parser.add_argument("--db",
                        help="Optional local.db path for converting timestamps to experiment hours")
    parser.add_argument("--output-dir",
                        help="Directory for generated summary files")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    input_path = Path(args.input).resolve()
    if not input_path.exists():
        raise FileNotFoundError(input_path)

    if input_path.suffix == ".csv":
        rows, total_bugs, bug_locations = load_rows_from_csv(input_path)
    elif input_path.suffix == ".json":
        rows, total_bugs, bug_locations = load_rows_from_bug_report_json(input_path)
    else:
        raise ValueError(f"Unsupported input type: {input_path.suffix}")

    if args.bug_metadata:
        metadata_locations = load_bug_metadata(Path(args.bug_metadata))
        bug_locations.update(metadata_locations)
        if total_bugs is None:
            total_bugs = len(metadata_locations)

    all_bug_ids = set(bug_locations) if bug_locations else {row["bug_id"] for row in rows}
    if total_bugs is None:
        total_bugs = len(all_bug_ids)

    output_dir = Path(args.output_dir).resolve() if args.output_dir else default_output_dir(input_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    db_path = Path(args.db).resolve() if args.db else input_path.parent / "local.db"
    experiment_start_epoch = read_experiment_start(db_path)
    trial_ids_by_fuzzer = read_trial_ids_by_fuzzer(db_path)
    time_mode = detect_time_mode(rows)

    fuzzer_summaries, bug_fuzzer_rows = build_summaries(rows, all_bug_ids, trial_ids_by_fuzzer)

    by_fuzzer_rows = []
    for summary in fuzzer_summaries:
        by_fuzzer_rows.append({
            "fuzzer": summary["fuzzer"],
            "trial_count": summary["trial_count"],
            "triggered_trial_count": summary["triggered_trial_count"],
            "reached_trial_count": summary["reached_trial_count"],
            "unique_triggered": summary["unique_triggered"],
            "unique_reached": summary["unique_reached"],
            "mean_triggered_per_trial": f"{summary['mean_triggered_per_trial']:.2f}",
            "mean_reached_per_trial": f"{summary['mean_reached_per_trial']:.2f}",
            "bugs_triggered_all_trials": summary["bugs_triggered_all_trials"],
            "bugs_reached_all_trials": summary["bugs_reached_all_trials"],
            "first_triggered_time": _format_timestamp(summary["first_triggered_time"], time_mode),
            "first_triggered_hours": _format_hours(summary["first_triggered_time"], experiment_start_epoch, time_mode),
            "first_reached_time": _format_timestamp(summary["first_reached_time"], time_mode),
            "first_reached_hours": _format_hours(summary["first_reached_time"], experiment_start_epoch, time_mode),
            "missing_triggered": ",".join(summary["missing_triggered"]),
            "missing_reached": ",".join(summary["missing_reached"]),
        })

    detailed_rows = []
    for row in bug_fuzzer_rows:
        detailed_rows.append({
            "bug_id": row["bug_id"],
            "crash_location": bug_locations.get(row["bug_id"], "-"),
            "fuzzer": row["fuzzer"],
            "triggered_trial_count": row["triggered_trial_count"],
            "reached_trial_count": row["reached_trial_count"],
            "best_triggered_time": _format_timestamp(row["best_triggered_time"], time_mode),
            "best_triggered_hours": _format_hours(row["best_triggered_time"], experiment_start_epoch, time_mode),
            "best_reached_time": _format_timestamp(row["best_reached_time"], time_mode),
            "best_reached_hours": _format_hours(row["best_reached_time"], experiment_start_epoch, time_mode),
        })

    stem = input_path.stem
    markdown_path = output_dir / f"{stem}_summary.md"
    by_fuzzer_csv_path = output_dir / f"{stem}_by_fuzzer.csv"
    by_bug_fuzzer_csv_path = output_dir / f"{stem}_by_bug_fuzzer.csv"

    write_markdown(markdown_path, input_path, db_path, experiment_start_epoch,
                   total_bugs, bug_locations, fuzzer_summaries, bug_fuzzer_rows,
                   time_mode)
    write_csv(
        by_fuzzer_csv_path,
        [
            "fuzzer", "trial_count", "triggered_trial_count", "reached_trial_count",
            "unique_triggered", "unique_reached",
            "mean_triggered_per_trial", "mean_reached_per_trial",
            "bugs_triggered_all_trials", "bugs_reached_all_trials",
            "first_triggered_time", "first_triggered_hours",
            "first_reached_time", "first_reached_hours",
            "missing_triggered", "missing_reached",
        ],
        by_fuzzer_rows,
    )
    write_csv(
        by_bug_fuzzer_csv_path,
        [
            "bug_id", "crash_location", "fuzzer", "triggered_trial_count",
            "reached_trial_count", "best_triggered_time", "best_triggered_hours",
            "best_reached_time", "best_reached_hours",
        ],
        detailed_rows,
    )

    logger.info("Wrote markdown summary: %s", markdown_path)
    logger.info("Wrote per-fuzzer CSV: %s", by_fuzzer_csv_path)
    logger.info("Wrote per-bug/fuzzer CSV: %s", by_bug_fuzzer_csv_path)


if __name__ == "__main__":
    main()
