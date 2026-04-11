#!/usr/bin/env python3
"""Watch a FuzzBench experiment for crash activity."""

from __future__ import annotations

import argparse
import sqlite3
import tarfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


def resolve_db_path(experiment: Path) -> Path:
    if experiment.name == "local.db":
        return experiment
    return experiment / "local.db"


def resolve_filestore_dir(experiment: Path) -> Path:
    if experiment.name == "local.db":
        experiment = experiment.parent
    nested = experiment / experiment.name
    if nested.exists():
        return nested
    return experiment


def read_db_summary(db_path: Path) -> dict:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        experiment_row = cur.execute(
            "select time_created, time_ended from experiment limit 1"
        ).fetchone()
        total_trials = cur.execute("select count(*) from trial").fetchone()[0]
        ended_trials = cur.execute(
            "select count(*) from trial where time_ended is not null"
        ).fetchone()[0]
        latest_snapshot = cur.execute("select max(time) from snapshot").fetchone()[0]
        crash_rows = cur.execute("select count(*) from crash").fetchone()[0]
        rows = cur.execute(
            """
            select trial.fuzzer, count(*)
            from crash
            join trial on crash.trial_id = trial.id
            group by trial.fuzzer
            order by trial.fuzzer
            """
        ).fetchall()
        state_rows = cur.execute(
            """
            select crash_state, count(*)
            from crash
            group by crash_state
            order by count(*) desc, crash_state
            limit 5
            """
        ).fetchall()
    finally:
        conn.close()

    return {
        "time_created": experiment_row[0] if experiment_row else None,
        "time_ended": experiment_row[1] if experiment_row else None,
        "total_trials": total_trials,
        "ended_trials": ended_trials,
        "latest_snapshot": latest_snapshot,
        "crash_rows": crash_rows,
        "crashes_by_fuzzer": rows,
        "top_crash_states": state_rows,
    }


def summarize_archives(experiment_dir: Path) -> dict:
    experiment_folders = resolve_filestore_dir(experiment_dir) / "experiment-folders"
    archives = sorted(experiment_folders.glob("**/crashes/*.tar.gz"))

    archive_count_by_fuzzer = Counter()
    member_prefixes = Counter()
    member_count_by_fuzzer = Counter()
    nonempty_crash_members = 0
    samples = []

    for archive in archives:
        fuzzer = archive.parents[2].name.split("-")[-1]
        archive_count_by_fuzzer[fuzzer] += 1
        try:
            with tarfile.open(archive, "r:gz") as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    member_count_by_fuzzer[fuzzer] += 1
                    prefix = member.name.split("/")[-1].split("-", 1)[0]
                    member_prefixes[prefix] += 1
                    if prefix == "crash" and member.size > 0:
                        nonempty_crash_members += 1
                    if len(samples) < 8:
                        samples.append((archive, member.name, member.size))
        except tarfile.TarError:
            continue

    return {
        "archive_count": len(archives),
        "archive_count_by_fuzzer": archive_count_by_fuzzer,
        "member_prefixes": member_prefixes,
        "member_count_by_fuzzer": member_count_by_fuzzer,
        "nonempty_crash_members": nonempty_crash_members,
        "samples": samples,
    }


def print_summary(db_path: Path, experiment_dir: Path) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    db = read_db_summary(db_path)
    archives = summarize_archives(experiment_dir)

    print(f"[{now}] {db_path}")
    print(
        f"experiment: created={db['time_created']} ended={db['time_ended']} "
        f"trials={db['ended_trials']}/{db['total_trials']} "
        f"latest_snapshot={db['latest_snapshot']}s crash_rows={db['crash_rows']}"
    )

    if db["crashes_by_fuzzer"]:
        print("db_crashes_by_fuzzer:")
        for fuzzer, count in db["crashes_by_fuzzer"]:
            print(f"  {fuzzer}: {count}")
    else:
        print("db_crashes_by_fuzzer: none")

    if db["top_crash_states"]:
        print("top_db_crash_states:")
        for state, count in db["top_crash_states"]:
            state = (state or "").replace("\n", " | ")
            print(f"  {count}x {state[:180]}")

    print(
        f"raw_crash_archives: {archives['archive_count']} "
        f"nonempty_crash_members={archives['nonempty_crash_members']}"
    )
    if archives["archive_count_by_fuzzer"]:
        print("raw_archives_by_fuzzer:")
        for fuzzer in sorted(archives["archive_count_by_fuzzer"]):
            print(f"  {fuzzer}: {archives['archive_count_by_fuzzer'][fuzzer]}")
    if archives["member_prefixes"]:
        print("raw_member_prefixes:")
        for prefix, count in archives["member_prefixes"].most_common():
            print(f"  {prefix}: {count}")
    if archives["samples"]:
        print("raw_samples:")
        for archive, member_name, size in archives["samples"]:
            rel = archive.relative_to(resolve_filestore_dir(experiment_dir) / "experiment-folders")
            print(f"  {rel}: {member_name} size={size}")
    print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Watch a FuzzBench experiment and report crash activity.",
    )
    parser.add_argument(
        "experiment",
        help="Experiment directory or local.db path.",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Polling interval in seconds.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Print one summary and exit.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    experiment = Path(args.experiment).resolve()
    db_path = resolve_db_path(experiment)
    experiment_dir = db_path.parent

    if not db_path.exists():
        raise FileNotFoundError(db_path)

    while True:
        print_summary(db_path, experiment_dir)
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
