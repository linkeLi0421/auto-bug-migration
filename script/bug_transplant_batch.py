#!/usr/bin/env python3
"""Batch bug transplant runner -- iterate all bugs for a project.

Reads the same CSV/JSON data sources as ``revert_patch_test.py``, selects
a target commit, resolves per-bug metadata (fuzzer, sanitizer, testcase),
and calls ``bug_transplant.py`` for each bug that needs transplanting.

Usage:
  # Run all bugs for wavpack
  python3 script/bug_transplant_batch.py ~/log/wavpack.csv \\
    --bug_info osv_testcases_summary.json \\
    --build_csv ~/log/wavpack_builds.csv \\
    --target wavpack

  # Single bug, skip data collection
  python3 script/bug_transplant_batch.py ~/log/wavpack.csv \\
    --bug_info osv_testcases_summary.json \\
    --build_csv ~/log/wavpack_builds.csv \\
    --target wavpack --bug_id OSV-2020-1006 --skip-collect

  # Dry run to see what would be executed
  python3 script/bug_transplant_batch.py ~/log/wavpack.csv \\
    --bug_info osv_testcases_summary.json \\
    --build_csv ~/log/wavpack_builds.csv \\
    --target wavpack --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
HOME_DIR = SCRIPT_DIR.parent
DATA_DIR = HOME_DIR / "data"
BUG_TRANSPLANT_SCRIPT = SCRIPT_DIR / "bug_transplant.py"


# ---------------------------------------------------------------------------
# CSV parsing (from revert_patch_test.py lines 1016-1045)
# ---------------------------------------------------------------------------

def parse_csv_file(file_path: str) -> list[dict]:
    with open(file_path, "r") as f:
        csv_content = f.read()
    return parse_csv_data(csv_content)


def parse_csv_data(csv_content: str) -> list[dict]:
    lines = csv_content.strip().split("\n")
    headers = lines[0].split(",")
    data = []

    for line in lines[1:]:
        values = line.split(",")
        if len(values) >= 2:
            row = {
                "commit_id": values[0],
                "osv_statuses": {},
                "poc_count": 0,
                "weak_poc_count": 0,
            }
            for i in range(1, len(headers)):
                bug_id = headers[i]
                status = values[i] if i < len(values) and values[i] else None
                row["osv_statuses"][bug_id] = status
                if status == "1|1":
                    row["poc_count"] += 1
                elif status == "0.5|1":
                    row["weak_poc_count"] += 1
            data.append(row)

    return data


# ---------------------------------------------------------------------------
# Testcase selection (from revert_patch_test.py lines 1048-1057)
# ---------------------------------------------------------------------------

def select_crash_test_input(bug_id: str, testcases_dir: str) -> str:
    """Return preferred testcase filename."""
    base_name = f"testcase-{bug_id}"
    return base_name


# ---------------------------------------------------------------------------
# Target commit selection (adapted from revert_patch_test.py lines 1310-1386)
# ---------------------------------------------------------------------------

STRONG_TRIGGER_STATUSES = {"1|1", "1|0", "0.5|1"}


def _is_ancestor(repo_path: str, older: str, newer: str) -> bool:
    """Check if *older* is an ancestor of *newer* using git CLI."""
    ret = subprocess.run(
        ["git", "merge-base", "--is-ancestor", older, newer],
        cwd=repo_path,
        capture_output=True,
    )
    return ret.returncode == 0


def _trigger_rank(status: str | None) -> int:
    if status in {"1|1", "1|0"}:
        return 2
    if status == "0.5|1":
        return 1
    return 0


def prepare_transplant(
    data: list[dict],
    repo_path: str | None,
    target_commit_override: str | None = None,
) -> tuple[set[str], dict[str, dict], dict]:
    """Select target commit and partition bugs.

    Returns:
        (bug_ids_trigger, bugs_need_transplant, target_row)
    """
    # Recount poc stats (CSV parser may have partial counts)
    for row in data:
        row["poc_count"] = 0
        row["weak_poc_count"] = 0
        for status in row["osv_statuses"].values():
            if status in STRONG_TRIGGER_STATUSES:
                row["poc_count"] += 1
            elif status == "0.5|1":
                row["weak_poc_count"] += 1

    # Select target commit
    if target_commit_override:
        target_row = None
        for row in data:
            if row["commit_id"].startswith(target_commit_override):
                target_row = row
                break
        if target_row is None:
            logger.error(
                "--target-commit %s not found in CSV", target_commit_override,
            )
            return set(), {}, {}
        logger.info(
            "Target commit (user-specified): %s", target_row["commit_id"][:12],
        )
    else:
        target_row = max(
            data, key=lambda r: (r["poc_count"], r["weak_poc_count"]),
        )
        logger.info(
            "Target commit (most bugs, poc_count=%d): %s",
            target_row["poc_count"], target_row["commit_id"][:12],
        )

    # Partition bugs: already triggering vs. need transplant
    bug_ids_trigger: set[str] = set()
    bug_ids_other: set[str] = set()
    for bug_id, status in target_row["osv_statuses"].items():
        if status in STRONG_TRIGGER_STATUSES:
            bug_ids_trigger.add(bug_id)
        else:
            bug_ids_other.add(bug_id)

    # For each non-triggering bug, find the best source commit
    bugs_need_transplant: dict[str, dict] = {}
    bug_best_rank: dict[str, int] = {}
    for row in data:
        for bug_id in bug_ids_other:
            status = row["osv_statuses"].get(bug_id)
            rank = _trigger_rank(status)
            if rank == 0:
                continue
            prev_rank = bug_best_rank.get(bug_id, 0)
            if rank > prev_rank:
                bugs_need_transplant[bug_id] = row
                bug_best_rank[bug_id] = rank
            elif rank == prev_rank and bug_id in bugs_need_transplant:
                # Same rank: prefer later commit (closer to target)
                if repo_path and _is_ancestor(
                    repo_path, bugs_need_transplant[bug_id]["commit_id"],
                    row["commit_id"],
                ):
                    bugs_need_transplant[bug_id] = row

    bugs_cant_use = {
        b for b in bug_ids_other
        if b not in bugs_need_transplant and b != "poc count"
    }

    logger.info("All bugs count: %d", len(target_row["osv_statuses"]))
    logger.info(
        "Target row poc_count=%d weak_poc_count=%d",
        target_row["poc_count"], target_row["weak_poc_count"],
    )
    logger.info("Already triggering: %d %s", len(bug_ids_trigger), bug_ids_trigger)
    logger.info(
        "Need transplant: %d %s",
        len(bugs_need_transplant), set(bugs_need_transplant.keys()),
    )
    if bugs_cant_use:
        logger.info("Cannot use (no triggering commit): %d %s", len(bugs_cant_use), bugs_cant_use)

    return bug_ids_trigger, bugs_need_transplant, target_row


# ---------------------------------------------------------------------------
# Bug metadata resolution
# ---------------------------------------------------------------------------

def resolve_bug_metadata(
    bug_id: str, bug_info_dataset: dict, testcases_dir: str,
) -> dict | None:
    """Extract per-bug metadata from bug info JSON.

    Returns None if bug_id is not in the dataset.
    """
    info = bug_info_dataset.get(bug_id)
    if not info:
        logger.warning("Bug %s not found in bug_info JSON", bug_id)
        return None

    reproduce = info.get("reproduce", {})
    fuzzer = reproduce.get("fuzz_target", "")
    sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
    crash_type = reproduce.get("crash_type", "")
    job_type = reproduce.get("job_type", "")

    # Architecture from job_type (e.g. "libfuzzer_asan_wavpack_i386_libfuzzer")
    parts = job_type.split("_")
    arch = "i386" if "i386" in parts else "x86_64"

    testcase = select_crash_test_input(bug_id, testcases_dir)

    return {
        "fuzzer": fuzzer,
        "sanitizer": sanitizer,
        "crash_type": crash_type,
        "arch": arch,
        "testcase": testcase,
    }


# ---------------------------------------------------------------------------
# Per-bug execution
# ---------------------------------------------------------------------------

def is_bug_completed(project: str, bug_id: str) -> bool:
    """Check if transplant artifacts already exist for this bug.

    A bug is considered completed if it has a diff file (even empty for
    testcase-only transplants) AND a testcase or crash log, or if the
    agent declared it impossible.
    """
    out_dir = DATA_DIR / "bug_transplant" / f"{project}_{bug_id}"
    if not out_dir.exists():
        return False
    # Agent declared impossible
    if (out_dir / "bug_transplant.impossible").exists():
        return True
    has_diff = any(
        (out_dir / name).exists()
        for name in ("bug_transplant.diff", "git_diff.diff")
    )
    has_testcase = any(
        p.name.startswith("testcase-") for p in out_dir.glob("testcase-*")
    )
    has_crash = (out_dir / "transplant_crash.txt").exists()
    return has_diff and (has_testcase or has_crash)


def run_single_bug(
    project: str,
    bug_id: str,
    buggy_commit: str,
    target_commit: str,
    metadata: dict,
    args: argparse.Namespace,
    container_name: str | None = None,
    claude_dir: str | None = None,
) -> dict:
    """Run bug_transplant.py for a single bug, return result dict."""
    result = {
        "bug_id": bug_id,
        "buggy_commit": buggy_commit,
        "target_commit": target_commit,
        "fuzzer": metadata["fuzzer"],
        "status": "error",
        "exit_code": -1,
        "elapsed_seconds": 0.0,
        "diff_path": None,
        "error_message": None,
    }

    cmd = [
        sys.executable, str(BUG_TRANSPLANT_SCRIPT),
        project,
        "--buggy-commit", buggy_commit,
        "--target-commit", target_commit,
        "--bug-id", bug_id,
        "--fuzzer-name", metadata["fuzzer"],
        "--testcase", metadata["testcase"],
        "--testcases-dir", args.testcases_dir,
    ]
    if args.build_csv:
        cmd += ["--build-csv", args.build_csv]
    if args.runner_image:
        cmd += ["--runner-image", args.runner_image]
    if args.skip_collect:
        cmd.append("--skip-collect")
    if args.agent:
        cmd += ["--agent", args.agent]
    if args.model:
        cmd += ["--model", args.model]
    if args.timeout:
        cmd += ["--timeout", str(args.timeout)]
    if args.keep_containers:
        cmd.append("--keep-container")
    if args.verbose:
        cmd.append("--verbose")
    # Shared container mode
    if container_name:
        cmd += ["--container-name", container_name]
    if claude_dir:
        cmd += ["--claude-dir", claude_dir]

    logger.info("[%s] Starting: buggy=%s target=%s fuzzer=%s",
                bug_id, buggy_commit[:8], target_commit[:8], metadata["fuzzer"])

    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=args.timeout + 120 if args.timeout else 3720,
        )
        result["exit_code"] = proc.returncode
        if proc.returncode == 0:
            result["status"] = "success"
        else:
            result["status"] = "failed"
            # Capture last 500 chars of output for diagnostics
            output = (proc.stdout + proc.stderr).strip()
            result["error_message"] = output[-500:] if output else "non-zero exit"
    except subprocess.TimeoutExpired:
        result["status"] = "error"
        result["error_message"] = "subprocess timeout"
        logger.error("[%s] Timed out", bug_id)
    except Exception as exc:
        result["status"] = "error"
        result["error_message"] = str(exc)
        logger.error("[%s] Exception: %s", bug_id, exc)

    result["elapsed_seconds"] = round(time.monotonic() - start, 1)

    # Check for output diff and crash stack
    out_dir = DATA_DIR / "bug_transplant" / f"{project}_{bug_id}"
    for name in ("bug_transplant.diff", "git_diff.diff"):
        p = out_dir / name
        if p.exists() and p.stat().st_size > 0:
            result["diff_path"] = str(p)
            break

    crash_path = out_dir / "transplant_crash.txt"
    if crash_path.exists() and crash_path.stat().st_size > 0:
        result["crash_log_path"] = str(crash_path)

    logger.info(
        "[%s] Finished: status=%s exit=%d elapsed=%.0fs diff=%s",
        bug_id, result["status"], result["exit_code"],
        result["elapsed_seconds"], result["diff_path"] or "none",
    )
    return result


# ---------------------------------------------------------------------------
# Progress and summary
# ---------------------------------------------------------------------------

def write_progress(output_dir: Path, results: list[dict], ongoing: list[str]) -> None:
    """Write incremental progress JSON."""
    completed = [r for r in results if r["status"] != "skipped"]
    skipped = [r for r in results if r["status"] == "skipped"]
    progress = {
        "completed": len(completed),
        "skipped": len(skipped),
        "ongoing": ongoing,
        "succeeded": sum(1 for r in completed if r["status"] == "success"),
        "failed": sum(1 for r in completed if r["status"] in ("failed", "error")),
        "results": results,
    }
    path = output_dir / "progress.json"
    path.write_text(json.dumps(progress, indent=2))


def write_summary(
    output_dir: Path,
    results: list[dict],
    target_commit: str,
    project: str,
    bug_ids_trigger: set[str],
    total_elapsed: float,
) -> None:
    """Write final summary JSON."""
    completed = [r for r in results if r["status"] != "skipped"]
    summary = {
        "type": "bug_transplant_batch",
        "project": project,
        "target_commit": target_commit,
        "total_bugs_in_csv": None,  # filled below
        "bugs_already_trigger": len(bug_ids_trigger),
        "bugs_already_trigger_ids": sorted(bug_ids_trigger),
        "bugs_attempted": len(completed),
        "bugs_skipped_resume": sum(1 for r in results if r["status"] == "skipped"),
        "bugs_succeeded": sum(1 for r in results if r["status"] == "success"),
        "bugs_failed": sum(1 for r in results if r["status"] in ("failed", "error")),
        "total_elapsed_seconds": round(total_elapsed, 1),
        "results": results,
    }
    path = output_dir / "summary.json"
    path.write_text(json.dumps(summary, indent=2))
    logger.info("Summary written: %s", path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Batch bug transplant via Claude Code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # All bugs for wavpack
              python3 script/bug_transplant_batch.py ~/log/wavpack.csv \\
                --bug_info osv_testcases_summary.json \\
                --build_csv ~/log/wavpack_builds.csv \\
                --target wavpack

              # Single bug, dry run
              python3 script/bug_transplant_batch.py ~/log/wavpack.csv \\
                --bug_info osv_testcases_summary.json \\
                --build_csv ~/log/wavpack_builds.csv \\
                --target wavpack --bug_id OSV-2020-1006 --dry-run
        """),
    )

    # Data sources (mirror revert_patch_test.py)
    parser.add_argument("target_test_result",
                        help="CSV with commit x bug status matrix")
    parser.add_argument("--bug_info", required=True,
                        help="JSON file with per-bug metadata (osv_testcases_summary.json)")
    parser.add_argument("--build_csv", default=None,
                        help="Build CSV mapping commits to OSS-Fuzz versions")
    parser.add_argument("--target", required=True,
                        help="OSS-Fuzz project name")

    # Filtering
    parser.add_argument("--target-commit", default=None,
                        help="Override target commit (default: commit with most bugs)")
    parser.add_argument("--bug_id", nargs="+", default=None,
                        help="Process specific bug(s) only")

    # Execution
    parser.add_argument("--agent", default="claude", choices=["claude", "codex"],
                        help="Code agent to use (default: claude)")
    parser.add_argument("--model", default=None,
                        help="Model to use (passed to agent CLI)")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel bug count (default: 1)")
    parser.add_argument("--timeout", type=int, default=3600,
                        help="Per-bug timeout in seconds (default: 3600)")

    # Data collection
    parser.add_argument("--testcases-dir",
                        default=os.environ.get("TESTCASES", ""),
                        help="Testcase directory (default: $TESTCASES)")
    parser.add_argument("--repo-path",
                        default=os.environ.get("REPO_PATH", ""),
                        help="Project git repo path for ancestry checks (default: $REPO_PATH)")
    parser.add_argument("--skip-collect", action="store_true",
                        help="Skip crash/trace collection")
    parser.add_argument("--runner-image", default=None,
                        help="Docker image pinning (e.g. 'auto')")

    # Modes
    parser.add_argument("--resume", action="store_true",
                        help="Skip already-completed bugs")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be executed without running")
    parser.add_argument("--keep-containers", action="store_true",
                        help="Keep containers alive for debugging")

    # Logging
    parser.add_argument("--verbose", "-V", action="store_true")

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # Validate
    if not args.testcases_dir:
        logger.error("Testcases dir not set. Use --testcases-dir or $TESTCASES.")
        return 1

    # ------------------------------------------------------------------
    # 1. Load data
    # ------------------------------------------------------------------
    logger.info("Loading CSV: %s", args.target_test_result)
    parsed_data = parse_csv_file(args.target_test_result)
    logger.info("Loaded %d commit rows", len(parsed_data))

    logger.info("Loading bug info: %s", args.bug_info)
    with open(args.bug_info) as f:
        bug_info_dataset = json.load(f)
    logger.info("Loaded %d bug entries", len(bug_info_dataset))

    # ------------------------------------------------------------------
    # 2. Select target commit and identify bugs
    # ------------------------------------------------------------------
    repo_path = None
    if args.repo_path:
        project_repo = os.path.join(args.repo_path, args.target)
        if os.path.isdir(project_repo):
            repo_path = project_repo
        elif os.path.isdir(args.repo_path):
            repo_path = args.repo_path

    bug_ids_trigger, bugs_need_transplant, target_row = prepare_transplant(
        parsed_data, repo_path, args.target_commit,
    )
    if not target_row:
        logger.error("Failed to select target commit")
        return 1

    target_commit = target_row["commit_id"]

    # Filter to specific bug(s) if requested
    if args.bug_id:
        filtered = {}
        for bid in args.bug_id:
            if bid in bugs_need_transplant:
                filtered[bid] = bugs_need_transplant[bid]
            elif bid in bug_ids_trigger:
                logger.info("Bug %s already triggers at target commit — skipping", bid)
            else:
                logger.warning("Bug %s not found in CSV; will attempt with target commit", bid)
                filtered[bid] = {"commit_id": args.target_commit or target_commit}
        bugs_need_transplant = filtered

    if not bugs_need_transplant:
        logger.info("No bugs need transplanting")
        return 0

    # ------------------------------------------------------------------
    # 3. Resolve metadata and validate
    # ------------------------------------------------------------------
    bug_tasks: list[tuple[str, str, dict]] = []  # (bug_id, buggy_commit, metadata)
    for bug_id, row in bugs_need_transplant.items():
        metadata = resolve_bug_metadata(bug_id, bug_info_dataset, args.testcases_dir)
        if metadata is None:
            logger.warning("Skipping %s: not in bug_info JSON", bug_id)
            continue
        if not metadata["fuzzer"]:
            logger.warning("Skipping %s: no fuzzer name in metadata", bug_id)
            continue
        # Check testcase exists
        testcase_path = os.path.join(args.testcases_dir, metadata["testcase"])
        if not os.path.exists(testcase_path):
            logger.warning("Skipping %s: testcase not found at %s", bug_id, testcase_path)
            continue
        bug_tasks.append((bug_id, row["commit_id"], metadata))

    logger.info("Bugs to process: %d", len(bug_tasks))

    # ------------------------------------------------------------------
    # Dry run
    # ------------------------------------------------------------------
    if args.dry_run:
        print(f"\n{'='*60}")
        print(f"DRY RUN — Project: {args.target}")
        print(f"Target commit: {target_commit[:12]}")
        print(f"Bugs already triggering: {len(bug_ids_trigger)}")
        print(f"Bugs to transplant: {len(bug_tasks)}")
        print(f"{'='*60}")
        for bug_id, buggy_commit, meta in bug_tasks:
            completed = is_bug_completed(args.target, bug_id) if args.resume else False
            status = "[SKIP-resume]" if completed else "[WILL RUN]"
            print(
                f"  {status} {bug_id}: "
                f"buggy={buggy_commit[:8]} fuzzer={meta['fuzzer']} "
                f"testcase={meta['testcase']}"
            )
        print()
        return 0

    # ------------------------------------------------------------------
    # 4. Build Docker images (once)
    # ------------------------------------------------------------------
    logger.info("Building Docker images for %s...", args.target)
    sys.path.insert(0, str(SCRIPT_DIR))
    from bug_transplant import build_project_image, build_agent_image

    project_image = build_project_image(args.target, target_commit, args.build_csv)
    agent_image = build_agent_image(args.target, project_image, args.agent)
    logger.info("Docker images ready: %s", agent_image)

    # ------------------------------------------------------------------
    # 5. Run bugs
    # ------------------------------------------------------------------
    artifacts_root = DATA_DIR / "bug_transplant" / f"batch_{args.target}_{target_commit[:8]}"
    artifacts_root.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []
    batch_start = time.monotonic()

    # --- Create shared container for sequential mode ---
    from bug_transplant import (
        setup_claude_dir, create_shared_container,
    )
    import shutil

    shared_container = None
    shared_claude_dir = None

    try:
        if args.jobs <= 1:
            # Create shared container + CLAUDE.md once for all bugs
            shared_container = f"bug-transplant-{args.target}-batch"
            first_fuzzer = bug_tasks[0][2]["fuzzer"] if bug_tasks else "unknown"

            # Build a temporary args-like object for setup_claude_dir
            class _SetupArgs:
                pass
            _sa = _SetupArgs()
            _sa.project = args.target
            _sa.target_commit = target_commit
            _sa.fuzzer_name = first_fuzzer
            shared_claude_path = setup_claude_dir(_sa)
            shared_claude_dir = str(shared_claude_path)

            # Create the shared container once
            ret = create_shared_container(
                project=args.target,
                target_commit=target_commit,
                container_name=shared_container,
                claude_dir=shared_claude_path,
                agent=args.agent,
                testcases_dir=args.testcases_dir,
            )
            if ret != 0:
                logger.error("Failed to create shared container")
                return 1

            # Sequential
            for bug_id, buggy_commit, metadata in bug_tasks:
                if args.resume and is_bug_completed(args.target, bug_id):
                    logger.info("[%s] Already completed, skipping (--resume)", bug_id)
                    results.append({"bug_id": bug_id, "status": "skipped"})
                    write_progress(artifacts_root, results, ongoing=[])
                    continue

                result = run_single_bug(
                    args.target, bug_id, buggy_commit, target_commit,
                    metadata, args,
                    container_name=shared_container,
                    claude_dir=shared_claude_dir,
                )
                results.append(result)
                write_progress(artifacts_root, results, ongoing=[])
        else:
            # Parallel via ThreadPoolExecutor
            ongoing: set[str] = set()
            with ThreadPoolExecutor(max_workers=args.jobs) as executor:
                fut_to_bug: dict = {}
                for bug_id, buggy_commit, metadata in bug_tasks:
                    if args.resume and is_bug_completed(args.target, bug_id):
                        logger.info("[%s] Already completed, skipping (--resume)", bug_id)
                        results.append({"bug_id": bug_id, "status": "skipped"})
                        continue

                    fut = executor.submit(
                        run_single_bug,
                        args.target, bug_id, buggy_commit, target_commit,
                        metadata, args,
                    )
                    fut_to_bug[fut] = bug_id
                    ongoing.add(bug_id)

                write_progress(artifacts_root, results, ongoing=sorted(ongoing))

                for fut in as_completed(fut_to_bug):
                    result = fut.result()
                    results.append(result)
                    ongoing.discard(fut_to_bug[fut])
                    write_progress(artifacts_root, results, ongoing=sorted(ongoing))

    except KeyboardInterrupt:
        logger.warning("Interrupted — writing partial summary")
    finally:
        # Clean up shared container
        if shared_container and not args.keep_containers:
            logger.info("Destroying shared container %s...", shared_container)
            subprocess.call(
                ["docker", "rm", "-f", shared_container],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        elif shared_container:
            logger.info("Shared container kept: docker exec -it %s bash",
                        shared_container)
        # Save final CLAUDE.md to artifacts
        if shared_claude_dir:
            claude_md = Path(shared_claude_dir) / "CLAUDE.md"
            if claude_md.exists():
                import shutil
                dest = artifacts_root / "CLAUDE.md"
                shutil.copy2(claude_md, dest)
                logger.info("Shared knowledge saved: %s", dest)
            # Clean up temp dir
            shutil.rmtree(Path(shared_claude_dir).parent, ignore_errors=True)

    # ------------------------------------------------------------------
    # 6. Write summary
    # ------------------------------------------------------------------
    total_elapsed = time.monotonic() - batch_start
    write_summary(
        artifacts_root, results, target_commit, args.target,
        bug_ids_trigger, total_elapsed,
    )

    # Print final stats
    succeeded = sum(1 for r in results if r["status"] == "success")
    failed = sum(1 for r in results if r["status"] in ("failed", "error"))
    skipped = sum(1 for r in results if r["status"] == "skipped")
    print(f"\n{'='*60}")
    print(f"Batch complete: {args.target} @ {target_commit[:12]}")
    print(f"  Succeeded: {succeeded}")
    print(f"  Failed:    {failed}")
    print(f"  Skipped:   {skipped}")
    print(f"  Already triggering at target: {len(bug_ids_trigger)}")
    print(f"  Total time: {total_elapsed:.0f}s")
    print(f"  Summary:  {artifacts_root / 'summary.json'}")
    print(f"{'='*60}\n")

    return 1 if failed > 0 and succeeded == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
