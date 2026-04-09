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
import shutil
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

# Statuses that count toward target-commit selection (high-confidence triggers).
STRONG_TRIGGER_STATUSES = {"1|1", "1|0", "0.5|1"}
# Statuses treated as "already triggering" when partitioning bugs at the chosen
# target commit.  Includes 0.5|0 (crashes but with mismatched signature) so we
# don't waste agent runs on bugs that already crash locally.
LOCAL_BUG_STATUSES = {"1|1", "1|0", "0.5|1", "0.5|0"}


def _is_ancestor(repo_path: str, older: str, newer: str) -> bool:
    """Check if *older* is an ancestor of *newer* using git CLI."""
    ret = subprocess.run(
        ["git", "merge-base", "--is-ancestor", older, newer],
        cwd=repo_path,
        capture_output=True,
    )
    return ret.returncode == 0


def find_adjacent_csv_commit(
    data: list[dict],
    buggy_commit: str,
    target_commit: str,
    repo_path: str,
) -> str | None:
    """Return the first CSV commit after *buggy_commit* in the direction of
    *target_commit*, by walking the git ancestry path and checking which
    commits appear in the CSV.

    This gives the window [buggy_commit, adjacent) that most likely contains
    the bug fix (or introduction), without scanning every individual git commit.
    """
    try:
        result = subprocess.run(
            ["git", "log",
             f"{buggy_commit}..{target_commit}",
             "--ancestry-path", "--reverse", "--format=%H"],
            cwd=repo_path,
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return None
        ordered_commits = [c for c in result.stdout.strip().splitlines() if c]
    except Exception as exc:
        logger.debug("find_adjacent_csv_commit git log error: %s", exc)
        return None

    csv_commit_set = {row["commit_id"] for row in data}
    for commit in ordered_commits:
        if commit in csv_commit_set:
            return commit
    return None


def generate_fix_diffs(
    bug_tasks: list[tuple[str, str, dict]],
    repo_path: str,
) -> None:
    """Pre-generate fix hint diffs for all bugs in bug_tasks.

    Runs git diff on the host repo and writes results to
    DATA_DIR/patch_diffs/fix_hint-<buggy_short>-<testcase>.diff.
    Done upfront so diffs exist even for bugs skipped by --resume.
    """
    patch_diffs_dir = DATA_DIR / "patch_diffs"
    patch_diffs_dir.mkdir(parents=True, exist_ok=True)

    for bug_id, buggy_commit, metadata in bug_tasks:
        adjacent_commit = metadata.get("adjacent_commit")
        if not adjacent_commit:
            continue
        testcase = metadata["testcase"]
        buggy_short = buggy_commit[:8]
        out_path = patch_diffs_dir / f"fix_hint-{buggy_short}-{testcase}.diff"
        if out_path.exists():
            logger.info("[%s] Fix diff already exists: %s", bug_id, out_path.name)
            continue
        try:
            result = subprocess.run(
                ["git", "diff", buggy_commit, adjacent_commit],
                cwd=repo_path,
                capture_output=True, encoding="utf-8", errors="replace",
            )
            diff_text = result.stdout
        except Exception as exc:
            logger.warning("[%s] git diff failed: %s", bug_id, exc)
            continue
        if not diff_text.strip():
            logger.info("[%s] Fix diff empty — skipping", bug_id)
            continue
        out_path.write_text(diff_text)
        logger.info("[%s] Fix diff saved: %s (adjacent=%s)",
                    bug_id, out_path.name, adjacent_commit[:8])


def collect_all_crash_trace_data(
    bug_tasks: list[tuple[str, str, dict]],
    args: argparse.Namespace,
) -> None:
    """Pre-collect crash logs and traces for all bugs, grouped by buggy commit.

    Each unique (buggy_commit, fuzzer) pair only needs one build, so this is
    much faster than letting each bug_transplant.py invocation rebuild.
    Failures are logged but non-fatal — the agent can still work without
    crash/trace data.
    """
    FUZZ_HELPER = SCRIPT_DIR / "fuzz_helper.py"
    crash_dir = DATA_DIR / "crash"
    crash_dir.mkdir(parents=True, exist_ok=True)

    for bug_id, buggy_commit, metadata in bug_tasks:
        testcase = metadata["testcase"]
        fuzzer = metadata["fuzzer"]
        buggy_short = buggy_commit[:8]

        # --- Crash ---
        crash_file = crash_dir / f"target_crash-{buggy_short}-{testcase}.txt"
        if not crash_file.exists():
            logger.info("[%s] Collecting crash data at %s...", bug_id, buggy_short)
            cmd = [
                sys.executable, str(FUZZ_HELPER),
                "collect_crash", args.target, fuzzer,
                "--commit", buggy_commit,
                "--testcases", args.testcases_dir,
                "--test_input", testcase,
            ]
            if args.build_csv:
                cmd += ["--build_csv", args.build_csv]
            if args.runner_image:
                cmd += ["--runner-image", args.runner_image]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.warning("[%s] collect_crash failed (exit %d)", bug_id, result.returncode)
            elif crash_file.exists():
                logger.info("[%s] Crash data collected: %s", bug_id, crash_file)

        # --- Trace ---
        trace_file = DATA_DIR / f"target_trace-{buggy_short}-{testcase}.txt"
        if not trace_file.exists():
            logger.info("[%s] Collecting trace data at %s...", bug_id, buggy_short)
            cmd = [
                sys.executable, str(FUZZ_HELPER),
                "collect_trace", args.target, fuzzer,
                "--commit", buggy_commit,
                "--testcases", args.testcases_dir,
                "--test_input", testcase,
            ]
            if args.build_csv:
                cmd += ["--build_csv", args.build_csv]
            if args.runner_image:
                cmd += ["--runner-image", args.runner_image]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.warning("[%s] collect_trace failed (exit %d)", bug_id, result.returncode)
            elif trace_file.exists():
                logger.info("[%s] Trace data collected: %s", bug_id, trace_file)


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
) -> tuple[set[str], dict[str, dict], set[str], dict]:
    """Select target commit and partition bugs.

    Returns:
        (bug_ids_trigger, bugs_need_transplant, bugs_cant_use, target_row)
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
        if status in LOCAL_BUG_STATUSES:
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

    return bug_ids_trigger, bugs_need_transplant, bugs_cant_use, target_row


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
    """Check if the output folder for this bug already exists."""
    out_dir = DATA_DIR / "bug_transplant" / f"{project}_{bug_id}"
    return out_dir.exists()


def run_single_bug(
    project: str,
    bug_id: str,
    buggy_commit: str,
    target_commit: str,
    metadata: dict,
    args: argparse.Namespace,
    container_name: str | None = None,
    agents_dir: str | None = None,
    repo_path: str | None = None,
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
    if repo_path:
        cmd += ["--repo-path", repo_path]
    if metadata.get("adjacent_commit"):
        cmd += ["--adjacent-commit", metadata["adjacent_commit"]]
    if args.model:
        cmd += ["--model", args.model]
    if args.timeout:
        cmd += ["--timeout", str(args.timeout)]
    if args.keep_containers:
        cmd.append("--keep-container")
    if args.verbose:
        cmd.append("--verbose")
    codex_mode = getattr(args, "codex_mode", "exec")
    if codex_mode == "interactive":
        cmd += ["--codex-mode", "interactive"]
    # Shared container mode
    if container_name:
        cmd += ["--container-name", container_name]
    if agents_dir:
        cmd += ["--agents-dir", agents_dir]

    logger.info("[%s] Starting: buggy=%s target=%s fuzzer=%s",
                bug_id, buggy_commit[:8], target_commit[:8], metadata["fuzzer"])

    start = time.monotonic()
    try:
        if codex_mode == "interactive":
            # Interactive mode: inherit terminal so tmux can attach
            rc = subprocess.call(
                cmd,
                timeout=args.timeout + 120 if args.timeout else 3720,
            )
            result["exit_code"] = rc
            result["status"] = "success" if rc == 0 else "failed"
            if rc != 0:
                result["error_message"] = f"exit code {rc}"
        else:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=args.timeout + 120 if args.timeout else 3720,
            )
            result["exit_code"] = proc.returncode
            if proc.returncode == 0:
                result["status"] = "success"
            else:
                result["status"] = "failed"
                output = (proc.stdout + proc.stderr).strip()
                result["error_message"] = output[-500:] if output else "non-zero exit"
                # Print full subprocess output so failures are visible in the log
                if output:
                    logger.error("[%s] Subprocess output:\n%s", bug_id, output)
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

    # Collect token usage from per-bug output
    usage_path = out_dir / "token_usage.json"
    if usage_path.exists():
        try:
            usage = json.loads(usage_path.read_text())
            result["token_usage"] = usage
            logger.info("[%s] Token usage: %d in (%d cached) + %d out | Cost: $%.4f",
                        bug_id, usage.get("input_tokens", 0),
                        usage.get("cached_input_tokens", 0),
                        usage.get("output_tokens", 0), usage.get("cost", 0))
        except Exception:
            pass

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


def _result_from_folder(project: str, bug_id: str) -> dict:
    """Derive a result entry from the output folder contents."""
    out_dir = DATA_DIR / "bug_transplant" / f"{project}_{bug_id}"
    if (out_dir / "bug_transplant.impossible").exists():
        reason = (out_dir / "bug_transplant.impossible").read_text().strip()
        return {"bug_id": bug_id, "status": "impossible", "reason": reason}
    has_diff = any(
        (out_dir / name).exists()
        for name in ("bug_transplant.diff", "git_diff.diff")
    )
    has_crash = (out_dir / "transplant_crash.txt").exists()
    has_testcase = any(out_dir.glob("testcase-*"))
    if has_diff and (has_crash or has_testcase):
        return {"bug_id": bug_id, "status": "success"}
    if has_diff:
        return {"bug_id": bug_id, "status": "failed", "reason": "diff but no crash/testcase"}
    return {"bug_id": bug_id, "status": "failed", "reason": "no artifacts"}


def write_summary(
    output_dir: Path,
    results: list[dict],
    target_commit: str,
    project: str,
    bug_ids_trigger: set[str],
    bug_info_dataset: dict,
    total_elapsed: float,
) -> None:
    """Write final summary JSON, merging with existing folder-based results."""
    # Load existing summary to preserve entries not in this run
    existing: dict[str, dict] = {}
    path = output_dir / "summary.json"
    if path.exists():
        try:
            old = json.loads(path.read_text())
            for r in old.get("results", []):
                bid = r.get("bug_id")
                if bid:
                    existing[bid] = r
        except Exception:
            pass

    # Scan all folders on disk to build ground-truth results
    for folder in (DATA_DIR / "bug_transplant").iterdir():
        if not folder.is_dir():
            continue
        prefix = f"{project}_"
        if not folder.name.startswith(prefix):
            continue
        bug_id = folder.name[len(prefix):]
        existing[bug_id] = _result_from_folder(project, bug_id)

    # Override with fresh results from this run, but let the on-disk
    # impossible marker win — the agent may exit 0 after writing it.
    for r in results:
        bid = r.get("bug_id")
        if bid and r.get("status") not in ("skipped", None):
            if existing.get(bid, {}).get("status") != "impossible":
                existing[bid] = r

    asan_bug_ids_trigger = {
        bug_id
        for bug_id in bug_ids_trigger
        if bug_info_dataset.get(bug_id, {}).get("reproduce", {})
        .get("sanitizer", "address").split(" ")[0] == "address"
    }

    merged_results = sorted(existing.values(), key=lambda r: r.get("bug_id", ""))
    completed = [r for r in merged_results if r["status"] not in ("skipped",)]
    summary = {
        "type": "bug_transplant_batch",
        "project": project,
        "target_commit": target_commit,
        "bugs_already_trigger": len(asan_bug_ids_trigger),
        "bugs_already_trigger_ids": sorted(asan_bug_ids_trigger),
        "bugs_attempted": len(completed),
        "bugs_succeeded": sum(1 for r in completed if r["status"] == "success"),
        "bugs_failed": sum(1 for r in completed if r["status"] in ("failed", "error", "impossible")),
        "total_elapsed_seconds": round(total_elapsed, 1),
        "results": merged_results,
    }
    path.write_text(json.dumps(summary, indent=2))
    logger.info("Summary written: %s", path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Batch bug transplant via Codex",
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
    parser.add_argument("--codex-mode", choices=["exec", "interactive"],
                        default="exec",
                        help="Agent invocation mode: exec (default, JSONL) "
                             "or interactive (TUI via tmux)")

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

    bug_ids_trigger, bugs_need_transplant, bugs_cant_use, target_row = prepare_transplant(
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
    skipped_non_asan: list[str] = []
    bug_tasks: list[tuple[str, str, dict]] = []  # (bug_id, buggy_commit, metadata)
    for bug_id, row in bugs_need_transplant.items():
        metadata = resolve_bug_metadata(bug_id, bug_info_dataset, args.testcases_dir)
        if metadata is None:
            logger.warning("Skipping %s: not in bug_info JSON", bug_id)
            continue
        if not metadata["fuzzer"]:
            logger.warning("Skipping %s: no fuzzer name in metadata", bug_id)
            continue
        if metadata["sanitizer"] != "address":
            skipped_non_asan.append(bug_id)
            continue
        # Check testcase exists
        testcase_path = os.path.join(args.testcases_dir, metadata["testcase"])
        if not os.path.exists(testcase_path):
            logger.warning("Skipping %s: testcase not found at %s", bug_id, testcase_path)
            continue
        # Find the adjacent CSV commit (first tested commit after buggy toward target)
        buggy_commit = row["commit_id"]
        if repo_path:
            adjacent = find_adjacent_csv_commit(
                parsed_data, buggy_commit, target_commit, repo_path,
            )
            if adjacent:
                metadata["adjacent_commit"] = adjacent
            else:
                logger.debug("[%s] No adjacent CSV commit found", bug_id)
        bug_tasks.append((bug_id, buggy_commit, metadata))

    # ------------------------------------------------------------------
    # Summary (printed after all filters applied)
    # ------------------------------------------------------------------
    logger.info("All bugs count: %d", len(target_row["osv_statuses"]))
    logger.info("Target commit: %s (poc_count=%d)",
                target_commit[:12], target_row["poc_count"])
    logger.info("Already triggering: %d %s", len(bug_ids_trigger), bug_ids_trigger)
    if bugs_cant_use:
        logger.info("Cannot use (no triggering commit): %d %s", len(bugs_cant_use), bugs_cant_use)
    if skipped_non_asan:
        logger.info("Skipped non-ASAN: %d %s", len(skipped_non_asan), skipped_non_asan)
    logger.info("Bugs to transplant: %d %s",
                len(bug_tasks), {b for b, _, _ in bug_tasks})

    # Generate fix diffs upfront so they exist even for --resume skipped bugs
    if repo_path:
        generate_fix_diffs(bug_tasks, repo_path)

    # Pre-collect crash/trace data for all bugs (skips already-collected)
    if not args.skip_collect:
        collect_all_crash_trace_data(bug_tasks, args)
    # Always skip per-bug collection since we handled it here
    args.skip_collect = True

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
    agent_image = build_agent_image(args.target, project_image)
    logger.info("Docker images ready: %s", agent_image)

    # ------------------------------------------------------------------
    # 5. Run bugs
    # ------------------------------------------------------------------
    artifacts_root = DATA_DIR / "bug_transplant" / f"batch_{args.target}_{target_commit[:8]}"
    artifacts_root.mkdir(parents=True, exist_ok=True)

    # Load previous results from existing summary/progress so --resume
    # preserves 'success'/'failed' status instead of overwriting with 'skipped'.
    prev_results: dict[str, dict] = {}
    for fname in ("summary.json", "progress.json"):
        prev_path = artifacts_root / fname
        if prev_path.exists():
            try:
                prev_data = json.loads(prev_path.read_text())
                for r in prev_data.get("results", []):
                    bid = r.get("bug_id")
                    if bid and bid not in prev_results:
                        prev_results[bid] = r
                if prev_results:
                    logger.info(
                        "Loaded %d previous results from %s", len(prev_results), fname
                    )
                    break
            except Exception:
                pass

    results: list[dict] = []
    batch_start = time.monotonic()

    # --- Create shared container for sequential mode ---
    from bug_transplant import (
        setup_agents_dir, create_shared_container,
    )
    import shutil

    shared_container = None
    shared_agents_dir = None

    try:
        if args.jobs <= 1:
            # Create shared container + AGENTS.md once for all bugs
            shared_container = f"bug-transplant-{args.target}-batch"
            first_fuzzer = bug_tasks[0][2]["fuzzer"] if bug_tasks else "unknown"

            # Build a temporary args-like object for setup_agents_dir
            class _SetupArgs:
                pass
            _sa = _SetupArgs()
            _sa.project = args.target
            _sa.target_commit = target_commit
            _sa.fuzzer_name = first_fuzzer
            shared_agents_path = setup_agents_dir(_sa)
            shared_agents_dir = str(shared_agents_path)

            # Create the shared container once
            ret = create_shared_container(
                project=args.target,
                target_commit=target_commit,
                container_name=shared_container,
                agents_dir=shared_agents_path,
                testcases_dir=args.testcases_dir,
            )
            if ret != 0:
                logger.error("Failed to create shared container")
                return 1

            # Sequential
            for bug_id, buggy_commit, metadata in bug_tasks:
                if args.resume and is_bug_completed(args.target, bug_id):
                    logger.info("[%s] Already completed, skipping (--resume)", bug_id)
                    prev = prev_results.get(bug_id)
                    results.append(prev if prev and prev.get("status") not in ("skipped", None)
                                   else {"bug_id": bug_id, "status": "skipped"})
                    write_progress(artifacts_root, results, ongoing=[])
                    continue

                result = run_single_bug(
                    args.target, bug_id, buggy_commit, target_commit,
                    metadata, args,
                    container_name=shared_container,
                    agents_dir=shared_agents_dir,
                    repo_path=repo_path,
                )
                results.append(result)
                write_progress(artifacts_root, results, ongoing=[])
                # Persist AGENTS.md after each bug so knowledge survives interruption
                _agents_md = Path(shared_agents_dir) / "AGENTS.md"
                if _agents_md.exists():
                    shutil.copy2(_agents_md, artifacts_root / "AGENTS.md")
        else:
            # Parallel via ThreadPoolExecutor
            ongoing: set[str] = set()
            with ThreadPoolExecutor(max_workers=args.jobs) as executor:
                fut_to_bug: dict = {}
                for bug_id, buggy_commit, metadata in bug_tasks:
                    if args.resume and is_bug_completed(args.target, bug_id):
                        logger.info("[%s] Already completed, skipping (--resume)", bug_id)
                        prev = prev_results.get(bug_id)
                        results.append(prev if prev and prev.get("status") not in ("skipped", None)
                                       else {"bug_id": bug_id, "status": "skipped"})
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
        # Save final AGENTS.md to artifacts
        if shared_agents_dir:
            agents_md = Path(shared_agents_dir) / "AGENTS.md"
            if agents_md.exists():
                dest = artifacts_root / "AGENTS.md"
                shutil.copy2(agents_md, dest)
                logger.info("Shared knowledge saved: %s", dest)
            # Clean up temp dir
            shutil.rmtree(shared_agents_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # 6. Write summary
    # ------------------------------------------------------------------
    total_elapsed = time.monotonic() - batch_start
    write_summary(
        artifacts_root, results, target_commit, args.target,
        bug_ids_trigger, bug_info_dataset, total_elapsed,
    )

    # Aggregate token usage
    total_input = sum(r.get("token_usage", {}).get("input_tokens", 0) for r in results)
    total_cached = sum(r.get("token_usage", {}).get("cached_input_tokens", 0) for r in results)
    total_output = sum(r.get("token_usage", {}).get("output_tokens", 0) for r in results)
    total_cost = sum(r.get("token_usage", {}).get("cost", 0) for r in results)

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
    if total_cost > 0:
        print(f"  Tokens:    {total_input} in ({total_cached} cached) + {total_output} out")
        print(f"  Cost:      ${total_cost:.4f}")
    print(f"  Summary:  {artifacts_root / 'summary.json'}")
    print(f"{'='*60}\n")

    return 1 if failed > 0 and succeeded == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
