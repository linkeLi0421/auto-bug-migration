#!/usr/bin/env python3
"""Merge per-bug transplant diffs into a single version triggering all bugs.

Takes the per-bug diffs produced by ``bug_transplant_batch.py`` and merges
them incrementally into the target commit.  After each diff is applied, ALL
previously-applied bugs (plus the local bugs that already trigger) are
verified.

Conflict resolution:
  1. ``git apply --check`` (dry run)
  2. If clean → ``git apply``
  3. If conflict → ``git apply --3way`` (let git attempt 3-way merge)
  4. If still fails → invoke Claude Code to resolve manually

Usage:
  python3 script/bug_transplant_merge.py \\
    --summary data/bug_transplant/batch_wavpack_0b99613e/summary.json \\
    --bug_info osv_testcases_summary.json \\
    --target wavpack \\
    --target-commit 0b99613e

  # Dry run (show merge order, detect file overlaps)
  python3 script/bug_transplant_merge.py \\
    --summary data/bug_transplant/batch_wavpack_0b99613e/summary.json \\
    --bug_info osv_testcases_summary.json \\
    --target wavpack --dry-run

  # Keep container for debugging
  python3 script/bug_transplant_merge.py \\
    --summary data/bug_transplant/batch_wavpack_0b99613e/summary.json \\
    --bug_info osv_testcases_summary.json \\
    --target wavpack --keep-container
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

logger = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
HOME_DIR = SCRIPT_DIR.parent
DATA_DIR = HOME_DIR / "data"


# ---------------------------------------------------------------------------
# Diff analysis — file overlap detection and merge ordering
# ---------------------------------------------------------------------------

def files_in_diff(diff_path: str) -> set[str]:
    """Extract file paths touched by a unified diff."""
    files = set()
    try:
        text = Path(diff_path).read_text(errors="replace")
    except OSError:
        return files
    for line in text.splitlines():
        # Match "--- a/path" or "+++ b/path"
        m = re.match(r'^[-+]{3}\s+[ab]/(.+)$', line)
        if m:
            files.add(m.group(1))
    return files


def compute_merge_order(
    bug_diffs: list[dict],
    local_bugs: list[dict],
) -> list[dict]:
    """Sort transplant diffs: fewest file overlaps with others first.

    Bugs touching unique files go first (no conflict risk).
    Bugs overlapping with many others go last.
    """
    # Pre-compute file sets
    for bd in bug_diffs:
        bd["_files"] = files_in_diff(bd["diff_path"])

    local_files = set()
    for lb in local_bugs:
        # Local bugs have no diff, but if they did we'd include their files
        pass

    def overlap_score(bd: dict) -> int:
        """Count how many OTHER diffs touch the same files."""
        score = 0
        for other in bug_diffs:
            if other["bug_id"] == bd["bug_id"]:
                continue
            if bd["_files"] & other["_files"]:
                score += 1
        return score

    return sorted(bug_diffs, key=lambda bd: (overlap_score(bd), len(bd["_files"])))


def detect_conflicts(bug_diffs: list[dict]) -> list[tuple[str, str, set[str]]]:
    """Return pairs of bugs that modify the same files."""
    conflicts = []
    for i, a in enumerate(bug_diffs):
        for b in bug_diffs[i + 1:]:
            overlap = a["_files"] & b["_files"]
            if overlap:
                conflicts.append((a["bug_id"], b["bug_id"], overlap))
    return conflicts


# ---------------------------------------------------------------------------
# Container helpers
# ---------------------------------------------------------------------------

def _exec(container: str, cmd: str, user: str | None = None) -> int:
    """docker exec, print output."""
    docker_cmd = ["docker", "exec"]
    if user:
        docker_cmd += ["-u", user]
    docker_cmd += [container, "bash", "-c", cmd]
    return subprocess.call(docker_cmd)


def _exec_capture(container: str, cmd: str, timeout: int = 600) -> tuple[int, str]:
    """docker exec, capture output."""
    docker_cmd = ["docker", "exec", container, "bash", "-c", cmd]
    try:
        result = subprocess.run(
            docker_cmd, capture_output=True, text=True, timeout=timeout,
        )
        return result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {timeout}s"


def _collect_sanitizers(bug_sanitizers: list[str]) -> list[str]:
    """Return deduplicated sanitizer list in safe build order.

    Order: address -> undefined -> memory.
    MSAN must be last because it recompiles system libraries (libc++) with
    MSAN instrumentation, permanently tainting them for the container.
    """
    # Fixed safe order — MSAN last because it's the most invasive
    SAFE_ORDER = ["address", "undefined", "memory"]
    needed = set(bug_sanitizers)
    return [s for s in SAFE_ORDER if s in needed]


def _build_via_fuzz_helper(
    project: str,
    target_commit: str,
    sanitizer: str,
    build_csv: str | None,
    out_dir: str,
) -> bool:
    """Build using fuzz_helper.py build_version (host-side).

    This handles prepare_repository(), correct OSS-Fuzz commit checkout,
    and Dockerfile matching — which ``compile`` inside the container cannot.
    """
    cmd = [
        sys.executable, str(SCRIPT_DIR / "fuzz_helper.py"),
        "build_version", project,
        "--commit", target_commit,
        "--sanitizer", sanitizer,
        "--no_corpus",
    ]
    if build_csv:
        cmd += ["--build_csv", build_csv]
    logger.info("Building via fuzz_helper.py: sanitizer=%s commit=%s", sanitizer, target_commit[:12])
    ret = subprocess.call(cmd)
    if ret != 0:
        logger.error("fuzz_helper.py build_version failed for sanitizer=%s (exit %d)", sanitizer, ret)
        return False
    # Stash binaries to /out/<sanitizer>/
    san_dir = os.path.join(out_dir, sanitizer)
    os.makedirs(san_dir, exist_ok=True)
    for f in os.listdir(out_dir):
        fpath = os.path.join(out_dir, f)
        if os.path.isfile(fpath) and os.access(fpath, os.X_OK):
            import shutil
            shutil.copy2(fpath, os.path.join(san_dir, f))
    logger.info("Binaries for sanitizer=%s saved to %s/", sanitizer, san_dir)
    return True


def start_merge_container(
    project: str,
    target_commit: str,
    testcases_dir: str,
    build_csv: str | None = None,
    extra_volumes: list[str] | None = None,
    bug_sanitizers: list[str] | None = None,
    agent_type: str = "claude",
) -> tuple[str, bool]:
    """Start a persistent container at the target commit for merging."""
    container_name = f"bug-merge-{project}"
    image_tag = f"bug-transplant-{project}:latest"

    # Check image exists
    ret = subprocess.call(
        ["docker", "image", "inspect", image_tag],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if ret != 0:
        logger.error(
            "Image %s not found. Run bug_transplant_batch.py first to build it.",
            image_tag,
        )
        sys.exit(1)

    # Remove any existing container
    subprocess.call(
        ["docker", "rm", "-f", container_name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    data_dir = str(DATA_DIR)
    out_dir = str(HOME_DIR / "build" / "out" / project)
    work_dir = str(HOME_DIR / "build" / "work" / project)
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(work_dir, exist_ok=True)

    # Detect project language from project.yaml
    project_yaml = HOME_DIR / "oss-fuzz" / "projects" / project / "project.yaml"
    language = "c++"
    if project_yaml.exists():
        for line in project_yaml.read_text().splitlines():
            if line.startswith("language:"):
                language = line.split(":", 1)[1].strip().strip('"').strip("'")
                break

    docker_cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "--privileged", "--shm-size=2g",
        # OSS-Fuzz build environment variables (required by /usr/local/bin/compile)
        "-e", "FUZZING_ENGINE=libfuzzer",
        "-e", "SANITIZER=address",
        "-e", "ARCHITECTURE=x86_64",
        "-e", f"FUZZING_LANGUAGE={language}",
        "-e", "HELPER=True",
        "-e", "MAKEFLAGS=--output-sync=line -j30",
        "-e", "CMAKE_BUILD_PARALLEL_LEVEL=30",
        "-e", "NINJA_STATUS=",
        "-e", "TERM=dumb",
        "-v", f"{data_dir}:/data",
        "-v", f"{os.path.abspath(testcases_dir)}:/corpus",
        "-v", f"{out_dir}:/out",
        "-v", f"{work_dir}:/work",
    ]

    # Agent credentials for conflict resolution (login mode)
    sys.path.insert(0, str(SCRIPT_DIR))
    from bug_transplant import AGENT_CONFIG
    cfg = AGENT_CONFIG.get(agent_type, AGENT_CONFIG["claude"])
    cred_dir = Path.home() / cfg["credentials_dir"]
    if cred_dir.exists():
        docker_cmd += ["-v", f"{cred_dir}:/tmp/.agent-creds-src:ro"]
    cred_config = cfg.get("credentials_config")
    if cred_config:
        cred_config_path = Path.home() / cred_config
        if cred_config_path.exists():
            docker_cmd += ["-v", f"{cred_config_path}:/tmp/.agent-config-src:ro"]

    api_key = os.environ.get(cfg["api_key_env"], "")
    if api_key:
        docker_cmd += ["-e", f"{cfg['api_key_env']}={api_key}"]

    if extra_volumes:
        for v in extra_volumes:
            docker_cmd += ["-v", v]

    docker_cmd += [image_tag, "sleep", "infinity"]

    logger.info("Starting merge container: %s", container_name)
    ret = subprocess.call(docker_cmd)
    if ret != 0:
        logger.error("Failed to start container")
        sys.exit(1)

    # Fix git safe.directory (container uid differs from repo owner)
    _exec(container_name, "git config --global --add safe.directory '*'", user="root")
    _exec(container_name, "sudo git config --global --add safe.directory '*'")

    # Checkout target commit
    _exec(container_name, f"cd /src/{project} && sudo git checkout -f {target_commit}", user="root")
    _exec(container_name, "sudo chown -R agent:agent /src/ /out/ /work/ 2>/dev/null || true", user="root")

    # Copy all testcases to /work
    _exec(container_name, "cp /corpus/testcase-* /work/ 2>/dev/null || true")

    # Build per-sanitizer using fuzz_helper.py on the HOST.
    # This handles prepare_repository(), OSS-Fuzz commit checkout, and
    # Dockerfile matching — which `compile` inside the container cannot.
    # The /out directory is shared between host builds and the container.
    sanitizers_needed = _collect_sanitizers(bug_sanitizers)
    for san in sanitizers_needed:
        if not _build_via_fuzz_helper(project, target_commit, san, build_csv, out_dir):
            if san == "address":
                logger.error("Cannot proceed without a working ASAN build")
                return container_name, False
            logger.warning("Skipping sanitizer=%s, bugs using it won't verify", san)

    return container_name, True


# ---------------------------------------------------------------------------
# Diff application
# ---------------------------------------------------------------------------

def try_apply_diff(container: str, diff_path: str, project: str) -> str:
    """Try to apply a diff inside the container.

    Returns: "clean", "3way", "conflict"
    """
    # Copy diff into container
    diff_name = Path(diff_path).name
    subprocess.call(
        ["docker", "cp", diff_path, f"{container}:/tmp/{diff_name}"],
    )

    # Try clean apply
    ret, output = _exec_capture(
        container,
        f"cd /src/{project} && git apply --check /tmp/{diff_name} 2>&1",
    )
    if ret == 0:
        # Apply cleanly
        ret2, _ = _exec_capture(
            container,
            f"cd /src/{project} && git apply /tmp/{diff_name} 2>&1",
        )
        if ret2 == 0:
            return "clean"

    # Try 3-way merge
    ret, output = _exec_capture(
        container,
        f"cd /src/{project} && git apply --3way /tmp/{diff_name} 2>&1",
    )
    if ret == 0:
        return "3way"

    # Report conflict
    logger.warning("Diff %s has conflicts:\n%s", diff_name, output[:500])
    return "conflict"


def resolve_conflict_with_agent(
    container: str,
    diff_path: str,
    bug_id: str,
    project: str,
    applied_bugs: list[str],
    agent: str = "claude",
    model: str | None = None,
) -> bool:
    """Use a code agent to resolve a merge conflict.

    Returns True if resolved successfully.
    """
    # Import agent config from bug_transplant
    sys.path.insert(0, str(SCRIPT_DIR))
    from bug_transplant import AGENT_CONFIG

    cfg = AGENT_CONFIG[agent]
    logger.info("[%s] Invoking %s to resolve conflict...", bug_id, agent)

    # Setup agent credentials
    creds_dir = cfg["credentials_dir"]
    _exec(
        container,
        f"cp -r /tmp/.agent-creds-src $HOME/{creds_dir} 2>/dev/null; "
        f"rm -rf $HOME/{creds_dir}/projects 2>/dev/null; "
        "true",
    )
    if cfg.get("credentials_config"):
        _exec(
            container,
            f"cp /tmp/.agent-config-src $HOME/{cfg['credentials_config']} 2>/dev/null; true",
        )

    diff_name = Path(diff_path).name
    applied_list = ", ".join(applied_bugs) if applied_bugs else "none yet"

    prompt = textwrap.dedent(f"""\
        I am merging multiple bug transplant patches into project {project}.

        The following bugs have already been applied successfully: {applied_list}

        I need to apply the patch at /tmp/{diff_name} for bug {bug_id}, but it
        has merge conflicts with the current state of the code.

        Please:
        1. Read the patch file /tmp/{diff_name} to understand what changes it makes
        2. Look at the current state of the conflicting files in /src/{project}
        3. Manually apply the changes from the patch, adapting them to work with
           the code as it currently is (including changes from previously applied bugs)
        4. Make sure the changes preserve the bug-triggering logic from the patch
        5. Do NOT revert changes from previously applied bugs

        After making changes, run: compile
        If there are build errors, fix them.
    """)

    escaped = shlex.quote(prompt)
    agent_cmd = cfg["run_cmd"].format(prompt=escaped)
    if model:
        agent_cmd += f" {cfg['model_flag']} {shlex.quote(model)}"

    ret, output = _exec_capture(container, agent_cmd, timeout=1800)

    if ret != 0:
        logger.error("[%s] %s agent failed (exit %d)", bug_id, agent, ret)
        return False

    # Verify it compiles
    ret, _ = _exec_capture(container, "sudo -E compile 2>&1", timeout=300)
    if ret != 0:
        logger.error("[%s] Build failed after Claude conflict resolution", bug_id)
        return False

    logger.info("[%s] Conflict resolved by Claude Code", bug_id)
    return True


# ---------------------------------------------------------------------------
# Bug verification
# ---------------------------------------------------------------------------

def _extract_stack_from_text(text: str) -> list[str]:
    """Extract function names from sanitizer crash output."""
    stack = []
    stack_re = re.compile(r"#\d+\s+0x[0-9a-f]+\s+in\s+([^\s]+)", re.IGNORECASE)
    for line in text.splitlines():
        m = stack_re.search(line)
        if m:
            # Clean: strip (anonymous namespace)::, __interceptor_, etc.
            name = m.group(1)
            name = re.sub(r'\(anonymous namespace\)::', '', name)
            name = re.sub(r'^__interceptor_', '', name)
            # Strip everything after '(' for C++ signatures
            if '(' in name:
                name = name[:name.index('(')]
            stack.append(name)
        if 'in LLVMFuzzerTestOneInput' in line:
            break
    return stack


def _extract_stack_from_file(path: str) -> list[str]:
    """Extract function names from a crash log file."""
    try:
        return _extract_stack_from_text(open(path, errors='replace').read())
    except FileNotFoundError:
        return []


def _stacks_match(reference: list[str], current: list[str], threshold: float = 0.5) -> bool:
    """Check if current stack matches reference using LCS ratio.

    Filters out sanitizer-internal frames before comparison.
    """
    san_re = re.compile(
        r'^(__asan|__lsan|__tsan|__msan|__ubsan|__sanitizer|__interception)',
    )
    ref_app = [f for f in reference if not san_re.match(f)]
    cur_app = [f for f in current if not san_re.match(f)]

    if not ref_app or not cur_app:
        return False

    # LCS (longest common subsequence)
    n, m = len(ref_app), len(cur_app)
    prev = [0] * (m + 1)
    for i in range(1, n + 1):
        curr = [0] * (m + 1)
        for j in range(1, m + 1):
            if ref_app[i - 1] == cur_app[j - 1]:
                curr[j] = prev[j - 1] + 1
            else:
                curr[j] = max(prev[j], curr[j - 1])
        prev = curr
    lcs_len = prev[m]
    ratio = lcs_len / max(len(ref_app), len(cur_app), 1)
    return ratio >= threshold


def verify_bug_triggers(
    container: str,
    bug_id: str,
    fuzzer: str,
    testcase: str,
    sanitizer: str = "address",
    crash_log: str | None = None,
) -> bool:
    """Run the fuzzer and compare crash stack against the reference.

    If *crash_log* is provided, extracts the reference stack from it and
    compares against the fuzzer output using LCS matching.  Otherwise
    falls back to checking for any sanitizer SUMMARY line.
    """
    env_prefix = ""
    if sanitizer == "address":
        env_prefix = "ASAN_OPTIONS=detect_leaks=0 "

    # Use per-sanitizer binary if available, fall back to /out/
    fuzzer_path = f"/out/{sanitizer}/{fuzzer}"
    fallback = f"/out/{fuzzer}"

    ret, output = _exec_capture(
        container,
        f"{env_prefix}([ -x {fuzzer_path} ] && {fuzzer_path} || {fallback}) /work/{testcase} 2>&1",
        timeout=120,
    )

    # Extract current stack from fuzzer output
    current_stack = _extract_stack_from_text(output)

    # If we have a reference crash log, compare stacks
    if crash_log:
        ref_stack = _extract_stack_from_file(crash_log)
        if ref_stack:
            if _stacks_match(ref_stack, current_stack):
                logger.info("[%s] Bug triggers OK (stack match)", bug_id)
                return True
            else:
                if current_stack:
                    logger.warning(
                        "[%s] Stack MISMATCH: ref=%s cur=%s",
                        bug_id, ref_stack[:3], current_stack[:3],
                    )
                else:
                    logger.warning("[%s] No crash (exit=%d)", bug_id, ret)
                return False
        # No reference stack available — fall through to basic check

    # Fallback: any sanitizer crash is a match
    has_summary = bool(re.search(
        r'SUMMARY:\s*(Address|Memory|Undefined|Thread|Leak)Sanitizer', output,
    ))
    if has_summary and current_stack:
        logger.info("[%s] Bug triggers OK (SUMMARY match)", bug_id)
        return True

    if current_stack:
        logger.info("[%s] Bug triggers OK (crash detected)", bug_id)
        return True

    logger.warning("[%s] Bug does NOT trigger (exit=%d)", bug_id, ret)
    return False


def verify_all_bugs(
    container: str,
    bugs: list[dict],
) -> dict[str, bool]:
    """Verify all bugs in the list, return {bug_id: triggered}."""
    results = {}
    for bug in bugs:
        ok = verify_bug_triggers(
            container,
            bug["bug_id"],
            bug["fuzzer"],
            bug["testcase"],
            bug.get("sanitizer", "address"),
            bug.get("crash_log"),
        )
        results[bug["bug_id"]] = ok
    return results


def _find_crash_log(bug_id: str, bug_info: dict) -> str | None:
    """Find the crash log file for a bug by scanning data/crash/.

    Returns the path if found, None otherwise.
    """
    crash_dir = DATA_DIR / "crash"
    if not crash_dir.exists():
        return None
    # Try to find by bug_id in filename
    for f in crash_dir.iterdir():
        if bug_id in f.name and f.name.startswith("target_crash-"):
            return str(f)
    return None


# ---------------------------------------------------------------------------
# Main merge logic
# ---------------------------------------------------------------------------

def run_merge(args: argparse.Namespace) -> int:
    # ------------------------------------------------------------------
    # 1. Load batch summary and bug_info
    # ------------------------------------------------------------------
    logger.info("Loading summary: %s", args.summary)
    with open(args.summary) as f:
        summary = json.load(f)

    project = summary.get("project", args.target)
    target_commit = summary.get("target_commit", args.target_commit or "")
    if not target_commit:
        logger.error("No target commit in summary or args")
        return 1

    logger.info("Loading bug info: %s", args.bug_info)
    with open(args.bug_info) as f:
        bug_info_dataset = json.load(f)

    # ------------------------------------------------------------------
    # 2. Categorize bugs: local (already trigger) vs transplanted (have diff)
    # ------------------------------------------------------------------
    local_bug_ids = set()
    if args.local_bugs:
        local_bug_ids = set(args.local_bugs)
        logger.info("Local bugs (from --local-bugs): %s", sorted(local_bug_ids))
    elif "bugs_already_trigger_ids" in summary:
        local_bug_ids = set(summary["bugs_already_trigger_ids"])
        logger.info("Local bugs (from summary): %s", sorted(local_bug_ids))
    else:
        logger.warning("No local bug IDs found in summary or --local-bugs. "
                        "Re-run bug_transplant_batch.py to update the summary.")

    # Build local bug metadata
    local_bugs: list[dict] = []
    for bug_id in local_bug_ids:
        info = bug_info_dataset.get(bug_id, {})
        reproduce = info.get("reproduce", {})
        fuzzer = reproduce.get("fuzz_target", "")
        sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
        if not fuzzer:
            logger.warning("No fuzzer for local bug %s, skipping verification", bug_id)
            continue
        testcase = f"testcase-{bug_id}"
        # Find crash log for stack comparison
        crash_log = _find_crash_log(bug_id, info)
        local_bugs.append({
            "bug_id": bug_id,
            "fuzzer": fuzzer,
            "testcase": testcase,
            "sanitizer": sanitizer,
            "crash_log": crash_log,
            "type": "local",
        })

    # Build transplanted bug list.
    # First check summary results, then scan disk for diffs the summary
    # may have missed (e.g. from --resume runs that only recorded "skipped").
    transplant_diffs: list[dict] = []
    seen_bug_ids: set[str] = set()

    # From summary results
    for result in summary.get("results", []):
        diff_path = result.get("diff_path")
        if diff_path and Path(diff_path).exists():
            bug_id = result["bug_id"]
            seen_bug_ids.add(bug_id)
            info = bug_info_dataset.get(bug_id, {})
            reproduce = info.get("reproduce", {})
            fuzzer = reproduce.get("fuzz_target", result.get("fuzzer", ""))
            sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
            crash_log = _find_crash_log(bug_id, info)
            transplant_diffs.append({
                "bug_id": bug_id,
                "diff_path": diff_path,
                "fuzzer": fuzzer,
                "testcase": f"testcase-{bug_id}",
                "sanitizer": sanitizer,
                "crash_log": crash_log,
                "type": "transplant",
            })

    # Scan disk for any bug diffs not in summary (e.g. skipped by --resume)
    bug_transplant_dir = DATA_DIR / "bug_transplant"
    for result in summary.get("results", []):
        bug_id = result.get("bug_id", "")
        if bug_id in seen_bug_ids or not bug_id:
            continue
        # Check if diff exists on disk
        out_dir = bug_transplant_dir / f"{project}_{bug_id}"
        for name in ("bug_transplant.diff", "git_diff.diff"):
            p = out_dir / name
            if p.exists() and p.stat().st_size > 0:
                seen_bug_ids.add(bug_id)
                info = bug_info_dataset.get(bug_id, {})
                reproduce = info.get("reproduce", {})
                fuzzer = reproduce.get("fuzz_target", "")
                sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
                crash_log = _find_crash_log(bug_id, info)
                logger.info("Found diff on disk for %s: %s", bug_id, p)
                transplant_diffs.append({
                    "bug_id": bug_id,
                    "diff_path": str(p),
                    "fuzzer": fuzzer,
                    "testcase": f"testcase-{bug_id}",
                    "sanitizer": sanitizer,
                    "crash_log": crash_log,
                    "type": "transplant",
                })
                break

    # Also scan for bug dirs not mentioned in summary at all
    if bug_transplant_dir.exists():
        for d in bug_transplant_dir.iterdir():
            if not d.is_dir() or not d.name.startswith(f"{project}_"):
                continue
            bug_id = d.name[len(f"{project}_"):]
            if bug_id in seen_bug_ids or bug_id in local_bug_ids:
                continue
            for name in ("bug_transplant.diff", "git_diff.diff"):
                p = d / name
                if p.exists() and p.stat().st_size > 0:
                    seen_bug_ids.add(bug_id)
                    info = bug_info_dataset.get(bug_id, {})
                    reproduce = info.get("reproduce", {})
                    fuzzer = reproduce.get("fuzz_target", "")
                    sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
                    crash_log = _find_crash_log(bug_id, info)
                    logger.info("Found extra diff on disk for %s: %s", bug_id, p)
                    transplant_diffs.append({
                        "bug_id": bug_id,
                        "diff_path": str(p),
                        "fuzzer": fuzzer,
                        "testcase": f"testcase-{bug_id}",
                        "sanitizer": sanitizer,
                        "crash_log": crash_log,
                        "type": "transplant",
                    })
                    break

    if not transplant_diffs:
        logger.error("No transplant diffs found (summary or disk)")
        return 1

    logger.info("Local bugs (already trigger): %d", len(local_bugs))
    logger.info("Transplant diffs to merge: %d", len(transplant_diffs))

    # ------------------------------------------------------------------
    # 3. Compute merge order and detect potential conflicts
    # ------------------------------------------------------------------
    ordered = compute_merge_order(transplant_diffs, local_bugs)

    conflicts = detect_conflicts(ordered)

    logger.info("Merge order:")
    for i, bd in enumerate(ordered):
        files_str = ", ".join(sorted(bd["_files"])) if bd.get("_files") else "?"
        logger.info("  %d. %s [files: %s]", i + 1, bd["bug_id"], files_str)
    if conflicts:
        logger.warning("Potential file conflicts:")
        for a, b, overlap in conflicts:
            logger.warning("  %s <-> %s: %s", a, b, overlap)
    else:
        logger.info("No file-level conflicts detected")

    # ------------------------------------------------------------------
    # Dry run
    # ------------------------------------------------------------------
    if args.dry_run:
        print(f"\n{'='*60}")
        print(f"DRY RUN — Merge plan for {project} @ {target_commit[:12]}")
        print(f"{'='*60}")
        print(f"\nLocal bugs (verify only): {len(local_bugs)}")
        for lb in local_bugs:
            print(f"  - {lb['bug_id']} (fuzzer: {lb['fuzzer']})")
        print(f"\nTransplant diffs to merge: {len(ordered)}")
        for i, bd in enumerate(ordered):
            files_str = ", ".join(sorted(bd["_files"]))
            print(f"  {i+1}. {bd['bug_id']} [{files_str}]")
        if conflicts:
            print(f"\nPotential conflicts: {len(conflicts)}")
            for a, b, overlap in conflicts:
                print(f"  {a} <-> {b}: {overlap}")
        else:
            print("\nNo file-level conflicts detected")
        print()
        return 0

    # ------------------------------------------------------------------
    # 4. Start container and run merge
    # ------------------------------------------------------------------
    # Collect all sanitizers needed across local + transplant bugs
    all_sanitizers = (
        [lb.get("sanitizer", "address") for lb in local_bugs]
        + [td.get("sanitizer", "address") for td in transplant_diffs]
    )
    sanitizers_needed = _collect_sanitizers(all_sanitizers)
    logger.info("Sanitizers needed: %s", sanitizers_needed)

    container, build_ok = start_merge_container(
        project, target_commit, args.testcases_dir,
        build_csv=args.build_csv,
        extra_volumes=args.volume,
        bug_sanitizers=all_sanitizers,
        agent_type=args.agent,
    )
    if not build_ok:
        logger.error("Baseline build failed — cannot merge. "
                      "Use --keep-container to debug: docker exec -it %s bash",
                      container)
        if not args.keep_container:
            subprocess.call(["docker", "rm", "-f", container],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return 1

    merge_results: list[dict] = []
    applied_bugs: list[str] = []  # successfully applied bug IDs
    all_verified_bugs: list[dict] = []  # bugs to verify after each step
    regression_failures: list[dict] = []

    try:
        # ------------------------------------------------------------------
        # 5. Verify local bugs trigger at baseline
        # ------------------------------------------------------------------
        if local_bugs:
            logger.info("=== Verifying %d local bugs at baseline ===", len(local_bugs))
            baseline = verify_all_bugs(container, local_bugs)
            for bug_id, ok in baseline.items():
                if ok:
                    all_verified_bugs.append(
                        next(lb for lb in local_bugs if lb["bug_id"] == bug_id)
                    )
                else:
                    logger.warning("Local bug %s does NOT trigger at baseline", bug_id)

        # ------------------------------------------------------------------
        # 6. Apply transplant diffs incrementally
        # ------------------------------------------------------------------
        for i, bd in enumerate(ordered):
            bug_id = bd["bug_id"]
            diff_path = bd["diff_path"]
            step = {
                "step": i + 1,
                "bug_id": bug_id,
                "diff_path": diff_path,
                "apply_method": None,
                "build_ok": False,
                "self_triggers": False,
                "regressions": [],
            }
            logger.info(
                "=== Step %d/%d: Applying %s ===", i + 1, len(ordered), bug_id,
            )

            # --- Try to apply ---
            method = try_apply_diff(container, diff_path, project)
            step["apply_method"] = method

            if method == "conflict":
                # Attempt agent-based resolution
                resolved = resolve_conflict_with_agent(
                    container, diff_path, bug_id, project,
                    applied_bugs, args.agent, args.model,
                )
                if resolved:
                    step["apply_method"] = "agent_resolved"
                else:
                    step["apply_method"] = "failed"
                    logger.error("[%s] Could not resolve conflict, skipping", bug_id)
                    merge_results.append(step)
                    continue

            # --- Build (only ASAN first, then other sanitizers if needed) ---
            # Always build ASAN first (primary), then rebuild other sanitizers
            # only if bugs using them exist in the verified set.
            logger.info("[%s] Building (address)...", bug_id)
            _exec_capture(
                container,
                f"cd /src/{project} && make clean 2>/dev/null; "
                f"rm -rf /work/* 2>/dev/null; true",
            )
            ret, build_output = _exec_capture(
                container, "sudo -E SANITIZER=address compile 2>&1", timeout=300,
            )
            build_failed = (ret != 0)
            if not build_failed:
                _exec_capture(
                    container,
                    "mkdir -p /out/address && "
                    "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && cp \"$f\" /out/address/; done; true",
                )
            else:
                logger.error("[%s] Build failed for sanitizer=address. Tail:", bug_id)
                logger.error("%s", build_output[-500:] if build_output else "(no output)")
            step["build_ok"] = not build_failed
            if build_failed:
                logger.error("[%s] Build failed after applying diff", bug_id)
                # Try to revert this diff
                _exec_capture(
                    container,
                    f"cd /src/{project} && git checkout -- . 2>&1",
                )
                # Re-apply all previous good diffs
                for prev_id in applied_bugs:
                    prev = next(
                        d for d in ordered if d["bug_id"] == prev_id
                    )
                    _exec_capture(
                        container,
                        f"cd /src/{project} && git apply /tmp/{Path(prev['diff_path']).name} 2>&1",
                    )
                _exec_capture(
                    container,
                    f"cd /src/{project} && make clean 2>/dev/null; rm -rf /work/* 2>/dev/null; true",
                )
                _exec_capture(container, "sudo -E SANITIZER=address compile 2>&1", timeout=300)
                _exec_capture(
                    container,
                    "mkdir -p /out/address && "
                    "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && cp \"$f\" /out/address/; done; true",
                )
                merge_results.append(step)
                continue

            # --- Verify this bug triggers ---
            logger.info("[%s] Verifying self-trigger...", bug_id)
            step["self_triggers"] = verify_bug_triggers(
                container, bug_id, bd["fuzzer"], bd["testcase"],
                bd.get("sanitizer", "address"),
                bd.get("crash_log"),
            )

            # --- Verify all previously applied bugs (regression check) ---
            if all_verified_bugs:
                logger.info("[%s] Regression check (%d bugs)...", bug_id, len(all_verified_bugs))
                reg_results = verify_all_bugs(container, all_verified_bugs)
                for rbug, ok in reg_results.items():
                    if not ok:
                        step["regressions"].append(rbug)
                        regression_failures.append({
                            "regressed_bug": rbug,
                            "caused_by_applying": bug_id,
                            "step": i + 1,
                        })
                        logger.warning(
                            "[%s] REGRESSION: %s stopped triggering!", bug_id, rbug,
                        )

            # Track successful application
            if step["self_triggers"]:
                applied_bugs.append(bug_id)
                all_verified_bugs.append(bd)

            merge_results.append(step)

        # ------------------------------------------------------------------
        # 7. Final verification of ALL bugs
        # ------------------------------------------------------------------
        logger.info("=== Final verification of all %d bugs ===", len(all_verified_bugs))
        final_results = verify_all_bugs(container, all_verified_bugs)
        final_pass = all(final_results.values())

        # ------------------------------------------------------------------
        # 8. Extract combined diff
        # ------------------------------------------------------------------
        output_dir = DATA_DIR / "bug_transplant" / f"merge_{project}_{target_commit[:8]}"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Get combined diff — only include files that the per-bug diffs
        # intentionally modified (avoids build artifacts from compile).
        touched_files: set[str] = set()
        for bd in ordered:
            touched_files.update(bd.get("_files", set()))
        if touched_files:
            file_args = " ".join(f"'{f}'" for f in sorted(touched_files))
            _, combined_diff = _exec_capture(
                container, f"cd /src/{project} && git diff -- {file_args}",
            )
        else:
            _, combined_diff = _exec_capture(
                container, f"cd /src/{project} && git diff",
            )
        combined_diff_path = output_dir / "combined.diff"
        combined_diff_path.write_text(combined_diff)
        logger.info("Combined diff: %s (%d bytes)", combined_diff_path, len(combined_diff))

        # Also copy to /out inside container
        _exec(container, f"cd /src/{project} && git diff > /out/combined.diff")

        # ------------------------------------------------------------------
        # 9. Write merge summary
        # ------------------------------------------------------------------
        merge_summary = {
            "type": "bug_transplant_merge",
            "project": project,
            "target_commit": target_commit,
            "local_bugs": [lb["bug_id"] for lb in local_bugs],
            "local_bugs_verified": sum(
                1 for lb in local_bugs
                if final_results.get(lb["bug_id"], False)
            ),
            "transplant_bugs_attempted": len(ordered),
            "transplant_bugs_applied": len(applied_bugs),
            "transplant_bugs_self_trigger": sum(
                1 for s in merge_results if s["self_triggers"]
            ),
            "total_bugs_triggering": sum(1 for v in final_results.values() if v),
            "total_bugs_expected": len(local_bugs) + len(ordered),
            "all_pass": final_pass,
            "regressions": regression_failures,
            "combined_diff_path": str(combined_diff_path),
            "combined_diff_bytes": len(combined_diff),
            "steps": merge_results,
            "final_verification": {
                bug_id: ok for bug_id, ok in final_results.items()
            },
        }

        summary_path = output_dir / "merge_summary.json"
        summary_path.write_text(json.dumps(merge_summary, indent=2))
        logger.info("Merge summary: %s", summary_path)

        # ------------------------------------------------------------------
        # 10. Print results
        # ------------------------------------------------------------------
        local_ok = merge_summary["local_bugs_verified"]
        transplant_ok = sum(1 for s in merge_results if s["self_triggers"])
        total_ok = local_ok + transplant_ok
        total_goal = len(local_bugs) + len(ordered)

        print(f"\n{'='*60}")
        print(f"  RESULT:  {total_ok} / {total_goal} bugs triggering")
        print(f"{'='*60}")
        print(f"  Project:              {project} @ {target_commit[:12]}")
        print()
        print(f"  Local bugs:           {local_ok}/{len(local_bugs)} verified")
        for lb in local_bugs:
            ok = final_results.get(lb["bug_id"], False)
            mark = "OK" if ok else "FAIL"
            print(f"    [{mark:>4}] {lb['bug_id']} (fuzzer: {lb['fuzzer']})")
        print()
        print(f"  Transplanted bugs:    {transplant_ok}/{len(ordered)} triggering")
        for step in merge_results:
            if step["self_triggers"]:
                mark = "  OK"
            elif step["apply_method"] == "failed":
                mark = "SKIP"
            elif not step["build_ok"]:
                mark = "BFAIL"
            else:
                mark = "FAIL"
            method = step["apply_method"]
            regs = f"  !! regressions: {step['regressions']}" if step["regressions"] else ""
            print(f"    [{mark:>4}] {step['bug_id']} (apply: {method}){regs}")
        print()
        if regression_failures:
            print(f"  Regressions:          {len(regression_failures)}")
            for rf in regression_failures:
                print(f"    {rf['regressed_bug']} broke when applying {rf['caused_by_applying']}")
            print()
        print(f"  Combined diff:        {combined_diff_path}")
        print(f"  Summary:              {summary_path}")
        print(f"{'='*60}\n")

        return 0 if final_pass else 1

    finally:
        if not args.keep_container:
            logger.info("Destroying container...")
            subprocess.call(
                ["docker", "rm", "-f", f"bug-merge-{project}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        else:
            logger.info(
                "Container kept: docker exec -it bug-merge-%s bash", project,
            )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Merge per-bug transplant diffs into one version",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 script/bug_transplant_merge.py \\
                --summary data/bug_transplant/batch_wavpack_0b99613e/summary.json \\
                --bug_info osv_testcases_summary.json \\
                --target wavpack

              # Dry run
              python3 script/bug_transplant_merge.py \\
                --summary data/bug_transplant/batch_wavpack_0b99613e/summary.json \\
                --bug_info osv_testcases_summary.json \\
                --target wavpack --dry-run
        """),
    )

    parser.add_argument("--summary", required=True,
                        help="Path to batch summary.json")
    parser.add_argument("--bug_info", required=True,
                        help="Bug info JSON (osv_testcases_summary.json)")
    parser.add_argument("--target", required=True,
                        help="OSS-Fuzz project name")
    parser.add_argument("--target-commit", default=None,
                        help="Override target commit (default: from summary)")
    parser.add_argument("--build_csv", default=None,
                        help="Build CSV mapping commits to OSS-Fuzz versions")
    parser.add_argument("--local-bugs", nargs="*", default=None,
                        help="Bug IDs that already trigger at target (override auto-detection)")

    # Execution
    parser.add_argument("--agent", default="claude", choices=["claude", "codex"],
                        help="Code agent for conflict resolution (default: claude)")
    parser.add_argument("--model", default=None,
                        help="Model to use (passed to agent CLI)")
    parser.add_argument("--testcases-dir",
                        default=os.environ.get("TESTCASES", ""),
                        help="Testcase directory (default: $TESTCASES)")
    parser.add_argument("-v", "--volume", action="append",
                        help="Additional volume mounts")

    # Modes
    parser.add_argument("--dry-run", action="store_true",
                        help="Show merge plan without executing")
    parser.add_argument("--keep-container", action="store_true",
                        help="Keep container alive for debugging")
    parser.add_argument("--verbose", "-V", action="store_true")

    return parser


def main() -> int:
    args = build_parser().parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.testcases_dir:
        logger.error("Testcases dir not set. Use --testcases-dir or $TESTCASES.")
        return 1

    return run_merge(args)


if __name__ == "__main__":
    sys.exit(main())
