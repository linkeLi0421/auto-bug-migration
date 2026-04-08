#!/usr/bin/env python3
"""Offline dispatch-wrapped merge of per-bug transplant patches.

Pre-wraps each bug's patch with dispatch gating before merging so bugs
can coexist without runtime interference. Each bug gets a bit in
__bug_dispatch[]; the fuzzer reads the dispatch byte from the first
byte(s) of the test input.

Usage:
    sudo -E python3 script/bug_transplant_merge_offline.py \
        --summary data/bug_transplant/batch_c-blosc2_79e921d9/summary.json \
        --bug_info osv_testcases_summary.json \
        --target c-blosc2 \
        --testcases-dir ~/oss-fuzz-for-select/pocs/tmp/ \
        --build_csv ~/log/c-blosc2_builds.csv
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
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR.parent / "data"
HOME_DIR = Path.home()

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# Import shared utilities from the existing merge script
sys.path.insert(0, str(SCRIPT_DIR))
from bug_transplant_merge import (
    _load_prompt,
    _exec,
    _exec_capture,
    _inject_dispatch_files,
    _apply_all_dispatch_bytes as _apply_all_dispatch_bytes_orig,
    _ensure_dispatch_capacity,
    _modify_harness_for_dispatch,
    _restore_testcases,
    _stage_untracked_source,
    start_merge_container,
    verify_bug_triggers,
    verify_all_bugs,
    _find_crash_log,
    compute_merge_order,
    files_in_diff,
    _prepare_container_testcases_dir,
    _save_work_testcase_to_host,
    CONTAINER_TESTCASES_DIR,
)


def _apply_all_dispatch_bytes(container, dispatch_state):
    """Prepend dispatch bytes to PoCs in /work/.

    Idempotent: compares the file size in /work/ against the pristine
    original in /testcases/.  If the file is already larger (i.e. the
    prefix was prepended by a previous call), it is left unchanged.

    The old implementation used ``d.startswith(prefix)`` which is a
    false-positive for zero-valued dispatch bytes (local bugs) when the
    testcase content naturally starts with 0x00 (e.g. H.264 NAL streams).
    """
    nbytes = dispatch_state.get("dispatch_bytes", 1)
    for bug_id, dval in dispatch_state["poc_bytes"].items():
        testcase = f"testcase-{bug_id}"
        prefix = dval.to_bytes(nbytes, "little")
        prefix_list = ",".join(str(b) for b in prefix)
        _exec_capture(
            container,
            f"if [ ! -f /work/{testcase} ]; then cp "
            f"{CONTAINER_TESTCASES_DIR}/{testcase} /work/{testcase}"
            f" 2>/dev/null; fi; python3 -c \""
            f"import os; p=bytes([{prefix_list}]); "
            f"orig=os.path.getsize('{CONTAINER_TESTCASES_DIR}/{testcase}') "
            f"if os.path.exists('{CONTAINER_TESTCASES_DIR}/{testcase}') else -1; "
            f"d=open('/work/{testcase}','rb').read(); "
            f"open('/work/{testcase}','wb').write(d if len(d)!=orig else p+d)\"",
        )
from bug_transplant import (
    CODEX_CONFIG, setup_codex_creds, build_codex_command, _exec_interactive,
)
from codex_usage import CodexUsageTracker

# Pathspecs to exclude build artifacts from git diff
_DIFF_EXCLUDES = (
    "':(exclude)CMakeFiles/' ':(exclude)*/CMakeFiles/' "
    "':(exclude)CMakeCache.txt' ':(exclude)cmake_install.cmake' "
    "':(exclude)*/cmake_install.cmake' ':(exclude)CTestTestfile.cmake' "
    "':(exclude)*/CTestTestfile.cmake' ':(exclude)CPackConfig.cmake' "
    "':(exclude)CPackSourceConfig.cmake' ':(exclude)cmake_uninstall.cmake' "
    "':(exclude)Makefile' ':(exclude)*/Makefile' "
    "':(exclude)*.o' ':(exclude)*.a' ':(exclude)*.so' ':(exclude)*.so.*' "
    "':(exclude)*.d' ':(exclude)*.pc' ':(exclude)config.h' "
    "':(exclude)blosc/config.h' "
    "':(exclude)build/' ':(exclude)_build/' "
    "':(exclude).codex/'"
)
_DIFF_INCLUDES = (
    "'*.c' '*.h' '*.cc' '*.cpp' '*.cxx' '*.hpp' '*.hh' '*.hxx' "
    "'*.cmake' '*.sh' "
    "'CMakeLists.txt' 'Makefile.am' '*/Makefile.am'"
)


# Session-wide token/cost tracker (shared across all codex invocations)
_usage_tracker = CodexUsageTracker()


def _strip_build_artifact_hunks(diff_text: str) -> str:
    """Remove diff hunks for build-artifact paths (CMakeFiles/, etc.)."""
    import re
    # Split into per-file sections on 'diff --git' boundaries
    parts = re.split(r'(?=^diff --git )', diff_text, flags=re.MULTILINE)
    _ARTIFACT_PATS = re.compile(r'CMakeFiles/|/CMakeFiles/')
    kept = [p for p in parts if not _ARTIFACT_PATS.search(p.split('\n', 1)[0])]
    return ''.join(kept)


def _clean_diff(container: str, project: str) -> str:
    """Get a clean git diff excluding build artifacts."""
    _stage_untracked_source(container, project)
    _, diff = _exec_capture(
        container,
        f"cd /src/{project} && git diff HEAD -- {_DIFF_INCLUDES} {_DIFF_EXCLUDES}",
    )
    return _strip_build_artifact_hunks(diff)


def _clean_diff_against(container: str, project: str, base_rev: str) -> str:
    """Get a clean git diff against a specific baseline revision."""
    _stage_untracked_source(container, project)
    _, diff = _exec_capture(
        container,
        f"cd /src/{project} && git diff {shlex.quote(base_rev)} -- {_DIFF_INCLUDES} {_DIFF_EXCLUDES}",
    )
    return _strip_build_artifact_hunks(diff)


def _save_source_snapshot(container: str, project: str) -> None:
    """Save a git stash snapshot of the source tree."""
    _exec_capture(container,
                  f"cd /src/{project} && git add -A && "
                  f"git stash push -m snapshot --include-untracked 2>/dev/null; true")


def _restore_source_snapshot(container: str, project: str) -> None:
    """Restore the most recent source snapshot."""
    _exec_capture(container,
                  f"cd /src/{project} && git checkout -f HEAD && "
                  f"git stash pop 2>/dev/null; true")


def _clean_container_working_tree_before_harness_diff(container: str, project: str) -> None:
    """Reset /src/<project> before reapplying a saved harness diff."""
    _exec_capture(
        container,
        f"cd /src/{project} && "
        "(git reset --hard HEAD 2>/dev/null || true) && "
        "(git clean -fdx 2>/dev/null || true) && "
        "rm -f __bug_dispatch.c __bug_dispatch.h 2>/dev/null || true",
    )


def _create_harness_baseline_commit(container: str, project: str) -> str:
    """Create a temporary commit for the harness-applied baseline."""
    ret, out = _exec_capture(
        container,
        f"cd /src/{project} && "
        "git add -A && "
        "git -c user.name='Codex' -c user.email='codex@example.com' "
        "commit --allow-empty -m 'codex harness baseline' >/dev/null 2>&1 && "
        "git rev-parse HEAD",
    )
    if ret != 0:
        raise RuntimeError(f"failed to create harness baseline commit: {out[-500:]}")
    return out.strip().splitlines()[-1]


def _restore_harness_baseline(container: str, project: str, baseline_rev: str) -> None:
    """Restore the exact harness baseline snapshot."""
    ret, out = _exec_capture(
        container,
        f"cd /src/{project} && "
        f"git checkout -f {shlex.quote(baseline_rev)} >/dev/null 2>&1 && "
        f"git reset --hard {shlex.quote(baseline_rev)} >/dev/null 2>&1 && "
        "git clean -fdx >/dev/null 2>&1 || true",
    )
    if ret != 0:
        raise RuntimeError(f"failed to restore harness baseline: {out[-500:]}")

_MAX_WRAP_RETRIES = 1


def _save_build_sh(container: str, output_dir: Path) -> None:
    """Snapshot /src/build.sh so it can be restored on resume.

    The agent may modify /src/build.sh to compile __bug_dispatch.c, but
    that file lives outside the project git repo and isn't captured by
    ``git diff``.  We save it alongside harness.diff.
    """
    ret, content = _exec_capture(container, "cat /src/build.sh 2>/dev/null")
    if ret != 0:
        return
    dst = output_dir / "harness_build.sh"
    dst.write_text(content)
    logger.info("Saved /src/build.sh (%d bytes) to %s", len(content), dst)


def _restore_build_sh(container: str, output_dir: Path) -> None:
    """Restore a previously saved /src/build.sh into the container."""
    src = output_dir / "harness_build.sh"
    if not src.exists():
        return
    content = src.read_text()
    _exec_capture(
        container,
        f"cat > /src/build.sh << 'BUILDEOF'\n{content}BUILDEOF",
    )
    _exec_capture(container, "chmod +x /src/build.sh")
    logger.info("Restored /src/build.sh from %s", src)


def _inject_dispatch_deps_fixer(container: str) -> None:
    """Inject a helper script + build.sh hook that creates autotools dep stubs.

    When Makefile.am references $(top_srcdir)/__bug_dispatch.c, autotools
    generates ``include .deps/<prefix>__bug_dispatch.P{o,lo}`` but never
    creates the top-level ``.deps/`` directory.  This writes a helper that
    scans generated Makefiles for those targets and touches them, then
    injects a one-line call in build.sh right before ``make``.
    """
    _exec_capture(
        container,
        "cat > /tmp/_fix_dispatch_deps.sh << 'FIXEOF'\n"
        "#!/bin/bash\n"
        "mkdir -p .deps\n"
        "grep -rh '__bug_dispatch.*\\.Pl\\|__bug_dispatch.*\\.Po' "
        "  */Makefile */*/Makefile */*/*/Makefile 2>/dev/null | "
        "grep -oE '[^ ]*__bug_dispatch[^ ]*' | sort -u | "
        "while read p; do mkdir -p $(dirname \"$p\") && touch \"$p\"; done\n"
        "FIXEOF\n"
        "chmod +x /tmp/_fix_dispatch_deps.sh",
    )
    _exec_capture(
        container,
        "grep -q '_fix_dispatch_deps' /src/build.sh 2>/dev/null || "
        "sed -i '/^make/i /tmp/_fix_dispatch_deps.sh' /src/build.sh",
    )


def _ensure_dispatch_linked_everywhere(container: str, project: str) -> None:
    """Ensure __bug_dispatch.c is compiled into libraries, not just fuzzers.

    Per-bug patches may add ``#include "__bug_dispatch.h"`` to library
    source files (e.g. libopensc).  Non-fuzzer tools that link the
    library will fail with undefined ``__bug_dispatch`` unless the
    object is also part of the library.  This function finds every
    Makefile.am that builds a library whose sources were patched and
    adds __bug_dispatch.c to it.
    """
    # Find all Makefile.am files in directories containing patched sources
    # that reference __bug_dispatch.
    ret, out = _exec_capture(
        container,
        f"cd /src/{project} && "
        f"grep -rl '__bug_dispatch' --include='*.c' --include='*.h' "
        f"src/ 2>/dev/null | "
        f"xargs -I{{}} dirname {{}} | sort -u",
    )
    if ret != 0 or not out.strip():
        return

    for src_dir in out.strip().splitlines():
        src_dir = src_dir.strip()
        if not src_dir:
            continue
        # Check if this directory has a Makefile.am with a _la_SOURCES
        ret2, makefile = _exec_capture(
            container,
            f"cat /src/{project}/{src_dir}/Makefile.am 2>/dev/null",
        )
        if ret2 != 0 or "__bug_dispatch" in makefile:
            continue  # already has it or no Makefile.am
        if "_la_SOURCES" not in makefile:
            continue  # not a library

        # Add __bug_dispatch.c after the first _la_SOURCES line
        makefile_path = f"/src/{project}/{src_dir}/Makefile.am"
        _exec_capture(
            container,
            f"awk 'NR==1{{found=0}} /_la_SOURCES/&&!found{{"
            f"print; print \"\\t$(top_srcdir)/__bug_dispatch.c \\\\\"; "
            f"found=1; next}} 1' {makefile_path} > {makefile_path}.tmp "
            f"&& mv {makefile_path}.tmp {makefile_path}",
        )
        logger.info("Added __bug_dispatch.c to %s/Makefile.am", src_dir)

    _inject_dispatch_deps_fixer(container)


# build_codex_command is now imported from bug_transplant


# ---------------------------------------------------------------------------
# Bug loading and categorization
# ---------------------------------------------------------------------------

def load_and_categorize_bugs(
    summary_path: str,
    bug_info_path: str,
    project: str,
    local_bug_overrides: list[str] | None = None,
    testcases_dir: str | None = None,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Load bugs and split into local, testcase-only, and diff bugs.

    Returns (local_bugs, testcase_only_bugs, diff_bugs).
    """
    with open(summary_path) as f:
        summary = json.load(f)
    with open(bug_info_path) as f:
        bug_info_dataset = json.load(f)

    target_commit = summary["target_commit"]
    bug_transplant_dir = DATA_DIR / "bug_transplant"

    # --- Local bugs (already trigger at target) ---
    local_bug_ids = set(local_bug_overrides or summary.get("bugs_already_trigger_ids", []))
    local_bugs = []
    for bid in local_bug_ids:
        info = bug_info_dataset.get(bid, {})
        reproduce = info.get("reproduce", {})
        fuzzer = reproduce.get("fuzz_target", "")
        sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
        if not fuzzer:
            continue
        crash_log = _find_crash_log(bid, info)
        local_bugs.append({
            "bug_id": bid,
            "fuzzer": fuzzer,
            "testcase": f"testcase-{bid}",
            "sanitizer": sanitizer,
            "crash_log": crash_log,
            "type": "local",
        })

    # --- Transplanted bugs ---
    testcase_only_bugs = []
    diff_bugs = []
    seen = set(local_bug_ids)

    for result in summary.get("results", []):
        bid = result.get("bug_id", "")
        if not bid or bid in seen:
            continue
        if result.get("status") not in (None, "success"):
            continue

        out_dir = bug_transplant_dir / f"{project}_{bid}"
        if not out_dir.exists():
            continue

        # Skip impossible
        if (out_dir / "bug_transplant.impossible").exists():
            logger.info("Skipping %s: declared impossible", bid)
            continue

        # Find diff
        diff_path = None
        for name in ("bug_transplant.diff", "git_diff.diff"):
            p = out_dir / name
            if p.exists():
                diff_path = str(p)
                break

        has_diff = diff_path and Path(diff_path).stat().st_size > 0

        # Find patched testcase
        patched_testcase = None
        for tc in out_dir.glob(f"testcase-{bid}*"):
            if tc.is_file() and tc.stat().st_size > 0:
                patched_testcase = str(tc)
                break

        if not has_diff and not patched_testcase:
            continue

        info = bug_info_dataset.get(bid, {})
        reproduce = info.get("reproduce", {})
        fuzzer = reproduce.get("fuzz_target", "")
        sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
        if sanitizer not in ("address", "undefined"):
            continue
        if not fuzzer:
            continue

        crash_log = _find_crash_log(bid, info)
        seen.add(bid)

        entry = {
            "bug_id": bid,
            "diff_path": diff_path if has_diff else None,
            "patched_testcase": patched_testcase,
            "fuzzer": fuzzer,
            "testcase": f"testcase-{bid}",
            "sanitizer": sanitizer,
            "crash_log": crash_log,
            "type": "transplant",
        }

        if has_diff:
            diff_bugs.append(entry)
        else:
            testcase_only_bugs.append(entry)

    # Also scan disk for bug dirs not in summary
    for d in bug_transplant_dir.iterdir():
        if not d.is_dir() or not d.name.startswith(f"{project}_"):
            continue
        bid = d.name[len(f"{project}_"):]
        if bid in seen:
            continue
        if (d / "bug_transplant.impossible").exists():
            continue

        diff_path = None
        for name in ("bug_transplant.diff", "git_diff.diff"):
            p = d / name
            if p.exists():
                diff_path = str(p)
                break
        has_diff = diff_path and Path(diff_path).stat().st_size > 0

        patched_testcase = None
        for tc in d.glob(f"testcase-{bid}*"):
            if tc.is_file() and tc.stat().st_size > 0:
                patched_testcase = str(tc)
                break

        if not has_diff and not patched_testcase:
            continue

        info = bug_info_dataset.get(bid, {})
        reproduce = info.get("reproduce", {})
        fuzzer = reproduce.get("fuzz_target", "")
        sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
        if sanitizer not in ("address", "undefined") or not fuzzer:
            continue

        crash_log = _find_crash_log(bid, info)
        seen.add(bid)

        entry = {
            "bug_id": bid,
            "diff_path": diff_path if has_diff else None,
            "patched_testcase": patched_testcase,
            "fuzzer": fuzzer,
            "testcase": f"testcase-{bid}",
            "sanitizer": sanitizer,
            "crash_log": crash_log,
            "type": "transplant",
        }
        if has_diff:
            diff_bugs.append(entry)
        else:
            testcase_only_bugs.append(entry)

    return local_bugs, testcase_only_bugs, diff_bugs


# ---------------------------------------------------------------------------
# Dispatch bit assignment
# ---------------------------------------------------------------------------

def assign_dispatch_bits(
    diff_bugs: list[dict],
    local_bugs: list[dict],
    testcase_only_bugs: list[dict],
) -> dict:
    """Assign dispatch bits to bugs with diffs. Return dispatch_state."""
    dispatch_bytes = max(1, (len(diff_bugs) - 1) // 8 + 1) if diff_bugs else 1
    poc_bytes: dict[str, int] = {}

    # Diff bugs get bits
    bits = {}
    for i, bug in enumerate(diff_bugs):
        bits[i] = {"bug_id": bug["bug_id"]}
        poc_bytes[bug["bug_id"]] = 1 << i

    # Local + testcase-only bugs get dispatch value 0 (no bit set)
    for bug in local_bugs + testcase_only_bugs:
        poc_bytes[bug["bug_id"]] = 0

    return {
        "next_bit": len(diff_bugs),
        "dispatch_bytes": dispatch_bytes,
        "bits": bits,
        "poc_bytes": poc_bytes,
        "harness_modified": False,
        "dispatch_file_injected": False,
    }


# ---------------------------------------------------------------------------
# Per-bug offline wrapping
# ---------------------------------------------------------------------------

def wrap_bug_with_dispatch(
    container: str,
    project: str,
    bug: dict,
    bit_index: int,
    dispatch_state: dict,
    model: str | None = None,
    codex_mode: str = "exec",
) -> tuple[bool, str]:
    """Invoke codex to wrap a bug's patch with dispatch gating.

    Returns (success, output).
    """
    bug_id = bug["bug_id"]
    diff_path = bug["diff_path"]
    dispatch_bit = bit_index % 8
    dispatch_byte = bit_index // 8
    dispatch_value = 1 << bit_index

    # Copy diff into container
    diff_content = Path(diff_path).read_text()
    _exec_capture(
        container,
        f"cat > /tmp/patch_{bug_id}.diff << 'PATCH_EOF'\n{diff_content}PATCH_EOF",
    )

    # Copy testcase (patched if available, else original)
    ptc = bug.get("patched_testcase")
    if ptc and Path(ptc).exists():
        tc_data = Path(ptc).read_bytes()
        subprocess.run(
            ["docker", "exec", "-i", container,
             "bash", "-c", f"cat > /work/{bug['testcase']}"],
            input=tc_data, timeout=10,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    # Setup codex credentials
    setup_codex_creds(container)

    prompt = _load_prompt(
        "dispatch_wrap_offline",
        project=project,
        bug_id=bug_id,
        dispatch_bit=str(dispatch_bit),
        dispatch_byte=str(dispatch_byte),
        dispatch_value=str(dispatch_value),
        patch_path=f"/tmp/patch_{bug_id}.diff",
        testcase_path=f"/work/{bug['testcase']}",
        output_testcase_path=f"/work/{bug['testcase']}",
    )

    agent_cmd = build_codex_command(prompt, model, mode=codex_mode)

    logger.info("[%s] Invoking codex for dispatch wrapping (bit %d)...",
                bug_id, bit_index)
    if codex_mode == "interactive":
        ret, output = _exec_interactive(container, agent_cmd, timeout=1800)
    else:
        ret, output = _exec_capture(container, agent_cmd, timeout=1800)

    _usage_tracker.log_usage(f"{bug_id} wrap", output, model)

    if ret != 0:
        logger.error("[%s] Agent failed (exit %d)", bug_id, ret)
        return False, output

    # Verify build
    ret, build_out = _exec_capture(container, "sudo -E compile 2>&1", timeout=300)
    if ret != 0:
        logger.error("[%s] Build failed after wrapping", bug_id)
        return False, build_out

    logger.info("[%s] Dispatch wrapping OK", bug_id)
    return True, output


# ---------------------------------------------------------------------------
# Main merge logic
# ---------------------------------------------------------------------------

def run_offline_merge(args: argparse.Namespace) -> int:
    """Run the full offline dispatch merge pipeline."""
    with open(args.summary) as f:
        summary = json.load(f)
    target_commit = args.target_commit or summary["target_commit"]
    project = args.target

    # Output directory
    output_dir = DATA_DIR / "bug_transplant" / f"merge_offline_{project}_{target_commit[:8]}"
    output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 1. Load and categorize bugs
    # ------------------------------------------------------------------
    local_bugs, testcase_only_bugs, diff_bugs = load_and_categorize_bugs(
        args.summary, args.bug_info, project,
        local_bug_overrides=args.local_bugs,
        testcases_dir=args.testcases_dir,
    )

    logger.info("Local bugs: %d", len(local_bugs))
    logger.info("Testcase-only bugs: %d", len(testcase_only_bugs))
    logger.info("Bugs with diffs (need dispatch): %d", len(diff_bugs))

    all_bugs = local_bugs + testcase_only_bugs + diff_bugs
    if not all_bugs:
        logger.error("No bugs to merge")
        return 1
    testcase_stage_dir = _prepare_container_testcases_dir(
        args.testcases_dir,
        output_dir / "testcases",
        testcase_names=[bug["testcase"] for bug in all_bugs],
    )

    # ------------------------------------------------------------------
    # 2. Assign dispatch bits
    # ------------------------------------------------------------------
    dispatch_state = assign_dispatch_bits(diff_bugs, local_bugs, testcase_only_bugs)
    logger.info("Dispatch bits assigned: %d bits, %d bytes",
                dispatch_state["next_bit"], dispatch_state["dispatch_bytes"])

    for i, bug in enumerate(diff_bugs):
        logger.info("  bit %d → %s (value %d)",
                     i, bug["bug_id"], dispatch_state["poc_bytes"][bug["bug_id"]])

    if args.dry_run:
        logger.info("Dry run — exiting")
        return 0

    # ------------------------------------------------------------------
    # 3. Start container
    # ------------------------------------------------------------------
    container, build_ok = start_merge_container(
        project, target_commit,
        testcases_dir=str(testcase_stage_dir),
        build_csv=args.build_csv,
        extra_volumes=args.volume,
    )
    if not build_ok:
        logger.error("Container startup / initial build failed")
        return 1

    try:
        # ------------------------------------------------------------------
        # 4. Inject dispatch files and modify harness
        # ------------------------------------------------------------------
        # If we already have a harness diff from a previous run, reuse it.
        # This avoids re-invoking a code agent unnecessarily and keeps resume
        # behavior deterministic.
        harness_diff_path = output_dir / "harness.diff"
        if harness_diff_path.exists() and harness_diff_path.stat().st_size > 0:
            logger.info("Harness diff already exists, reusing: %s", harness_diff_path)
            _clean_container_working_tree_before_harness_diff(container, project)
            hdiff = harness_diff_path.read_text()
            _exec_capture(container,
                          f"cat > /tmp/harness.diff << 'HEOF'\n{hdiff}HEOF")
            ret, out = _exec_capture(container,
                                     f"cd /src/{project} && git apply /tmp/harness.diff 2>&1")
            if ret != 0:
                logger.error("Failed to apply existing harness.diff")
                logger.error(out)
                return 1
            _restore_build_sh(container, output_dir)
            _inject_dispatch_deps_fixer(container)
            ret, out = _exec_capture(container, "sudo -E compile 2>&1", timeout=300)
            if ret != 0:
                logger.error("Build failed after applying existing harness.diff")
                logger.error(out[-500:] if out else "(no output)")
                return 1
            dispatch_state["dispatch_file_injected"] = True
            dispatch_state["harness_modified"] = True
        else:
            harness_diff_path = None

        if harness_diff_path is None:
            _inject_dispatch_files(container, project, dispatch_state["dispatch_bytes"])
            dispatch_state["dispatch_file_injected"] = True
            # Find the primary fuzzer name (all bugs should share it)
            primary_fuzzer = (diff_bugs + testcase_only_bugs + local_bugs)[0]["fuzzer"]
            ok = _modify_harness_for_dispatch(
                container, project, primary_fuzzer,
                model=args.model,
            )
            if not ok:
                logger.error("Failed to modify harness for dispatch")
                return 1
            dispatch_state["harness_modified"] = True

            # Capture the harness diff immediately so we can re-apply it after
            # every git checkout -f during phase 1 and phase 2.
            harness_diff = _clean_diff(container, project)
            harness_diff_path = output_dir / "harness.diff"
            if harness_diff.strip():
                harness_diff_path.write_text(harness_diff)
                logger.info("Harness diff saved (%d bytes)", len(harness_diff))
            else:
                logger.warning("No harness diff captured after modification!")
                harness_diff_path = None

            # Save /src/build.sh — the agent may have modified it to
            # compile __bug_dispatch.c, but it's outside the git repo.
            _save_build_sh(container, output_dir)

        harness_baseline_rev = _create_harness_baseline_commit(container, project)
        logger.info("Harness baseline commit: %s", harness_baseline_rev[:12])

        # Stash ASAN binaries (harness modification already built with ASAN)
        _exec_capture(container,
                      "mkdir -p /out/address && "
                      "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && "
                      "cp \"$f\" /out/address/; done; true")
        # Copy testcases (originals + patched)
        _restore_testcases(container, project, all_bugs)
        _apply_all_dispatch_bytes(container, dispatch_state)

        # Persist patched local testcases into this run's testcase dir before
        # local verification. Later restores will prefer these patched files.
        for bug in local_bugs:
            tc_name = bug["testcase"]
            staged_patched = testcase_stage_dir / f"{tc_name}-patched"
            if _save_work_testcase_to_host(container, tc_name, staged_patched):
                bug["patched_testcase"] = str(staged_patched)
                logger.info("[%s] Staged patched local testcase: %s",
                            bug["bug_id"], staged_patched)

        # ------------------------------------------------------------------
        # 5. Verify local bugs at baseline
        # ------------------------------------------------------------------
        logger.info("\n=== Verifying local bugs at baseline ===")
        for bug in local_bugs:
            triggers = verify_bug_triggers(
                container, bug["bug_id"], bug["fuzzer"],
                bug["testcase"], bug.get("sanitizer", "address"),
                bug.get("crash_log"),
            )
            status = "OK" if triggers else "FAIL"
            logger.info("[%s] local: %s", bug["bug_id"], status)

        # ------------------------------------------------------------------
        # 6. Verify testcase-only bugs
        # ------------------------------------------------------------------
        logger.info("\n=== Verifying testcase-only bugs ===")
        for bug in testcase_only_bugs:
            triggers = verify_bug_triggers(
                container, bug["bug_id"], bug["fuzzer"],
                bug["testcase"], bug.get("sanitizer", "address"),
                bug.get("crash_log"),
            )
            status = "OK" if triggers else "FAIL"
            logger.info("[%s] testcase-only: %s", bug["bug_id"], status)

        # ------------------------------------------------------------------
        # 7. Phase 1: Wrap each patch independently on clean source
        # ------------------------------------------------------------------
        wrapped_diffs: dict[str, str] = {}  # bug_id -> wrapped diff path
        merge_results: list[dict] = []

        # Load previously wrapped diffs from disk (for --start-step resume)
        for bd in diff_bugs:
            bid = bd["bug_id"]
            existing = output_dir / f"wrapped_{bid}.diff"
            if existing.exists() and existing.stat().st_size > 0:
                wrapped_diffs[bid] = str(existing)
                logger.info("[%s] Loaded existing wrapped diff (%d bytes)",
                            bid, existing.stat().st_size)

        start_step = getattr(args, "start_step", 0)
        for i, bd in enumerate(diff_bugs):
            bug_id = bd["bug_id"]
            bit_index = next(
                idx for idx, info in dispatch_state["bits"].items()
                if info["bug_id"] == bug_id
            )

            # Skip if already wrapped (resume) or before start-step
            if bug_id in wrapped_diffs:
                logger.info("[%s] Already wrapped, skipping", bug_id)
                continue
            if i < start_step:
                logger.info("[%s] Before start-step %d, skipping", bug_id, start_step)
                continue

            logger.info("\n=== Wrap %d/%d: %s (bit %d) ===",
                        i + 1, len(diff_bugs), bug_id, bit_index)

            step = {
                "step": i + 1,
                "bug_id": bug_id,
                "bit_index": bit_index,
                "success": False,
            }

            # Reset source to the exact harness baseline, then apply only the
            # bug-specific wrapped delta on top of it.
            _restore_harness_baseline(container, project, harness_baseline_rev)

            output = ""
            for attempt in range(_MAX_WRAP_RETRIES + 1):
                success, output = wrap_bug_with_dispatch(
                    container, project, bd, bit_index,
                    dispatch_state, model=args.model,
                    codex_mode=getattr(args, "codex_mode", "exec"),
                )

                if success:
                    # Extract only the delta from the harness baseline.
                    wrapped_diff = _clean_diff_against(
                        container, project, harness_baseline_rev,
                    )
                    if wrapped_diff.strip():
                        wrapped_path = output_dir / f"wrapped_{bug_id}.diff"
                        wrapped_path.write_text(wrapped_diff)
                        wrapped_diffs[bug_id] = str(wrapped_path)
                        step["success"] = True
                        logger.info("[%s] Wrapped diff saved: %s (%d bytes)",
                                    bug_id, wrapped_path, len(wrapped_diff))
                        break
                    else:
                        logger.warning("[%s] Agent produced no diff after wrapping", bug_id)

                logger.warning("[%s] Attempt %d failed, retrying...",
                               bug_id, attempt + 1)
                # Reset for retry to the exact harness baseline.
                _restore_harness_baseline(container, project, harness_baseline_rev)

            if not step["success"]:
                logger.error("[%s] FAILED after %d attempts, skipping",
                             bug_id, _MAX_WRAP_RETRIES + 1)

            step["output"] = output[-500:] if output else ""
            merge_results.append(step)
            _save_progress(output_dir, dispatch_state, merge_results,
                           list(wrapped_diffs.keys()))

        # ------------------------------------------------------------------
        # 8. Phase 2: Merge all wrapped diffs via code agent
        # ------------------------------------------------------------------
        combined_path = output_dir / "combined.diff"
        if combined_path.exists() and combined_path.stat().st_size > 0:
            # Reuse existing combined diff — skip the agent merge entirely.
            logger.info("combined.diff already exists, reusing: %s (%d bytes)",
                        combined_path, combined_path.stat().st_size)
            _restore_harness_baseline(container, project, harness_baseline_rev)
            cdiff = combined_path.read_text()
            _exec_capture(container,
                          f"cat > /tmp/combined.diff << 'CEOF'\n{cdiff}CEOF")
            ret, out = _exec_capture(
                container,
                f"cd /src/{project} && git apply /tmp/combined.diff 2>&1",
            )
            if ret != 0:
                logger.error("Failed to apply existing combined.diff: %s", out[-500:])
                return 1
            _ensure_dispatch_linked_everywhere(container, project)
            ret, out = _exec_capture(container, "sudo -E compile 2>&1", timeout=300)
            if ret != 0:
                logger.error("Build failed after applying combined.diff: %s",
                             out[-500:] if out else "(no output)")
                return 1
            applied_bugs = list(wrapped_diffs.keys())
        else:
            logger.info("\n=== Merging %d wrapped diffs ===", len(wrapped_diffs))

            # Reset source to the exact harness baseline before merging wrapped
            # bug deltas.
            _restore_harness_baseline(container, project, harness_baseline_rev)

            # Copy all wrapped patches into container
            patch_descriptions = []
            for bug_id, wdiff_path in wrapped_diffs.items():
                diff_content = Path(wdiff_path).read_text()
                if not diff_content.strip():
                    continue
                fname = f"wrapped_{bug_id}.diff"
                _exec_capture(container,
                              f"cat > /tmp/{fname} << 'DIFFEOF'\n{diff_content}DIFFEOF")
                patch_descriptions.append(f"- `/tmp/{fname}` — {bug_id}")

            if not patch_descriptions:
                logger.info("No patches to merge (all were dispatch-only)")
                applied_bugs = list(wrapped_diffs.keys())
            else:
                # Use code agent to merge patches in chunks (avoid single huge prompt).
                # We keep the existing merge prompt/behavior, but run it multiple times.
                # Each chunk is merged on top of the previous chunk's result.
                max_chunk = 15
                total_patches = len(patch_descriptions)
                logger.info(
                    "Merging %d patches in chunks of <=%d via codex",
                    total_patches, max_chunk,
                )

                applied_bugs = []
                merge_failed = False
                for chunk_idx, start in enumerate(range(0, total_patches, max_chunk), start=1):
                    chunk = patch_descriptions[start:start + max_chunk]
                    patch_list = "\n".join(chunk)
                    merge_prompt = _load_prompt(
                        "merge_wrapped_patches",
                        project=project,
                        target_commit=target_commit,
                        patch_list=patch_list,
                    )

                    setup_codex_creds(container)
                    codex_mode = getattr(args, "codex_mode", "exec")
                    agent_cmd = build_codex_command(
                        merge_prompt, args.model, mode=codex_mode,
                    )

                    logger.info(
                        "Invoking codex to merge chunk %d (%d patches: %d..%d/%d)",
                        chunk_idx,
                        len(chunk),
                        start + 1,
                        min(start + len(chunk), total_patches),
                        total_patches,
                    )
                    if codex_mode == "interactive":
                        ret, output = _exec_interactive(container, agent_cmd, timeout=3600)
                    else:
                        ret, output = _exec_capture(container, agent_cmd, timeout=3600)
                    _usage_tracker.log_usage(f"merge chunk {chunk_idx}", output, args.model)
                    if ret != 0:
                        logger.error(
                            "Agent failed on chunk %d (exit %d). Output tail: %s",
                            chunk_idx, ret, output[-500:] if output else "",
                        )
                        merge_failed = True
                        break

                    # Verify build after each chunk so failures are localized.
                    ret, build_out = _exec_capture(
                        container, "sudo -E compile 2>&1", timeout=300,
                    )
                    if ret != 0:
                        logger.error(
                            "Build failed after chunk %d: %s",
                            chunk_idx, build_out[-500:],
                        )
                        merge_failed = True
                        break

                    # Track which bug IDs were included in this chunk
                    for desc in chunk:
                        m = re.search(r"—\s+(OSV-[0-9]{4}-[0-9]+)\s*$", desc)
                        if m:
                            applied_bugs.append(m.group(1))

                if not merge_failed:
                    # If everything succeeded, consider all wrapped diffs merged.
                    applied_bugs = list(wrapped_diffs.keys())

        # Build ASAN with all patches applied
        logger.info("Building with all patches applied...")
        _ensure_dispatch_linked_everywhere(container, project)
        _exec_capture(container, "sudo -E compile 2>&1", timeout=300)
        _exec_capture(container,
                      "mkdir -p /out/address && "
                      "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && "
                      "cp \"$f\" /out/address/; done; true")

        # Restore testcases with dispatch bytes
        _restore_testcases(container, project, all_bugs)
        _apply_all_dispatch_bytes(container, dispatch_state)

        # ------------------------------------------------------------------
        # 9. Final verification
        # ------------------------------------------------------------------
        logger.info("\n=== Final verification ===")
        _restore_testcases(container, project, all_bugs)
        _apply_all_dispatch_bytes(container, dispatch_state)

        final_results = verify_all_bugs(container, all_bugs)
        triggered = sum(1 for v in final_results.values() if v)
        total = len(final_results)
        logger.info("\nRESULT: %d / %d bugs triggering", triggered, total)
        for bid, ok in final_results.items():
            logger.info("  %s: %s", bid, "OK" if ok else "FAIL")

        # ------------------------------------------------------------------
        # 10. Save combined diff + testcases
        # ------------------------------------------------------------------
        combined_diff = _clean_diff_against(container, project, harness_baseline_rev)
        combined_path = output_dir / "combined.diff"
        combined_path.write_text(combined_diff)
        logger.info("Combined diff: %s (%d bytes)", combined_path, len(combined_diff))

    # Save testcases
        tc_dir = output_dir / "testcases"
        tc_dir.mkdir(exist_ok=True)
        # Only mark artifacts as "patched" if we actually introduced dispatch
        # bytes / harness changes. (In this offline pipeline this is normally
        # true, but keep the check to avoid misleading filenames.)
        mark_patched = bool(dispatch_state.get("dispatch_bytes", 0)) and bool(
            dispatch_state.get("harness_modified")
        )
        for bug in all_bugs:
            tc_name = bug["testcase"]
            tc_ret = subprocess.run(
                ["docker", "exec", container,
                 "bash", "-c", f"cat /work/{tc_name}"],
                capture_output=True, timeout=10,
            )
            if tc_ret.returncode == 0 and tc_ret.stdout:
                if mark_patched:
                    # After rewrite, treat the saved artifact as the patched testcase.
                    (tc_dir / f"{tc_name}-patched").write_bytes(tc_ret.stdout)
                else:
                    (tc_dir / tc_name).write_bytes(tc_ret.stdout)

        logger.info("Testcases saved to %s", tc_dir)

        # Save summary
        merge_summary = {
            "project": project,
            "target_commit": target_commit,
            "local_bugs": len(local_bugs),
            "testcase_only_bugs": len(testcase_only_bugs),
            "diff_bugs": len(diff_bugs),
            "applied": applied_bugs,
            "dispatch_state": {k: v for k, v in dispatch_state.items()
                               if k != "bits"},
            "triggered": triggered,
            "total": total,
            "results": {bid: ok for bid, ok in final_results.items()},
            "steps": merge_results,
        }
        (output_dir / "summary.json").write_text(
            json.dumps(merge_summary, indent=2))
        logger.info("Summary: %s", output_dir / "summary.json")

        _usage_tracker.log_session_total()

        return 0 if triggered == total else 1

    finally:
        if not args.keep_container:
            logger.info("Destroying container %s...", container)
            subprocess.call(
                ["docker", "rm", "-f", container],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        else:
            logger.info("Container kept: docker exec -it %s bash", container)


def _save_progress(output_dir, dispatch_state, merge_results, applied_bugs):
    """Save intermediate progress to disk."""
    progress = {
        "dispatch_state": {k: v for k, v in dispatch_state.items()
                           if k != "bits"},
        "applied_bugs": applied_bugs,
        "steps": merge_results,
    }
    (output_dir / "progress.json").write_text(json.dumps(progress, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Offline dispatch-wrapped merge of per-bug transplant patches",
    )
    parser.add_argument("--summary", required=True,
                        help="Path to batch summary.json")
    parser.add_argument("--bug_info", required=True,
                        help="Path to osv_testcases_summary.json")
    parser.add_argument("--target", required=True,
                        help="OSS-Fuzz project name")
    parser.add_argument("--target-commit", default=None,
                        help="Override target commit")
    parser.add_argument("--build_csv", default=None,
                        help="Build CSV for historical image pinning")
    parser.add_argument("--testcases-dir", default=None,
                        help="Directory containing testcase files")
    parser.add_argument("--local-bugs", nargs="*", default=None,
                        help="Bug IDs that already trigger at target")
    parser.add_argument("--model", default=None,
                        help="Model override for codex")
    parser.add_argument("-v", "--volume", action="append",
                        help="Extra Docker volume mounts")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show plan without executing")
    parser.add_argument("--keep-container", action="store_true",
                        help="Keep container for debugging")
    parser.add_argument("--start-step", type=int, default=0,
                        help="Resume from step N")
    parser.add_argument("--max-steps", type=int, default=None,
                        help="Stop after N steps")
    parser.add_argument("--codex-mode", choices=["exec", "interactive"],
                        default="exec",
                        help="Agent invocation mode: exec (default, JSONL) "
                             "or interactive (TUI via tmux)")
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    return run_offline_merge(args)


if __name__ == "__main__":
    sys.exit(main())
