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
PROMPTS_DIR = SCRIPT_DIR / "prompts"


def _load_prompt(name: str, **kwargs: str) -> str:
    """Load a prompt template from script/prompts/ and format it.

    Reads ``script/prompts/{name}.md``, strips the YAML-style header
    (everything before the first blank line after ``## Prompt``), and
    calls ``.format(**kwargs)`` on the body.
    """
    path = PROMPTS_DIR / f"{name}.md"
    text = path.read_text()
    # Extract body after "## Prompt" header
    marker = "## Prompt"
    idx = text.find(marker)
    if idx != -1:
        text = text[idx + len(marker):]
    # Strip leading blank lines
    text = text.lstrip("\n")
    return textwrap.dedent(text).format(**kwargs)


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


def _find_conflicting_bugs(
    current_bd: dict,
    applied_bugs: list[str],
    all_diffs: list[dict],
) -> list[dict]:
    """Find which previously-applied bug(s) have file overlap with *current_bd*."""
    current_files = current_bd.get("_files", set())
    conflicting = []
    for prev_id in applied_bugs:
        prev_bd = next((d for d in all_diffs if d["bug_id"] == prev_id), None)
        if prev_bd and current_files & prev_bd.get("_files", set()):
            conflicting.append(prev_bd)
    return conflicting


# ---------------------------------------------------------------------------
# Bug ownership markers — annotate source after each diff is applied
# ---------------------------------------------------------------------------

def _annotate_diff_ownership(
    container: str,
    project: str,
    diff_path: str,
    bug_id: str,
) -> None:
    """Insert //BUG_START and //BUG_END markers around code added by a diff.

    After a bug's diff has been applied to the source tree, this function
    parses the diff to find contiguous groups of added lines (``+`` lines)
    and wraps them with ownership comments so that a later conflict-
    resolution agent can see which code belongs to which bug and avoid
    modifying it.

    The annotation is done with a Python helper script executed inside the
    container, operating on the files already modified by the diff.
    """
    # Read the diff content
    diff_text = Path(diff_path).read_text(errors="replace")

    # Parse: collect (file, start_line, count) for each contiguous added block.
    # We track the "new file" line number so we know where added lines land.
    annotations: list[tuple[str, list[tuple[int, int]]]] = []
    current_file = None
    file_blocks: dict[str, list[tuple[int, int]]] = {}

    new_line = 0
    in_hunk = False
    add_start = None
    add_count = 0

    for raw_line in diff_text.splitlines():
        # Detect file header
        m = re.match(r'^\+\+\+ b/(.+)$', raw_line)
        if m:
            # Flush previous add block
            if add_start is not None and current_file:
                file_blocks.setdefault(current_file, []).append(
                    (add_start, add_count))
                add_start = None
                add_count = 0
            current_file = m.group(1)
            in_hunk = False
            continue

        # Detect hunk header
        hm = re.match(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@', raw_line)
        if hm:
            # Flush
            if add_start is not None and current_file:
                file_blocks.setdefault(current_file, []).append(
                    (add_start, add_count))
                add_start = None
                add_count = 0
            new_line = int(hm.group(1))
            in_hunk = True
            continue

        if not in_hunk or current_file is None:
            continue

        if raw_line.startswith('+'):
            if add_start is None:
                add_start = new_line
                add_count = 1
            else:
                add_count += 1
            new_line += 1
        elif raw_line.startswith('-'):
            # Deleted line — flush any add block
            if add_start is not None:
                file_blocks.setdefault(current_file, []).append(
                    (add_start, add_count))
                add_start = None
                add_count = 0
            # Deleted lines don't advance new_line
        else:
            # Context line — flush any add block
            if add_start is not None:
                file_blocks.setdefault(current_file, []).append(
                    (add_start, add_count))
                add_start = None
                add_count = 0
            new_line += 1

    # Flush final block
    if add_start is not None and current_file:
        file_blocks.setdefault(current_file, []).append(
            (add_start, add_count))

    if not file_blocks:
        return

    # Only annotate C/C++ source files where // comments are valid
    c_exts = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
    file_blocks = {
        f: b for f, b in file_blocks.items()
        if Path(f).suffix.lower() in c_exts
    }
    if not file_blocks:
        return

    # Build a Python script that inserts markers into the source files.
    # Process blocks in reverse order so line numbers stay valid.
    marker_start = f"//BUG_START {bug_id}"
    marker_end = f"//BUG_END {bug_id}"

    # Write script to a temp file inside the container to avoid shell
    # quoting issues with nested quotes and multi-line code.
    script_lines = [
        "import sys",
        "",
        "def annotate(path, blocks, ms, me):",
        "    with open(path) as f:",
        "        lines = f.readlines()",
        "    for start, count in sorted(blocks, reverse=True):",
        "        idx = start - 1",
        "        if idx < 0 or idx > len(lines):",
        "            continue",
        "        # Skip if already annotated (by any bug)",
        "        if idx > 0 and '//BUG_START' in lines[idx - 1]:",
        "            continue",
        "        end_idx = idx + count",
        "        lines.insert(end_idx, me + '\\n')",
        "        lines.insert(idx, ms + '\\n')",
        "    with open(path, 'w') as f:",
        "        f.writelines(lines)",
        "",
    ]

    for fpath, blocks in file_blocks.items():
        blocks_repr = repr(blocks)
        script_lines.append(
            f"annotate('/src/{project}/{fpath}', {blocks_repr}, "
            f"{marker_start!r}, {marker_end!r})"
        )

    script = "\n".join(script_lines) + "\n"

    # Write script into the container via heredoc, then run it
    write_cmd = "cat > /tmp/_annotate.py << 'ANNOTATE_EOF'\n" + script + "ANNOTATE_EOF"
    _exec_capture(container, write_cmd, timeout=10)
    ret, output = _exec_capture(
        container, "python3 /tmp/_annotate.py", timeout=30,
    )
    if ret != 0:
        logger.warning("[%s] Annotation failed: %s", bug_id, output[:300])
    else:
        n_files = len(file_blocks)
        n_blocks = sum(len(b) for b in file_blocks.values())
        logger.info("[%s] Annotated %d block(s) across %d file(s)",
                    bug_id, n_blocks, n_files)


# ---------------------------------------------------------------------------
# Dispatch branch infrastructure
# ---------------------------------------------------------------------------

_DISPATCH_HEADER = """\
#ifndef __BUG_DISPATCH_H
#define __BUG_DISPATCH_H
#include <stdint.h>
extern volatile uint8_t __bug_dispatch;
#endif
"""

_DISPATCH_SOURCE = """\
#include <stdint.h>
volatile uint8_t __bug_dispatch = 0;
"""


def _inject_dispatch_files(container: str, project: str) -> None:
    """Create __bug_dispatch.h and __bug_dispatch.c inside /src/{project}."""
    for fname, content in (("__bug_dispatch.h", _DISPATCH_HEADER),
                           ("__bug_dispatch.c", _DISPATCH_SOURCE)):
        _exec_capture(
            container,
            f"cat > /src/{project}/{fname} << 'DISPATCH_EOF'\n{content}DISPATCH_EOF",
        )
    logger.info("Injected __bug_dispatch.h/.c into /src/%s", project)


def _apply_all_dispatch_bytes(
    container: str,
    dispatch_state: dict,
) -> None:
    """Prepend dispatch bytes to PoCs in /work/ (idempotent — reads from /corpus/)."""
    for bug_id, dval in dispatch_state["poc_bytes"].items():
        testcase = f"testcase-{bug_id}"
        _exec_capture(
            container,
            f"cp /corpus/{testcase} /work/{testcase} 2>/dev/null; "
            f"python3 -c \""
            f"d=open('/work/{testcase}','rb').read(); "
            f"open('/work/{testcase}','wb').write(bytes([{dval}])+d)\"",
        )


def _modify_harness_for_dispatch(
    container: str,
    project: str,
    fuzzer: str,
    agent: str = "claude",
    model: str | None = None,
) -> bool:
    """Use agent to modify the fuzz harness to consume a dispatch byte.

    Returns True if harness was modified and builds successfully.
    """
    sys.path.insert(0, str(SCRIPT_DIR))
    from bug_transplant import AGENT_CONFIG

    cfg = AGENT_CONFIG[agent]

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

    prompt = _load_prompt("harness_dispatch", project=project, fuzzer=fuzzer)

    escaped = shlex.quote(prompt)
    agent_cmd = cfg["run_cmd"].format(prompt=escaped)
    if model:
        agent_cmd += f" {cfg['model_flag']} {shlex.quote(model)}"

    logger.info("Invoking %s to modify harness for dispatch byte...", agent)
    ret, output = _exec_capture(container, agent_cmd, timeout=1800)
    if ret != 0:
        logger.error("Harness modification agent failed (exit %d)", ret)
        return False

    ret, _ = _exec_capture(container, "sudo -E compile 2>&1", timeout=300)
    if ret != 0:
        logger.error("Build failed after harness modification")
        return False

    logger.info("Harness modified for dispatch byte mechanism")
    return True


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



def _rebuild_project_image(project: str, target_commit: str,
                           build_csv: str | None, agent_type: str) -> str:
    """Rebuild the project Docker image from the correct historical OSS-Fuzz commit.

    Uses ``fuzz_helper.py build_version --runner-image auto`` to build the
    project Docker image with the correct historical base-builder digest
    pinned.  This is the same method used to build the CSV, so the merge
    container gets the same compiler, ASAN runtime, and base libraries.

    The compiled binaries from build_version are a side-effect we ignore —
    we only need the ``gcr.io/oss-fuzz/{project}`` image it produces.
    """
    sys.path.insert(0, str(SCRIPT_DIR))
    from bug_transplant import build_agent_image

    # Use fuzz_helper.py build_version to build the project Docker image.
    # This handles: oss-fuzz commit checkout, base-builder digest pinning,
    # Dockerfile patching, and docker build — exactly matching how the
    # builds CSV was produced.
    cmd = [
        sys.executable, str(SCRIPT_DIR / "fuzz_helper.py"),
        "build_version", project,
        "--commit", target_commit,
        "--sanitizer", "address",
        "--no_corpus",
        "--runner-image", "auto",
    ]
    if build_csv:
        cmd += ["--build_csv", build_csv]

    logger.info("Building project image via fuzz_helper.py build_version --runner-image auto")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if result.returncode != 0:
        logger.error("fuzz_helper.py build_version failed (exit %d)", result.returncode)
        logger.error("Build output (last 40 lines):\n%s",
                      "\n".join(result.stdout.splitlines()[-40:]))
        sys.exit(1)
    logger.info("Project image built: gcr.io/oss-fuzz/%s", project)

    # Layer the agent CLI on top of the freshly built project image
    project_image = f"gcr.io/oss-fuzz/{project}"
    image_tag = build_agent_image(project, project_image, agent_type)
    logger.info("Agent image built: %s", image_tag)
    return image_tag


def start_merge_container(
    project: str,
    target_commit: str,
    testcases_dir: str,
    build_csv: str | None = None,
    extra_volumes: list[str] | None = None,
    agent_type: str = "claude",
) -> tuple[str, bool]:
    """Start a persistent container at the target commit for merging."""
    container_name = f"bug-merge-{project}"

    # Rebuild the project image from the historical OSS-Fuzz commit so the
    # container has the correct compiler, ASAN runtime, and base libraries.
    image_tag = _rebuild_project_image(project, target_commit, build_csv, agent_type)

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

    # Build ASAN and UBSAN (no MSAN — it taints libc++ permanently).
    for san in ("address", "undefined"):
        logger.info("Building %s inside container...", san)
        _exec_capture(
            container_name,
            f"cd /src/{project} && make clean 2>/dev/null; "
            f"rm -rf .obj *.a *.o 2>/dev/null; "
            f"rm -f /src/*.o 2>/dev/null; true",
        )
        ret, build_output = _exec_capture(
            container_name,
            f"sudo -E SANITIZER={san} compile 2>&1",
            timeout=300,
        )
        if ret != 0:
            logger.error("%s build failed. Tail:", san)
            logger.error("%s", build_output[-500:] if build_output else "(no output)")
            if san == "address":
                return container_name, False
            logger.warning("Skipping %s, bugs using it won't verify", san)
            continue
        # Stash per-sanitizer binaries
        _exec_capture(
            container_name,
            f"mkdir -p /out/{san} && "
            "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && "
            f"cp \"$f\" /out/{san}/; done; true",
        )
        logger.info("Build OK for %s", san)

    # Restore testcases (compile may wipe /work)
    _exec_capture(container_name, "cp /corpus/testcase-* /work/ 2>/dev/null; true")

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
    conflicting_diffs: list[tuple[str, str]] | None = None,
    dispatch_bit: int | None = None,
) -> str:
    """Use a code agent to resolve a merge conflict.

    When *conflicting_diffs* and *dispatch_bit* are provided, the agent is
    instructed to use input-driven dispatch branches for truly contradictory
    changes.

    Returns:
      ``"resolved"``  – combined without dispatch branches
      ``"dispatch"``  – dispatch branch(es) used
      ``"failed"``    – could not resolve
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

    # Copy conflicting patches into container for agent to read
    conflict_desc_lines = []
    if conflicting_diffs:
        for cbug_id, cdiff_path in conflicting_diffs:
            cdiff_name = Path(cdiff_path).name
            subprocess.call(
                ["docker", "cp", cdiff_path, f"{container}:/tmp/{cdiff_name}"],
            )
            conflict_desc_lines.append(
                f"  - Bug {cbug_id}: /tmp/{cdiff_name}"
            )
    conflict_desc = "\n".join(conflict_desc_lines) if conflict_desc_lines else "  (unknown)"

    # Build dispatch-aware prompt when dispatch infrastructure is available
    fmt_kwargs = dict(
        project=project, applied_list=applied_list, diff_name=diff_name,
        bug_id=bug_id, conflict_desc=conflict_desc,
    )
    if dispatch_bit is not None:
        fmt_kwargs["dispatch_bit"] = dispatch_bit
        prompt = _load_prompt("conflict_resolve_dispatch", **fmt_kwargs)
    else:
        prompt = _load_prompt("conflict_resolve_no_dispatch", **fmt_kwargs)

    escaped = shlex.quote(prompt)
    agent_cmd = cfg["run_cmd"].format(prompt=escaped)
    if model:
        agent_cmd += f" {cfg['model_flag']} {shlex.quote(model)}"

    ret, output = _exec_capture(container, agent_cmd, timeout=1800)

    if ret != 0:
        logger.error("[%s] %s agent failed (exit %d)", bug_id, agent, ret)
        return "failed"

    # Verify it compiles
    ret, _ = _exec_capture(container, "sudo -E compile 2>&1", timeout=300)
    if ret != 0:
        logger.error("[%s] Build failed after conflict resolution", bug_id)
        return "failed"

    # Determine whether dispatch branches were used
    if dispatch_bit is not None and "DISPATCH_USED" in output:
        logger.info("[%s] Conflict resolved with dispatch branch (bit %s)",
                    bug_id, dispatch_bit)
        return "dispatch"

    logger.info("[%s] Conflict resolved by combining (no dispatch)", bug_id)
    return "resolved"


def resolve_with_dispatch(
    container: str,
    bug_id: str,
    project: str,
    regressed_bugs: list[dict],
    dispatch_bit: int,
    current_diff_path: str | None = None,
    agent: str = "claude",
    model: str | None = None,
) -> bool:
    """Add dispatch branches to fix regressions caused by a transplant diff.

    Called AFTER a transplant diff has been applied and verified, when
    regression checking reveals that previously-working bugs stopped
    triggering.  The agent reads both the newly-applied patch and the
    regressed bugs' patches to identify contradictory code, then wraps
    it in dispatch branches.

    Returns True if dispatch was applied and build succeeds.
    """
    sys.path.insert(0, str(SCRIPT_DIR))
    from bug_transplant import AGENT_CONFIG

    cfg = AGENT_CONFIG[agent]
    logger.info("[%s] Invoking %s to add dispatch branches (bit %d) "
                "for %d regressed bugs...",
                bug_id, agent, dispatch_bit, len(regressed_bugs))

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

    # Copy patches into container for the agent to read
    patch_lines = []
    if current_diff_path:
        subprocess.call(
            ["docker", "cp", current_diff_path,
             f"{container}:/tmp/patch_{bug_id}.diff"],
        )
        patch_lines.append(
            f"  - Bug {bug_id} (newly applied): /tmp/patch_{bug_id}.diff"
        )

    for rb in regressed_bugs:
        rp = rb.get("diff_path")
        if rp:
            rb_id = rb["bug_id"]
            subprocess.call(
                ["docker", "cp", rp,
                 f"{container}:/tmp/patch_{rb_id}.diff"],
            )
            patch_lines.append(
                f"  - Bug {rb_id} (regressed): /tmp/patch_{rb_id}.diff"
            )
    patch_list = "\n".join(patch_lines) if patch_lines else "  (no patches available)"

    regressed_ids = ", ".join(b["bug_id"] for b in regressed_bugs)

    prompt = _load_prompt(
        "regression_dispatch",
        project=project, bug_id=bug_id, regressed_ids=regressed_ids,
        dispatch_bit=dispatch_bit,
    )

    escaped = shlex.quote(prompt)
    agent_cmd = cfg["run_cmd"].format(prompt=escaped)
    if model:
        agent_cmd += f" {cfg['model_flag']} {shlex.quote(model)}"

    ret, output = _exec_capture(container, agent_cmd, timeout=1800)
    if ret != 0:
        logger.error("[%s] Dispatch agent failed (exit %d)", bug_id, ret)
        return False

    ret, _ = _exec_capture(container, "sudo -E compile 2>&1", timeout=300)
    if ret != 0:
        logger.error("[%s] Build failed after dispatch resolution", bug_id)
        return False

    logger.info("[%s] Dispatch branches added (bit %d)", bug_id, dispatch_bit)
    return True


def _revert_and_rebuild(
    container: str,
    project: str,
    applied_bugs: list[str],
    ordered: list[dict],
    dispatch_state: dict,
) -> None:
    """Revert all source changes and re-apply only successfully applied bugs.

    Used when a patch must be rolled back (build failure, self-trigger
    failure, etc.) to restore the source tree to a known-good state.
    """
    _exec_capture(
        container,
        f"cd /src/{project} && git checkout -- . 2>&1",
    )
    for prev_id in applied_bugs:
        prev = next(d for d in ordered if d["bug_id"] == prev_id)
        _exec_capture(
            container,
            f"cd /src/{project} && git apply /tmp/{Path(prev['diff_path']).name} 2>&1",
        )
    for san in ("address", "undefined"):
        _exec_capture(
            container,
            f"cd /src/{project} && make clean 2>/dev/null; "
            f"rm -rf .obj *.a *.o 2>/dev/null; "
            f"rm -f /src/*.o 2>/dev/null; true",
        )
        _exec_capture(
            container, f"sudo -E SANITIZER={san} compile 2>&1", timeout=300,
        )
        _exec_capture(
            container,
            f"mkdir -p /out/{san} && "
            "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && "
            f"cp \"$f\" /out/{san}/; done; true",
        )
    _exec_capture(container, "cp /corpus/testcase-* /work/ 2>/dev/null; true")
    if dispatch_state["poc_bytes"]:
        _apply_all_dispatch_bytes(container, dispatch_state)


def _rebuild_and_apply_dispatch(
    container: str,
    project: str,
    dispatch_state: dict,
) -> None:
    """Rebuild ASAN+UBSAN and re-apply dispatch bytes after code changes."""
    for san in ("address", "undefined"):
        _exec_capture(
            container,
            f"cd /src/{project} && make clean 2>/dev/null; "
            f"rm -rf .obj *.a *.o 2>/dev/null; "
            f"rm -f /src/*.o 2>/dev/null; true",
        )
        _exec_capture(
            container,
            f"sudo -E SANITIZER={san} compile 2>&1",
            timeout=300,
        )
        _exec_capture(
            container,
            f"mkdir -p /out/{san} && "
            "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && "
            f"cp \"$f\" /out/{san}/; done; true",
        )
    _exec_capture(container, "cp /corpus/testcase-* /work/ 2>/dev/null; true")
    if dispatch_state["poc_bytes"]:
        _apply_all_dispatch_bytes(container, dispatch_state)


def resolve_self_trigger_with_dispatch(
    container: str,
    bug_id: str,
    project: str,
    applied_bugs_data: list[dict],
    crash_log: str | None,
    current_diff_path: str | None,
    dispatch_bit: int,
    agent: str = "claude",
    model: str | None = None,
) -> bool:
    """Add dispatch branches to unblock a bug whose self-trigger fails.

    Called when a transplant diff has been applied and builds, but the bug
    does not trigger — indicating that a previously-applied patch blocks the
    testcase from reaching the crash site.  The agent reads the crash log and
    all patches to identify the blocking change and wraps it in a dispatch
    branch.

    Returns True if dispatch was applied and build succeeds.
    """
    sys.path.insert(0, str(SCRIPT_DIR))
    from bug_transplant import AGENT_CONFIG

    cfg = AGENT_CONFIG[agent]
    logger.info("[%s] Invoking %s to unblock self-trigger (bit %d), "
                "analyzing %d previous patches...",
                bug_id, agent, dispatch_bit, len(applied_bugs_data))

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

    # Copy current bug's patch into container
    patch_lines = []
    if current_diff_path:
        subprocess.call(
            ["docker", "cp", current_diff_path,
             f"{container}:/tmp/patch_{bug_id}.diff"],
        )

    # Copy crash log into container
    crash_line = "(no crash log available)"
    if crash_log and Path(crash_log).exists():
        subprocess.call(
            ["docker", "cp", crash_log,
             f"{container}:/tmp/crash_{bug_id}.txt"],
        )
        crash_line = f"/tmp/crash_{bug_id}.txt"

    # Copy previously-applied patches
    prev_lines = []
    for pb in applied_bugs_data:
        pb_id = pb["bug_id"]
        pp = pb.get("diff_path")
        if pp:
            subprocess.call(
                ["docker", "cp", pp,
                 f"{container}:/tmp/patch_{pb_id}.diff"],
            )
            prev_lines.append(f"  - Bug {pb_id}: /tmp/patch_{pb_id}.diff")
    prev_list = "\n".join(prev_lines) if prev_lines else "  (none)"

    prompt = _load_prompt(
        "self_trigger_dispatch",
        project=project, bug_id=bug_id, crash_line=crash_line,
        prev_list=prev_list, dispatch_bit=dispatch_bit,
    )

    escaped = shlex.quote(prompt)
    agent_cmd = cfg["run_cmd"].format(prompt=escaped)
    if model:
        agent_cmd += f" {cfg['model_flag']} {shlex.quote(model)}"

    ret, output = _exec_capture(container, agent_cmd, timeout=1800)
    if ret != 0:
        logger.error("[%s] Self-trigger dispatch agent failed (exit %d)",
                     bug_id, ret)
        return False

    ret, _ = _exec_capture(container, "sudo -E compile 2>&1", timeout=300)
    if ret != 0:
        logger.error("[%s] Build failed after self-trigger dispatch", bug_id)
        return False

    logger.info("[%s] Self-trigger dispatch applied (bit %d)", bug_id,
                dispatch_bit)
    return True


# ---------------------------------------------------------------------------
# Bug verification
# ---------------------------------------------------------------------------

def _extract_stack_from_text(text: str) -> list[str]:
    """Extract function names from sanitizer crash output."""
    stack = []
    # Symbolized: #N 0xHEX in function_name
    sym_re = re.compile(r"#\d+\s+0x[0-9a-f]+\s+in\s+([^\s]+)", re.IGNORECASE)
    # Unsymbolized: #N 0xHEX (binary+0xOFFSET) — use binary+offset as frame ID
    unsym_re = re.compile(r"#\d+\s+0x[0-9a-f]+\s+\(([^)]+\+0x[0-9a-f]+)\)", re.IGNORECASE)
    for line in text.splitlines():
        m = sym_re.search(line)
        if m:
            # Clean: strip (anonymous namespace)::, __interceptor_, etc.
            name = m.group(1)
            name = re.sub(r'\(anonymous namespace\)::', '', name)
            name = re.sub(r'^__interceptor_', '', name)
            # Strip everything after '(' for C++ signatures
            if '(' in name:
                name = name[:name.index('(')]
            stack.append(name)
        elif not stack or not sym_re.search(line):
            # Only use unsymbolized fallback if no symbolized frames found yet
            m2 = unsym_re.search(line)
            if m2:
                stack.append(m2.group(1))
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
    """Run the fuzzer binary for the given sanitizer and check for a crash.

    If *crash_log* is provided, extracts the reference stack from it and
    compares against the fuzzer output using LCS matching.  Otherwise
    falls back to checking for any sanitizer SUMMARY line.
    """
    sym_path = "/out/llvm-symbolizer"
    san_opts = {
        "address": f"export ASAN_OPTIONS=detect_leaks=0:external_symbolizer_path={sym_path}; ",
        "undefined": f"export UBSAN_OPTIONS=external_symbolizer_path={sym_path}:print_stacktrace=1; ",
    }
    env_prefix = san_opts.get(sanitizer, "")
    fuzzer_path = f"/out/{sanitizer}/{fuzzer}"

    cmd = (
        f"{env_prefix}"
        f"if [ ! -x {fuzzer_path} ]; then "
        f"echo 'ERROR: {fuzzer_path} not found'; exit 99; fi; "
        f"{fuzzer_path} -runs=10 /work/{testcase} 2>&1"
    )
    logger.debug("[%s] verify cmd: %s", bug_id, cmd)
    ret, output = _exec_capture(container, cmd, timeout=120)
    logger.debug("[%s] verify exit=%d output_len=%d tail=%.500s",
                 bug_id, ret, len(output), output[-500:] if output else "(empty)")

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
                    logger.warning("[%s] Stack comparison inconclusive (exit=%d)", bug_id, ret)
                # Fall through to SUMMARY check instead of returning False —
                # unsymbolized stacks can't match symbolized references, but
                # the bug may still be triggering.
        # No reference stack or mismatch — fall through to basic check

    # Fallback: any sanitizer crash is a match
    has_summary = bool(re.search(
        r'SUMMARY:\s*(Address|Memory|Undefined|Thread|Leak)Sanitizer', output,
    ))
    if has_summary:
        if current_stack:
            logger.info("[%s] Bug triggers OK (SUMMARY + stack match)", bug_id)
        else:
            logger.info("[%s] Bug triggers OK (SUMMARY match, unsymbolized)", bug_id)
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
            logger.warning("No fuzzer for local bug %s, skipping", bug_id)
            continue
        if sanitizer not in ("address", "undefined"):
            logger.warning("Skipping %s local bug %s (only ASAN/UBSAN supported)", sanitizer, bug_id)
            continue
        testcase = f"testcase-{bug_id}"
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
            if sanitizer not in ("address", "undefined"):
                logger.warning("Skipping %s transplant bug %s (only ASAN/UBSAN supported)", sanitizer, bug_id)
                continue
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
                if sanitizer != "address":
                    continue
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
                    info = bug_info_dataset.get(bug_id, {})
                    reproduce = info.get("reproduce", {})
                    sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
                    if sanitizer != "address":
                        continue
                    seen_bug_ids.add(bug_id)
                    fuzzer = reproduce.get("fuzz_target", "")
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
    container, build_ok = start_merge_container(
        project, target_commit, args.testcases_dir,
        build_csv=args.build_csv,
        extra_volumes=args.volume,
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
    dispatch_state: dict = {
        "next_bit": 0,                # next available bit index
        "bits": {},                    # {bit_index: {bug_new, bug_existing}}
        "poc_bytes": {},               # {bug_id: int} dispatch byte per bug
        "harness_modified": False,     # dispatch byte consumption in harness
        "dispatch_file_injected": False,  # __bug_dispatch.h/.c created
    }

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
        max_steps = getattr(args, "max_steps", None)
        for i, bd in enumerate(ordered):
            if max_steps is not None and i >= max_steps:
                logger.info("Reached --max-steps %d, stopping early", max_steps)
                break
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

            # Annotate source with bug ownership markers after clean apply
            if method in ("clean", "3way"):
                _annotate_diff_ownership(container, project, diff_path, bug_id)

            if method == "conflict":
                # Identify which previously-applied bugs overlap
                conflicting = _find_conflicting_bugs(bd, applied_bugs, ordered)
                conflicting_info = [
                    (c["bug_id"], c["diff_path"]) for c in conflicting
                ]

                # Inject dispatch files on first conflict (idempotent)
                if not dispatch_state["dispatch_file_injected"]:
                    _inject_dispatch_files(container, project)
                    dispatch_state["dispatch_file_injected"] = True

                bit_index = dispatch_state["next_bit"]

                result = resolve_conflict_with_agent(
                    container, diff_path, bug_id, project,
                    applied_bugs, args.agent, args.model,
                    conflicting_diffs=conflicting_info,
                    dispatch_bit=bit_index,
                )

                if result == "dispatch":
                    step["apply_method"] = "dispatch"
                    dispatch_state["bits"][bit_index] = {
                        "bug_new": bug_id,
                        "bug_existing": [c["bug_id"] for c in conflicting],
                    }
                    dispatch_state["poc_bytes"].setdefault(bug_id, 0)
                    dispatch_state["poc_bytes"][bug_id] |= (1 << bit_index)
                    for c in conflicting:
                        dispatch_state["poc_bytes"].setdefault(c["bug_id"], 0)
                    dispatch_state["next_bit"] += 1

                    if not dispatch_state["harness_modified"]:
                        ok = _modify_harness_for_dispatch(
                            container, project, bd["fuzzer"],
                            args.agent, args.model,
                        )
                        if ok:
                            dispatch_state["harness_modified"] = True
                        else:
                            logger.error("[%s] Harness modification failed", bug_id)
                            step["apply_method"] = "failed"
                            merge_results.append(step)
                            continue

                elif result == "resolved":
                    step["apply_method"] = "agent_resolved"
                else:
                    step["apply_method"] = "failed"
                    logger.error("[%s] Could not resolve conflict, skipping", bug_id)
                    merge_results.append(step)
                    continue

            # --- Build ASAN + UBSAN ---
            logger.info("[%s] Building (ASAN + UBSAN)...", bug_id)
            build_failed = False
            for san in ("address", "undefined"):
                _exec_capture(
                    container,
                    f"cd /src/{project} && make clean 2>/dev/null; "
                    f"rm -rf .obj *.a *.o 2>/dev/null; "
                    f"rm -f /src/*.o 2>/dev/null; true",
                )
                ret, build_output = _exec_capture(
                    container, f"sudo -E SANITIZER={san} compile 2>&1", timeout=300,
                )
                if ret != 0:
                    logger.error("[%s] Build failed for %s. Tail:", bug_id, san)
                    logger.error("%s", build_output[-500:] if build_output else "(no output)")
                    if san == "address":
                        build_failed = True
                        break
                    continue
                _exec_capture(
                    container,
                    f"mkdir -p /out/{san} && "
                    "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && "
                    f"cp \"$f\" /out/{san}/; done; true",
                )
            # Restore testcases (compile may wipe /work)
            _exec_capture(container, "cp /corpus/testcase-* /work/ 2>/dev/null; true")
            if dispatch_state["poc_bytes"]:
                _apply_all_dispatch_bytes(container, dispatch_state)

            # Save per-step diff snapshot for debugging
            if not build_failed:
                step_dir = (DATA_DIR / "bug_transplant"
                            / f"merge_{project}_{target_commit[:8]}" / "steps")
                step_dir.mkdir(parents=True, exist_ok=True)
                _, step_diff = _exec_capture(
                    container, f"cd /src/{project} && git diff",
                )
                step_file = step_dir / f"step_{i+1:02d}_{bug_id}.diff"
                step_file.write_text(step_diff)
                step["step_diff_path"] = str(step_file)
                logger.info("[%s] Saved step diff: %s (%d bytes)",
                            bug_id, step_file, len(step_diff))

            step["build_ok"] = not build_failed
            if build_failed:
                logger.error("[%s] Build failed after applying diff, reverting", bug_id)
                _revert_and_rebuild(
                    container, project, applied_bugs, ordered, dispatch_state)
                merge_results.append(step)
                continue

            # --- Verify this bug triggers ---
            logger.info("[%s] Verifying self-trigger...", bug_id)
            step["self_triggers"] = verify_bug_triggers(
                container, bug_id, bd["fuzzer"], bd["testcase"],
                bd.get("sanitizer", "address"),
                bd.get("crash_log"),
            )

            # --- If self-trigger fails, try dispatch to unblock ---
            if not step["self_triggers"] and applied_bugs:
                logger.info(
                    "[%s] Self-trigger failed — attempting dispatch to "
                    "unblock from %d previous patches...",
                    bug_id, len(applied_bugs),
                )

                if not dispatch_state["dispatch_file_injected"]:
                    _inject_dispatch_files(container, project)
                    dispatch_state["dispatch_file_injected"] = True

                bit_index = dispatch_state["next_bit"]
                prev_bugs_data = [
                    next(d for d in ordered if d["bug_id"] == pid)
                    for pid in applied_bugs
                ]

                dispatch_ok = resolve_self_trigger_with_dispatch(
                    container, bug_id, project,
                    prev_bugs_data, bd.get("crash_log"),
                    bd["diff_path"], bit_index,
                    agent=args.agent, model=args.model,
                )

                if dispatch_ok:
                    if not dispatch_state["harness_modified"]:
                        hok = _modify_harness_for_dispatch(
                            container, project, bd["fuzzer"],
                            args.agent, args.model,
                        )
                        if hok:
                            dispatch_state["harness_modified"] = True
                            for lb in local_bugs:
                                dispatch_state["poc_bytes"].setdefault(
                                    lb["bug_id"], 0)
                            for tbd in ordered:
                                dispatch_state["poc_bytes"].setdefault(
                                    tbd["bug_id"], 0)

                    if dispatch_state["harness_modified"]:
                        dispatch_state["bits"][bit_index] = {
                            "bug_new": bug_id,
                            "bug_blocked_by": list(applied_bugs),
                            "type": "self_trigger_unblock",
                        }
                        dispatch_state["poc_bytes"].setdefault(bug_id, 0)
                        dispatch_state["poc_bytes"][bug_id] |= (1 << bit_index)
                        dispatch_state["next_bit"] += 1

                        _rebuild_and_apply_dispatch(
                            container, project, dispatch_state)

                        step["self_triggers"] = verify_bug_triggers(
                            container, bug_id, bd["fuzzer"], bd["testcase"],
                            bd.get("sanitizer", "address"),
                            bd.get("crash_log"),
                        )
                        if step["self_triggers"]:
                            step["apply_method"] += "+dispatch"
                            logger.info(
                                "[%s] Self-trigger OK after dispatch", bug_id)
                        else:
                            logger.warning(
                                "[%s] Still fails after dispatch", bug_id)

            # --- If still can't self-trigger, revert this patch ---
            if not step["self_triggers"]:
                logger.warning(
                    "[%s] Cannot self-trigger (likely due to incompatible "
                    "compile-time changes like macros/structs that cannot "
                    "be dispatched). Reverting patch to avoid breaking "
                    "other bugs.", bug_id,
                )
                step["apply_method"] = "reverted"
                _revert_and_rebuild(
                    container, project, applied_bugs, ordered, dispatch_state)
                merge_results.append(step)
                continue

            # --- Verify all previously applied bugs (regression check) ---
            if all_verified_bugs:
                logger.info("[%s] Regression check (%d bugs)...", bug_id, len(all_verified_bugs))
                reg_results = verify_all_bugs(container, all_verified_bugs)
                regressed = []
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
                        regressed.append(
                            next(b for b in all_verified_bugs if b["bug_id"] == rbug)
                        )

                # --- Attempt dispatch branches if regressions found ---
                if regressed and step["self_triggers"]:
                    logger.info("[%s] Attempting dispatch branches for %d regressions...",
                                bug_id, len(regressed))

                    # Inject dispatch files on first use
                    if not dispatch_state["dispatch_file_injected"]:
                        _inject_dispatch_files(container, project)
                        dispatch_state["dispatch_file_injected"] = True

                    bit_index = dispatch_state["next_bit"]
                    dispatch_ok = resolve_with_dispatch(
                        container, bug_id, project, regressed,
                        bit_index, current_diff_path=bd["diff_path"],
                        agent=args.agent, model=args.model,
                    )

                    if dispatch_ok:
                        # Modify harness to consume dispatch byte (once)
                        if not dispatch_state["harness_modified"]:
                            hok = _modify_harness_for_dispatch(
                                container, project, bd["fuzzer"],
                                args.agent, args.model,
                            )
                            if hok:
                                dispatch_state["harness_modified"] = True
                                # ALL PoCs need dispatch byte once harness is modified
                                for lb in local_bugs:
                                    dispatch_state["poc_bytes"].setdefault(lb["bug_id"], 0)
                                for tbd in ordered:
                                    dispatch_state["poc_bytes"].setdefault(tbd["bug_id"], 0)
                            else:
                                logger.error("[%s] Harness modification failed", bug_id)

                        if dispatch_state["harness_modified"]:
                            # Record bit assignment
                            dispatch_state["bits"][bit_index] = {
                                "bug_new": bug_id,
                                "bug_existing": [b["bug_id"] for b in regressed],
                            }
                            dispatch_state["poc_bytes"].setdefault(bug_id, 0)
                            dispatch_state["poc_bytes"][bug_id] |= (1 << bit_index)
                            for b in regressed:
                                dispatch_state["poc_bytes"].setdefault(b["bug_id"], 0)
                            dispatch_state["next_bit"] += 1

                            _rebuild_and_apply_dispatch(
                                container, project, dispatch_state)

                            # Re-verify regressed bugs
                            re_results = verify_all_bugs(container, regressed)
                            fixed = [bid for bid, ok in re_results.items() if ok]
                            still_broken = [bid for bid, ok in re_results.items() if not ok]
                            if fixed:
                                logger.info("[%s] Dispatch fixed: %s", bug_id, fixed)
                                step["regressions"] = still_broken
                            if still_broken:
                                logger.warning("[%s] Still regressed after dispatch: %s",
                                               bug_id, still_broken)
                            step["apply_method"] += "+dispatch"

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
        # Also include dispatch infrastructure files if used.
        touched_files: set[str] = set()
        for bd in ordered:
            touched_files.update(bd.get("_files", set()))
        if dispatch_state["harness_modified"]:
            # Include dispatch files and any harness changes in the diff
            touched_files.add("__bug_dispatch.h")
            touched_files.add("__bug_dispatch.c")
            # The harness file is unknown by name but git diff will pick it up
            # when we use plain `git diff` as fallback; for safety, include
            # all tracked changes if dispatch was used.
            _, all_diff = _exec_capture(
                container, f"cd /src/{project} && git diff",
            )
            # Parse the full diff to find harness file(s)
            for line in all_diff.splitlines():
                m = re.match(r'^[-+]{3}\s+[ab]/(.+)$', line)
                if m:
                    touched_files.add(m.group(1))
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

        # Save dispatch-modified PoCs to output directory
        if dispatch_state["poc_bytes"]:
            poc_dir = output_dir / "testcases"
            poc_dir.mkdir(parents=True, exist_ok=True)
            # Copy modified PoCs from /work/ in container to host
            for bid, dval in dispatch_state["poc_bytes"].items():
                testcase = f"testcase-{bid}"
                host_path = poc_dir / testcase
                subprocess.call(
                    ["docker", "cp",
                     f"{container}:/work/{testcase}",
                     str(host_path)],
                )
            logger.info("Saved %d dispatch-modified PoCs to %s",
                        len(dispatch_state["poc_bytes"]), poc_dir)

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
            "dispatch": {
                "branches_used": len(dispatch_state["bits"]),
                "bits": {
                    str(k): v for k, v in dispatch_state["bits"].items()
                },
                "poc_dispatch_bytes": {
                    k: hex(v) for k, v in dispatch_state["poc_bytes"].items()
                },
                "harness_modified": dispatch_state["harness_modified"],
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
        if dispatch_state["bits"]:
            print(f"  Dispatch branches:    {len(dispatch_state['bits'])}")
            for bit_idx, info in dispatch_state["bits"].items():
                existing = ", ".join(info["bug_existing"])
                print(f"    [bit {bit_idx}] {info['bug_new']} vs {existing}")
            print(f"  Dispatch PoC bytes:")
            for bid, dval in sorted(dispatch_state["poc_bytes"].items(),
                                    key=lambda x: x[1], reverse=True):
                if dval > 0:
                    print(f"    {bid}: 0x{dval:02x}")
            # All others implicitly 0x00
            n_zero = sum(1 for v in dispatch_state["poc_bytes"].values() if v == 0)
            if n_zero:
                print(f"    ({n_zero} other bugs: 0x00)")
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
    parser.add_argument("--max-steps", type=int, default=None,
                        help="Stop after N transplant diffs (for debugging)")
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
