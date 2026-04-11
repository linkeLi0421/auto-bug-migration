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
import copy
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
CONTAINER_TESTCASES_DIR = "/testcases"

# Projects where the git repo directory differs from the project name.
_SOURCE_REPO_MAP: dict[str, str] = {
    "ghostscript": "ghostpdl",
    "php": "php-src",
}


def _source_dir(project: str) -> str:
    """Return the source directory path for a project inside the container."""
    repo_name = _SOURCE_REPO_MAP.get(project, project)
    return f"/src/{repo_name}"


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


def _prepare_container_testcases_dir(
    source_dir: str | Path,
    staged_dir: str | Path,
    testcase_names: list[str] | set[str] | tuple[str, ...] | None = None,
) -> Path:
    """Stage testcase-* files for a specific merge run.

    The container mounts *staged_dir* and should never read testcases
    directly from the original source directory. This keeps each merge task
    isolated to its own testcase set.
    """
    source = Path(source_dir)
    staged = Path(staged_dir)
    staged.mkdir(parents=True, exist_ok=True)

    for old in staged.glob("testcase-*"):
        if old.is_file():
            old.unlink()

    selected = set(testcase_names or [])
    for testcase in source.glob("testcase-*"):
        if not testcase.is_file():
            continue
        if selected and testcase.name not in selected:
            continue
        shutil.copy2(testcase, staged / testcase.name)

    return staged


def _save_work_testcase_to_host(
    container: str,
    testcase_name: str,
    output_path: str | Path,
) -> bool:
    """Copy `/work/<testcase_name>` from the container to a host path."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["docker", "exec", container, "bash", "-c", f"cat /work/{testcase_name}"],
        capture_output=True,
        timeout=10,
    )
    if result.returncode != 0 or not result.stdout:
        return False
    out.write_bytes(result.stdout)
    return True


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
    # Pre-compute file sets (testcase-only bugs have no files)
    for bd in bug_diffs:
        bd["_files"] = files_in_diff(bd["diff_path"]) if bd.get("diff_path") else set()

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
            f"annotate('{_source_dir(project)}/{fpath}', {blocks_repr}, "
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

_DISPATCH_HEADER_TEMPLATE = """\
#ifndef __BUG_DISPATCH_H
#define __BUG_DISPATCH_H
#include <stdint.h>
#define __BUG_DISPATCH_BYTES {dispatch_bytes}
extern volatile uint8_t __bug_dispatch[__BUG_DISPATCH_BYTES];
#endif
"""

_DISPATCH_SOURCE = """\
#include "__bug_dispatch.h"
volatile uint8_t __bug_dispatch[__BUG_DISPATCH_BYTES] = {0};
"""

_MAX_STEP_RETRIES = 1


def _inject_dispatch_files(
    container: str, project: str, dispatch_bytes: int = 1,
) -> None:
    """Create __bug_dispatch.h and __bug_dispatch.c in the source dir."""
    header = _DISPATCH_HEADER_TEMPLATE.format(dispatch_bytes=dispatch_bytes)
    src = _source_dir(project)
    for fname, content in (("__bug_dispatch.h", header),
                           ("__bug_dispatch.c", _DISPATCH_SOURCE)):
        _exec_capture(
            container,
            f"cat > {src}/{fname} << 'DISPATCH_EOF'\n{content}DISPATCH_EOF",
        )
    logger.info("Injected __bug_dispatch.h/.c into /src/%s (bytes=%d)",
                project, dispatch_bytes)


def _apply_all_dispatch_bytes(
    container: str,
    dispatch_state: dict,
) -> None:
    """Prepend dispatch bytes to PoCs in /work/.

    This must NOT clobber patched testcases already restored into /work/.
    It is idempotent: if the testcase already begins with the expected
    dispatch prefix, it is left unchanged.
    """
    nbytes = dispatch_state.get("dispatch_bytes", 1)
    for bug_id, dval in dispatch_state["poc_bytes"].items():
        testcase = f"testcase-{bug_id}"
        # Serialize as little-endian: Python bit N → byte[N//8] bit N%8
        prefix = dval.to_bytes(nbytes, "little")
        prefix_list = ",".join(str(b) for b in prefix)
        _exec_capture(
            container,
            # If /work file doesn't exist yet, fall back to the staged testcase dir.
            f"if [ ! -f /work/{testcase} ]; then "
            f"cp {CONTAINER_TESTCASES_DIR}/{testcase} /work/{testcase} 2>/dev/null; fi; "
            f"python3 -c \""
            f"p=bytes([{prefix_list}]); "
            f"d=open('/work/{testcase}','rb').read(); "
            f"open('/work/{testcase}','wb').write(d if d.startswith(p) else (p+d))\"",
        )


def _ensure_dispatch_capacity(
    dispatch_state: dict,
    container: str,
    project: str,
) -> None:
    """Grow the dispatch byte array if next_bit exceeds current capacity."""
    needed = (dispatch_state["next_bit"] // 8) + 1
    current = dispatch_state.get("dispatch_bytes", 1)
    if needed <= current:
        return
    dispatch_state["dispatch_bytes"] = needed
    logger.info("Growing dispatch array: %d -> %d byte(s)", current, needed)
    _inject_dispatch_files(container, project, needed)
    _rebuild_and_apply_dispatch(container, project, dispatch_state)


def _modify_harness_for_dispatch(
    container: str,
    project: str,
    fuzzer: str,
    model: str | None = None,
) -> bool:
    """Use agent to modify the fuzz harness to consume a dispatch byte.

    Returns True if harness was modified and builds successfully.
    """
    sys.path.insert(0, str(SCRIPT_DIR))
    from bug_transplant import setup_codex_creds, build_codex_command

    setup_codex_creds(container)

    prompt = _load_prompt("harness_dispatch", project=project, fuzzer=fuzzer,
                          source_dir=_source_dir(project))
    agent_cmd = build_codex_command(prompt, model)

    logger.info("Invoking codex to modify harness for dispatch byte...")
    ret, output = _exec_capture(container, agent_cmd, timeout=1800)
    if ret != 0:
        logger.error("Harness modification agent failed (exit %d): %s",
                     ret, output[-500:] if output else "(no output)")
        return False

    ret, _ = _exec_capture(container, "cd /src && sudo -E compile 2>&1", timeout=300)
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
            docker_cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=timeout,
        )
        return result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {timeout}s"



def _restore_testcases(
    container: str, project: str, bugs: list[dict] | None = None,
) -> None:
    """Restore testcases to /work for the given bugs only.

    For each bug: use patched testcase from the per-bug output dir if it
    exists, otherwise copy the original from the staged testcase dir.
    If *bugs* is None, falls back to copying all testcases from that dir
    (legacy behavior).
    """
    if bugs is None:
        _exec_capture(
            container,
            f"cp {CONTAINER_TESTCASES_DIR}/testcase-* /work/ 2>/dev/null; true",
        )
        return

    bug_transplant_dir = DATA_DIR / "bug_transplant"
    for bug in bugs:
        tc_name = bug.get("testcase", f"testcase-{bug['bug_id']}")
        explicit_patched = bug.get("patched_testcase")
        if explicit_patched and Path(explicit_patched).is_file():
            subprocess.run(
                ["docker", "exec", "-i", container,
                 "bash", "-c", f"cat > /work/{tc_name}"],
                input=Path(explicit_patched).read_bytes(), timeout=10,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            continue
        # Check for patched testcase in per-bug output dir
        out_dir = bug_transplant_dir / f"{project}_{bug['bug_id']}"
        patched = None
        if out_dir.exists():
            for tc in out_dir.glob(f"{tc_name}*"):
                if tc.is_file() and tc.stat().st_size > 0:
                    patched = tc
                    break
        if patched:
            subprocess.run(
                ["docker", "exec", "-i", container,
                 "bash", "-c", f"cat > /work/{tc_name}"],
                input=patched.read_bytes(), timeout=10,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        else:
            # Copy original from the staged testcase dir.
            _exec_capture(container,
                          f"cp {CONTAINER_TESTCASES_DIR}/{tc_name} /work/{tc_name} 2>/dev/null; true")


def _rebuild_project_image(project: str, target_commit: str,
                           build_csv: str | None) -> str:
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
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        logger.error("fuzz_helper.py build_version failed (exit %d)", result.returncode)
        logger.error("Build output (last 40 lines):\n%s",
                      "\n".join(result.stdout.splitlines()[-40:]))
        sys.exit(1)
    logger.info("Project image built: gcr.io/oss-fuzz/%s", project)

    # Layer the agent CLI on top of the freshly built project image
    project_image = f"gcr.io/oss-fuzz/{project}"
    image_tag = build_agent_image(project, project_image)
    logger.info("Agent image built: %s", image_tag)
    return image_tag


def start_merge_container(
    project: str,
    target_commit: str,
    testcases_dir: str,
    build_csv: str | None = None,
    extra_volumes: list[str] | None = None,
) -> tuple[str, bool]:
    """Start a persistent container at the target commit for merging."""
    container_name = f"bug-merge-{project}"

    # Rebuild the project image from the historical OSS-Fuzz commit so the
    # container has the correct compiler, ASAN runtime, and base libraries.
    image_tag = _rebuild_project_image(project, target_commit, build_csv)

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
        "-e", "MAKEFLAGS=--output-sync=line",
        "-e", "CMAKE_BUILD_PARALLEL_LEVEL=30",
        "-e", "NINJA_STATUS=",
        "-e", "TERM=dumb",
        "-v", f"{data_dir}:/data",
        "-v", f"{os.path.abspath(testcases_dir)}:{CONTAINER_TESTCASES_DIR}",
        "-v", f"{out_dir}:/out",
        "-v", f"{work_dir}:/work",
    ]

    # Codex credentials for conflict resolution (login mode)
    sys.path.insert(0, str(SCRIPT_DIR))
    from bug_transplant import CODEX_CONFIG
    cred_dir = Path.home() / CODEX_CONFIG["credentials_dir"]
    if cred_dir.exists():
        docker_cmd += ["-v", f"{cred_dir}:/tmp/.agent-creds-src:ro"]

    api_key = os.environ.get(CODEX_CONFIG["api_key_env"], "")
    if api_key:
        docker_cmd += ["-e", f"{CODEX_CONFIG['api_key_env']}={api_key}"]

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
    _exec(container_name, f"cd {_source_dir(project)} && sudo git checkout -f {target_commit}", user="root")
    _exec(container_name, "sudo chown -R agent:agent /src/ /out/ /work/ 2>/dev/null || true", user="root")

    # Copy all testcases to /work from the staged testcase dir.
    _exec(
        container_name,
        f"cp {CONTAINER_TESTCASES_DIR}/testcase-* /work/ 2>/dev/null || true",
    )

    # Overwrite with patched testcases from transplant output dirs
    bug_transplant_dir = DATA_DIR / "bug_transplant"
    if bug_transplant_dir.exists():
        for d in bug_transplant_dir.iterdir():
            if not d.is_dir() or not d.name.startswith(f"{project}_"):
                continue
            for tc in d.glob("testcase-*"):
                if tc.is_file() and tc.stat().st_size > 0:
                    ret = subprocess.run(
                        ["docker", "exec", "-i", container_name,
                         "bash", "-c", f"cat > /work/{tc.name}"],
                        input=tc.read_bytes(), timeout=10,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    )
                    if ret.returncode == 0:
                        logger.info("Copied patched testcase: %s", tc.name)

    # Ghostscript: build.sh destructively does
    #   rm -rf freetype && mv /src/freetype freetype
    # which fails on repeated compiles.  Patch it to use cp instead of
    # mv so /src/freetype survives across builds.
    if project == "ghostscript":
        _exec_capture(
            container_name,
            r"""sed -i 's|^rm -rf freetype.*|rm -rf freetype 2>/dev/null; true|; """
            r"""s|^rm -rf zlib.*|rm -rf zlib 2>/dev/null; true|; """
            r"""s|^mv \$SRC/freetype freetype|if [ -d "$SRC/freetype" ]; then cp -a "$SRC/freetype" freetype; fi|' """
            "/src/build.sh",
        )

    # Build ASAN only (UBSAN removed to simplify the merge flow).
    logger.info("Building address inside container...")
    _exec_capture(
        container_name,
        f"cd {_source_dir(project)} && make clean 2>/dev/null; "
        f"rm -rf .obj *.a *.o 2>/dev/null; "
        f"rm -f /src/*.o 2>/dev/null; true",
    )
    ret, build_output = _exec_capture(
        container_name,
        "cd /src && sudo -E SANITIZER=address compile 2>&1",
        timeout=300,
    )
    if ret != 0:
        logger.error("ASAN build failed. Tail:")
        logger.error("%s", build_output[-500:] if build_output else "(no output)")
        return container_name, False
    # Stash ASAN binaries
    _exec_capture(
        container_name,
        "mkdir -p /out/address && "
        "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && "
        "cp \"$f\" /out/address/; done; true",
    )
    logger.info("Build OK for address")

    # Restore testcases (compile may wipe /work)
    _restore_testcases(container_name, project)

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
        f"cd {_source_dir(project)} && git apply --check /tmp/{diff_name} 2>&1",
    )
    if ret == 0:
        # Apply cleanly
        ret2, _ = _exec_capture(
            container,
            f"cd {_source_dir(project)} && git apply /tmp/{diff_name} 2>&1",
        )
        if ret2 == 0:
            return "clean"

    # Try 3-way merge
    ret, output = _exec_capture(
        container,
        f"cd {_source_dir(project)} && git apply --3way /tmp/{diff_name} 2>&1",
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
    model: str | None = None,
    conflicting_diffs: list[tuple[str, str]] | None = None,
    dispatch_bit: int | None = None,
    feedback: str | None = None,
    attempt: int = 0,
) -> str:
    """Use codex to resolve a merge conflict.

    When *conflicting_diffs* and *dispatch_bit* are provided, the agent is
    instructed to use input-driven dispatch branches for truly contradictory
    changes.

    Returns:
      ``"resolved"``  – combined without dispatch branches
      ``"dispatch"``  – dispatch branch(es) used
      ``"failed"``    – could not resolve
    """
    sys.path.insert(0, str(SCRIPT_DIR))
    from bug_transplant import setup_codex_creds, build_codex_command

    logger.info("[%s] Invoking codex to resolve conflict...", bug_id)
    setup_codex_creds(container)

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

    # Build the dispatch prompt. Conflict resolution always gets a dispatch
    # bit in this merge flow, but the prompt now asks the agent to dispatch
    # only the minimal conflicting logic rather than whole patches.
    if dispatch_bit is None:
        raise ValueError(
            f"[{bug_id}] dispatch_bit must be set for conflict resolution"
        )
    prompt = _load_prompt(
        "conflict_resolve_dispatch",
        project=project, applied_list=applied_list, diff_name=diff_name,
        bug_id=bug_id, conflict_desc=conflict_desc,
        dispatch_byte=dispatch_bit // 8, dispatch_bit=dispatch_bit % 8,
        source_dir=_source_dir(project),
    )
    if feedback:
        prompt += (
            "\n\nFeedback from a previous failed attempt on this step:\n"
            f"{feedback.strip()}\n"
        )

    _save_prompt_to_container(container, bug_id, "conflict_resolve", prompt, attempt)

    agent_cmd = build_codex_command(prompt, model)
    ret, output = _exec_capture(container, agent_cmd, timeout=1800)

    if ret != 0:
        logger.error("[%s] codex agent failed (exit %d): %s",
                     bug_id, ret, output[-500:] if output else "(no output)")
        return "failed"

    # Verify it compiles
    ret, _ = _exec_capture(container, "cd /src && sudo -E compile 2>&1", timeout=300)
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
    model: str | None = None,
    feedback: str | None = None,
    attempt: int = 0,
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
    from bug_transplant import setup_codex_creds, build_codex_command

    logger.info("[%s] Invoking codex to add dispatch branches (bit %d) "
                "for %d regressed bugs...",
                bug_id, dispatch_bit, len(regressed_bugs))

    setup_codex_creds(container)

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
        dispatch_byte=dispatch_bit // 8, dispatch_bit=dispatch_bit % 8,
        patch_list=patch_list,
    )
    if feedback:
        prompt += (
            "\n\nFeedback from a previous failed attempt on this step:\n"
            f"{feedback.strip()}\n"
        )

    _save_prompt_to_container(container, bug_id, "regression_dispatch", prompt, attempt)

    agent_cmd = build_codex_command(prompt, model)
    ret, output = _exec_capture(container, agent_cmd, timeout=1800)
    if ret != 0:
        logger.error("[%s] Dispatch agent failed (exit %d): %s",
                     bug_id, ret, output[-500:] if output else "(no output)")
        return False

    ret, _ = _exec_capture(container, "cd /src && sudo -E compile 2>&1", timeout=300)
    if ret != 0:
        logger.error("[%s] Build failed after dispatch resolution", bug_id)
        return False

    logger.info("[%s] Dispatch branches added (bit %d)", bug_id, dispatch_bit)
    return True


def _stage_untracked_source(container: str, project: str) -> None:
    """Mark untracked source files as intent-to-add so git diff includes them.

    Excludes build artifact directories (CMakeFiles, .obj, etc.) that
    contain generated .c/.h files which would break ``git apply`` on
    resume because they already exist in a fresh build.
    """
    _exec_capture(
        container,
        f"cd {_source_dir(project)} && "
        f"git ls-files --others --exclude-standard "
        f"'*.c' '*.h' '*.cc' '*.cpp' '*.cxx' '*.hpp' '*.hh' '*.hxx' "
        f"| grep -v -e 'CMakeFiles/' -e '\\.obj/' -e '^build/' "
        f"-e 'config\\.h$' -e 'cmake_install\\.cmake' "
        f"| xargs -r git add -N 2>/dev/null; true",
    )


def _save_prompt_to_container(
    container: str,
    bug_id: str,
    label: str,
    prompt: str,
    attempt: int = 0,
) -> None:
    """Save an agent prompt inside the container for debugging.

    Written to ``/tmp/prompt_{bug_id}_{label}_a{attempt}.txt`` so each
    retry attempt is preserved and can be inspected or copied out.
    """
    fname = f"prompt_{bug_id}_{label}_a{attempt}.txt"
    _exec_capture(
        container,
        f"cat > /tmp/{fname} << 'PROMPT_EOF'\n"
        f"{prompt}\nPROMPT_EOF",
    )


def _save_step_diff(
    container: str,
    project: str,
    target_commit: str,
    step_index: int,
    bug_id: str,
    suffix: str,
    step: dict,
) -> None:
    """Save a git diff snapshot for debugging.

    *suffix* distinguishes multiple snapshots within one step, e.g.
    ``apply``, ``conflict_dispatch``, ``regression_dispatch``,
    ``self_trigger_dispatch``.
    """
    step_dir = (DATA_DIR / "bug_transplant"
                / f"merge_{project}_{target_commit[:8]}" / "steps")
    step_dir.mkdir(parents=True, exist_ok=True)
    _stage_untracked_source(container, project)
    _, diff_text = _exec_capture(
        container, f"cd {_source_dir(project)} && git diff",
    )
    step_file = step_dir / f"step_{step_index+1:02d}_{bug_id}_{suffix}.diff"
    step_file.write_text(diff_text)
    step.setdefault("step_diffs", {})[suffix] = str(step_file)
    logger.info("[%s] Saved %s diff: %s (%d bytes)",
                bug_id, suffix, step_file, len(diff_text))

    # Copy all saved prompts from the container for this bug (all attempts)
    _, prompt_list = _exec_capture(
        container,
        f"ls /tmp/prompt_{bug_id}_*.txt 2>/dev/null || true",
    )
    for container_path in prompt_list.strip().splitlines():
        if not container_path:
            continue
        fname = container_path.split("/")[-1]
        host_path = step_dir / f"step_{step_index+1:02d}_{fname}"
        subprocess.call(
            ["docker", "cp", f"{container}:{container_path}", str(host_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )


def _save_step_state(
    project: str,
    target_commit: str,
    step_index: int,
    dispatch_state: dict,
    applied_bugs: list[str],
    merge_results: list[dict],
    all_verified_bug_ids: list[str],
) -> None:
    """Save merge state after each step so we can resume with --start-step."""
    step_dir = (DATA_DIR / "bug_transplant"
                / f"merge_{project}_{target_commit[:8]}" / "steps")
    step_dir.mkdir(parents=True, exist_ok=True)
    def _json_safe(obj):
        """Strip non-serializable fields (sets) from dicts."""
        if isinstance(obj, dict):
            return {k: _json_safe(v) for k, v in obj.items() if k != "_files"}
        if isinstance(obj, list):
            return [_json_safe(v) for v in obj]
        if isinstance(obj, set):
            return sorted(obj)
        return obj

    state = _json_safe({
        "step_index": step_index,
        "dispatch_state": dispatch_state,
        "applied_bugs": applied_bugs,
        "merge_results": merge_results,
        "all_verified_bug_ids": all_verified_bug_ids,
    })
    state_file = step_dir / f"step_{step_index+1:02d}_state.json"
    state_file.write_text(json.dumps(state, indent=2))
    logger.debug("Saved step state: %s", state_file)


def _load_step_state(
    project: str,
    target_commit: str,
    step_index: int,
) -> dict | None:
    """Load merge state saved after a completed step."""
    step_dir = (DATA_DIR / "bug_transplant"
                / f"merge_{project}_{target_commit[:8]}" / "steps")
    state_file = step_dir / f"step_{step_index+1:02d}_state.json"
    if not state_file.exists():
        logger.error("Step state file not found: %s", state_file)
        return None
    return json.loads(state_file.read_text())


def _find_step_apply_diff(
    project: str,
    target_commit: str,
    step_index: int,
) -> Path | None:
    """Find the apply diff for a given step (the cumulative source snapshot)."""
    step_dir = (DATA_DIR / "bug_transplant"
                / f"merge_{project}_{target_commit[:8]}" / "steps")
    # Look for the latest diff variant for this step.
    # Order: regression_dispatch is the final state (after regressions
    # are fixed), self_trigger_dispatch is after self-trigger unblock,
    # conflict_dispatch after conflict resolution, apply is the initial.
    for suffix in ("regression_dispatch", "self_trigger_dispatch",
                   "conflict_dispatch", "apply"):
        p = step_dir / f"step_{step_index+1:02d}_*_{suffix}.diff"
        matches = sorted(step_dir.glob(f"step_{step_index+1:02d}_*_{suffix}.diff"))
        if matches:
            return matches[-1]
    return None


def _save_source_snapshot(container: str, project: str) -> None:
    """Save the current source state as a diff for rollback.

    Uses ``git add -N`` to mark untracked source files as intent-to-add,
    then ``git diff`` captures both tracked modifications and new files.
    """
    _stage_untracked_source(container, project)
    _exec_capture(
        container,
        f"cd {_source_dir(project)} && git diff > /tmp/_snap.diff 2>&1",
    )


def _revert_and_rebuild(
    container: str,
    project: str,
    applied_bugs: list[str],
    ordered: list[dict],
    dispatch_state: dict,
) -> None:
    """Restore source to the pre-step snapshot and rebuild.

    Used when a patch must be rolled back (build failure, self-trigger
    failure, etc.) to restore the source tree to the state before the
    failed step was attempted.
    """
    # Discard failed step's changes and clean up intent-to-add entries
    _exec_capture(
        container,
        f"cd {_source_dir(project)} && git checkout -- . 2>&1",
    )
    _exec_capture(
        container,
        f"cd {_source_dir(project)} && git reset 2>&1",
    )
    _exec_capture(
        container,
        f"cd {_source_dir(project)} && git clean -fd 2>&1",
    )
    # Re-apply the snapshot diff (includes new files via intent-to-add)
    _exec_capture(
        container,
        f"cd {_source_dir(project)} && git apply --allow-empty /tmp/_snap.diff 2>&1",
    )
    _exec_capture(
        container,
        f"cd {_source_dir(project)} && make clean 2>/dev/null; "
        f"rm -rf .obj *.a *.o 2>/dev/null; "
        f"rm -f /src/*.o 2>/dev/null; true",
    )
    _exec_capture(
        container, "sudo -E SANITIZER=address compile 2>&1", timeout=300,
    )
    _exec_capture(
        container,
        "mkdir -p /out/address && "
        "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && "
        "cp \"$f\" /out/address/; done; true",
    )
    _restore_testcases(container, project)
    if dispatch_state["poc_bytes"]:
        _apply_all_dispatch_bytes(container, dispatch_state)


def _rebuild_and_apply_dispatch(
    container: str,
    project: str,
    dispatch_state: dict,
) -> None:
    """Rebuild ASAN and re-apply dispatch bytes after code changes."""
    _exec_capture(
        container,
        f"cd {_source_dir(project)} && make clean 2>/dev/null; "
        f"rm -rf .obj *.a *.o 2>/dev/null; "
        f"rm -f /src/*.o 2>/dev/null; true",
    )
    _exec_capture(
        container,
        "cd /src && sudo -E SANITIZER=address compile 2>&1",
        timeout=300,
    )
    _exec_capture(
        container,
        "mkdir -p /out/address && "
        "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && "
        "cp \"$f\" /out/address/; done; true",
    )
    _restore_testcases(container, project)
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
    model: str | None = None,
    feedback: str | None = None,
    attempt: int = 0,
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
    from bug_transplant import setup_codex_creds, build_codex_command

    logger.info("[%s] Invoking codex to unblock self-trigger (bit %d), "
                "analyzing %d previous patches...",
                bug_id, dispatch_bit, len(applied_bugs_data))

    setup_codex_creds(container)

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
        prev_list=prev_list,
        dispatch_byte=dispatch_bit // 8, dispatch_bit=dispatch_bit % 8,
    )
    if feedback:
        prompt += (
            "\n\nFeedback from a previous failed attempt on this step:\n"
            f"{feedback.strip()}\n"
        )

    _save_prompt_to_container(container, bug_id, "self_trigger_dispatch", prompt, attempt)

    agent_cmd = build_codex_command(prompt, model)
    ret, output = _exec_capture(container, agent_cmd, timeout=1800)
    if ret != 0:
        logger.error("[%s] Self-trigger dispatch agent failed (exit %d): %s",
                     bug_id, ret, output[-500:] if output else "(no output)")
        return False

    ret, _ = _exec_capture(container, "cd /src && sudo -E compile 2>&1", timeout=300)
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


def _top_app_stack_frame(crash_log_path: str | None) -> str:
    """Return the first non-sanitizer stack frame from a crash log."""
    if not crash_log_path:
        return "unknown"
    san_re = re.compile(
        r'^(__asan|__lsan|__tsan|__msan|__ubsan|__sanitizer|__interception)',
    )
    for frame in _extract_stack_from_file(crash_log_path):
        if not san_re.match(frame):
            return frame
    return "unknown"


def _extract_diff_functions(diff_text: str) -> set[str]:
    """Extract function names from diff @@ context lines."""
    return set(re.findall(r'@@[^@]*@@\s*(?:\w+\s+)*(\w+)\s*\(', diff_text))


def _diagnose_self_trigger_failure(
    container: str,
    project: str,
    bug_id: str,
    crash_log: str | None,
    applied_bugs_data: list[dict],
    current_bug_data: dict | None = None,
) -> str:
    """Identify which previous patches likely block the testcase.

    Cross-references the crash path functions (then files as fallback)
    with each previously-applied patch.
    """
    # Get crash path functions
    crash_funcs = set()
    san_re = re.compile(
        r'^(__asan|__lsan|__tsan|__msan|__ubsan|__sanitizer|__interception)',
    )
    if crash_log:
        crash_funcs = {
            f for f in _extract_stack_from_file(crash_log)
            if not san_re.match(f)
        }
    crash_path_str = " → ".join(list(crash_funcs)[:6]) if crash_funcs else "unknown"

    # What the agent changed this attempt
    _, diff_stat = _exec_capture(
        container, f"cd {_source_dir(project)} && git diff --stat 2>/dev/null",
    )

    # Files the current bug's standalone patch touches
    bug_files: set[str] = set()
    if current_bug_data:
        bug_files = files_in_diff(current_bug_data.get("diff_path", ""))

    lines = [
        f"Result: Bug {bug_id} did not crash.",
        f"Expected crash path: {crash_path_str}",
        "",
        "What you changed (git diff --stat):",
        f"  {diff_stat.strip() if diff_stat else '(no changes)'}",
    ]

    # Try function-level matching first
    func_blockers = []
    file_blockers = []
    for pb in applied_bugs_data:
        diff_path = pb.get("diff_path")
        if not diff_path:
            continue
        try:
            diff_text = Path(diff_path).read_text(errors="replace")
        except OSError:
            continue
        diff_funcs = _extract_diff_functions(diff_text)
        func_overlap = crash_funcs & diff_funcs
        if func_overlap:
            func_blockers.append((pb["bug_id"], "functions", sorted(func_overlap)))
        else:
            # File-level fallback: does this patch touch the same files
            # as the current bug's patch?
            pb_files = files_in_diff(diff_path)
            file_overlap = bug_files & pb_files
            if file_overlap:
                file_blockers.append((pb["bug_id"], "files", sorted(file_overlap)))

    blockers = func_blockers or file_blockers
    if blockers:
        match_type = "crash-path functions" if func_blockers else "same files as this bug's patch"
        lines.append("")
        lines.append(f"Likely blockers (previous patches touching {match_type}):")
        for pb_id, kind, items in blockers:
            lines.append(f"  - {pb_id}: {kind}: {', '.join(items)}")
        lines.append("")
        lines.append("Action: check these patches' changes and dispatch any "
                      "that block the testcase from reaching the crash site.")
    else:
        lines.append("")
        lines.append("No specific blocker identified by function or file overlap.")
        lines.append("Action: run `git diff` and check every change in the "
                      "testcase's code path for early returns or validation "
                      "that rejects the input before the crash site.")

    return "\n".join(lines)


def _diagnose_regression(
    container: str,
    project: str,
    bug_id: str,
    regressed_bugs_data: list[dict],
) -> str:
    """For each regressed bug, identify what the agent likely broke.

    Runs each regressed bug's testcase to see current behavior, and
    finds which files the agent changed that overlap with the regressed
    bug's patch.
    """
    # Get files the agent changed
    _, agent_names = _exec_capture(
        container, f"cd {_source_dir(project)} && git diff --name-only 2>/dev/null",
    )
    agent_files = set(agent_names.strip().splitlines()) if agent_names else set()

    lines = [f"Result: {len(regressed_bugs_data)} bug(s) regressed."]

    for rb in regressed_bugs_data:
        rb_id = rb["bug_id"]
        lines.append("")
        lines.append(f"{rb_id}:")

        # Run regressed bug's testcase to see current behavior
        fuzzer_path = f"/out/address/{rb['fuzzer']}"
        _, output = _exec_capture(
            container,
            f"{fuzzer_path} /work/{rb['testcase']} 2>&1 | tail -5",
            timeout=30,
        )
        tail = output.strip().splitlines()[-2:] if output else ["unknown"]
        lines.append(f"  Now: {' | '.join(tail)}")

        # Expected behavior from crash log
        top_frame = _top_app_stack_frame(rb.get("crash_log"))
        lines.append(f"  Expected crash in: {top_frame}")

        # Find overlapping files
        rb_files = files_in_diff(rb.get("diff_path", ""))
        overlap = agent_files & rb_files
        if overlap:
            lines.append(f"  Your changes overlap with this bug in: {', '.join(sorted(overlap))}")
            lines.append(f"  → Wrap your changes in these files with dispatch branches.")
        else:
            lines.append(f"  No direct file overlap found — check indirect effects.")

    return "\n".join(lines)


def _build_step_feedback(
    failure_type: str,
    bug_id: str,
    container: str,
    project: str,
    crash_log: str | None = None,
    build_output: str | None = None,
    regressed_bugs_data: list[dict] | None = None,
    applied_bugs_data: list[dict] | None = None,
    current_bug_data: dict | None = None,
) -> str:
    """Build diagnostic feedback for the agent about a failed step attempt.

    *failure_type* is one of ``"build"``, ``"self_trigger"``, ``"regression"``.
    """
    lines = [f"Previous attempt for {bug_id} failed.", ""]

    if failure_type == "build":
        lines.append("Result: Build failed.")
        if build_output:
            tail_lines = build_output.strip().splitlines()[-15:]
            tail = "\n".join(f"  {l}" for l in tail_lines)
            lines.append(f"Build error tail:\n{tail}")

    elif failure_type == "self_trigger":
        diag = _diagnose_self_trigger_failure(
            container, project, bug_id, crash_log,
            applied_bugs_data or [],
            current_bug_data=current_bug_data,
        )
        lines.append(diag)

    elif failure_type == "regression":
        diag = _diagnose_regression(
            container, project, bug_id,
            regressed_bugs_data or [],
        )
        lines.append(diag)

    return "\n".join(lines)


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


_VERIFY_ATTEMPTS = 10


def verify_bug_triggers(
    container: str,
    bug_id: str,
    fuzzer: str,
    testcase: str,
    sanitizer: str = "address",
    crash_log: str | None = None,
) -> bool:
    """Run the fuzzer binary for the given sanitizer and check for a crash.

    Retries up to ``_VERIFY_ATTEMPTS`` times to handle non-deterministic
    bugs (same approach as ``fuzz_helper.py reproduce`` which uses
    ``-runs=10``).  Returns True as soon as any attempt detects the crash.

    If *crash_log* is provided, extracts the reference stack from it and
    compares against the fuzzer output using LCS matching.  Otherwise
    falls back to checking for any sanitizer SUMMARY line.
    """
    sym_path = "/out/llvm-symbolizer"
    env_prefix = f"export ASAN_OPTIONS=detect_leaks=0:detect_stack_use_after_return=1:max_uar_stack_size_log=16:external_symbolizer_path={sym_path}; "
    fuzzer_path = f"/out/{sanitizer}/{fuzzer}"

    ref_stack = None
    if crash_log:
        ref_stack = _extract_stack_from_file(crash_log)

    for attempt in range(_VERIFY_ATTEMPTS):
        cmd = (
            f"{env_prefix}"
            f"if [ ! -x {fuzzer_path} ]; then "
            f"echo 'ERROR: {fuzzer_path} not found'; exit 99; fi; "
            f"{fuzzer_path} -runs=10 /work/{testcase} 2>&1"
        )
        logger.debug("[%s] verify cmd (attempt %d/%d): %s",
                     bug_id, attempt + 1, _VERIFY_ATTEMPTS, cmd)
        ret, output = _exec_capture(container, cmd, timeout=120)
        logger.debug("[%s] verify exit=%d output_len=%d tail=%.500s",
                     bug_id, ret, len(output), output[-500:] if output else "(empty)")

        # Extract current stack from fuzzer output
        current_stack = _extract_stack_from_text(output)

        # If we have a reference crash log, compare stacks
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
                elif attempt == _VERIFY_ATTEMPTS - 1:
                    logger.warning("[%s] Stack comparison inconclusive (exit=%d)", bug_id, ret)
                # Fall through to SUMMARY check instead of returning False —
                # unsymbolized stacks can't match symbolized references, but
                # the bug may still be triggering.

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

        if attempt < _VERIFY_ATTEMPTS - 1:
            logger.debug("[%s] No crash on attempt %d/%d, retrying...",
                         bug_id, attempt + 1, _VERIFY_ATTEMPTS)

    logger.warning("[%s] Bug does NOT trigger after %d attempts (exit=%d)",
                   bug_id, _VERIFY_ATTEMPTS, ret)
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
        if sanitizer != "address":
            logger.info("Skipping %s local bug %s (non-ASAN)", sanitizer, bug_id)
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
    # A transplanted bug has either a non-empty diff, a patched testcase, or both.
    # Testcase-only transplants (empty diff + patched testcase) are included
    # and skip the diff-apply step during merge.
    transplant_diffs: list[dict] = []
    seen_bug_ids: set[str] = set()
    bug_transplant_dir = DATA_DIR / "bug_transplant"

    def _load_transplant_bug(bug_id: str, diff_path: str | None, source: str):
        """Helper to build a transplant entry from a bug's output directory."""
        if bug_id in seen_bug_ids or bug_id in local_bug_ids:
            return
        out_dir = bug_transplant_dir / f"{project}_{bug_id}"

        # Skip impossible bugs
        if out_dir.exists() and (out_dir / "bug_transplant.impossible").exists():
            logger.info("Skipping %s: declared impossible", bug_id)
            return

        # Find diff (may be empty for testcase-only transplants)
        if not diff_path or not Path(diff_path).exists():
            if out_dir.exists():
                for name in ("bug_transplant.diff", "git_diff.diff"):
                    p = out_dir / name
                    if p.exists():
                        diff_path = str(p)
                        break

        # Find patched testcase in output dir
        patched_testcase = None
        if out_dir.exists():
            for tc in out_dir.glob(f"testcase-{bug_id}*"):
                if tc.is_file() and tc.stat().st_size > 0:
                    patched_testcase = str(tc)
                    break

        # Need at least a non-empty diff OR a patched testcase
        has_diff = diff_path and Path(diff_path).exists() and Path(diff_path).stat().st_size > 0
        if not has_diff and not patched_testcase:
            return

        info = bug_info_dataset.get(bug_id, {})
        reproduce = info.get("reproduce", {})
        fuzzer = reproduce.get("fuzz_target", "")
        sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
        if sanitizer != "address":
            logger.info("Skipping %s transplant bug %s (non-ASAN)", sanitizer, bug_id)
            return
        crash_log = _find_crash_log(bug_id, info)
        seen_bug_ids.add(bug_id)
        entry = {
            "bug_id": bug_id,
            "diff_path": diff_path if has_diff else None,
            "patched_testcase": patched_testcase,
            "fuzzer": fuzzer,
            "testcase": f"testcase-{bug_id}",
            "sanitizer": sanitizer,
            "crash_log": crash_log,
            "type": "transplant",
            "testcase_only": not has_diff,
        }
        logger.info("Found %s for %s: diff=%s testcase=%s (%s)",
                     source, bug_id,
                     "yes" if has_diff else "empty",
                     "patched" if patched_testcase else "original",
                     "testcase-only" if not has_diff else "with-diff")
        transplant_diffs.append(entry)

    # From summary results
    for result in summary.get("results", []):
        bug_id = result.get("bug_id", "")
        if not bug_id:
            continue
        if result.get("status") not in (None, "success"):
            logger.info("Skipping %s: status=%s", bug_id, result.get("status"))
            continue
        _load_transplant_bug(bug_id, result.get("diff_path"), "summary")

    # Scan disk for any bug dirs not yet loaded
    if bug_transplant_dir.exists():
        for d in bug_transplant_dir.iterdir():
            if not d.is_dir() or not d.name.startswith(f"{project}_"):
                continue
            bug_id = d.name[len(f"{project}_"):]
            _load_transplant_bug(bug_id, None, "disk")

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

    testcase_names = [bug["testcase"] for bug in (local_bugs + transplant_diffs)]
    output_dir = DATA_DIR / "bug_transplant" / f"merge_{project}_{target_commit[:8]}"
    testcase_stage_dir = _prepare_container_testcases_dir(
        args.testcases_dir,
        output_dir / "testcases",
        testcase_names=testcase_names,
    )

    # ------------------------------------------------------------------
    # 4. Start container and run merge
    # ------------------------------------------------------------------
    container, build_ok = start_merge_container(
        project, target_commit, str(testcase_stage_dir),
        build_csv=args.build_csv,
        extra_volumes=args.volume,
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
        "dispatch_bytes": 1,           # current __bug_dispatch[] array size
        "bits": {},                    # {bit_index: {bug_new, bug_existing}}
        "poc_bytes": {},               # {bug_id: int} dispatch bitmask per bug
        "harness_modified": False,     # dispatch byte consumption in harness
        "dispatch_file_injected": False,  # __bug_dispatch.h/.c created
    }
    start_step = getattr(args, "start_step", None)  # 1-based from CLI

    try:
        # ------------------------------------------------------------------
        # 5. Restore state if --start-step, else verify local bugs
        # ------------------------------------------------------------------
        if start_step and start_step > 1:
            prev_idx = start_step - 2  # 0-based index of the step to restore
            logger.info("=== Restoring state from step %d ===", start_step - 1)

            # Load saved state
            saved = _load_step_state(project, target_commit, prev_idx)
            if saved is None:
                logger.error("Cannot resume: no state file for step %d", start_step - 1)
                return 1

            # Find and apply the cumulative diff
            diff_path = _find_step_apply_diff(project, target_commit, prev_idx)
            if diff_path is None:
                logger.error("Cannot resume: no apply diff for step %d", start_step - 1)
                return 1

            logger.info("Applying cumulative diff: %s", diff_path)

            # Copy diff into container via docker cp and apply
            subprocess.call(
                ["docker", "cp", str(diff_path),
                 f"{container}:/tmp/_resume.diff"],
            )
            ret, out = _exec_capture(
                container,
                f"cd {_source_dir(project)} && git apply /tmp/_resume.diff",
            )
            if ret != 0:
                logger.error("Failed to apply resume diff: %s", out[-500:] if out else "")
                return 1

            # Restore dispatch_state
            dispatch_state = saved["dispatch_state"]
            # Handle selector-format state (from newer code version)
            if "dispatches" in dispatch_state and "bits" not in dispatch_state:
                dispatch_state["bits"] = {
                    int(k): v for k, v in dispatch_state["dispatches"].items()
                }
                dispatch_state["next_bit"] = dispatch_state.pop("next_selector", 0)
                dispatch_state.pop("dispatches", None)
                dispatch_state.pop("bug_selectors", None)
                dispatch_state.pop("dispatch_mode", None)
            else:
                # Convert string keys back to int for bits dict
                dispatch_state["bits"] = {
                    int(k): v for k, v in dispatch_state["bits"].items()
                }
            applied_bugs = saved["applied_bugs"]
            merge_results = saved["merge_results"]

            # Re-inject dispatch files if they were used (with correct size)
            if dispatch_state.get("dispatch_file_injected"):
                dbytes = dispatch_state.get("dispatch_bytes", 1)
                _inject_dispatch_files(container, project, dbytes)

            # Rebuild all_verified_bugs from saved IDs
            saved_ids = set(saved["all_verified_bug_ids"])
            for lb in local_bugs:
                if lb["bug_id"] in saved_ids:
                    all_verified_bugs.append(lb)
            for bd in ordered:
                if bd["bug_id"] in saved_ids and bd["bug_id"] not in {
                    lb["bug_id"] for lb in local_bugs
                }:
                    all_verified_bugs.append(bd)

            # Rebuild ASAN and set up dispatch bytes
            logger.info("Rebuilding from restored state...")
            _exec_capture(
                container,
                f"cd {_source_dir(project)} && make clean 2>/dev/null; "
                f"rm -rf .obj *.a *.o 2>/dev/null; "
                f"rm -f /src/*.o 2>/dev/null; true",
            )
            ret, bout = _exec_capture(
                container,
                "cd /src && sudo -E SANITIZER=address compile 2>&1", timeout=300,
            )
            if ret != 0:
                logger.error("Build failed for address after restore: %s",
                             bout[-500:] if bout else "")
                return 1
            _exec_capture(
                container,
                "mkdir -p /out/address && "
                "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && "
                "cp \"$f\" /out/address/; done; true",
            )
            _exec_capture(container,
                          f"cp {CONTAINER_TESTCASES_DIR}/testcase-* /work/ 2>/dev/null; true")
            _restore_testcases(container, project)
            if dispatch_state["poc_bytes"]:
                _apply_all_dispatch_bytes(container, dispatch_state)

            logger.info("Restored: %d applied bugs, dispatch next_bit=%d (%d byte(s))",
                        len(applied_bugs), dispatch_state["next_bit"],
                        dispatch_state.get("dispatch_bytes", 1))
        else:
            if local_bugs:
                logger.info("=== Verifying %d local bugs at baseline ===",
                            len(local_bugs))
                baseline = verify_all_bugs(container, local_bugs)
                for bug_id, ok in baseline.items():
                    if ok:
                        all_verified_bugs.append(
                            next(lb for lb in local_bugs
                                 if lb["bug_id"] == bug_id)
                        )
                    else:
                        logger.warning(
                            "Local bug %s does NOT trigger at baseline",
                            bug_id)

        # ------------------------------------------------------------------
        # 6. Apply transplant diffs incrementally
        # ------------------------------------------------------------------
        max_steps = getattr(args, "max_steps", None)
        skip_until = (start_step - 1) if start_step else 0  # 0-based
        for i, bd in enumerate(ordered):
            if i < skip_until:
                continue
            if max_steps is not None and i >= max_steps:
                logger.info("Reached --max-steps %d, stopping early", max_steps)
                break
            bug_id = bd["bug_id"]
            diff_path = bd.get("diff_path")
            is_testcase_only = bd.get("testcase_only", False)
            logger.info(
                "\n\n=== Step %d/%d: %s %s ===", i + 1, len(ordered),
                "Registering (testcase-only)" if is_testcase_only else "Applying",
                bug_id,
            )

            # Save source snapshot before this step (for rollback)
            _save_source_snapshot(container, project)
            dispatch_state_before_step = copy.deepcopy(dispatch_state)
            step_feedback = None
            retry_count = 0

            while True:  # retry loop
                if retry_count > 0:
                    logger.info(
                        "[%s] Retrying step with feedback (%d/%d)...",
                        bug_id, retry_count, _MAX_STEP_RETRIES,
                    )
                    dispatch_state = copy.deepcopy(dispatch_state_before_step)
                    _revert_and_rebuild(
                        container, project, applied_bugs, ordered,
                        dispatch_state,
                    )

                step = {
                    "step": i + 1,
                    "bug_id": bug_id,
                    "diff_path": diff_path,
                    "apply_method": None,
                    "build_ok": False,
                    "self_triggers": False,
                    "regressions": [],
                }
                step_regression_failures = []

                # --- Testcase-only bugs: no diff to apply ---
                if is_testcase_only:
                    step["apply_method"] = "testcase_only"
                    logger.info("[%s] Testcase-only transplant — no diff to apply", bug_id)
                    # Copy patched testcase into container
                    ptc = bd.get("patched_testcase")
                    if ptc and Path(ptc).exists():
                        tc_data = Path(ptc).read_bytes()
                        subprocess.run(
                            ["docker", "exec", "-i", container,
                             "bash", "-c", f"cat > /work/{bd['testcase']}"],
                            input=tc_data, timeout=10,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                    # Skip directly to build + verify (no diff apply or conflict resolution)
                    # Build is already done from previous step; just verify
                    step["build_ok"] = True
                    # Check if bug triggers
                    triggers = verify_bug_triggers(
                        container, bug_id, bd["fuzzer"],
                        bd["testcase"],
                        bd.get("sanitizer", "address"),
                        bd.get("crash_log"),
                    )
                    step["self_triggers"] = triggers
                    if triggers:
                        logger.info("[%s] Testcase-only bug triggers OK", bug_id)
                        applied_bugs.append(bug_id)
                        all_verified_bugs.append(bd)
                    else:
                        logger.warning("[%s] Testcase-only bug does NOT trigger", bug_id)
                    merge_results.append(step)
                    _save_step_state(
                        project, target_commit, i, dispatch_state,
                        applied_bugs, merge_results,
                        [b["bug_id"] for b in all_verified_bugs],
                    )
                    break  # exit retry loop

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
                        _inject_dispatch_files(container, project, dispatch_state.get("dispatch_bytes", 1))
                        dispatch_state["dispatch_file_injected"] = True

                    _ensure_dispatch_capacity(dispatch_state, container, project)
                    bit_index = dispatch_state["next_bit"]

                    result = resolve_conflict_with_agent(
                        container, diff_path, bug_id, project,
                        applied_bugs, args.model,
                        conflicting_diffs=conflicting_info,
                        dispatch_bit=bit_index,
                        feedback=step_feedback,
                        attempt=retry_count,
                    )

                    if result == "dispatch":
                        _save_step_diff(container, project, target_commit,
                                        i, bug_id, "conflict_dispatch", step)
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
                                args.model,
                            )
                            if ok:
                                dispatch_state["harness_modified"] = True
                            else:
                                logger.error("[%s] Harness modification failed", bug_id)
                                step["apply_method"] = "failed"
                                dispatch_state = copy.deepcopy(dispatch_state_before_step)
                                _revert_and_rebuild(
                                    container, project, applied_bugs, ordered,
                                    dispatch_state,
                                )
                                merge_results.append(step)
                                break

                    elif result == "resolved":
                        step["apply_method"] = "agent_resolved"
                    else:
                        # Conflict resolution failed — retry or give up
                        if retry_count < _MAX_STEP_RETRIES:
                            step_feedback = _build_step_feedback(
                                "build", bug_id, container, project,
                                build_output="Conflict resolution failed",
                            )
                            retry_count += 1
                            continue
                        step["apply_method"] = "failed"
                        logger.error("[%s] Could not resolve conflict, skipping", bug_id)
                        dispatch_state = copy.deepcopy(dispatch_state_before_step)
                        _revert_and_rebuild(
                            container, project, applied_bugs, ordered,
                            dispatch_state,
                        )
                        merge_results.append(step)
                        break

                # --- Build ASAN ---
                logger.info("[%s] Building (ASAN)...", bug_id)
                build_failed = False
                last_build_output = ""
                _exec_capture(
                    container,
                    f"cd {_source_dir(project)} && make clean 2>/dev/null; "
                    f"rm -rf .obj *.a *.o 2>/dev/null; "
                    f"rm -f /src/*.o 2>/dev/null; true",
                )
                ret, build_output = _exec_capture(
                    container, "sudo -E SANITIZER=address compile 2>&1", timeout=300,
                )
                if ret != 0:
                    logger.error("[%s] Build failed for address. Tail:", bug_id)
                    logger.error("%s", build_output[-500:] if build_output else "(no output)")
                    build_failed = True
                    last_build_output = build_output or ""
                if not build_failed:
                    _exec_capture(
                        container,
                        "mkdir -p /out/address && "
                        "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && "
                        "cp \"$f\" /out/address/; done; true",
                    )
                # Restore testcases (compile may wipe /work)
                _restore_testcases(container, project)
                if dispatch_state["poc_bytes"]:
                    _apply_all_dispatch_bytes(container, dispatch_state)

                # Save per-step diff snapshot for debugging
                if not build_failed:
                    _save_step_diff(container, project, target_commit,
                                    i, bug_id, "apply", step)

                step["build_ok"] = not build_failed
                if build_failed:
                    # Retry build failure only if conflict resolution was used
                    if (retry_count < _MAX_STEP_RETRIES
                            and method == "conflict"):
                        step_feedback = _build_step_feedback(
                            "build", bug_id, container, project,
                            build_output=last_build_output,
                        )
                        logger.warning(
                            "[%s] Build failed after conflict resolution, retrying",
                            bug_id,
                        )
                        retry_count += 1
                        continue
                    logger.error("[%s] Build failed after applying diff, reverting", bug_id)
                    dispatch_state = copy.deepcopy(dispatch_state_before_step)
                    _revert_and_rebuild(
                        container, project, applied_bugs, ordered,
                        dispatch_state,
                    )
                    merge_results.append(step)
                    break

                # --- Verify this bug triggers ---
                logger.info("[%s] Verifying self-trigger...", bug_id)
                step["self_triggers"] = verify_bug_triggers(
                    container, bug_id, bd["fuzzer"], bd["testcase"],
                    bd.get("sanitizer", "address"),
                    bd.get("crash_log"),
                )

                # --- If self-trigger fails, try dispatch to unblock ---
                if not step["self_triggers"] and applied_bugs:
                    # Skip bugs whose changes are already fully dispatched
                    # (gated behind a dispatch bit), since they can't block
                    # the default code path.
                    dispatched_bugs = {
                        info["bug_new"]
                        for info in dispatch_state["bits"].values()
                    }
                    undispatched = [
                        pid for pid in applied_bugs
                        if pid not in dispatched_bugs
                    ]
                    if not undispatched:
                        logger.info(
                            "[%s] Self-trigger failed but all %d previous "
                            "patches are already dispatched — skipping "
                            "self-trigger dispatch (patch itself likely bad)",
                            bug_id, len(applied_bugs),
                        )
                    else:
                        logger.info(
                            "[%s] Self-trigger failed — attempting dispatch to "
                            "unblock from %d previous patches "
                            "(%d already dispatched, skipped)...",
                            bug_id, len(undispatched),
                            len(applied_bugs) - len(undispatched),
                        )

                    if undispatched:
                        if not dispatch_state["dispatch_file_injected"]:
                            _inject_dispatch_files(container, project, dispatch_state.get("dispatch_bytes", 1))
                            dispatch_state["dispatch_file_injected"] = True

                        _ensure_dispatch_capacity(dispatch_state, container, project)
                        bit_index = dispatch_state["next_bit"]
                        prev_bugs_data = [
                            next(d for d in ordered if d["bug_id"] == pid)
                            for pid in undispatched
                        ]

                        dispatch_ok = resolve_self_trigger_with_dispatch(
                            container, bug_id, project,
                            prev_bugs_data, bd.get("crash_log"),
                            bd["diff_path"], bit_index,
                            model=args.model,
                            feedback=step_feedback,
                            attempt=retry_count,
                        )

                        if dispatch_ok:
                            if not dispatch_state["harness_modified"]:
                                hok = _modify_harness_for_dispatch(
                                    container, project, bd["fuzzer"],
                                    args.model,
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
                                    "bug_blocked_by": list(undispatched),
                                    "type": "self_trigger_unblock",
                                }
                                dispatch_state["poc_bytes"].setdefault(bug_id, 0)
                                dispatch_state["poc_bytes"][bug_id] |= (1 << bit_index)
                                dispatch_state["next_bit"] += 1

                                _rebuild_and_apply_dispatch(
                                    container, project, dispatch_state)
                                _save_step_diff(container, project, target_commit,
                                                i, bug_id, "self_trigger_dispatch", step)

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

                # --- If still can't self-trigger, retry or revert ---
                if not step["self_triggers"]:
                    if retry_count < _MAX_STEP_RETRIES:
                        prev_data = [
                            next(d for d in ordered if d["bug_id"] == pid)
                            for pid in applied_bugs
                        ]
                        step_feedback = _build_step_feedback(
                            "self_trigger", bug_id, container, project,
                            crash_log=bd.get("crash_log"),
                            applied_bugs_data=prev_data,
                            current_bug_data=bd,
                        )
                        logger.warning(
                            "[%s] Self-trigger failed, retrying step", bug_id,
                        )
                        retry_count += 1
                        continue
                    logger.warning(
                        "[%s] Cannot self-trigger after %d attempt(s). "
                        "Reverting patch to avoid breaking other bugs.",
                        bug_id, retry_count + 1,
                    )
                    step["apply_method"] = "reverted"
                    dispatch_state = copy.deepcopy(dispatch_state_before_step)
                    _revert_and_rebuild(
                        container, project, applied_bugs, ordered,
                        dispatch_state,
                    )
                    merge_results.append(step)
                    break

                # --- Verify all previously applied bugs (regression check) ---
                if all_verified_bugs:
                    logger.info("[%s] Regression check (%d bugs)...", bug_id, len(all_verified_bugs))
                    reg_results = verify_all_bugs(container, all_verified_bugs)
                    regressed = []
                    for rbug, ok in reg_results.items():
                        if not ok:
                            step["regressions"].append(rbug)
                            step_regression_failures.append({
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
                            _inject_dispatch_files(container, project, dispatch_state.get("dispatch_bytes", 1))
                            dispatch_state["dispatch_file_injected"] = True

                        _ensure_dispatch_capacity(dispatch_state, container, project)
                        bit_index = dispatch_state["next_bit"]
                        dispatch_ok = resolve_with_dispatch(
                            container, bug_id, project, regressed,
                            bit_index, current_diff_path=bd["diff_path"],
                            model=args.model,
                            feedback=step_feedback,
                            attempt=retry_count,
                        )

                        if dispatch_ok:
                            # Modify harness to consume dispatch byte (once)
                            if not dispatch_state["harness_modified"]:
                                hok = _modify_harness_for_dispatch(
                                    container, project, bd["fuzzer"],
                                    args.model,
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
                                _save_step_diff(container, project, target_commit,
                                                i, bug_id, "regression_dispatch", step)

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

                # --- If regressions remain, retry or accept ---
                if step["regressions"] and retry_count < _MAX_STEP_RETRIES:
                    reg_data = [
                        next(b for b in all_verified_bugs
                             if b["bug_id"] == rid)
                        for rid in step["regressions"]
                    ]
                    step_feedback = _build_step_feedback(
                        "regression", bug_id, container, project,
                        regressed_bugs_data=reg_data,
                    )
                    logger.warning(
                        "[%s] Regressions remain (%s), retrying step",
                        bug_id, step["regressions"],
                    )
                    retry_count += 1
                    continue

                # --- Step complete (success or accepted with regressions) ---
                if step["self_triggers"]:
                    applied_bugs.append(bug_id)
                    all_verified_bugs.append(bd)

                regression_failures.extend(step_regression_failures)
                merge_results.append(step)
                break  # exit retry loop

            # Save state for --start-step resume
            _save_step_state(
                project, target_commit, i, dispatch_state,
                applied_bugs, merge_results,
                [b["bug_id"] for b in all_verified_bugs],
            )

        # ------------------------------------------------------------------
        # 7. Final verification of ALL bugs
        # ------------------------------------------------------------------
        logger.info("=== Final verification of all %d bugs ===", len(all_verified_bugs))
        final_results = verify_all_bugs(container, all_verified_bugs)
        final_pass = all(final_results.values())

        # ------------------------------------------------------------------
        # 8. Extract combined diff
        # ------------------------------------------------------------------
        output_dir.mkdir(parents=True, exist_ok=True)

        # Get combined diff — only include files that the per-bug diffs
        # intentionally modified (avoids build artifacts from compile).
        # Also include dispatch infrastructure files if used.
        # Stage untracked source files so new files appear in the diff.
        _stage_untracked_source(container, project)
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
                container, f"cd {_source_dir(project)} && git diff",
            )
            # Parse the full diff to find harness file(s)
            for line in all_diff.splitlines():
                m = re.match(r'^[-+]{3}\s+[ab]/(.+)$', line)
                if m:
                    touched_files.add(m.group(1))
        if touched_files:
            file_args = " ".join(f"'{f}'" for f in sorted(touched_files))
            _, combined_diff = _exec_capture(
                container, f"cd {_source_dir(project)} && git diff -- {file_args}",
            )
        else:
            _, combined_diff = _exec_capture(
                container, f"cd {_source_dir(project)} && git diff",
            )
        combined_diff_path = output_dir / "combined.diff"
        combined_diff_path.write_text(combined_diff)
        logger.info("Combined diff: %s (%d bytes)", combined_diff_path, len(combined_diff))

        # Also copy to /out inside container
        _exec(container, f"cd {_source_dir(project)} && git diff > /out/combined.diff")

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
                if info.get("type") == "self_trigger_unblock":
                    blocked_by = ", ".join(info.get("bug_blocked_by", []))
                    print(f"    [bit {bit_idx}] {info['bug_new']} unblocked from {blocked_by}")
                else:
                    existing = ", ".join(info.get("bug_existing", []))
                    print(f"    [bit {bit_idx}] {info['bug_new']} vs {existing}")
            print(f"  Dispatch PoC bytes:")
            for bid, dval in sorted(dispatch_state["poc_bytes"].items(),
                                    key=lambda x: x[1], reverse=True):
                if dval > 0:
                    nbytes = dispatch_state.get("dispatch_bytes", 1)
                    hex_width = nbytes * 2
                    print(f"    {bid}: 0x{dval:0{hex_width}x}")
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
    parser.add_argument("--model", default=None,
                        help="Model to use (passed to codex CLI)")
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
    parser.add_argument("--start-step", type=int, default=None,
                        help="Resume from step N (requires previous run's step diffs)")
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
