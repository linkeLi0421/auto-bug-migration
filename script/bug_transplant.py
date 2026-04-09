#!/usr/bin/env python3
"""Bug transplant launcher -- runs Codex inside an OSS-Fuzz container.

Workflow:
  Phase 0: Collect crash log and function trace via fuzz_helper.py
  Phase 1: Build Codex-layered Docker image on top of the project image
  Phase 2: Start persistent container with proper volumes
  Phase 3: Run Codex with the bug transplant prompt
  Phase 4: Collect output diff

Usage:
  # Full pipeline (collect data + run Codex):
  sudo -E python3 script/bug_transplant.py wavpack \\
    --buggy-commit 348ff60b \\
    --target-commit 0b99613e \\
    --bug-id OSV-2020-1006 \\
    --fuzzer-name fuzzer_decode_file \\
    --testcase testcase-OSV-2020-1006

  # Skip data collection (crash/trace already in data/):
  sudo -E python3 script/bug_transplant.py wavpack \\
    --buggy-commit 348ff60b \\
    --target-commit 0b99613e \\
    --bug-id OSV-2020-1006 \\
    --fuzzer-name fuzzer_decode_file \\
    --testcase testcase-OSV-2020-1006 \\
    --skip-collect

  # Use a specific model:
  sudo -E python3 script/bug_transplant.py wavpack \\
    ... \\
    --model o3
"""

from __future__ import annotations

import argparse
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

# Lazy-initialized in main(); imported here so the module can be used as a library.
_usage_tracker = None

# Pin CLI version for reproducibility.
CODEX_VERSION = "0.116.0"  # @openai/codex

# Codex agent configuration
CODEX_CONFIG = {
    "npm_package": "@openai/codex",
    "cli_name": "codex",
    "cli_entry": "@openai/codex/bin/codex.js",
    "api_key_env": "OPENAI_API_KEY",
    "credentials_dir": ".codex",
    "run_cmd": "codex exec --dangerously-bypass-approvals-and-sandbox {prompt}",
    "model_flag": "--model",
}


def setup_codex_creds(container: str) -> None:
    """Copy codex credentials into container."""
    _exec(
        container,
        "cp -r /tmp/.agent-creds-src /home/agent/.codex 2>/dev/null; "
        "rm -rf /home/agent/.codex/projects 2>/dev/null; "
        "chown -R agent:agent /home/agent/.codex 2>/dev/null; "
        "true",
        user="root",
    )


def build_codex_command(
    prompt: str, model: str | None = None, mode: str = "exec",
) -> str:
    """Build the codex CLI command.

    *mode* selects the invocation style:
      - ``"exec"``  (default) — ``codex exec … --json`` (non-interactive, JSONL)
      - ``"interactive"`` — ``codex … `` (TUI, needs a TTY via tmux)
    """
    escaped = shlex.quote(prompt)
    if mode == "interactive":
        cmd = f"codex --dangerously-bypass-approvals-and-sandbox {escaped}"
    else:
        cmd = f"codex exec --dangerously-bypass-approvals-and-sandbox {escaped}"
    if model:
        cmd += f" --model {shlex.quote(model)}"
    if mode != "interactive":
        cmd += " --json"
    return cmd

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
HOME_DIR = SCRIPT_DIR.parent
OSS_FUZZ_DIR = HOME_DIR / "oss-fuzz"
DATA_DIR = HOME_DIR / "data"
FUZZ_HELPER = SCRIPT_DIR / "fuzz_helper.py"
PROMPT_TEMPLATE = SCRIPT_DIR / "prompts" / "bug_transplant.md"
MINIMIZE_TEMPLATE = SCRIPT_DIR / "prompts" / "minimize_patch.md"
MEMORY_TEMPLATE = SCRIPT_DIR / "prompts" / "bug_transplant_memory.md"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _container_repo_dir(project: str) -> str:
    """Return the git repo root inside the container for a project."""
    return _source_dir(project)


def _container_agents_md_path(project: str) -> str:
    """Return the shared AGENTS.md mount path inside the container."""
    return f"/src/{project}/AGENTS.md"


def _git_clean_excludes(project: str) -> str:
    """Return project-specific git-clean exclusions."""
    excludes = ["-e .codex/"]
    if _container_agents_md_path(project) == f"{_container_repo_dir(project)}/AGENTS.md":
        excludes.insert(0, "-e AGENTS.md")
    return " ".join(excludes)


def _build_container_env(language: str) -> list[str]:
    """Match the default build env used by fuzz_helper.py build_version."""
    return [
        "FUZZING_ENGINE=libfuzzer",
        "SANITIZER=address",
        "ARCHITECTURE=x86_64",
        f"FUZZING_LANGUAGE={language}",
        "HELPER=True",
        "MAKEFLAGS=--output-sync=line",
        "CMAKE_BUILD_PARALLEL_LEVEL=30",
        "NINJA_STATUS=",
        "TERM=dumb",
        "CLICOLOR=0",
        "FORCE_COLOR=0",
        "GCC_COLORS=",
        "CLANG_FORCE_COLOR=0",
        "CMAKE_COLOR_DIAGNOSTICS=OFF",
    ]

def _run_quiet(cmd: list[str], label: str = "", **kwargs) -> int:
    """Run a command, capture output, and only show it on failure.

    On success, output is logged at DEBUG level.
    On failure, the last 30 lines of combined output are logged at ERROR.
    """
    label = label or cmd[0]
    logger.info("Running: %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", **kwargs)
    combined = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        tail = "\n".join(combined.splitlines()[-30:])
        logger.error("[%s] failed (exit %d). Last 30 lines:\n%s",
                     label, proc.returncode, tail)
    elif combined.strip():
        logger.debug("[%s] output:\n%s", label, combined.strip())
    return proc.returncode


# Projects where the git repo directory differs from the project name.
_SOURCE_REPO_MAP: dict[str, str] = {
    "ghostscript": "ghostpdl",
    "php": "php-src",
}


def _source_dir(project: str) -> str:
    """Return the source directory path for a project inside the container."""
    repo_name = _SOURCE_REPO_MAP.get(project, project)
    return f"/src/{repo_name}"


# ---------------------------------------------------------------------------
# Phase 0: Collect crash and trace data
# ---------------------------------------------------------------------------

def collect_crash_data(args: argparse.Namespace) -> bool:
    """Run fuzz_helper.py collect_crash to get the crash stack."""
    crash_file = (
        DATA_DIR / "crash"
        / f"target_crash-{args.buggy_commit[:8]}-{args.testcase}.txt"
    )
    if crash_file.exists():
        logger.info("Crash data already exists: %s", crash_file)
        return True

    logger.info("Collecting crash data for %s at %s...", args.project, args.buggy_commit)
    cmd = [
        sys.executable, str(FUZZ_HELPER),
        "collect_crash", args.project,
        args.fuzzer_name,
        "--commit", args.buggy_commit,
        "--testcases", args.testcases_dir,
        "--test_input", args.testcase,
    ]
    if args.build_csv:
        cmd += ["--build_csv", args.build_csv]
    if args.runner_image:
        cmd += ["--runner-image", args.runner_image]

    ret = _run_quiet(cmd, label="collect_crash")
    if ret != 0:
        return False

    if not crash_file.exists():
        logger.error("Expected crash file not found: %s", crash_file)
        return False

    logger.info("Crash data collected: %s", crash_file)
    return True


def collect_trace_data(args: argparse.Namespace) -> bool:
    """Run fuzz_helper.py collect_trace to get the function trace."""
    trace_file = (
        DATA_DIR
        / f"target_trace-{args.buggy_commit[:8]}-{args.testcase}.txt"
    )
    if trace_file.exists():
        logger.info("Trace data already exists: %s", trace_file)
        return True

    logger.info("Collecting trace data for %s at %s...", args.project, args.buggy_commit)
    cmd = [
        sys.executable, str(FUZZ_HELPER),
        "collect_trace", args.project,
        args.fuzzer_name,
        "--commit", args.buggy_commit,
        "--testcases", args.testcases_dir,
        "--test_input", args.testcase,
    ]
    if args.build_csv:
        cmd += ["--build_csv", args.build_csv]
    if args.runner_image:
        cmd += ["--runner-image", args.runner_image]

    ret = _run_quiet(cmd, label="collect_trace")
    if ret != 0:
        return False

    if not trace_file.exists():
        logger.error("Expected trace file not found: %s", trace_file)
        return False

    logger.info("Trace data collected: %s", trace_file)
    return True


def collect_fix_diff(args: argparse.Namespace) -> bool:
    """Generate a diff between the buggy commit and the adjacent CSV commit.

    The adjacent commit must be provided via args.adjacent_commit (pre-computed
    by bug_transplant_batch.py from the CSV row immediately after the buggy row
    in the direction of the target).

    Saves the diff to DATA_DIR/patch_diffs/fix_hint-<buggy_short>-<testcase>.diff.
    Returns True if the diff was saved (or already exists), False otherwise.
    """
    adjacent_commit = getattr(args, 'adjacent_commit', None)
    repo_path = getattr(args, 'repo_path', None)
    if not adjacent_commit or not repo_path:
        return False

    buggy_short = args.buggy_commit[:8]
    patch_diffs_dir = DATA_DIR / "patch_diffs"
    patch_diffs_dir.mkdir(exist_ok=True)
    out_path = patch_diffs_dir / f"fix_hint-{buggy_short}-{args.testcase}.diff"

    if out_path.exists():
        logger.info("Fix diff already exists: %s", out_path)
        return True

    try:
        diff_result = subprocess.run(
            ["git", "diff", args.buggy_commit, adjacent_commit],
            cwd=repo_path,
            capture_output=True, encoding="utf-8", errors="replace",
        )
        diff_text = diff_result.stdout
    except Exception as exc:
        logger.debug("collect_fix_diff git diff error: %s", exc)
        return False

    if not diff_text.strip():
        logger.info("Fix diff is empty — skipping")
        return False

    out_path.write_text(diff_text)
    logger.info("Fix diff saved: %s (adjacent=%s)", out_path, adjacent_commit[:8])
    return True


# ---------------------------------------------------------------------------
# Phase 1: Build Docker image with Codex layered on top
# ---------------------------------------------------------------------------

def build_project_image(
    project: str,
    target_commit: str | None = None,
    build_csv: str | None = None,
) -> str:
    """Build the OSS-Fuzz project image using the correct OSS-Fuzz commit.

    Uses ``fuzz_helper.py build_version`` to call ``prepare_repository()``
    (checkout matching OSS-Fuzz commit) and ``build_image_impl()`` so the
    project's ``build.sh`` matches the target commit.

    Returns the project image tag.
    """
    image_tag = f"gcr.io/oss-fuzz/{project}"

    # Use fuzz_helper.py build_version to build with correct OSS-Fuzz commit.
    # This calls prepare_repository() + build_image_impl() + runs a build.
    # Even if the image exists, re-build to ensure build.sh matches.
    if target_commit:
        logger.info("Building project image for %s at commit %s...", project, target_commit[:12])
        cmd = [
            sys.executable, str(FUZZ_HELPER),
            "build_version", project,
            "--commit", target_commit,
            "--no_corpus",
        ]
        if build_csv:
            cmd += ["--build_csv", build_csv]
        ret = _run_quiet(cmd, label="build_version")
        if ret != 0:
            logger.error("fuzz_helper.py build_version failed for %s", project)
            sys.exit(1)
        return image_tag

    # Fallback: simple build_image if no target commit
    ret = subprocess.call(
        ["docker", "image", "inspect", image_tag],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if ret == 0:
        logger.info("Project image already exists: %s", image_tag)
        return image_tag

    logger.info("Building OSS-Fuzz project image for %s...", project)
    helper_py = OSS_FUZZ_DIR / "infra" / "helper.py"
    ret = _run_quiet(
        [sys.executable, str(helper_py), "build_image", project],
        label="build_image",
    )
    if ret != 0:
        logger.error("Failed to build project image for %s", project)
        sys.exit(1)

    return image_tag


def build_agent_image(project: str, project_image: str) -> str:
    """Layer the Codex CLI on top of the project image.

    Produces ``bug-transplant-<project>:latest``.
    """
    npm_pkg = CODEX_CONFIG["npm_package"]
    cli_name = CODEX_CONFIG["cli_name"]
    cli_entry = CODEX_CONFIG["cli_entry"]
    tag = f"bug-transplant-{project}:latest"
    repo_dir = _container_repo_dir(project)

    # Skip rebuild if the agent image already exists
    inspect = subprocess.run(
        ["docker", "image", "inspect", tag],
        capture_output=True,
        text=True,
    )
    if inspect.returncode == 0:
        workdir_inspect = subprocess.run(
            ["docker", "image", "inspect", tag, "--format", "{{.Config.WorkingDir}}"],
            capture_output=True,
            text=True,
        )
        current_workdir = workdir_inspect.stdout.strip()
        if workdir_inspect.returncode == 0 and current_workdir == repo_dir:
            logger.info("Agent image already exists, reusing: %s", tag)
            return tag
        logger.info(
            "Rebuilding agent image %s because working directory is %r, expected %r",
            tag, current_workdir, repo_dir,
        )
        subprocess.call(
            ["docker", "rmi", "-f", tag],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    logger.info("Building codex agent image '%s' on top of '%s'...", tag, project_image)

    dockerfile_content = textwrap.dedent(f"""\
        # Stage 1: Install agent CLI on a modern base (glibc >= 2.28).
        FROM ubuntu:22.04 AS agent-builder
        ENV DEBIAN_FRONTEND=noninteractive
        RUN apt-get update && apt-get install -y --no-install-recommends \\
                curl ca-certificates \\
            && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \\
            && apt-get install -y --no-install-recommends nodejs \\
            && npm install -g {npm_pkg}@{CODEX_VERSION} \\
            && rm -rf /var/lib/apt/lists/*

        # Stage 2: Project image with agent CLI copied in.
        FROM {project_image}
        ENV DEBIAN_FRONTEND=noninteractive

        # Copy Node.js and agent CLI with all dependencies
        COPY --from=agent-builder /usr/bin/node /usr/local/bin/node
        COPY --from=agent-builder /usr/lib/node_modules /usr/local/lib/node_modules
        # Copy glibc and libstdc++ from builder so node binary works on old bases
        COPY --from=agent-builder /lib/x86_64-linux-gnu/libc.so.6 /opt/node-libs/libc.so.6
        COPY --from=agent-builder /lib/x86_64-linux-gnu/libm.so.6 /opt/node-libs/libm.so.6
        COPY --from=agent-builder /lib/x86_64-linux-gnu/libpthread.so.0 /opt/node-libs/libpthread.so.0
        COPY --from=agent-builder /lib/x86_64-linux-gnu/libdl.so.2 /opt/node-libs/libdl.so.2
        COPY --from=agent-builder /lib/x86_64-linux-gnu/librt.so.1 /opt/node-libs/librt.so.1
        COPY --from=agent-builder /lib64/ld-linux-x86-64.so.2 /opt/node-libs/ld-linux-x86-64.so.2
        COPY --from=agent-builder /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /opt/node-libs/libstdc++.so.6
        COPY --from=agent-builder /lib/x86_64-linux-gnu/libgcc_s.so.1 /opt/node-libs/libgcc_s.so.1

        # Create wrapper script that uses the bundled libs
        RUN echo '#!/bin/bash' > /usr/local/bin/{cli_name} \\
            && echo 'exec /opt/node-libs/ld-linux-x86-64.so.2 --library-path /opt/node-libs /usr/local/bin/node /usr/local/lib/node_modules/{cli_entry} "$@"' >> /usr/local/bin/{cli_name} \\
            && chmod +x /usr/local/bin/{cli_name}

        # sudo may not exist on older base images
        RUN apt-get update && apt-get install -y --no-install-recommends sudo \\
            && rm -rf /var/lib/apt/lists/* || true

        # Create a non-root user (some CLIs refuse to run as root)
        RUN (useradd -m -d /home/agent -s /bin/bash agent 2>/dev/null || true) \\
            && echo "agent ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \\
            && chown -R agent:agent /src/ /out/ /work/ || true

        # Wrapper so the agent can call "compile" without sudo
        # (codex CLI may block sudo even with --dangerously-bypass-approvals-and-sandbox)
        RUN printf '#!/bin/bash\\ncd /src && exec sudo -E /usr/local/bin/compile "$@"\\n' \
            > /home/agent/compile && chmod +x /home/agent/compile

        ENV HOME=/home/agent
        ENV PATH="/home/agent:$PATH"
        USER agent

        WORKDIR {repo_dir}
        CMD ["sleep", "infinity"]
    """)

    with tempfile.TemporaryDirectory() as tmpdir:
        df_path = Path(tmpdir) / "Dockerfile"
        df_path.write_text(dockerfile_content)
        ret = _run_quiet(
            ["docker", "build", "-t", tag, "-f", str(df_path), tmpdir],
            label="build_agent_image",
        )
        if ret != 0:
            logger.error("Failed to build codex agent image")
            sys.exit(1)

    logger.info("Codex agent image built: %s", tag)
    return tag


# ---------------------------------------------------------------------------
# Phase 2 + 3: Run Codex inside a persistent container
# ---------------------------------------------------------------------------

def build_prompt(args: argparse.Namespace) -> str:
    """Read the prompt template and fill in parameters."""
    template = PROMPT_TEMPLATE.read_text()
    buggy_short = args.buggy_commit[:8]
    repo_dir = _container_repo_dir(args.project)
    agents_md = _container_agents_md_path(args.project)

    adjacent_commit = getattr(args, 'adjacent_commit', None)
    if adjacent_commit:
        fix_diff_line = (
            f"\n- `/data/patch_diffs/fix_hint-{buggy_short}-{args.testcase}.diff` -- "
            f"diff from buggy commit to adjacent CSV commit `{adjacent_commit[:8]}` "
            f"(optional hint from the next tested commit toward the fix; use if helpful, not as a required recipe)"
        )
        adjacent_commit_hint = (
            f" If available, you may inspect"
            f" `/data/patch_diffs/fix_hint-{buggy_short}-{args.testcase}.diff`:"
            f" it is the diff from the buggy commit to the next tested commit"
            f" `{adjacent_commit[:8]}` and may contain a relevant clue, but it is only a hint."
        )
    else:
        fix_diff_line = ""
        adjacent_commit_hint = ""

    source_dir = getattr(args, "source_dir", None) or _source_dir(args.project)
    prompt = template.format(
        project=args.project,
        bug_id=args.bug_id,
        buggy_commit=args.buggy_commit,
        target_commit=args.target_commit,
        buggy_short=buggy_short,
        testcase_name=args.testcase,
        fuzzer_name=args.fuzzer_name,
        repo_dir=repo_dir,
        agents_md=agents_md,
        fix_diff_line=fix_diff_line,
        adjacent_commit=adjacent_commit or "",
        adjacent_commit_hint=adjacent_commit_hint,
        source_dir=source_dir,
    )
    return prompt


def _build_minimize_prompt(args: argparse.Namespace) -> str:
    """Read the minimize prompt template and fill in parameters."""
    template = MINIMIZE_TEMPLATE.read_text()
    source_dir = getattr(args, "source_dir", None) or _source_dir(args.project)
    return template.format(
        project=args.project,
        bug_id=args.bug_id,
        buggy_short=args.buggy_commit[:8],
        target_commit=args.target_commit,
        testcase_name=args.testcase,
        fuzzer_name=args.fuzzer_name,
        source_dir=source_dir,
    )


def setup_agents_dir(args: argparse.Namespace) -> Path:
    """Prepare a temporary directory containing AGENTS.md shared knowledge.

    Returns the path to the temporary directory that will be
    mounted into the container at /src/{project}/AGENTS.md.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="bug_transplant_agents_"))

    # Seed AGENTS.md: use saved knowledge from a previous batch run if available,
    # otherwise fall back to the blank template.
    agents_md = tmpdir / "AGENTS.md"
    saved_agents_md = (
        DATA_DIR / "bug_transplant"
        / f"batch_{args.project}_{args.target_commit[:8]}"
        / "AGENTS.md"
    )
    if saved_agents_md.exists():
        agents_md.write_text(saved_agents_md.read_text())
        logger.info("Seeding AGENTS.md from previous run: %s", saved_agents_md)
    else:
        template = MEMORY_TEMPLATE.read_text()
        agents_md.write_text(template.format(
            project=args.project,
            target_commit=args.target_commit,
            fuzzer_name=args.fuzzer_name,
        ))

    return tmpdir


def create_shared_container(
    project: str,
    target_commit: str,
    container_name: str,
    agents_dir: Path,
    testcases_dir: str = "",
    env: list[str] | None = None,
    volume: list[str] | None = None,
) -> int:
    """Create a persistent container for batch bug transplant.

    Returns 0 on success, non-zero on failure.
    """
    image_tag = f"bug-transplant-{project}:latest"

    data_dir = str(DATA_DIR)
    testcases_dir = str(Path(testcases_dir).resolve()) if testcases_dir else ""
    script_dir = str(SCRIPT_DIR)
    out_dir = str(HOME_DIR / "build" / "out" / project)
    work_dir = str(HOME_DIR / "build" / "work" / project)

    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(work_dir, exist_ok=True)

    # Remove existing container with same name
    subprocess.call(
        ["docker", "rm", "-f", container_name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    # Detect project language
    project_yaml = HOME_DIR / "oss-fuzz" / "projects" / project / "project.yaml"
    language = "c++"
    if project_yaml.exists():
        for line in project_yaml.read_text().splitlines():
            if line.startswith("language:"):
                language = line.split(":", 1)[1].strip().strip('"').strip("'")
                break

    docker_run_cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "--privileged",
        "--shm-size=2g",
        "-v", f"{data_dir}:/data",
        "-v", f"{testcases_dir}:/corpus",
        "-v", f"{script_dir}:/script:ro",
        "-v", f"{out_dir}:/out",
        "-v", f"{work_dir}:/work",
        "-v", f"{agents_dir}/AGENTS.md:/src/{project}/AGENTS.md",
    ]
    for env_var in _build_container_env(language):
        docker_run_cmd += ["-e", env_var]

    # Mount codex credentials
    cred_dir = Path.home() / CODEX_CONFIG["credentials_dir"]
    if cred_dir.exists():
        docker_run_cmd += ["-v", f"{cred_dir}:/tmp/.agent-creds-src:ro"]

    if env:
        for e in env:
            docker_run_cmd += ["-e", e]
    if volume:
        for v in volume:
            docker_run_cmd += ["-v", v]

    docker_run_cmd += [image_tag, "sleep", "infinity"]

    repo_dir = _container_repo_dir(project)
    agents_md_path = _container_agents_md_path(project)
    logger.info("Creating shared container: %s", container_name)
    ret = _run_quiet(docker_run_cmd, label="docker-run-shared")
    if ret != 0:
        logger.error("Failed to create shared container")
        return 1

    # Initial setup: git safe directory, checkout, credentials
    _exec(container_name, "git config --global --add safe.directory '*'", user="root")
    clean_excludes = _git_clean_excludes(project)
    clean_ret = _exec(
        container_name,
        f"cd {shlex.quote(repo_dir)} && git clean -fdx {clean_excludes}",
        user="root",
    )
    checkout_ret = _exec(
        container_name,
        f"cd {shlex.quote(repo_dir)} && git checkout -f {shlex.quote(target_commit)}",
        user="root",
    )
    if clean_ret != 0 or checkout_ret != 0:
        logger.error(
            "Failed to prepare repo in container %s (repo_dir=%s)",
            container_name, repo_dir,
        )
        return 1
    if repo_dir != f"/src/{project}":
        _exec(
            container_name,
            f"ln -sf {shlex.quote(agents_md_path)} {shlex.quote(repo_dir)}/AGENTS.md 2>/dev/null || true",
            user="root",
        )
    _exec(container_name, "sudo chown -R agent:agent /src/ /out/ /work/ /data/ 2>/dev/null || true", user="root")

    # Setup codex credentials
    setup_codex_creds(container_name)

    logger.info("Shared container ready: %s", container_name)
    return 0


def run_agent_in_container(args: argparse.Namespace) -> int:
    """Start container, run Codex agent, collect results.

    Returns 0 on success, non-zero on failure.
    """
    image_tag = f"bug-transplant-{args.project}:latest"
    reuse_container = getattr(args, "container_name", None)
    container_name = reuse_container or f"bug-transplant-{args.project}-{args.bug_id}"
    buggy_short = args.buggy_commit[:8]

    # Prepare volumes
    data_dir = str(DATA_DIR)
    testcases_dir = str(Path(args.testcases_dir).resolve())
    script_dir = str(SCRIPT_DIR)
    out_dir = str(HOME_DIR / "build" / "out" / args.project)
    work_dir = str(HOME_DIR / "build" / "work" / args.project)

    # Clean and recreate build directories to avoid stale binaries/artifacts
    # from previous runs (prevents "Text file busy" and wrong test results).
    # When reusing a shared container, do NOT delete the host-side directories:
    # Docker bind-mount backing directories must not be removed while the
    # container is running — doing so breaks the mount inside the container.
    if reuse_container:
        os.makedirs(out_dir, exist_ok=True)
        os.makedirs(work_dir, exist_ok=True)
    else:
        shutil.rmtree(out_dir, ignore_errors=True)
        shutil.rmtree(work_dir, ignore_errors=True)
        os.makedirs(out_dir, exist_ok=True)
        os.makedirs(work_dir, exist_ok=True)

    # Use shared agents_dir if provided (batch mode), otherwise create new
    shared_agents_dir = getattr(args, "agents_dir", None)
    agents_dir = Path(shared_agents_dir) if shared_agents_dir else setup_agents_dir(args)
    owns_agents_dir = shared_agents_dir is None
    repo_dir = _container_repo_dir(args.project)
    agents_md_path = _container_agents_md_path(args.project)

    if not reuse_container:
        # --- Stop any existing container with the same name ---
        subprocess.call(
            ["docker", "rm", "-f", container_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        # Detect project language from project.yaml
        project_yaml = HOME_DIR / "oss-fuzz" / "projects" / args.project / "project.yaml"
        language = "c++"
        if project_yaml.exists():
            for line in project_yaml.read_text().splitlines():
                if line.startswith("language:"):
                    language = line.split(":", 1)[1].strip().strip('"').strip("'")
                    break

        # --- Start persistent container ---
        docker_run_cmd = [
            "docker", "run", "-d",
            "--name", container_name,
            "--privileged",
            "--shm-size=2g",
            # Volumes
            "-v", f"{data_dir}:/data",
            "-v", f"{testcases_dir}:/corpus",
            "-v", f"{script_dir}:/script:ro",
            "-v", f"{out_dir}:/out",
            "-v", f"{work_dir}:/work",
            # AGENTS.md as shared memory (rw)
            "-v", f"{agents_dir}/AGENTS.md:/src/{args.project}/AGENTS.md",
        ]
        for env_var in _build_container_env(language):
            docker_run_cmd += ["-e", env_var]

        # Mount codex credentials (login mode)
        cred_dir = Path.home() / CODEX_CONFIG["credentials_dir"]
        if cred_dir.exists():
            docker_run_cmd += ["-v", f"{cred_dir}:/tmp/.agent-creds-src:ro"]

        # Additional user-specified env vars
        if args.env:
            for e in args.env:
                docker_run_cmd += ["-e", e]

        # Additional user-specified volume mounts
        if args.volume:
            for v in args.volume:
                docker_run_cmd += ["-v", v]

        docker_run_cmd += [image_tag, "sleep", "infinity"]

        logger.info("Starting container: %s", container_name)
        ret = _run_quiet(docker_run_cmd, label="docker-run")
        if ret != 0:
            logger.error("Failed to start container")
            return 1
    else:
        logger.info("Reusing container: %s", container_name)
        # Wipe /out and /work contents from inside the container so stale
        # binaries don't bleed across bugs. (We cannot rmtree the host-side
        # directories while the bind mount is live.)
        _exec(container_name, "rm -rf /out/* /work/*", user="root")

    try:
        args.source_dir = repo_dir
        prompt = build_prompt(args)
        repo_dir_q = shlex.quote(repo_dir)
        clean_excludes = _git_clean_excludes(args.project)

        # --- Checkout target commit inside container ---
        logger.info("Checking out target commit %s...", args.target_commit)
        _exec(container_name, "git config --global --add safe.directory '*'", user="root")
        # Clean build artifacts (cmake-generated Makefiles, .o files, etc.)
        # before checkout so they don't pollute the git diff later.
        clean_ret = _exec(
            container_name,
            f"cd {repo_dir_q} && git clean -fdx {clean_excludes}",
            user="root",
        )
        checkout_ret = _exec(
            container_name,
            f"cd {repo_dir_q} && git checkout -f {shlex.quote(args.target_commit)}",
            user="root",
        )
        if clean_ret != 0 or checkout_ret != 0:
            logger.error(
                "Failed to prepare repo in container %s (repo_dir=%s)",
                container_name, repo_dir,
            )
            return 1
        if repo_dir != f"/src/{args.project}":
            _exec(
                container_name,
                f"ln -sf {shlex.quote(agents_md_path)} {repo_dir_q}/AGENTS.md 2>/dev/null || true",
                user="root",
            )

        # --- Copy testcase to /work for easier access ---
        _exec(
            container_name,
            f"cp /corpus/{args.testcase} /work/{args.testcase}",
            user="root",
        )
        _exec(container_name, "sudo chown -R agent:agent /src/ /out/ /work/ /data/ 2>/dev/null || true", user="root")

        # --- Setup codex credentials ---
        setup_codex_creds(container_name)

        # --- Run agent ---
        codex_mode = getattr(args, "codex_mode", "exec")
        logger.info("Running codex agent (mode=%s, this may take a while)...",
                     codex_mode)
        agent_cmd = build_codex_command(
            prompt, getattr(args, "model", None), mode=codex_mode,
        )
        agent_cmd = f"cd {repo_dir_q} && {agent_cmd}"

        start_time = time.monotonic()
        if codex_mode == "interactive":
            exit_code, output = _exec_interactive(
                container_name, agent_cmd, timeout=args.timeout,
            )
        else:
            exit_code, output = _exec_capture(
                container_name, agent_cmd, timeout=args.timeout,
            )
        elapsed = time.monotonic() - start_time

        if _usage_tracker:
            _usage_tracker.log_usage("transplant", output, getattr(args, "model", None))

        logger.info(
            "Codex agent finished in %.0fs (exit code %d)",
            elapsed, exit_code,
        )

        # --- Save output ---
        output_dir = DATA_DIR / "bug_transplant" / f"{args.project}_{args.bug_id}"
        os.makedirs(output_dir, exist_ok=True)

        if codex_mode == "interactive":
            # TUI output captured via tmux pipe-pane (includes ANSI codes)
            (output_dir / "agent_output_tui.txt").write_text(output)
        else:
            # Save raw JSONL and human-readable transcript
            (output_dir / "agent_output.jsonl").write_text(output)
            (output_dir / "agent_output.txt").write_text(
                _format_codex_output(output)
            )

        # Check if agent declared the bug impossible to transplant
        impossible_path = output_dir / "bug_transplant.impossible"
        imp_ret = subprocess.run(
            ["docker", "exec", container_name,
             "bash", "-c", "cat /out/bug_transplant.impossible"],
            capture_output=True, timeout=10,
        )
        if imp_ret.returncode == 0 and imp_ret.stdout.strip():
            impossible_path.write_text(imp_ret.stdout.decode(errors='replace'))
        if impossible_path.exists():
            reason = impossible_path.read_text().strip()
            logger.warning("Agent declared bug impossible: %s", reason)
            return 0  # treat as success (intentional skip)

        # Collect source-only diff (exclude build artifacts from CMake
        # in-source builds, .o/.a/.so files, and agent config dirs).
        # Always regenerate from git to avoid the agent accidentally
        # capturing build artifacts via bare `git diff`.
        diff_path = output_dir / "bug_transplant.diff"
        _git_diff_excludes = (
            "':(exclude).codex/' "
            "':(exclude)CMakeFiles/' ':(exclude)*/CMakeFiles/' "
            "':(exclude)CMakeCache.txt' ':(exclude)cmake_install.cmake' "
            "':(exclude)*/cmake_install.cmake' ':(exclude)CTestTestfile.cmake' "
            "':(exclude)*/CTestTestfile.cmake' ':(exclude)CPackConfig.cmake' "
            "':(exclude)CPackSourceConfig.cmake' ':(exclude)cmake_uninstall.cmake' "
            "':(exclude)Makefile' ':(exclude)*/Makefile' "
            "':(exclude)*.o' ':(exclude)*.a' ':(exclude)*.so' ':(exclude)*.so.*' "
            "':(exclude)*.d' ':(exclude)*.pc' ':(exclude)config.h' "
            "':(exclude)build/' ':(exclude)_build/'"
        )
        _, git_diff = _exec_capture(
            container_name,
            f"cd {repo_dir_q} && "
            f"git diff HEAD -- . {_git_diff_excludes}",
        )
        diff_path.write_text(git_diff)
        if git_diff.strip():
            logger.info("Source diff saved: %s (%d bytes)", diff_path, len(git_diff))
        else:
            logger.info("Diff is empty (testcase-only transplant or no changes)")

        # --- Collect modified testcase (agent may have patched it) ---
        # Use docker exec + cat to avoid docker cp bind mount issues
        testcase_out = output_dir / args.testcase
        for tc_src in [f"/out/{args.testcase}", f"/work/{args.testcase}", f"/tmp/{args.testcase}"]:
            tc_ret = subprocess.run(
                ["docker", "exec", container_name,
                 "bash", "-c", f"cat {tc_src}"],
                capture_output=True, timeout=30,
            )
            if tc_ret.returncode == 0 and tc_ret.stdout:
                testcase_out.write_bytes(tc_ret.stdout)
                logger.info("Collected testcase from %s: %s", tc_src, testcase_out)
                break
        else:
            logger.warning("No modified testcase found in container")

        # ---------------------------------------------------------------
        # Post-agent verification: rebuild with official `compile` and
        # check that the bug actually triggers.  The agent may have used
        # a non-standard build that produces different binaries.
        # ---------------------------------------------------------------
        if exit_code == 0:
            logger.info("=== Post-agent verification ===")
            fuzzer = args.fuzzer_name
            testcase = args.testcase

            # Force official build (delete fuzzer binary to force re-link;
            # autotools/cmake may not re-link when only library sources change)
            logger.info("Rebuilding with official compile...")
            _exec_capture(
                container_name,
                f"find {repo_dir_q} -name '{fuzzer}' -type f -executable -delete; "
                f"rm -f /out/{fuzzer}",
            )
            ret_build, build_out = _exec_capture(
                container_name, "cd /src && sudo -E compile 2>&1", timeout=300,
            )
            if ret_build != 0:
                logger.error("Official compile failed after agent run")
                logger.error("Build tail: %s", build_out[-500:] if build_out else "")
                return 1

            # Restore testcase: prefer agent's modified copy from /out,
            # fall back to /work (agent may have modified in-place),
            # last resort: original from /corpus
            _exec_capture(
                container_name,
                f"if [ -f /out/{testcase} ]; then cp /out/{testcase} /work/{testcase}; "
                f"elif [ ! -f /work/{testcase} ]; then cp /corpus/{testcase} /work/{testcase}; fi; true",
            )

            # Run fuzzer with testcase — retry up to 3 times for
            # non-deterministic bugs (same as fuzz_helper.py reproduce).
            fuzzer_path = f"/out/{fuzzer}"
            sym_path = "/out/llvm-symbolizer"
            verify_cmd = (
                f"export ASAN_OPTIONS=detect_leaks=0"
                f":external_symbolizer_path={sym_path}; "
                f"if [ ! -x {fuzzer_path} ]; then "
                f"echo 'ERROR: {fuzzer_path} not found'; exit 99; fi; "
                f"{fuzzer_path} -runs=10 /work/{testcase} 2>&1"
            )
            has_crash = False
            crash_matches = False
            fuzz_out = ""
            for _attempt in range(3):
                ret_fuzz, fuzz_out = _exec_capture(
                    container_name, verify_cmd, timeout=120,
                )

                # Check for crash
                has_crash = bool(re.search(
                    r'SUMMARY:\s*(Address|Memory|Undefined|Thread|Leak)Sanitizer',
                    fuzz_out,
                ))

                # Compare crash stack with original to detect wrong-bug triggers
                if has_crash:
                    original_crash_file = (
                        DATA_DIR / "crash"
                        / f"target_crash-{buggy_short}-{testcase}.txt"
                    )
                    crash_matches = True  # assume match if no original to compare
                    if original_crash_file.exists():
                        orig_text = original_crash_file.read_text()
                        crash_matches = _crash_stacks_match(orig_text, fuzz_out)
                        if not crash_matches:
                            logger.warning(
                                "Crash stack MISMATCH (see above for details)",
                            )

                if has_crash and crash_matches:
                    break
                logger.debug("Verify attempt %d/3: no crash, retrying...",
                             _attempt + 1)

            if has_crash and crash_matches:
                logger.info("Post-agent verification PASSED: bug triggers "
                            "with official build")
                # Save crash stack
                crash_out_path = output_dir / "transplant_crash.txt"
                crash_out_path.write_text(fuzz_out)
                logger.info("Crash stack saved: %s", crash_out_path)

                # --- Phase 2: Minimization (separate agent) ---
                logger.info("=== Minimization phase ===")
                minimize_prompt = _build_minimize_prompt(args)
                minimize_cmd = build_codex_command(
                    minimize_prompt, getattr(args, "model", None),
                    mode=codex_mode,
                )
                min_start = time.monotonic()
                if codex_mode == "interactive":
                    min_exit, min_output = _exec_interactive(
                        container_name, minimize_cmd, timeout=args.timeout,
                    )
                else:
                    min_exit, min_output = _exec_capture(
                        container_name, minimize_cmd, timeout=args.timeout,
                    )
                min_elapsed = time.monotonic() - min_start
                if _usage_tracker:
                    _usage_tracker.log_usage("minimize", min_output, getattr(args, "model", None))
                logger.info("Minimization finished in %.0fs (exit %d)",
                            min_elapsed, min_exit)
                if codex_mode == "interactive":
                    (output_dir / "minimize_output.txt").write_text(min_output)
                else:
                    (output_dir / "minimize_output.jsonl").write_text(min_output)
                    (output_dir / "minimize_output.txt").write_text(
                        _format_codex_output(min_output)
                    )

                # Re-save the (now minimized) diff via git diff
                _, min_diff = _exec_capture(
                    container_name,
                    f"cd {repo_dir_q} && "
                    f"git diff HEAD -- . {_git_diff_excludes}",
                )
                diff_path.write_text(min_diff)
                logger.info("Minimized diff saved: %s (%d bytes)",
                            diff_path, len(min_diff))

                # Re-collect testcase (minimizer may have changed it)
                testcase_out = output_dir / testcase
                for tc_src in [f"/out/{testcase}", f"/work/{testcase}"]:
                    tc_ret = subprocess.run(
                        ["docker", "exec", container_name,
                         "bash", "-c", f"cat {tc_src}"],
                        capture_output=True, timeout=30,
                    )
                    if tc_ret.returncode == 0 and tc_ret.stdout:
                        testcase_out.write_bytes(tc_ret.stdout)
                        logger.info("Re-collected testcase from %s", tc_src)
                        break

                # Re-verify after minimization: force rebuild to avoid
                # stale binaries (autotools/cmake dependency tracking issue)
                _exec_capture(
                    container_name,
                    f"find {repo_dir_q} -name '{fuzzer}' -type f -executable -delete; "
                    f"rm -f /out/{fuzzer}",
                )
                ret_rebuild, _ = _exec_capture(
                    container_name, "cd /src && sudo -E compile 2>&1", timeout=300,
                )
                if ret_rebuild != 0:
                    logger.warning("Post-minimize rebuild failed")
                _exec_capture(
                    container_name,
                    f"if [ -f /out/{testcase} ]; then cp /out/{testcase} /work/{testcase}; "
                    f"elif [ ! -f /work/{testcase} ]; then cp /corpus/{testcase} /work/{testcase}; fi; true",
                )
                has_crash2 = False
                crash_matches2 = False
                for _min_attempt in range(3):
                    ret_fuzz2, fuzz_out2 = _exec_capture(
                        container_name, verify_cmd, timeout=120)
                    has_crash2 = bool(re.search(
                        r'SUMMARY:\s*(Address|Memory|Undefined|Thread|Leak)Sanitizer',
                        fuzz_out2))
                    if has_crash2:
                        if original_crash_file.exists():
                            crash_matches2 = _crash_stacks_match(
                                orig_text, fuzz_out2)
                        else:
                            crash_matches2 = True
                        if crash_matches2:
                            break
                        logger.warning(
                            "Post-minimize attempt %d: crash is wrong bug, "
                            "retrying...", _min_attempt + 1)
                if has_crash2 and crash_matches2:
                    logger.info("Post-minimize verification PASSED")
                    crash_out_path.write_text(fuzz_out2)
                elif has_crash2 and not crash_matches2:
                    logger.warning("Post-minimize verification: crash is "
                                   "WRONG BUG — keeping pre-minimize diff")
                else:
                    logger.warning("Post-minimize verification FAILED — "
                                   "keeping pre-minimize diff")
                    # Restore the unminimized diff
                    _, pre_min_diff = _exec_capture(
                        container_name,
                        f"cd {repo_dir_q} && git diff")
                    diff_path.write_text(pre_min_diff)
            elif has_crash and not crash_matches:
                logger.error(
                    "Post-agent verification FAILED: crash is a DIFFERENT "
                    "bug, not the original. Removing artifacts.")
                if diff_path.exists():
                    diff_path.unlink()
                return 1
            else:
                logger.error(
                    "Post-agent verification FAILED: bug does NOT trigger "
                    "with official compile. The agent may have used a "
                    "non-standard build. exit=%d tail=%.300s",
                    ret_fuzz,
                    fuzz_out[-300:] if fuzz_out else "(empty)",
                )
                # Remove unverified diff so downstream doesn't use it
                if diff_path.exists():
                    diff_path.unlink()
                    logger.info("Removed unverified diff: %s", diff_path)
                return 1

        # Agent failed — remove any partial diff
        if exit_code != 0 and diff_path.exists():
            diff_path.unlink()
            logger.info("Agent failed (exit %d), removed partial diff: %s",
                        exit_code, diff_path)

        return exit_code

    finally:
        if reuse_container:
            # Reused container — reset source for next bug but keep container
            logger.info("Resetting source tree for next bug...")
            _exec(container_name,
                  f"cd {repo_dir_q} && git checkout -f {shlex.quote(args.target_commit)} && "
                  f"git clean -fdx {clean_excludes}",
                  user="root")
        elif not args.keep_container:
            logger.info("Destroying container %s...", container_name)
            subprocess.call(
                ["docker", "rm", "-f", container_name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        else:
            logger.info(
                "Container kept alive: docker exec -it %s bash", container_name,
            )
        # Clean up temp agents directory (only if we own it)
        if owns_agents_dir:
            shutil.rmtree(agents_dir, ignore_errors=True)


def _extract_crash_funcs(text: str, limit: int = 0) -> list:
    """Extract function names from crash stack frames in /src/ project code.

    Args:
        text: ASan/MSan/etc. crash output.
        limit: Max functions to return (0 = all).
    """
    funcs = []
    for m in re.finditer(r'#\d+\s+\S+ in (\S+)\s+/src/', text):
        funcs.append(m.group(1))
    return funcs[:limit] if limit else funcs


def _extract_sanitizer_class(text: str):
    """Extract sanitizer error class and access direction from crash output.

    Returns (error_class, direction) e.g. ("heap-buffer-overflow", "READ")
    or (None, None) if not found.
    """
    m = re.search(
        r'ERROR:\s*\w+Sanitizer:\s*([\w-]+)\s+on address.*?\n'
        r'(READ|WRITE)\s+of\s+size',
        text, re.DOTALL,
    )
    if m:
        return m.group(1), m.group(2)
    # Fallback: try SUMMARY line for class, separate search for direction
    m_summary = re.search(r'SUMMARY:\s*\w+Sanitizer:\s*([\w-]+)', text)
    m_dir = re.search(r'(READ|WRITE)\s+of\s+size', text)
    return (
        m_summary.group(1) if m_summary else None,
        m_dir.group(1) if m_dir else None,
    )


def _extract_crash_files(text: str) -> set:
    """Extract source file basenames from crash stack frames in /src/."""
    files = set()
    for m in re.finditer(r'/src/\S+/([\w._-]+\.\w+):\d+', text):
        files.add(m.group(1))
    return files


def _crash_stacks_match(orig_text: str, new_text: str) -> bool:
    """Two-tier crash matching: exact (top-3 overlap) then same-vulnerability.

    Tier 1: Any overlap in top-3 project-code functions (fast, high confidence).
    Tier 2: Same sanitizer class + same access direction + overlapping call
            chain (any depth) + same source file area.
    """
    # Tier 1: top-3 function overlap (original strict check)
    orig_top3 = _extract_crash_funcs(orig_text, limit=3)
    new_top3 = _extract_crash_funcs(new_text, limit=3)
    if orig_top3 and new_top3 and set(orig_top3) & set(new_top3):
        return True

    # If the reference crash log has no usable data (e.g. build failed during
    # collect_crash), accept any sanitizer crash rather than rejecting it.
    if not orig_top3 and not _extract_crash_funcs(orig_text):
        logger.info("Reference crash log has no stack data — accepting any sanitizer crash")
        return True

    # Tier 2: same-vulnerability match
    orig_class, orig_dir = _extract_sanitizer_class(orig_text)
    new_class, new_dir = _extract_sanitizer_class(new_text)

    # 2a. Same sanitizer class
    if orig_class and new_class and orig_class != new_class:
        logger.warning(
            "Crash class mismatch: original=%s new=%s",
            orig_class, new_class,
        )
        return False

    # 2b. Same access direction
    if orig_dir and new_dir and orig_dir != new_dir:
        logger.warning(
            "Crash direction mismatch: original=%s new=%s",
            orig_dir, new_dir,
        )
        return False

    # 2c. Overlapping call chain (full depth, including allocation stack)
    orig_all = set(_extract_crash_funcs(orig_text))
    new_all = set(_extract_crash_funcs(new_text))
    chain_overlap = orig_all & new_all
    if not chain_overlap:
        logger.warning(
            "No overlapping functions in full call chain: "
            "original=%s new=%s",
            sorted(orig_all)[:5], sorted(new_all)[:5],
        )
        return False

    # 2d. Same source file area
    orig_files = _extract_crash_files(orig_text)
    new_files = _extract_crash_files(new_text)
    if orig_files and new_files and not orig_files & new_files:
        logger.warning(
            "No overlapping crash source files: original=%s new=%s",
            sorted(orig_files), sorted(new_files),
        )
        return False

    logger.info(
        "Crash accepted via same-vulnerability match: class=%s dir=%s "
        "shared_funcs=%s shared_files=%s",
        new_class, new_dir, sorted(chain_overlap),
        sorted(orig_files & new_files) if orig_files and new_files else "n/a",
    )
    return True


_CMD_OUTPUT_MAX_LINES = 30


def _format_codex_output(jsonl_output: str) -> str:
    """Convert codex --json JSONL output to agent-message-only summary.

    Only keeps AGENT: messages (the reasoning/status updates).
    Command outputs are omitted — full output is in the .jsonl file.
    """
    import json as _json
    lines = []
    for raw in jsonl_output.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            ev = _json.loads(raw)
        except _json.JSONDecodeError:
            continue
        if ev.get("type") != "item.completed":
            continue
        item = ev.get("item", {})
        if item.get("type") == "agent_message":
            text = item.get("text", "")
            if text:
                lines.append(f"\n{'='*60}")
                lines.append(f"AGENT:")
                lines.append(text)
    return "\n".join(lines) + "\n" if lines else jsonl_output


def _exec(container_name: str, command: str, user: str | None = None) -> int:
    """docker exec a command, printing output to console."""
    cmd = ["docker", "exec"]
    if user:
        cmd += ["-u", user]
    cmd += [container_name, "bash", "-c", command]
    return subprocess.call(cmd)


def _exec_capture(
    container_name: str, command: str, timeout: int = 3600,
) -> tuple[int, str]:
    """docker exec a command, capturing output."""
    cmd = ["docker", "exec", container_name, "bash", "-c", command]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        output = result.stdout + result.stderr
        return result.returncode, output
    except subprocess.TimeoutExpired:
        logger.error("Command timed out after %ds", timeout)
        return 124, f"TIMEOUT after {timeout}s"


def _exec_interactive(
    container_name: str, command: str, timeout: int = 3600,
) -> tuple[int, str]:
    """Run *command* inside a container with an interactive TTY via tmux.

    Launches a tmux session that runs ``docker exec -it`` so the Codex TUI
    gets a proper PTY, then attaches so the user can interact.  Uses
    ``tmux pipe-pane`` to capture all terminal output for cost tracking.

    Returns ``(exit_code, captured_output)`` — same signature as
    :func:`_exec_capture` so callers can handle both modes uniformly.
    """
    session = f"codex_{os.getpid()}_{int(time.time())}"
    exit_file = f"/tmp/.codex_exit_{session}"
    log_file = f"/tmp/.codex_log_{session}"
    Path(exit_file).unlink(missing_ok=True)
    Path(log_file).unlink(missing_ok=True)

    docker_cmd = (
        f"docker exec -it {container_name} bash -c {shlex.quote(command)}"
    )
    inner = f"{docker_cmd}; echo $? > {exit_file}"

    try:
        subprocess.run(
            ["tmux", "new-session", "-d", "-s", session, "bash", "-c", inner],
            check=True,
        )
    except FileNotFoundError:
        logger.error("tmux not found — install tmux for interactive mode")
        return 1, ""
    except subprocess.CalledProcessError as exc:
        logger.error("Failed to create tmux session: %s", exc)
        return 1, ""

    # Capture all pane output to a log file for cost tracking.
    subprocess.run(
        ["tmux", "pipe-pane", "-t", session, f"cat >> {log_file}"],
        check=False,
    )

    # Attach blocks until the session ends (command finishes).
    subprocess.call(["tmux", "attach-session", "-t", session])

    # Read captured output
    output = ""
    try:
        output = Path(log_file).read_text(errors="replace")
    except FileNotFoundError:
        logger.warning("No captured output from tmux pipe-pane")
    finally:
        Path(log_file).unlink(missing_ok=True)

    try:
        exit_code = int(Path(exit_file).read_text().strip())
    except (FileNotFoundError, ValueError):
        logger.warning("Could not read exit code from %s", exit_file)
        exit_code = 1
    finally:
        Path(exit_file).unlink(missing_ok=True)

    return exit_code, output


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bug transplant via Codex inside OSS-Fuzz container",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Full pipeline
              sudo -E python3 script/bug_transplant.py wavpack \\
                --buggy-commit 348ff60b --target-commit 0b99613e \\
                --bug-id OSV-2020-1006 --fuzzer-name fuzzer_decode_file \\
                --testcase testcase-OSV-2020-1006

              # Skip data collection, keep container alive for debugging
              sudo -E python3 script/bug_transplant.py wavpack \\
                --buggy-commit 348ff60b --target-commit 0b99613e \\
                --bug-id OSV-2020-1006 --fuzzer-name fuzzer_decode_file \\
                --testcase testcase-OSV-2020-1006 \\
                --skip-collect --keep-container
        """),
    )

    # Required
    parser.add_argument("project", help="OSS-Fuzz project name")
    parser.add_argument("--buggy-commit", required=True,
                        help="Commit hash where the bug exists")
    parser.add_argument("--target-commit", required=True,
                        help="Current/fixed commit to transplant into")
    parser.add_argument("--bug-id", required=True,
                        help="Bug identifier (e.g. OSV-2020-1006)")
    parser.add_argument("--fuzzer-name", required=True,
                        help="Fuzzer binary name (e.g. fuzzer_decode_file)")
    parser.add_argument("--testcase", required=True,
                        help="Testcase filename (must exist in testcases dir)")

    # Data collection
    parser.add_argument("--testcases-dir",
                        default=os.environ.get("TESTCASES", ""),
                        help="Directory containing testcase files "
                             "(default: $TESTCASES env var)")
    parser.add_argument("--repo-path",
                        default=os.environ.get("REPO_PATH", ""),
                        help="Local git repo of the target project for fix-diff generation "
                             "(default: $REPO_PATH env var)")
    parser.add_argument("--adjacent-commit", default=None,
                        help="First CSV commit after the buggy commit toward target "
                             "(pre-computed by bug_transplant_batch.py)")
    parser.add_argument("--build-csv", default=None,
                        help="Build CSV mapping commits to OSS-Fuzz versions")
    parser.add_argument("--runner-image", default=None,
                        help="Base runner image (e.g. 'auto')")
    parser.add_argument("--skip-collect", action="store_true",
                        help="Skip crash/trace collection (data already exists)")

    # Agent
    parser.add_argument("--model", default=None,
                        help="Model to use (passed to agent CLI)")
    parser.add_argument("--timeout", type=int, default=3600,
                        help="Timeout in seconds for agent (default: 3600)")
    parser.add_argument("--codex-mode", choices=["exec", "interactive"],
                        default="exec",
                        help="Agent invocation mode: exec (default, JSONL) "
                             "or interactive (TUI via tmux)")

    # Docker
    parser.add_argument("--keep-container", action="store_true",
                        help="Keep container alive after completion for debugging")
    parser.add_argument("--container-name", default=None,
                        help="Reuse an existing container (batch mode)")
    parser.add_argument("--agents-dir", default=None,
                        help="Shared AGENTS.md directory (batch mode)")
    parser.add_argument("-e", "--env", action="append",
                        help="Additional env vars for container (VAR=value)")
    parser.add_argument("-v", "--volume", action="append",
                        help="Additional volume mounts (host:container)")

    # Logging
    parser.add_argument("--verbose", "-V", action="store_true",
                        help="Verbose logging")

    return parser


def main() -> int:
    global _usage_tracker

    parser = build_parser()
    args = parser.parse_args()

    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # Initialize codex token tracker
    from codex_usage import CodexUsageTracker
    _usage_tracker = CodexUsageTracker()

    # Validate testcases dir
    if not args.testcases_dir:
        logger.error(
            "Testcases directory not specified. "
            "Set --testcases-dir or $TESTCASES environment variable."
        )
        return 1

    buggy_short = args.buggy_commit[:8]

    # ------------------------------------------------------------------
    # Phase 0: Collect crash and trace data
    # ------------------------------------------------------------------
    if not args.skip_collect:
        logger.info("=== Phase 0: Collecting crash and trace data ===")
        if not collect_crash_data(args):
            logger.error("Failed to collect crash data")
            return 1
        if not collect_trace_data(args):
            logger.warning("Failed to collect trace data (non-fatal, agent will work without it)")
    else:
        logger.info("=== Phase 0: Skipped (--skip-collect) ===")
        # Verify data exists
        crash_file = DATA_DIR / "crash" / f"target_crash-{buggy_short}-{args.testcase}.txt"
        trace_file = DATA_DIR / f"target_trace-{buggy_short}-{args.testcase}.txt"
        missing = []
        if not crash_file.exists():
            missing.append(str(crash_file))
        if not trace_file.exists():
            missing.append(str(trace_file))
        if missing:
            logger.warning("Missing data files (agent will work without them):")
            for f in missing:
                logger.warning("  %s", f)

    # Fix diff: generate for standalone runs (batch pre-generates these already)
    if args.repo_path:
        project_repo = os.path.join(args.repo_path, args.project)
        args.repo_path = project_repo if os.path.isdir(project_repo) else args.repo_path
        collect_fix_diff(args)

    # ------------------------------------------------------------------
    # Phase 1: Build Docker images
    # ------------------------------------------------------------------
    logger.info("=== Phase 1: Building Docker images ===")
    project_image = build_project_image(args.project)
    agent_image = build_agent_image(args.project, project_image)

    # ------------------------------------------------------------------
    # Phase 2+3: Run Codex in container
    # ------------------------------------------------------------------
    logger.info("=== Phase 2+3: Running Codex in container ===")
    exit_code = run_agent_in_container(args)

    # ------------------------------------------------------------------
    # Phase 4: Report results
    # ------------------------------------------------------------------
    output_dir = DATA_DIR / "bug_transplant" / f"{args.project}_{args.bug_id}"
    diff_path = output_dir / "bug_transplant.diff"
    git_diff_path = output_dir / "git_diff.diff"

    logger.info("=== Results ===")
    logger.info("Output directory: %s", output_dir)
    if diff_path.exists() and diff_path.stat().st_size > 0:
        logger.info("Bug transplant diff: %s", diff_path)
    elif git_diff_path.exists() and git_diff_path.stat().st_size > 0:
        logger.info("Git diff (fallback): %s", git_diff_path)
    else:
        logger.warning("No diff produced -- check agent_output.txt for details")

    if (output_dir / "agent_output.txt").exists():
        logger.info("Agent output: %s", output_dir / "agent_output.txt")

    _usage_tracker.log_session_total()

    # Write usage stats to output dir so batch can aggregate
    if _usage_tracker.cost > 0 and output_dir.exists():
        import json
        usage_path = output_dir / "token_usage.json"
        usage_path.write_text(json.dumps({
            "input_tokens": _usage_tracker.input_tokens,
            "cached_input_tokens": _usage_tracker.cached_input_tokens,
            "output_tokens": _usage_tracker.output_tokens,
            "cost": round(_usage_tracker.cost, 6),
        }, indent=2))

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
