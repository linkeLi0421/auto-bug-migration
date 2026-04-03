#!/usr/bin/env python3
"""Bug transplant launcher -- runs Claude Code inside an OSS-Fuzz container.

Workflow:
  Phase 0: Collect crash log and function trace via fuzz_helper.py
  Phase 1: Build Claude-layered Docker image on top of the project image
  Phase 2: Start persistent container with proper volumes
  Phase 3: Run Claude Code with the bug transplant prompt
  Phase 4: Collect output diff

Usage:
  # Full pipeline (collect data + run Claude Code):
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

  # Use a specific Claude model:
  sudo -E python3 script/bug_transplant.py wavpack \\
    ... \\
    --claude-model claude-sonnet-4-6
"""

from __future__ import annotations

import argparse
import logging
import os
import re
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

# Pin CLI versions for reproducibility.
# Update deliberately after testing with new versions.
AGENT_VERSIONS = {
    "claude": "2.1.81",   # @anthropic-ai/claude-code
    "codex": "0.116.0",   # @openai/codex
    "opencode": "latest",  # Go binary, installed via brew/curl
}

# Agent-specific configuration
AGENT_CONFIG = {
    "claude": {
        "npm_package": "@anthropic-ai/claude-code",
        "cli_name": "claude",
        "cli_entry": "@anthropic-ai/claude-code/cli.js",
        "api_key_env": "ANTHROPIC_API_KEY",
        "credentials_dir": ".claude",        # ~/.<this> on host
        "credentials_config": ".claude.json", # ~/.<this> on host
        "run_cmd": "claude -p {prompt} --output-format text --dangerously-skip-permissions",
        "model_flag": "--model",
    },
    "codex": {
        "npm_package": "@openai/codex",
        "cli_name": "codex",
        "cli_entry": "@openai/codex/bin/codex.js",
        "api_key_env": "OPENAI_API_KEY",
        "credentials_dir": ".codex",
        "credentials_config": None,
        "run_cmd": "codex exec --dangerously-bypass-approvals-and-sandbox {prompt}",
        "model_flag": "--model",
    },
    "opencode": {
        "npm_package": None,                  # Go binary, not npm
        "cli_name": "opencode",
        "cli_entry": None,                    # installed as Go binary
        "api_key_env": "ANTHROPIC_API_KEY",   # default; also supports OPENAI_API_KEY etc.
        "credentials_dir": ".opencode",
        "credentials_config": ".opencode.json",
        "run_cmd": "opencode run {prompt}",   # run subcommand, message as positional arg
        "model_flag": "-m",                   # -m provider/model format
    },
}

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

    logger.info("Running: %s", " ".join(cmd))
    ret = subprocess.call(cmd)
    if ret != 0:
        logger.error("collect_crash failed (exit %d)", ret)
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

    logger.info("Running: %s", " ".join(cmd))
    ret = subprocess.call(cmd)
    if ret != 0:
        logger.error("collect_trace failed (exit %d)", ret)
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
            capture_output=True, text=True,
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
# Phase 1: Build Docker image with Claude Code layered on top
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
        ret = subprocess.call(cmd)
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
    ret = subprocess.call(
        [sys.executable, str(helper_py), "build_image", project],
        cwd=str(OSS_FUZZ_DIR),
    )
    if ret != 0:
        logger.error("Failed to build project image for %s", project)
        sys.exit(1)

    return image_tag


def build_agent_image(project: str, project_image: str, agent: str = "claude") -> str:
    """Layer a code agent CLI on top of the project image.

    Produces ``bug-transplant-<project>:latest``.
    Supports agent types: ``claude``, ``codex``, ``opencode``.
    """
    cfg = AGENT_CONFIG[agent]
    version = AGENT_VERSIONS[agent]
    npm_pkg = cfg["npm_package"]
    cli_name = cfg["cli_name"]
    cli_entry = cfg["cli_entry"]
    tag = f"bug-transplant-{project}:latest"

    # Skip rebuild if the agent image already exists
    inspect = subprocess.run(
        ["docker", "image", "inspect", tag],
        capture_output=True,
    )
    if inspect.returncode == 0:
        logger.info("%s agent image already exists, reusing: %s", agent, tag)
        return tag

    logger.info("Building %s agent image '%s' on top of '%s'...", agent, tag, project_image)

    if npm_pkg:
        # Node.js-based agent (claude, codex)
        dockerfile_content = textwrap.dedent(f"""\
            # Stage 1: Install agent CLI on a modern base (glibc >= 2.28).
            FROM ubuntu:22.04 AS agent-builder
            ENV DEBIAN_FRONTEND=noninteractive
            RUN apt-get update && apt-get install -y --no-install-recommends \\
                    curl ca-certificates \\
                && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \\
                && apt-get install -y --no-install-recommends nodejs \\
                && npm install -g {npm_pkg}@{version} \\
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

            ENV HOME=/home/agent
            USER agent

            WORKDIR /src/{project}
            CMD ["sleep", "infinity"]
        """)
    else:
        # Go-based agent (opencode) — install via curl
        dockerfile_content = textwrap.dedent(f"""\
            # Stage 1: Install Go-based agent on a modern base.
            FROM ubuntu:22.04 AS agent-builder
            ENV DEBIAN_FRONTEND=noninteractive
            RUN apt-get update && apt-get install -y --no-install-recommends \\
                    curl ca-certificates \\
                && curl -fsSL https://opencode.ai/install | bash \\
                && rm -rf /var/lib/apt/lists/*

            # Stage 2: Project image with agent binary copied in.
            FROM {project_image}
            ENV DEBIAN_FRONTEND=noninteractive

            # Copy opencode binary
            COPY --from=agent-builder /root/.opencode/bin/{cli_name} /usr/local/bin/{cli_name}

            # sudo may not exist on older base images
            RUN apt-get update && apt-get install -y --no-install-recommends sudo \\
                && rm -rf /var/lib/apt/lists/* || true

            # Create a non-root user (some CLIs refuse to run as root)
            RUN (useradd -m -d /home/agent -s /bin/bash agent 2>/dev/null || true) \\
                && echo "agent ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \\
                && chown -R agent:agent /src/ /out/ /work/ || true

            ENV HOME=/home/agent
            USER agent

            WORKDIR /src/{project}
            CMD ["sleep", "infinity"]
        """)

    with tempfile.TemporaryDirectory() as tmpdir:
        df_path = Path(tmpdir) / "Dockerfile"
        df_path.write_text(dockerfile_content)
        ret = subprocess.call(
            ["docker", "build", "-t", tag, "-f", str(df_path), tmpdir],
        )
        if ret != 0:
            logger.error("Failed to build Claude agent image")
            sys.exit(1)

    logger.info("Claude agent image built: %s", tag)
    return tag


# ---------------------------------------------------------------------------
# Phase 2 + 3: Run Claude Code inside a persistent container
# ---------------------------------------------------------------------------

def build_prompt(args: argparse.Namespace) -> str:
    """Read the prompt template and fill in parameters."""
    template = PROMPT_TEMPLATE.read_text()
    buggy_short = args.buggy_commit[:8]

    adjacent_commit = getattr(args, 'adjacent_commit', None)
    if adjacent_commit:
        fix_diff_line = (
            f"\n- `/data/patch_diffs/fix_hint-{buggy_short}-{args.testcase}.diff` -- "
            f"diff from buggy commit to adjacent CSV commit `{adjacent_commit[:8]}` "
            f"(the next tested commit toward the fix — read this first)"
        )
        adjacent_commit_hint = (
            f" If available, start by reading"
            f" `/data/patch_diffs/fix_hint-{buggy_short}-{args.testcase}.diff`:"
            f" it is the diff from the buggy commit to the next tested commit"
            f" `{adjacent_commit[:8]}` and likely contains the fix."
        )
    else:
        fix_diff_line = ""
        adjacent_commit_hint = ""

    prompt = template.format(
        project=args.project,
        bug_id=args.bug_id,
        buggy_commit=args.buggy_commit,
        target_commit=args.target_commit,
        buggy_short=buggy_short,
        testcase_name=args.testcase,
        fuzzer_name=args.fuzzer_name,
        fix_diff_line=fix_diff_line,
        adjacent_commit=adjacent_commit or "",
        adjacent_commit_hint=adjacent_commit_hint,
    )
    return prompt


def _build_minimize_prompt(args: argparse.Namespace) -> str:
    """Read the minimize prompt template and fill in parameters."""
    template = MINIMIZE_TEMPLATE.read_text()
    return template.format(
        project=args.project,
        bug_id=args.bug_id,
        buggy_short=args.buggy_commit[:8],
        target_commit=args.target_commit,
        testcase_name=args.testcase,
        fuzzer_name=args.fuzzer_name,
    )


def setup_claude_dir(args: argparse.Namespace) -> Path:
    """Prepare a temporary directory containing Claude settings and CLAUDE.md.

    Returns the path to a temporary .claude/ directory that will be
    mounted into the container at /src/{project}/.claude/.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="bug_transplant_claude_"))
    claude_dir = tmpdir / ".claude"
    claude_dir.mkdir()

    # Write settings to allow all tools without prompting
    settings = claude_dir / "settings.json"
    settings.write_text(
        '{"permissions": {"allow": ["Bash(*)", "Read(*)", "Write(*)", '
        '"Edit(*)", "Glob(*)", "Grep(*)"],'
        '"deny": ["WebSearch", "WebFetch"]}}\n'
    )

    # Write opencode.json to allow all tools without prompting (for opencode agent)
    opencode_cfg = tmpdir / "opencode.json"
    opencode_cfg.write_text('{"permission": "allow"}\n')

    # Seed CLAUDE.md: use saved knowledge from a previous batch run if available,
    # otherwise fall back to the blank template.
    claude_md = claude_dir / "CLAUDE.md"
    saved_claude_md = (
        DATA_DIR / "bug_transplant"
        / f"batch_{args.project}_{args.target_commit[:8]}"
        / "CLAUDE.md"
    )
    if saved_claude_md.exists():
        claude_md.write_text(saved_claude_md.read_text())
        logger.info("Seeding CLAUDE.md from previous run: %s", saved_claude_md)
    else:
        template = MEMORY_TEMPLATE.read_text()
        claude_md.write_text(template.format(
            project=args.project,
            target_commit=args.target_commit,
            fuzzer_name=args.fuzzer_name,
        ))

    return claude_dir


def create_shared_container(
    project: str,
    target_commit: str,
    container_name: str,
    claude_dir: Path,
    agent: str = "claude",
    testcases_dir: str = "",
    env: list[str] | None = None,
    volume: list[str] | None = None,
) -> int:
    """Create a persistent container for batch bug transplant.

    Returns 0 on success, non-zero on failure.
    """
    cfg = AGENT_CONFIG[agent]
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
        "-v", f"{testcases_dir}:/corpus",
        "-v", f"{script_dir}:/script:ro",
        "-v", f"{out_dir}:/out",
        "-v", f"{work_dir}:/work",
        "-v", f"{claude_dir}/settings.json:/src/{project}/.claude/settings.json:ro",
        "-v", f"{claude_dir}/../opencode.json:/src/{project}/opencode.json:ro",
        "-v", f"{claude_dir}/CLAUDE.md:/src/{project}/CLAUDE.md",
    ]

    # Mount agent credentials
    cred_dir = Path.home() / cfg["credentials_dir"]
    if cred_dir.exists():
        docker_run_cmd += ["-v", f"{cred_dir}:/tmp/.agent-creds-src:ro"]
    cred_config = cfg.get("credentials_config")
    if cred_config:
        cred_config_path = Path.home() / cred_config
        if cred_config_path.exists():
            docker_run_cmd += ["-v", f"{cred_config_path}:/tmp/.agent-config-src:ro"]

    api_key = os.environ.get(cfg["api_key_env"], "")
    if api_key:
        docker_run_cmd += ["-e", f"{cfg['api_key_env']}={api_key}"]

    if env:
        for e in env:
            docker_run_cmd += ["-e", e]
    if volume:
        for v in volume:
            docker_run_cmd += ["-v", v]

    docker_run_cmd += [image_tag, "sleep", "infinity"]

    logger.info("Creating shared container: %s", container_name)
    ret = subprocess.call(docker_run_cmd)
    if ret != 0:
        logger.error("Failed to create shared container")
        return 1

    # Initial setup: git safe directory, checkout, credentials
    _exec(container_name, "git config --global --add safe.directory '*'", user="root")
    _exec(container_name, f"cd /src/{project} && git clean -fdx -e CLAUDE.md -e .claude/", user="root")
    _exec(container_name, f"cd /src/{project} && git checkout -f {target_commit}", user="root")
    _exec(container_name, "sudo chown -R agent:agent /src/ /out/ /work/ /data/ 2>/dev/null || true", user="root")

    # Setup agent credentials
    creds_dir = cfg["credentials_dir"]
    _exec(
        container_name,
        f"cp -r /tmp/.agent-creds-src /home/agent/{creds_dir} 2>/dev/null; "
        f"rm -rf /home/agent/{creds_dir}/projects 2>/dev/null; "
        f"chown -R agent:agent /home/agent/{creds_dir} 2>/dev/null; true",
        user="root",
    )
    if cfg.get("credentials_config"):
        _exec(
            container_name,
            f"cp /tmp/.agent-config-src /home/agent/{cfg['credentials_config']} 2>/dev/null; "
            f"chown agent:agent /home/agent/{cfg['credentials_config']} 2>/dev/null; true",
            user="root",
        )

    if agent == "claude":
        _exec(
            container_name,
            f"mkdir -p /home/agent/.claude/projects/-src-{project}/; "
            f"cp /src/{project}/.claude/settings.json "
            f"/home/agent/.claude/projects/-src-{project}/settings.json 2>/dev/null; "
            f"cp /src/{project}/CLAUDE.md "
            f"/home/agent/.claude/projects/-src-{project}/CLAUDE.md 2>/dev/null; "
            "true",
        )

    logger.info("Shared container ready: %s", container_name)
    return 0


def run_agent_in_container(args: argparse.Namespace) -> int:
    """Start container, run code agent, collect results.

    Returns 0 on success, non-zero on failure.
    """
    agent = getattr(args, "agent", "claude")
    cfg = AGENT_CONFIG[agent]

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

    # Use shared claude_dir if provided (batch mode), otherwise create new
    shared_claude_dir = getattr(args, "claude_dir", None)
    claude_dir = Path(shared_claude_dir) if shared_claude_dir else setup_claude_dir(args)
    owns_claude_dir = shared_claude_dir is None

    prompt = build_prompt(args)

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
            # OSS-Fuzz build env vars (required by /usr/local/bin/compile)
            "-e", "FUZZING_ENGINE=libfuzzer",
            "-e", "SANITIZER=address",
            "-e", "ARCHITECTURE=x86_64",
            "-e", f"FUZZING_LANGUAGE={language}",
            "-e", "HELPER=True",
            "-e", "MAKEFLAGS=--output-sync=line -j30",
            "-e", "CMAKE_BUILD_PARALLEL_LEVEL=30",
            "-e", "NINJA_STATUS=",
            "-e", "TERM=dumb",
            # Volumes
            "-v", f"{data_dir}:/data",
            "-v", f"{testcases_dir}:/corpus",
            "-v", f"{script_dir}:/script:ro",
            "-v", f"{out_dir}:/out",
            "-v", f"{work_dir}:/work",
            # Claude settings (ro) + CLAUDE.md as shared memory (rw)
            "-v", f"{claude_dir}/settings.json:/src/{args.project}/.claude/settings.json:ro",
            "-v", f"{claude_dir}/../opencode.json:/src/{args.project}/opencode.json:ro",
            "-v", f"{claude_dir}/CLAUDE.md:/src/{args.project}/CLAUDE.md",
        ]

        # Mount agent credentials (login mode)
        cred_dir = Path.home() / cfg["credentials_dir"]
        if cred_dir.exists():
            docker_run_cmd += ["-v", f"{cred_dir}:/tmp/.agent-creds-src:ro"]
        cred_config = cfg.get("credentials_config")
        if cred_config:
            cred_config_path = Path.home() / cred_config
            if cred_config_path.exists():
                docker_run_cmd += ["-v", f"{cred_config_path}:/tmp/.agent-config-src:ro"]

        # Environment — pass API key if set (fallback for non-login mode)
        api_key = os.environ.get(cfg["api_key_env"], "")
        if api_key:
            docker_run_cmd += ["-e", f"{cfg['api_key_env']}={api_key}"]

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
        ret = subprocess.call(docker_run_cmd)
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
        # --- Checkout target commit inside container ---
        logger.info("Checking out target commit %s...", args.target_commit)
        _exec(container_name, "git config --global --add safe.directory '*'", user="root")
        # Clean build artifacts (cmake-generated Makefiles, .o files, etc.)
        # before checkout so they don't pollute the git diff later.
        # Exclude .claude/ and .codex/ — they are bind-mounted for credentials.
        _exec(container_name, f"cd /src/{args.project} && git clean -fdx -e .claude/ -e .codex/", user="root")
        _exec(container_name, f"cd /src/{args.project} && git checkout -f {args.target_commit}", user="root")

        # --- Copy testcase to /work for easier access ---
        _exec(
            container_name,
            f"cp /corpus/{args.testcase} /work/{args.testcase}",
            user="root",
        )
        _exec(container_name, "sudo chown -R agent:agent /src/ /out/ /work/ /data/ 2>/dev/null || true", user="root")

        # --- Setup agent credentials (run as root to read host-owned 600 files) ---
        creds_dir = cfg["credentials_dir"]
        _exec(
            container_name,
            f"cp -r /tmp/.agent-creds-src /home/agent/{creds_dir} 2>/dev/null; "
            f"rm -rf /home/agent/{creds_dir}/projects 2>/dev/null; "
            f"chown -R agent:agent /home/agent/{creds_dir} 2>/dev/null; "
            "true",
            user="root",
        )
        if cfg.get("credentials_config"):
            _exec(
                container_name,
                f"cp /tmp/.agent-config-src /home/agent/{cfg['credentials_config']} 2>/dev/null; "
                f"chown agent:agent /home/agent/{cfg['credentials_config']} 2>/dev/null; true",
                user="root",
            )

        # --- Copy Claude settings into the agent's home (claude only) ---
        if agent == "claude":
            _exec(
                container_name,
                f"mkdir -p /home/agent/.claude/projects/-src-{args.project}/; "
                f"cp /src/{args.project}/.claude/settings.json "
                f"/home/agent/.claude/projects/-src-{args.project}/settings.json 2>/dev/null; "
                f"cp /src/{args.project}/CLAUDE.md "
                f"/home/agent/.claude/projects/-src-{args.project}/CLAUDE.md 2>/dev/null; "
                "true",
            )

        # --- Run agent ---
        logger.info("Running %s agent (this may take a while)...", agent)
        agent_cmd = _build_agent_command(prompt, args)

        start_time = time.monotonic()
        exit_code, output = _exec_capture(
            container_name, agent_cmd, timeout=args.timeout,
        )
        elapsed = time.monotonic() - start_time

        # claude exits 0 even on max-turns — detect from output text
        if exit_code == 0 and "Reached max turns" in output:
            logger.warning("Agent hit max turns limit — treating as failure")
            exit_code = 1

        if agent == "codex" and _usage_tracker:
            _usage_tracker.log_usage("transplant", output, getattr(args, "model", None))

        logger.info(
            "%s agent finished in %.0fs (exit code %d, %d bytes output)",
            agent, elapsed, exit_code, len(output),
        )

        # --- Save output ---
        output_dir = DATA_DIR / "bug_transplant" / f"{args.project}_{args.bug_id}"
        os.makedirs(output_dir, exist_ok=True)

        # Save raw Claude output
        (output_dir / "claude_output.txt").write_text(output)

        # Save full conversation JSONL (before next bug overwrites it)
        _, jsonl_list = _exec_capture(
            container_name,
            f"ls -t /home/agent/.claude/projects/-src-{args.project}/*.jsonl 2>/dev/null | head -1",
        )
        jsonl_path = jsonl_list.strip()
        if jsonl_path:
            subprocess.call(
                ["docker", "cp", f"{container_name}:{jsonl_path}",
                 str(output_dir / "conversation.jsonl")],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
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
            "':(exclude).claude/' ':(exclude).codex/' "
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
            f"cd /src/{args.project} && "
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

            # Force official build
            logger.info("Rebuilding with official compile...")
            ret_build, build_out = _exec_capture(
                container_name, "sudo -E compile 2>&1", timeout=300,
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

            # Run fuzzer with testcase
            fuzzer_path = f"/out/{fuzzer}"
            sym_path = "/out/llvm-symbolizer"
            verify_cmd = (
                f"export ASAN_OPTIONS=detect_leaks=0"
                f":external_symbolizer_path={sym_path}; "
                f"if [ ! -x {fuzzer_path} ]; then "
                f"echo 'ERROR: {fuzzer_path} not found'; exit 99; fi; "
                f"{fuzzer_path} -runs=10 /work/{testcase} 2>&1"
            )
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
                    # Extract crashing function (first #0 or #1 in project code)
                    def _extract_crash_funcs(text):
                        funcs = []
                        for m in re.finditer(r'#\d+\s+\S+ in (\S+)\s+/src/', text):
                            funcs.append(m.group(1))
                        return funcs[:3]  # top 3 functions in project code

                    orig_funcs = _extract_crash_funcs(orig_text)
                    new_funcs = _extract_crash_funcs(fuzz_out)
                    # Check if any of the top crash functions overlap
                    if orig_funcs and new_funcs and not set(orig_funcs) & set(new_funcs):
                        crash_matches = False
                        logger.warning(
                            "Crash stack MISMATCH: original=%s new=%s",
                            orig_funcs, new_funcs,
                        )

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
                minimize_cmd = _build_agent_command(minimize_prompt, args)
                min_start = time.monotonic()
                min_exit, min_output = _exec_capture(
                    container_name, minimize_cmd, timeout=args.timeout,
                )
                min_elapsed = time.monotonic() - min_start
                if agent == "codex" and _usage_tracker:
                    _usage_tracker.log_usage("minimize", min_output, getattr(args, "model", None))
                logger.info("Minimization finished in %.0fs (exit %d)",
                            min_elapsed, min_exit)
                (output_dir / "minimize_output.txt").write_text(min_output)

                # Re-save the (now minimized) diff via git diff
                _, min_diff = _exec_capture(
                    container_name,
                    f"cd /src/{args.project} && "
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

                # Re-verify after minimization (use agent's testcase)
                _exec_capture(
                    container_name,
                    f"if [ -f /out/{testcase} ]; then cp /out/{testcase} /work/{testcase}; "
                    f"elif [ ! -f /work/{testcase} ]; then cp /corpus/{testcase} /work/{testcase}; fi; true",
                )
                ret_fuzz2, fuzz_out2 = _exec_capture(
                    container_name, verify_cmd, timeout=120)
                has_crash2 = bool(re.search(
                    r'SUMMARY:\s*(Address|Memory|Undefined|Thread|Leak)Sanitizer',
                    fuzz_out2))
                if has_crash2:
                    logger.info("Post-minimize verification PASSED")
                    crash_out_path.write_text(fuzz_out2)
                else:
                    logger.warning("Post-minimize verification FAILED — "
                                   "keeping pre-minimize diff")
                    # Restore the unminimized diff
                    _, pre_min_diff = _exec_capture(
                        container_name,
                        f"cd /src/{args.project} && git diff")
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
                  f"cd /src/{args.project} && git checkout -f {args.target_commit} && "
                  f"git clean -fdx -e CLAUDE.md -e .claude/",
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
        # Clean up temp claude directory (only if we own it)
        if owns_claude_dir:
            shutil.rmtree(claude_dir.parent, ignore_errors=True)


def _build_agent_command(prompt: str, args: argparse.Namespace) -> str:
    """Build the CLI command for the selected agent."""
    import shlex

    agent = getattr(args, "agent", "claude")
    cfg = AGENT_CONFIG[agent]
    escaped = shlex.quote(prompt)

    # Build command from template
    cmd = cfg["run_cmd"].format(prompt=escaped)

    # Add model flag if specified
    model = getattr(args, "model", None)
    if model:
        cmd += f" {cfg['model_flag']} {shlex.quote(model)}"

    # Enable JSONL output for codex so we can parse token usage
    if agent == "codex":
        cmd += " --json"

    return cmd


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
            text=True,
            timeout=timeout,
        )
        output = result.stdout + result.stderr
        return result.returncode, output
    except subprocess.TimeoutExpired:
        logger.error("Command timed out after %ds", timeout)
        return 124, f"TIMEOUT after {timeout}s"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bug transplant via Claude Code inside OSS-Fuzz container",
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
    parser.add_argument("--agent", default="claude", choices=["claude", "codex", "opencode"],
                        help="Code agent to use (default: claude)")
    parser.add_argument("--model", default=None,
                        help="Model to use (passed to agent CLI)")
    parser.add_argument("--timeout", type=int, default=3600,
                        help="Timeout in seconds for agent (default: 3600)")

    # Docker
    parser.add_argument("--keep-container", action="store_true",
                        help="Keep container alive after completion for debugging")
    parser.add_argument("--container-name", default=None,
                        help="Reuse an existing container (batch mode)")
    parser.add_argument("--claude-dir", default=None,
                        help="Shared CLAUDE.md directory (batch mode)")
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
            logger.error("Failed to collect trace data")
            return 1
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
            logger.warning("Missing data files (Claude Code will work without them):")
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
    agent_image = build_agent_image(args.project, project_image, args.agent)

    # ------------------------------------------------------------------
    # Phase 2+3: Run Claude Code in container
    # ------------------------------------------------------------------
    logger.info("=== Phase 2+3: Running Claude Code in container ===")
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
        logger.warning("No diff produced -- check claude_output.txt for details")

    if (output_dir / "claude_output.txt").exists():
        logger.info("Claude output: %s", output_dir / "claude_output.txt")

    _usage_tracker.log_session_total()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
