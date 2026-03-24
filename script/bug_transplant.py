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

# Pin CLI versions for reproducibility.
# Update deliberately after testing with new versions.
AGENT_VERSIONS = {
    "claude": "2.1.81",   # @anthropic-ai/claude-code
    "codex": "0.116.0",            # @openai/codex
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
        "cli_entry": "@openai/codex/bin/codex.js",  # npm bin: codex -> bin/codex.js
        "api_key_env": "OPENAI_API_KEY",
        "credentials_dir": ".codex",
        "credentials_config": None,          # codex uses dir only
        "run_cmd": "codex exec --dangerously-bypass-approvals-and-sandbox {prompt}",
        "model_flag": "--model",
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
PROMPT_TEMPLATE = SCRIPT_DIR / "bug_transplant_prompt.md"
CLAUDE_MD_TEMPLATE = SCRIPT_DIR / "bug_transplant_claude.md"


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
    Supports agent types: ``claude``, ``codex``.
    """
    cfg = AGENT_CONFIG[agent]
    version = AGENT_VERSIONS[agent]
    npm_pkg = cfg["npm_package"]
    cli_name = cfg["cli_name"]
    cli_entry = cfg["cli_entry"]
    tag = f"bug-transplant-{project}:latest"

    # Always rebuild — the base project image may have changed
    logger.info("Building %s agent image '%s' on top of '%s'...", agent, tag, project_image)

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

    prompt = template.format(
        project=args.project,
        bug_id=args.bug_id,
        buggy_commit=args.buggy_commit,
        target_commit=args.target_commit,
        buggy_short=buggy_short,
        testcase_name=args.testcase,
        fuzzer_name=args.fuzzer_name,
    )
    return prompt


def setup_claude_md(args: argparse.Namespace) -> Path:
    """Prepare a temporary directory containing CLAUDE.md for mounting.

    Returns the path to a temporary .claude/ directory that will be
    mounted into the container at /src/{project}/.claude/.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="bug_transplant_claude_"))
    claude_dir = tmpdir / ".claude"
    claude_dir.mkdir()

    # Copy template as CLAUDE.md
    shutil.copy2(CLAUDE_MD_TEMPLATE, claude_dir / "CLAUDE.md")

    # Write settings to allow all tools without prompting
    settings = claude_dir / "settings.json"
    settings.write_text(
        '{"permissions": {"allow": ["Bash(*)", "Read(*)", "Write(*)", '
        '"Edit(*)", "Glob(*)", "Grep(*)"],'
        '"deny": ["WebSearch", "WebFetch"]}}\n'
    )

    return claude_dir


def run_agent_in_container(args: argparse.Namespace) -> int:
    """Start container, run code agent, collect results.

    Returns 0 on success, non-zero on failure.
    """
    agent = getattr(args, "agent", "claude")
    cfg = AGENT_CONFIG[agent]

    image_tag = f"bug-transplant-{args.project}:latest"
    container_name = f"bug-transplant-{args.project}-{args.bug_id}"
    buggy_short = args.buggy_commit[:8]

    # Prepare volumes
    data_dir = str(DATA_DIR)
    testcases_dir = str(Path(args.testcases_dir).resolve())
    script_dir = str(SCRIPT_DIR)
    out_dir = str(HOME_DIR / "build" / "out" / args.project)
    work_dir = str(HOME_DIR / "build" / "work" / args.project)

    # Ensure output directories exist
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(work_dir, exist_ok=True)

    # Prepare CLAUDE.md mount (used by claude; harmless for others)
    claude_dir = setup_claude_md(args)

    prompt = build_prompt(args)

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
        # CLAUDE.md for project guidance (claude only, harmless for others)
        "-v", f"{claude_dir}/CLAUDE.md:/src/{args.project}/.claude/CLAUDE.md:ro",
        "-v", f"{claude_dir}/settings.json:/src/{args.project}/.claude/settings.json:ro",
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

    try:
        # --- Checkout target commit inside container ---
        logger.info("Checking out target commit %s...", args.target_commit)
        _exec(container_name, "git config --global --add safe.directory '*'", user="root")
        # Clean build artifacts (cmake-generated Makefiles, .o files, etc.)
        # before checkout so they don't pollute the git diff later.
        _exec(container_name, f"cd /src/{args.project} && git clean -fdx", user="root")
        _exec(container_name, f"cd /src/{args.project} && git checkout -f {args.target_commit}", user="root")

        # --- Copy testcase to /work for easier access ---
        _exec(
            container_name,
            f"cp /corpus/{args.testcase} /work/{args.testcase}",
            user="root",
        )
        _exec(container_name, "sudo chown -R agent:agent /src/ /out/ /work/ /data/ 2>/dev/null || true", user="root")

        # --- Setup agent credentials (login mode) ---
        creds_dir = cfg["credentials_dir"]
        _exec(
            container_name,
            f"cp -r /tmp/.agent-creds-src $HOME/{creds_dir} 2>/dev/null; "
            f"rm -rf $HOME/{creds_dir}/projects 2>/dev/null; "
            "true",
        )
        if cfg.get("credentials_config"):
            _exec(
                container_name,
                f"cp /tmp/.agent-config-src $HOME/{cfg['credentials_config']} 2>/dev/null; true",
            )

        # --- Copy project CLAUDE.md into the agent's home (claude only) ---
        if agent == "claude":
            _exec(
                container_name,
                f"mkdir -p /home/agent/.claude/projects/-src-{args.project}/; "
                f"cp /src/{args.project}/.claude/CLAUDE.md "
                f"/home/agent/.claude/projects/-src-{args.project}/CLAUDE.md 2>/dev/null; "
                f"cp /src/{args.project}/.claude/settings.json "
                f"/home/agent/.claude/projects/-src-{args.project}/settings.json 2>/dev/null; "
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
        logger.info(
            "%s agent finished in %.0fs (exit code %d, %d bytes output)",
            agent, elapsed, exit_code, len(output),
        )

        # --- Save output ---
        output_dir = DATA_DIR / "bug_transplant" / f"{args.project}_{args.bug_id}"
        os.makedirs(output_dir, exist_ok=True)

        # Save raw Claude output
        (output_dir / "claude_output.txt").write_text(output)

        # Prefer the agent's own diff (saved by the agent during its run).
        # This only contains intentional changes — no build artifacts.
        # Fall back to git diff if the agent didn't save one.
        diff_path = output_dir / "bug_transplant.diff"
        agent_diff_ret = subprocess.call(
            ["docker", "cp",
             f"{container_name}:/out/bug_transplant.diff",
             str(diff_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        agent_diff = ""
        if agent_diff_ret == 0 and diff_path.exists():
            agent_diff = diff_path.read_text()

        if agent_diff.strip():
            logger.info("Using agent's diff: %s (%d bytes)", diff_path, len(agent_diff))
        else:
            # Fallback: capture from git (includes untracked files, excludes
            # agent config dirs and common build artifacts)
            logger.info("Agent didn't save diff, falling back to git diff")
            _, git_diff = _exec_capture(
                container_name,
                f"cd /src/{args.project} && "
                f"git add -AN -- . "
                f"':(exclude).claude/' ':(exclude).codex/' "
                f"':(exclude)build/' ':(exclude)_build/' "
                f"':(exclude)*.o' ':(exclude)*.a' ':(exclude)*.so' && "
                f"git diff -- . "
                f"':(exclude).claude/' ':(exclude).codex/'",
            )
            diff_path.write_text(git_diff)
            if git_diff.strip():
                logger.info("Git diff saved: %s (%d bytes)", diff_path, len(git_diff))
            else:
                logger.warning("Diff is empty -- agent may not have produced changes")

        # ---------------------------------------------------------------
        # Post-agent verification: rebuild with official `compile` and
        # check that the bug actually triggers.  The agent may have used
        # a non-standard build that produces different binaries.
        # ---------------------------------------------------------------
        if exit_code == 0 and (agent_diff.strip() if 'agent_diff' in dir() else True):
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

            # Copy testcase in case compile wiped /work
            _exec_capture(
                container_name,
                "cp /corpus/testcase-* /work/ 2>/dev/null; true",
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
            if has_crash:
                logger.info("Post-agent verification PASSED: bug triggers "
                            "with official build")
            else:
                logger.error(
                    "Post-agent verification FAILED: bug does NOT trigger "
                    "with official compile. The agent may have used a "
                    "non-standard build. exit=%d tail=%.300s",
                    ret_fuzz,
                    fuzz_out[-300:] if fuzz_out else "(empty)",
                )
                return 1

        return exit_code

    finally:
        if not args.keep_container:
            logger.info("Destroying container %s...", container_name)
            subprocess.call(
                ["docker", "rm", "-f", container_name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        else:
            logger.info(
                "Container kept alive: docker exec -it %s bash", container_name,
            )
        # Clean up temp CLAUDE.md directory
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
    parser.add_argument("--build-csv", default=None,
                        help="Build CSV mapping commits to OSS-Fuzz versions")
    parser.add_argument("--runner-image", default=None,
                        help="Base runner image (e.g. 'auto')")
    parser.add_argument("--skip-collect", action="store_true",
                        help="Skip crash/trace collection (data already exists)")

    # Agent
    parser.add_argument("--agent", default="claude", choices=["claude", "codex"],
                        help="Code agent to use (default: claude)")
    parser.add_argument("--model", default=None,
                        help="Model to use (passed to agent CLI)")
    parser.add_argument("--timeout", type=int, default=3600,
                        help="Timeout in seconds for agent (default: 3600)")

    # Docker
    parser.add_argument("--keep-container", action="store_true",
                        help="Keep container alive after completion for debugging")
    parser.add_argument("-e", "--env", action="append",
                        help="Additional env vars for container (VAR=value)")
    parser.add_argument("-v", "--volume", action="append",
                        help="Additional volume mounts (host:container)")

    # Logging
    parser.add_argument("--verbose", "-V", action="store_true",
                        help="Verbose logging")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

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

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
