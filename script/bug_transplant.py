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
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

logger = logging.getLogger(__name__)

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

def build_project_image(project: str) -> str:
    """Build the OSS-Fuzz project image (if not already built).

    Returns the project image tag.
    """
    image_tag = f"gcr.io/oss-fuzz/{project}"

    # Check if already built
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


def build_claude_image(project: str, project_image: str) -> str:
    """Layer Claude Code CLI on top of the project image.

    Produces ``bug-transplant-<project>:latest``.  Follows the same pattern
    as ``runners/claude_runner.py:build_project_image()``.
    """
    tag = f"bug-transplant-{project}:latest"

    # Check cache
    ret = subprocess.call(
        ["docker", "image", "inspect", tag],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if ret == 0:
        logger.info("Claude agent image already exists: %s", tag)
        return tag

    logger.info("Building Claude agent image '%s' on top of '%s'...", tag, project_image)

    dockerfile_content = textwrap.dedent(f"""\
        FROM {project_image}

        ENV DEBIAN_FRONTEND=noninteractive

        # Node.js 20.x LTS + Claude Code CLI
        RUN apt-get update && apt-get install -y --no-install-recommends \\
                curl ca-certificates clangd sudo \\
            && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \\
            && apt-get install -y --no-install-recommends nodejs \\
            && npm install -g @anthropic-ai/claude-code \\
            && rm -rf /var/lib/apt/lists/*

        # Create a non-root user (Claude CLI refuses --dangerously-skip-permissions as root)
        RUN useradd -m -d /home/agent -s /bin/bash agent \\
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


def run_claude_in_container(args: argparse.Namespace) -> int:
    """Start container, run Claude Code, collect results.

    Returns 0 on success, non-zero on failure.
    """
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

    # Prepare CLAUDE.md mount
    claude_dir = setup_claude_md(args)

    # Prepare Claude credentials mount
    claude_home = Path.home() / ".claude"
    claude_json = Path.home() / ".claude.json"

    prompt = build_prompt(args)

    # --- Stop any existing container with the same name ---
    subprocess.call(
        ["docker", "rm", "-f", container_name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

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
        # CLAUDE.md for project guidance
        "-v", f"{claude_dir}/CLAUDE.md:/src/{args.project}/.claude/CLAUDE.md:ro",
        "-v", f"{claude_dir}/settings.json:/src/{args.project}/.claude/settings.json:ro",
    ]

    # Mount Claude credentials if they exist
    if claude_home.exists():
        docker_run_cmd += ["-v", f"{claude_home}:/tmp/.claude-src:ro"]
    if claude_json.exists():
        docker_run_cmd += ["-v", f"{claude_json}:/tmp/.claude.json.src:ro"]

    # Environment
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if anthropic_key:
        docker_run_cmd += ["-e", f"ANTHROPIC_API_KEY={anthropic_key}"]
    else:
        logger.warning("ANTHROPIC_API_KEY not set -- Claude Code will fail to call the API")

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
        _exec(container_name, f"sudo git checkout -f {args.target_commit}", user="root")

        # --- Copy testcase to /work for easier access ---
        _exec(
            container_name,
            f"cp /corpus/{args.testcase} /work/{args.testcase}",
            user="root",
        )
        _exec(container_name, "sudo chown -R agent:agent /src/ /out/ /work/ /data/ 2>/dev/null || true", user="root")

        # --- Setup Claude credentials ---
        _exec(
            container_name,
            "cp -r /tmp/.claude-src $HOME/.claude 2>/dev/null; "
            "rm -rf $HOME/.claude/projects 2>/dev/null; "
            "cp /tmp/.claude.json.src $HOME/.claude.json 2>/dev/null; "
            "true",
        )

        # --- Copy project CLAUDE.md into the agent's home ---
        _exec(
            container_name,
            f"mkdir -p /home/agent/.claude/projects/-src-{args.project}/; "
            f"cp /src/{args.project}/.claude/CLAUDE.md "
            f"/home/agent/.claude/projects/-src-{args.project}/CLAUDE.md 2>/dev/null; "
            f"cp /src/{args.project}/.claude/settings.json "
            f"/home/agent/.claude/projects/-src-{args.project}/settings.json 2>/dev/null; "
            "true",
        )

        # --- Run Claude Code ---
        logger.info("Running Claude Code (this may take a while)...")
        claude_cmd = _build_claude_command(prompt, args)

        start_time = time.monotonic()
        exit_code, output = _exec_capture(
            container_name, claude_cmd, timeout=args.timeout,
        )
        elapsed = time.monotonic() - start_time
        logger.info(
            "Claude Code finished in %.0fs (exit code %d, %d bytes output)",
            elapsed, exit_code, len(output),
        )

        # --- Save output ---
        output_dir = DATA_DIR / "bug_transplant" / f"{args.project}_{args.bug_id}"
        os.makedirs(output_dir, exist_ok=True)

        # Save raw Claude output
        (output_dir / "claude_output.txt").write_text(output)

        # Capture diff from the source tree (most reliable — doesn't
        # depend on Claude remembering to run "git diff > /out/...")
        _, git_diff = _exec_capture(
            container_name, f"cd /src/{args.project} && git diff",
        )
        diff_path = output_dir / "bug_transplant.diff"
        diff_path.write_text(git_diff)
        if git_diff.strip():
            logger.info("Bug transplant diff saved: %s (%d bytes)", diff_path, len(git_diff))
        else:
            logger.warning("Diff is empty -- Claude may not have produced changes")

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


def _build_claude_command(prompt: str, args: argparse.Namespace) -> str:
    """Build the ``claude -p ...`` shell command."""
    import shlex

    escaped = shlex.quote(prompt)
    cmd = f"claude -p {escaped} --output-format text --dangerously-skip-permissions"
    if args.claude_model:
        cmd += f" --model {shlex.quote(args.claude_model)}"
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

    # Claude Code
    parser.add_argument("--claude-model", default=None,
                        help="Claude model to use (default: CLI default)")
    parser.add_argument("--timeout", type=int, default=3600,
                        help="Timeout in seconds for Claude Code (default: 3600)")

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
    claude_image = build_claude_image(args.project, project_image)

    # ------------------------------------------------------------------
    # Phase 2+3: Run Claude Code in container
    # ------------------------------------------------------------------
    logger.info("=== Phase 2+3: Running Claude Code in container ===")
    exit_code = run_claude_in_container(args)

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
