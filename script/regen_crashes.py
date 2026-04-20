#!/usr/bin/env python3
"""Regenerate crash files for a transplant benchmark after rebasing the image.

For each bug in bug_metadata.json, runs the corresponding PoC seed file
against the built fuzz target, captures ASan output, writes
crashes/<bug_id>.txt, and updates crash_file/crash_line in bug_metadata.json.
"""
import json
import re
import subprocess
import sys
from pathlib import Path


def run_poc(image: str, fuzz_target: str, poc_host_path: Path,
            asan_options: str) -> tuple[int, str]:
    """Run PoC inside the image; return (exitcode, combined output)."""
    cmd = [
        "docker", "run", "--rm", "--entrypoint", "",
        "-v", f"{poc_host_path}:/tmp/testcase:ro",
        "-e", f"ASAN_OPTIONS={asan_options}",
        # Suppress UBSAN stack traces and continue past pre-existing UB (e.g.
        # ghostscript's gsromfs init shift-overflow) so the real ASan-detected
        # bug is the only report parsed out of the log.
        "-e", "UBSAN_OPTIONS=print_stacktrace=0:halt_on_error=0",
        image,
        # -runs=10 lets stack-use-after-return and some flaky heap bugs fire
        # consistently — a single execution often misses them.
        f"/out/{fuzz_target}", "-runs=10", "/tmp/testcase",
    ]
    result = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=60,
    )
    return result.returncode, result.stdout.decode("utf-8", errors="replace")


# Match an ASan stack frame line end-to-end. The function name may contain
# spaces (C++ signatures like `foo(int, bool)`), so capture it lazily up to
# the trailing "/...:<line>(:<col>)?" path token. Anchoring to end-of-line via
# re.MULTILINE prevents the function capture from swallowing the next frame.
CRASH_LINE_RE = re.compile(
    r"#\d+\s+0x[0-9a-f]+\s+in\s+(.+?)\s+(/[^\s:]+):(\d+)(?::\d+)?\s*$",
    re.MULTILINE,
)


def parse_first_project_frame(output: str, project_marker: str) -> tuple[str, int, str] | None:
    """Return (file, line, function) of the first stack frame inside project source."""
    for m in CRASH_LINE_RE.finditer(output):
        func, path, line = m.group(1), m.group(2), int(m.group(3))
        if project_marker in path:
            return path, line, func
    return None


PROJECT_REPO_NAME_OVERRIDES = {
    # OSS-Fuzz project name differs from the upstream checkout directory.
    "ghostscript": "ghostpdl",
}


def main() -> int:
    if len(sys.argv) not in (3, 4):
        print("Usage: regen_crashes.py <benchmark_dir> <runner_image> [project_repo_name]")
        return 2
    bench_dir = Path(sys.argv[1]).resolve()
    image = sys.argv[2]
    repo_name_override = sys.argv[3] if len(sys.argv) == 4 else None

    metadata_path = bench_dir / "bug_metadata.json"
    metadata = json.loads(metadata_path.read_text())
    project = metadata["project"]
    repo_name = (repo_name_override or PROJECT_REPO_NAME_OVERRIDES.get(project, project))
    fuzz_target = metadata.get("fuzz_target")
    if not fuzz_target:
        # Try benchmark.yaml
        for line in (bench_dir / "benchmark.yaml").read_text().splitlines():
            if line.startswith("fuzz_target:"):
                fuzz_target = line.split(":", 1)[1].strip()
                break
    if not fuzz_target:
        print("Cannot determine fuzz_target", file=sys.stderr)
        return 2

    asan_opts = "detect_leaks=0:detect_stack_use_after_return=1"
    project_marker = f"/src/{repo_name}/"
    crashes_dir = bench_dir / "crashes"
    seeds_dir = bench_dir / "seeds"

    changed = 0
    missing_seeds = []
    no_crash = []
    updated_bugs = {}

    for bug_id, info in metadata["bugs"].items():
        poc_candidates = [
            seeds_dir / f"testcase-{bug_id}-patched",
            seeds_dir / f"testcase-{bug_id}",
        ]
        poc = next((p for p in poc_candidates if p.is_file()), None)
        if poc is None:
            missing_seeds.append(bug_id)
            updated_bugs[bug_id] = info
            continue

        try:
            rc, out = run_poc(image, fuzz_target, poc, asan_opts)
        except subprocess.TimeoutExpired:
            print(f"{bug_id}: TIMEOUT")
            updated_bugs[bug_id] = info
            continue

        if "AddressSanitizer" not in out and "runtime error" not in out:
            no_crash.append(bug_id)
            updated_bugs[bug_id] = info
            print(f"{bug_id}: no crash detected (rc={rc})")
            continue

        (crashes_dir / f"{bug_id}.txt").write_text(out)

        frame = parse_first_project_frame(out, project_marker)
        new_info = dict(info)
        if frame:
            path, line, func = frame
            if (new_info.get("crash_file") != path
                    or new_info.get("crash_line") != line
                    or new_info.get("crash_function") != func):
                changed += 1
            new_info["crash_file"] = path
            new_info["crash_line"] = line
            new_info["crash_function"] = func
        updated_bugs[bug_id] = new_info
        print(f"{bug_id}: "
              f"{new_info.get('crash_function')} @ {new_info.get('crash_file')}:{new_info.get('crash_line')}")

    metadata["bugs"] = updated_bugs
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")

    print()
    print(f"Total bugs: {len(metadata['bugs'])}")
    print(f"Crash files regenerated: {len(metadata['bugs']) - len(missing_seeds) - len(no_crash)}")
    print(f"Bugs with updated crash location: {changed}")
    if missing_seeds:
        print(f"Missing PoC seeds: {missing_seeds}")
    if no_crash:
        print(f"No crash detected: {no_crash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
