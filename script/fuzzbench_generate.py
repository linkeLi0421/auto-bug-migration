#!/usr/bin/env python3
"""Generate a FuzzBench benchmark directory from bug transplant merge output.

Reads the merge output (summary.json, combined.diff, harness.diff, testcases/)
and the project's OSS-Fuzz build files to produce a self-contained FuzzBench
benchmark directory that can be dropped into fuzzbench/benchmarks/.

Usage:
    python3 script/fuzzbench_generate.py \
        --merge-dir data/merge_offline_c-blosc2_79e921d9 \
        --build-csv data/c-blosc2_builds.csv \
        --fuzz-target decompress_frame_fuzzer \
        --output-dir /tmp/fuzzbench_benchmarks
"""

import argparse
import csv
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
OSS_FUZZ_DIR = PROJECT_ROOT / "oss-fuzz"


def commit_merge_container(container_name: str, project: str,
                           target_commit: str) -> str:
    """Commit a running merge container as a Docker image.

    Returns the image tag (e.g. 'opensc-merge:6903aebf').
    """
    tag = f"{project}-merge:{target_commit[:8]}"
    logger.info("Committing container %s as image %s ...", container_name, tag)
    result = subprocess.run(
        ["docker", "commit", container_name, tag],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"docker commit failed: {result.stderr.strip()}")
    logger.info("Committed image: %s", tag)
    return tag


def generate_dockerfile_from_container(merge_image: str, project: str) -> str:
    """Generate a Dockerfile that uses a committed merge container as base.

    The merge container already has:
    - All apt packages installed
    - Source code cloned at /src/{project}
    - Patches previously applied (checkout_commit.py will reset, build.sh re-applies)

    FuzzBench's benchmark-builder pipeline will layer the fuzzer's compiler
    on top and run build.sh, which re-applies patches and recompiles with
    the fuzzer's $CC/$CXX.
    """
    return f"""# Use the committed merge container as base for identical build environment.
# This image has the exact same OS packages, library versions, and source tree
# that were used during bug transplant verification.
FROM {merge_image}

# The merge container runs as a non-root user (agent).  Switch back to root
# so downstream Dockerfiles (AFL++'s builder, benchmark-builder, etc.) can
# install packages and write to system directories.
USER root

# docker commit can snapshot a broken apt state - fix it so downstream
# Dockerfiles (e.g. AFL++'s builder.Dockerfile) can apt-get install.
RUN rm -rf /var/lib/apt/lists/* && mkdir -p /var/lib/apt/lists/partial && apt-get update

WORKDIR /src/{project}

# Keep ASan stack-use-after-return detection enabled for direct testcase replay.
ENV ASAN_OPTIONS="detect_leaks=0:detect_stack_use_after_return=1"

# Bug transplant patches (re-applied by build.sh after checkout_commit.py resets source)
COPY patches/ /src/patches/
COPY seeds/ /src/benchmark_seeds/
COPY build.sh $SRC/
"""


def read_summary(merge_dir: Path) -> dict:
    summary_path = merge_dir / "summary.json"
    with open(summary_path) as f:
        return json.load(f)


def copy_seed_candidates(merge_dir: Path, seeds_dir: Path) -> int:
    """Copy per-bug testcase candidates into the benchmark build context.

    These are not inserted into the FuzzBench corpus directly. build.sh uses
    them to create non-crashing variants and filters each candidate by replaying
    it once against the built target.
    """
    testcases_dir = merge_dir / "testcases"
    if not testcases_dir.is_dir():
        logger.warning("No testcase directory found for seed candidates: %s",
                       testcases_dir)
        return 0

    candidates = sorted(testcases_dir.glob("testcase-*-patched"))
    if not candidates:
        candidates = [
            p for p in sorted(testcases_dir.glob("testcase-*"))
            if not p.name.endswith("-patched")
        ]

    copied = 0
    for src in candidates:
        if not src.is_file():
            continue
        shutil.copy2(src, seeds_dir / src.name)
        copied += 1
    return copied


def read_oss_fuzz_commit(build_csv: Path, project: str, target_commit: str) -> str:
    """Read oss_fuzz_commit from builds CSV for the given target commit."""
    oss_fuzz_commit = None
    with open(build_csv) as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 3 and row[0] == project:
                oss_fuzz_commit = row[2]  # keep last as fallback
                if row[1] in target_commit or target_commit in row[1]:
                    return oss_fuzz_commit
    if oss_fuzz_commit:
        logger.warning("No exact commit match in CSV, using last entry: %s", oss_fuzz_commit)
        return oss_fuzz_commit
    raise ValueError(f"No entry for {project} in {build_csv}")


def get_oss_fuzz_commit_date(oss_fuzz_dir: Path, oss_fuzz_commit: str) -> str:
    """Get ISO 8601 date string from the oss-fuzz commit."""
    result = subprocess.run(
        ["git", "show", "-s", "--format=%ci", oss_fuzz_commit],
        cwd=oss_fuzz_dir, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Cannot get date for oss-fuzz commit {oss_fuzz_commit}")
    # Format: "2021-03-14 10:30:00 +0100" -> ISO 8601
    raw = result.stdout.strip()
    dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S %z")
    return dt.isoformat()


def get_oss_fuzz_commit_timestamp(oss_fuzz_dir: Path, oss_fuzz_commit: str) -> int:
    """Get unix timestamp of oss-fuzz commit."""
    result = subprocess.run(
        ["git", "show", "-s", "--format=%ct", oss_fuzz_commit],
        cwd=oss_fuzz_dir, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Cannot get timestamp for {oss_fuzz_commit}")
    return int(result.stdout.strip())


def get_builder_digest(oss_fuzz_dir: Path, oss_fuzz_commit: str,
                       override_digest: str = None) -> str:
    """Get base-builder image digest for reproducible builds."""
    if override_digest:
        d = override_digest
        if not d.startswith("sha256:"):
            d = f"sha256:{d}"
        return d

    timestamp = get_oss_fuzz_commit_timestamp(oss_fuzz_dir, oss_fuzz_commit)
    sys.path.insert(0, str(SCRIPT_DIR))
    from buildAndtest import get_base_builder_for_date
    digest = get_base_builder_for_date(timestamp)
    if not digest.startswith("sha256:"):
        digest = f"sha256:{digest}"
    return digest


def checkout_oss_fuzz(oss_fuzz_dir: Path, oss_fuzz_commit: str):
    """Checkout oss-fuzz repo to the specified commit (non-destructive)."""
    subprocess.run(
        ["git", "checkout", "-f", oss_fuzz_commit],
        cwd=oss_fuzz_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=True,
    )


def get_git_commit_date(repo_dir: Path, commit: str) -> str:
    """Get ISO 8601 date string for a commit in an arbitrary git repo."""
    result = subprocess.run(
        ["git", "show", "-s", "--format=%ci", commit],
        cwd=repo_dir, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Cannot get date for commit {commit} in {repo_dir}")
    raw = result.stdout.strip()
    dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S %z")
    return dt.isoformat()


def find_project_repo_for_commit(project: str, target_commit: str,
                                 oss_fuzz_dir: Path,
                                 project_repo_name: str) -> Path | None:
    """Find a local git checkout of the project that contains target_commit."""
    candidates = [
        oss_fuzz_dir / "build" / "work" / project_repo_name,
        PROJECT_ROOT / project,
        PROJECT_ROOT / project_repo_name,
        Path("/tmp") / f"{project}-upstream",
        Path("/tmp") / project_repo_name,
        Path("/tmp") / "OpenSC",
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        result = subprocess.run(
            ["git", "show", "-s", "--format=%ci", target_commit],
            cwd=candidate, capture_output=True, text=True,
        )
        if result.returncode == 0:
            return candidate
    return None


def generate_dockerfile(project: str, oss_fuzz_dir: Path, builder_digest: str,
                        dispatch_bytes: int) -> str:
    """Generate Dockerfile content from OSS-Fuzz project Dockerfile template."""
    src_dockerfile = oss_fuzz_dir / "projects" / project / "Dockerfile"
    content = src_dockerfile.read_text()

    # Remove depth restrictions (need full history for git checkout)
    content = content.replace("--depth 1", "")
    content = content.replace("--depth=1", "")

    # Pin base-builder to specific digest
    if not re.search(r"gcr\.io/oss-fuzz-base/base-builder@sha256:", content):
        content = re.sub(
            r"gcr\.io/oss-fuzz-base/base-builder(:[a-zA-Z0-9._-]+)?",
            f"gcr.io/oss-fuzz-base/base-builder@{builder_digest}",
            content,
        )

    # Fix old pip if needed
    if "pip3 install" in content and "pip3 install --upgrade pip" not in content:
        content = content.replace(
            "pip3 install",
            "pip3 install --upgrade pip && \\\n    pip3 install",
            1,
        )

    # FuzzBench's coverage builder extends the benchmark image and expects
    # basic download/archive tools to be present.
    if " apt-get install -y " in content:
        content = re.sub(
            r"(apt-get install -y\s+)([^\n]+)",
            lambda m: (m.group(1) + m.group(2) if all(
                pkg in m.group(2) for pkg in ("wget", "unzip")) else
                       m.group(1) + m.group(2).rstrip() + " wget unzip"),
            content,
            count=1,
        )

    # Add benchmark-specific env/config before the final COPY build.sh line.
    insert_lines = []
    if project == "opensc":
        insert_lines.extend([
            "# Keep ASan stack-use-after-return detection enabled for direct testcase replay.",
            'ENV ASAN_OPTIONS="detect_leaks=0:detect_stack_use_after_return=1"',
        ])
    insert_lines.extend([
        "# Bug transplant patches",
        "COPY patches/ /src/patches/",
        "COPY seeds/ /src/benchmark_seeds/",
    ])
    patch_lines = "\n".join(insert_lines)

    # Try to insert before the COPY build.sh line
    if re.search(r"COPY\s+build\.sh", content):
        content = re.sub(
            r"(COPY\s+build\.sh)",
            f"{patch_lines}\n\\1",
            content,
            count=1,
        )
    else:
        # Append at the end
        content += f"\n{patch_lines}\n"

    return content


def get_project_repo_name(project: str, dockerfile_content: str) -> str:
    """Infer the cloned source directory name from the OSS-Fuzz Dockerfile."""
    match = re.search(r"git clone\b.*?\s([A-Za-z0-9_.-]+)\s*$", dockerfile_content,
                      flags=re.MULTILINE)
    if match:
        return match.group(1)
    return project


def get_pinned_builder_digest(dockerfile_content: str) -> str | None:
    """Return the existing base-builder digest from a Dockerfile if present."""
    match = re.search(
        r"gcr\.io/oss-fuzz-base/base-builder@(?P<digest>sha256:[a-f0-9]+)",
        dockerfile_content,
    )
    if match:
        return match.group("digest")
    return None


def generate_build_sh(project: str, target_commit: str, fuzz_target: str,
                      oss_fuzz_dir: Path, dispatch_bytes: int,
                      merge_dir: Path = None) -> str:
    """Generate build.sh that checks out the target commit, applies patches, and builds."""
    # Use harness_build.sh from merge output if available (project-specific build)
    harness_build = merge_dir / "harness_build.sh" if merge_dir else None
    if harness_build and harness_build.exists():
        original = harness_build.read_text()
        logger.info("Using harness_build.sh from merge output")
    else:
        src_build_sh = oss_fuzz_dir / "projects" / project / "build.sh"
        original = src_build_sh.read_text()

    # Extract the original build commands (everything after the license header)
    # We'll find the first non-comment, non-shebang line
    lines = original.split("\n")
    build_start = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and not stripped.startswith("!"):
            build_start = i
            break

    original_build = "\n".join(lines[build_start:])

    # Modify seed corpus lines to prepend dispatch bytes
    # Replace direct zip commands that package seeds
    dispatch_prefixes = []
    for dispatch_value in [0] + [1 << i for i in range(dispatch_bytes * 8)]:
        prefix = dispatch_value.to_bytes(dispatch_bytes, "little")
        dispatch_prefixes.append(
            "'" + "".join(r"\x" + f"{byte:02x}" for byte in prefix) + "'"
        )
    dispatch_prefix_list = " ".join(dispatch_prefixes)

    build_sh = f"""#!/bin/bash -eu
# Generated by fuzzbench_generate.py for bug transplant evaluation

cd /src/{project}

# Checkout target commit
git checkout {target_commit}

# Apply dispatch harness first (modifies build system), then bug patches
if ! git apply --check /src/patches/harness.diff 2>/dev/null; then
    echo "Trying git apply --3way for harness.diff..."
    git apply --3way /src/patches/harness.diff
else
    git apply /src/patches/harness.diff
fi

if ! git apply --check /src/patches/combined.diff 2>/dev/null; then
    echo "Trying git apply --3way for combined.diff..."
    git apply --3way /src/patches/combined.diff
else
    git apply /src/patches/combined.diff
fi

# --- Fix library CMakeLists.txt for new source files from combined.diff ---
# combined.diff may create new .c files (e.g., zfp_getcell.c) that need to
# be added to the library's explicit source list.
if [ -d blosc ] && [ -f blosc/CMakeLists.txt ]; then
    for newfile in blosc/*.c; do
        base=$(basename "$newfile")
        if ! grep -q "$base" blosc/CMakeLists.txt 2>/dev/null; then
            echo "Adding $base to blosc/CMakeLists.txt"
            sed -i "/^set(SOURCES /s/)/ $base)/" blosc/CMakeLists.txt
        fi
    done
fi
"""

    original_build_patched = patch_project_build_commands(
        project, original_build, fuzz_target)

    build_sh += f"""
# --- Original build commands ---
{original_build_patched}

# --- Seed corpus: expand original seeds and per-bug testcase candidates ---
# FuzzBench uses $OUT/{{fuzz_target}}_seed_corpus.zip as initial corpus.
# Create one seed variant for the default path plus one for each dispatch bit.
# Per-bug reproducers are used only as source material: exact crashing inputs
# are filtered out before packaging.
seed_zip="$OUT/{fuzz_target}_seed_corpus.zip"
seed_target="$OUT/{fuzz_target}"
mkdir -p /tmp/seeds_dispatch /tmp/original_seeds /tmp/benchmark_seed_candidates

if [ -f "$seed_zip" ]; then
    unzip -q -o "$seed_zip" -d /tmp/original_seeds 2>/dev/null || true
    for f in /tmp/original_seeds/*; do
        [ -f "$f" ] || continue
        base=$(basename "$f")
        for dispatch in {dispatch_prefix_list}; do
            dispatch_name=$(printf '%s' "$dispatch" | tr -d '\\x')
            printf '%b' "$dispatch" | cat - "$f" > "/tmp/seeds_dispatch/${{base}}.dispatch_${{dispatch_name}}"
        done
    done
fi

if [ -d /src/benchmark_seeds ]; then
    for f in /src/benchmark_seeds/*; do
        [ -f "$f" ] || continue
        base=$(basename "$f")
        size=$(wc -c < "$f")
        [ "$size" -gt 0 ] || continue

        cp "$f" "/tmp/benchmark_seed_candidates/${{base}}.exact"
        # Zero the dispatch byte (byte 0): deactivates dispatch-gated patches
        # while keeping the full APDU conversation and card driver routing intact.
        cp "$f" "/tmp/benchmark_seed_candidates/${{base}}.dispatch_zero"
        printf '\\000' | dd of="/tmp/benchmark_seed_candidates/${{base}}.dispatch_zero" bs=1 seek=0 conv=notrunc 2>/dev/null || true
        for keep in 1 2 8 16 64 256 1024; do
            if [ "$size" -gt "$keep" ]; then
                head -c "$keep" "$f" > "/tmp/benchmark_seed_candidates/${{base}}.head_${{keep}}"
            fi
        done
        if [ "$size" -gt 1 ]; then
            head -c "$((size - 1))" "$f" > "/tmp/benchmark_seed_candidates/${{base}}.trim_1"
            cp "$f" "/tmp/benchmark_seed_candidates/${{base}}.zero_last"
            printf '\\000' | dd of="/tmp/benchmark_seed_candidates/${{base}}.zero_last" bs=1 seek="$((size - 1))" conv=notrunc 2>/dev/null || true
            cp "$f" "/tmp/benchmark_seed_candidates/${{base}}.ff_last"
            printf '\\377' | dd of="/tmp/benchmark_seed_candidates/${{base}}.ff_last" bs=1 seek="$((size - 1))" conv=notrunc 2>/dev/null || true
        fi
        if [ "$size" -gt 4 ]; then
            mid=$((size / 2))
            cp "$f" "/tmp/benchmark_seed_candidates/${{base}}.zero_mid"
            printf '\\000' | dd of="/tmp/benchmark_seed_candidates/${{base}}.zero_mid" bs=1 seek="$mid" conv=notrunc 2>/dev/null || true
            cp "$f" "/tmp/benchmark_seed_candidates/${{base}}.ff_mid"
            printf '\\377' | dd of="/tmp/benchmark_seed_candidates/${{base}}.ff_mid" bs=1 seek="$mid" conv=notrunc 2>/dev/null || true
        fi
    done
fi

if [ -x "$seed_target" ] && ls /tmp/benchmark_seed_candidates/* 1>/dev/null 2>&1; then
    for f in /tmp/benchmark_seed_candidates/*; do
        [ -f "$f" ] || continue
        if timeout 10s env ASAN_OPTIONS="${{ASAN_OPTIONS:-detect_leaks=0:detect_stack_use_after_return=1}}" "$seed_target" "$f" >/tmp/seed_replay.log 2>&1; then
            cp "$f" "/tmp/seeds_dispatch/poc_$(basename "$f")"
        fi
    done
fi

if ls /tmp/seeds_dispatch/* 1>/dev/null 2>&1; then
    rm -f "$seed_zip"
    zip -j -q "$seed_zip" /tmp/seeds_dispatch/*
fi
"""
    return build_sh


def patch_project_build_commands(project: str, original_build: str,
                                 fuzz_target: str) -> str:
    """Apply repo-specific fixes to benchmark build commands."""
    if project == "opensc":
        return patch_opensc_build_commands(original_build, fuzz_target)

    # Patch cmake to disable tests/benchmarks (they fail because
    # __bug_dispatch is only linked into fuzz targets, not the main library).
    patched = original_build
    if "cmake" in patched and "-DBUILD_TESTS" not in patched:
        patched = patched.replace(
            "-DBUILD_FUZZERS=ON",
            "-DBUILD_FUZZERS=ON -DBUILD_TESTS=OFF -DBUILD_BENCHMARKS=OFF -DBUILD_EXAMPLES=OFF",
        )
    return patched


def patch_opensc_build_commands(original_build: str, fuzz_target: str) -> str:
    """Build OpenSC with autotools, then relink the target with CXX if needed.

    OpenSC's autotools build links fuzzers as C programs. In FuzzBench the
    injected fuzzing engine archive needs the C++ runtime, so a plain CC link
    step fails. We first try the native build with ``CCLD=$CXX`` and explicit
    ``-lstdc++``. If autotools still doesn't emit the target binary, we reuse
    the built static libraries and relink the fuzz target manually with CXX.
    """
    lines = original_build.splitlines()
    bootstrap_line = "./bootstrap"
    for line in lines:
        stripped = line.strip()
        if stripped in {"./bootstrap", "autoreconf -fiv"}:
            bootstrap_line = stripped
            break

    configure_line = next(
        (line.strip() for line in lines if line.strip().startswith("./configure ")),
        None,
    )
    if configure_line is None:
        configure_line = (
            "./configure --disable-optimization --disable-shared "
            "--disable-pcsc --enable-ctapi --enable-fuzzing"
        )

    configure_line = re.sub(
        r'FUZZING_LIBS=\"[^\"]*\"',
        'FUZZING_LIBS="-lstdc++"',
        configure_line,
    )
    if 'FUZZING_LIBS=' not in configure_line:
        configure_line += ' FUZZING_LIBS="-lstdc++"'
    if 'CC="$CC"' not in configure_line:
        configure_line += ' CC="$CC"'
    if 'CXX="$CXX"' not in configure_line:
        configure_line += ' CXX="$CXX"'
    # Disable notify - it pulls in glib/gio which breaks the manual link step.
    if '--disable-notify' not in configure_line:
        configure_line += ' --disable-notify'

    return f"""# Clean stale build artifacts from the merge container (if any).
# Without this, make reuses .o/.a files compiled with a different compiler
# and libopensc.a may include notify.o with glib deps that break linking.
make distclean 2>/dev/null || true

{bootstrap_line}

# FuzzBench injects a prebuilt engine archive that needs a C++ link step.
{configure_line}

# Autotools/libtool can generate libopensc __bug_dispatch dep includes without
# creating the corresponding top-level .deps entries. Mirror the merge helper's
# workaround with explicit stub files for this project layout.
mkdir -p .deps
touch .deps/libopensc_la-__bug_dispatch.Plo \
      .deps/libopensc_la-__bug_dispatch.Tpo \
      .deps/libopensc_static_la-__bug_dispatch.Plo \
      .deps/libopensc_static_la-__bug_dispatch.Tpo

set +e
make -j$(nproc) CCLD="$CXX"
make_status=$?
if [ $make_status -ne 0 ]; then
    make -j1 CCLD="$CXX"
fi
set -e

FUZZ_LIB="${{LIB_FUZZING_ENGINE:-}}"
if [ ! -f "$FUZZ_LIB" ]; then
    for candidate in /usr/lib/libFuzzer.a /usr/lib/libFuzzingEngine.a; do
        if [ -f "$candidate" ]; then
            FUZZ_LIB="$candidate"
            break
        fi
    done
fi
if [ ! -f "$FUZZ_LIB" ]; then
    echo "Missing fuzzing engine archive: $LIB_FUZZING_ENGINE" >&2
    exit 1
fi

target_src="src/tests/fuzzing/{fuzz_target}.c"
target_obj="src/tests/fuzzing/{fuzz_target}.o"
target_bin="src/tests/fuzzing/{fuzz_target}"

if [ -x "$target_bin" ]; then
    cp "$target_bin" "$OUT/{fuzz_target}"
else
    if [ ! -f "$target_obj" ]; then
        $CC $CFLAGS -I. -Isrc -Isrc/libopensc -Isrc/common \\
            -c "$target_src" -o "$target_obj"
    fi

    $CXX $CXXFLAGS -o "$OUT/{fuzz_target}" \\
        "$target_obj" \\
        src/libopensc/.libs/libopensc.a \\
        src/common/.libs/libscdl.a \\
        src/common/.libs/libcompat.a \\
        "$FUZZ_LIB" \\
        -lcrypto -lz -ldl -lpthread -lstdc++
fi

if [ -d "src/tests/fuzzing/corpus/{fuzz_target}" ]; then
    zip -j "$OUT/{fuzz_target}_seed_corpus.zip" \\
        src/tests/fuzzing/corpus/{fuzz_target}/*
fi
"""


def generate_benchmark_yaml(project: str, fuzz_target: str, target_commit: str,
                            commit_date: str) -> str:
    """Generate benchmark.yaml content."""
    return f"""project: {project}
fuzz_target: {fuzz_target}
commit: {target_commit}
commit_date: {commit_date}
type: bug
"""


def _is_runtime_frame(filepath: str) -> bool:
    """Return True if the file path belongs to sanitizer/fuzzer runtime, not project code."""
    runtime_markers = ("/compiler-rt/", "/llvm-project/", "/lib/fuzzer/",
                       "/lib/asan/", "/lib/msan/", "/lib/ubsan/", "/lib/tsan/",
                       "/lib/lsan/", "/lib/dfsan/")
    return any(m in filepath for m in runtime_markers)


def parse_crash_line(crash_text: str) -> dict:
    """Parse ASAN/UBSAN crash output to extract crash file and line.

    Walks the stack trace to find the first frame in project source code,
    skipping sanitizer/fuzzer runtime frames. Falls back to the SUMMARY
    line only if no project frame is found.

    Returns dict with 'file', 'line', 'function' keys (any may be None).
    """
    result = {"file": None, "line": None, "function": None}

    # Walk stack frames: find the first one in project source (not runtime)
    for m in re.finditer(
            r"#\d+\s+\S+\s+in\s+(\S+)\s+(/\S+?):(\d+)", crash_text):
        filepath = m.group(2)
        if not _is_runtime_frame(filepath):
            result["function"] = m.group(1)
            result["file"] = filepath
            result["line"] = int(m.group(3))
            return result

    # Fallback: SUMMARY line (may point to runtime, but better than nothing)
    summary_match = re.search(
        r"SUMMARY:\s+\w+Sanitizer:\s+\S+\s+(/\S+?):(\d+)(?::\d+)?\s+in\s+(\S+)",
        crash_text)
    if summary_match:
        result["file"] = summary_match.group(1)
        result["line"] = int(summary_match.group(2))
        result["function"] = summary_match.group(3)
        return result

    return result


def collect_crash_lines_from_image(bench_dir: Path, summary: dict,
                                   fuzz_target: str) -> dict:
    """Collect crash lines by running PoCs against the built benchmark image.

    Builds the benchmark Docker image, then runs each bug's PoC inside the
    container to get crash output with correct post-merge line numbers.

    Returns dict: {bug_id: {"file": str, "line": int, "function": str}}
    """
    image_tag = f"crash-line-collector:{summary['project']}"
    dispatch_bytes = summary["dispatch_state"]["dispatch_bytes"]

    # Build the image
    logger.info("Building benchmark image for crash line collection...")
    result = subprocess.run(
        ["docker", "build", "-t", image_tag, str(bench_dir)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logger.error("Docker build failed:\n%s", result.stderr[-2000:])
        return {}

    # Build the fuzz target inside the container
    logger.info("Compiling fuzz target inside container...")
    container_name = f"crash-collect-{summary['project']}"
    subprocess.run(
        ["docker", "rm", "-f", container_name],
        capture_output=True,
    )
    result = subprocess.run(
        ["docker", "run", "--name", container_name,
         "-e", "SANITIZER=address",
         "-e", "FUZZING_ENGINE=libfuzzer",
         "-e", "FUZZING_LANGUAGE=c++",
         "-e", "ARCHITECTURE=x86_64",
         "-e", "SRC=/src",
         "-e", "WORK=/work",
         "-e", "OUT=/out",
         image_tag, "bash", "-lc", "sudo -E /usr/local/bin/compile"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logger.error("Compile failed:\n%s", result.stderr[-2000:])
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        return {}

    # Commit the compiled state
    compiled_tag = f"{image_tag}-compiled"
    subprocess.run(
        ["docker", "commit", container_name, compiled_tag],
        capture_output=True, check=True,
    )
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)

    # Run each bug's PoC
    crash_lines = {}
    testcases_dir = Path(summary.get("_merge_dir", "")) / "testcases"
    poc_bytes = summary["dispatch_state"]["poc_bytes"]

    # Save crash outputs for later inspection
    crash_output_dir = bench_dir / "crashes"
    crash_output_dir.mkdir(exist_ok=True)

    for bug_id in summary["results"]:
        # Find the PoC testcase
        poc_name = f"testcase-{bug_id}-patched"
        poc_path = testcases_dir / poc_name
        if not poc_path.exists():
            poc_name = f"testcase-{bug_id}"
            poc_path = testcases_dir / poc_name
        if not poc_path.exists():
            logger.debug("  %s: no PoC found", bug_id)
            continue

        # Run the PoC - use -runs=10 so stack-use-after-return bugs
        # have enough iterations for ASAN's fake stack to detect stale frames.
        result = subprocess.run(
            ["docker", "run", "--rm",
             "-v", f"{poc_path.resolve()}:/tmp/testcase:ro",
             "-e", "ASAN_OPTIONS=detect_leaks=0:detect_stack_use_after_return=1:max_uar_stack_size_log=16",
             compiled_tag,
             f"/out/{fuzz_target}", "-runs=10", "/tmp/testcase"],
            capture_output=True, text=True, timeout=30,
        )

        # Parse crash output (combine stdout + stderr)
        crash_text = result.stdout + result.stderr

        # Save full crash output
        crash_file = crash_output_dir / f"{bug_id}.txt"
        crash_file.write_text(crash_text)

        parsed = parse_crash_line(crash_text)
        if parsed["file"] and parsed["line"]:
            crash_lines[bug_id] = parsed
            logger.debug("  %s: %s:%d in %s",
                         bug_id, parsed["file"], parsed["line"],
                         parsed["function"] or "?")
        else:
            logger.warning("  %s: no crash line parsed (exit=%d, output=%d bytes)",
                           bug_id, result.returncode, len(crash_text))
            if crash_text:
                logger.debug("  %s output tail: %s", bug_id, crash_text[-500:])

    # Cleanup
    subprocess.run(["docker", "rmi", "-f", compiled_tag], capture_output=True)
    subprocess.run(["docker", "rmi", "-f", image_tag], capture_output=True)

    return crash_lines


def generate_bug_metadata(summary: dict, crash_lines: dict = None) -> dict:
    """Generate bug metadata for post-experiment triage."""
    dispatch_state = summary["dispatch_state"]
    bugs = {}
    for bug_id, bit_value in dispatch_state["poc_bytes"].items():
        bug_entry = {
            "dispatch_value": bit_value,
            "triggered": summary["results"].get(bug_id, False),
        }
        if crash_lines and bug_id in crash_lines:
            cl = crash_lines[bug_id]
            bug_entry["crash_file"] = cl["file"]
            bug_entry["crash_line"] = cl["line"]
            bug_entry["crash_function"] = cl["function"]
        bugs[bug_id] = bug_entry
    return {
        "project": summary["project"],
        "target_commit": summary["target_commit"],
        "dispatch_bytes": dispatch_state["dispatch_bytes"],
        "total_bugs": len(summary["results"]),
        "bugs": bugs,
    }


def generate_experiment_config(output_dir: Path, benchmark_name: str) -> str:
    """Generate a sample local experiment config."""
    return f"""# FuzzBench local experiment config
# Generated by fuzzbench_generate.py

trials: 3
max_total_time: 86400  # 24 hours per trial

local_experiment: true
experiment_filestore: {output_dir}/fuzzbench-data
report_filestore: {output_dir}/fuzzbench-reports
docker_registry: gcr.io/fuzzbench

# Sample run command:
# PYTHONPATH=. python3 experiment/run_experiment.py \\
#   --experiment-config experiment_config.yaml \\
#   --benchmarks {benchmark_name} \\
#   --fuzzers afl aflplusplus honggfuzz libfuzzer \\
#   --experiment-name transplant-eval
"""


def main():
    parser = argparse.ArgumentParser(
        description="Generate FuzzBench benchmark from bug transplant merge output",
    )
    parser.add_argument("--merge-dir", required=True,
                        help="Path to merge output directory (contains summary.json)")
    parser.add_argument("--build-csv", required=True,
                        help="Path to builds CSV (maps commits to oss-fuzz commits)")
    parser.add_argument("--fuzz-target", required=True,
                        help="Fuzz target name (e.g., decompress_frame_fuzzer)")
    parser.add_argument("--output-dir", default=str(PROJECT_ROOT / "fuzzbench-output"),
                        help="Output directory for generated benchmark(s) (default: fuzzbench-output/)")
    parser.add_argument("--oss-fuzz-dir", default=str(OSS_FUZZ_DIR),
                        help="Path to local oss-fuzz checkout")
    parser.add_argument("--builder-digest",
                        help="Override base-builder digest (e.g., sha256:abc...)")
    parser.add_argument("--benchmark-name",
                        help="Custom benchmark name (default: {project}_transplant_{target})")
    parser.add_argument(
        "--use-current-oss-fuzz-checkout",
        action="store_true",
        help=("Use the current local oss-fuzz checkout exactly as-is instead of "
              "checking out the commit from builds.csv. This is useful when the "
              "merge workflow already prepared a historical OSS-Fuzz environment."),
    )
    parser.add_argument(
        "--merge-container",
        help=("Name of a running merge container (e.g. 'bug-merge-opensc') to "
              "commit as a Docker image and use as the benchmark's Dockerfile "
              "base.  This guarantees the FuzzBench build environment is "
              "identical to the one that verified the bugs."),
    )
    parser.add_argument(
        "--fuzzer", nargs="+",
        help=("Fuzzer(s) to build after generation (e.g. 'aflplusplus libfuzzer'). "
              "Runs 'make build-{fuzzer}-{benchmark}' in the FuzzBench directory."),
    )
    parser.add_argument(
        "--fuzzbench-dir",
        help="Path to FuzzBench checkout (default: auto-detect from output-dir or PROJECT_ROOT/fuzzbench)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    merge_dir = Path(args.merge_dir)
    build_csv = Path(args.build_csv)
    oss_fuzz_dir = Path(args.oss_fuzz_dir)
    output_base = Path(args.output_dir)

    # 1. Read merge summary
    summary = read_summary(merge_dir)
    project = summary["project"]
    target_commit = summary["target_commit"]
    dispatch_bytes = summary["dispatch_state"]["dispatch_bytes"]
    logger.info("Project: %s, commit: %s, dispatch_bytes: %d, bugs: %d",
                project, target_commit[:8], dispatch_bytes, len(summary["results"]))

    # 2. Commit merge container if requested (before any OSS-Fuzz checkout).
    merge_image = None
    if args.merge_container:
        merge_image = commit_merge_container(
            args.merge_container, project, target_commit)

    # 3. Select the OSS-Fuzz project files to mirror into the benchmark.
    if args.use_current_oss_fuzz_checkout:
        oss_fuzz_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=oss_fuzz_dir, capture_output=True, text=True, check=True,
        ).stdout.strip()
        logger.info("Using current OSS-Fuzz checkout: %s", oss_fuzz_commit)
    else:
        oss_fuzz_commit = read_oss_fuzz_commit(build_csv, project, target_commit)
        logger.info("OSS-Fuzz commit from builds.csv: %s", oss_fuzz_commit)
        checkout_oss_fuzz(oss_fuzz_dir, oss_fuzz_commit)

    src_dockerfile = oss_fuzz_dir / "projects" / project / "Dockerfile"
    dockerfile_content = src_dockerfile.read_text()
    project_repo_name = get_project_repo_name(project, dockerfile_content)
    project_repo_dir = find_project_repo_for_commit(
        project, target_commit, oss_fuzz_dir, project_repo_name)
    if project_repo_dir:
        commit_date = get_git_commit_date(project_repo_dir, target_commit)
        logger.info("Target project commit date: %s", commit_date)
    else:
        commit_date = get_oss_fuzz_commit_date(oss_fuzz_dir, oss_fuzz_commit)
        logger.warning(
            "Project source repo for %s not found locally, falling back to OSS-Fuzz commit date %s",
            target_commit[:12], commit_date)

    # 4. Preserve the same builder image the selected OSS-Fuzz project uses.
    if not merge_image:
        pinned_builder_digest = get_pinned_builder_digest(dockerfile_content)
        builder_digest = (
            args.builder_digest
            or pinned_builder_digest
            or get_builder_digest(oss_fuzz_dir, oss_fuzz_commit)
        )
        if not builder_digest.startswith("sha256:"):
            builder_digest = f"sha256:{builder_digest}"
        logger.info("Builder digest: %s", builder_digest)

    # 5. Create benchmark directory
    fuzz_target = args.fuzz_target
    benchmark_name = args.benchmark_name or f"{project}_transplant_{fuzz_target}"
    bench_dir = output_base / benchmark_name
    bench_dir.mkdir(parents=True, exist_ok=True)
    patches_dir = bench_dir / "patches"
    patches_dir.mkdir(exist_ok=True)
    seeds_dir = bench_dir / "seeds"
    seeds_dir.mkdir(exist_ok=True)

    # 6. Generate Dockerfile
    if merge_image:
        dockerfile = generate_dockerfile_from_container(merge_image, project)
        logger.info("Generated Dockerfile from merge container image %s", merge_image)
    else:
        dockerfile = generate_dockerfile(project, oss_fuzz_dir, builder_digest, dispatch_bytes)
        logger.info("Generated Dockerfile from OSS-Fuzz template")
    (bench_dir / "Dockerfile").write_text(dockerfile)

    # 7. Generate build.sh
    build_sh = generate_build_sh(project, target_commit, fuzz_target,
                                 oss_fuzz_dir, dispatch_bytes,
                                 merge_dir=merge_dir)
    (bench_dir / "build.sh").write_text(build_sh)
    os.chmod(bench_dir / "build.sh", 0o755)
    logger.info("Generated build.sh")

    # 8. Generate benchmark.yaml
    yaml_content = generate_benchmark_yaml(project, fuzz_target, target_commit, commit_date)
    (bench_dir / "benchmark.yaml").write_text(yaml_content)
    logger.info("Generated benchmark.yaml")

    # 9. Copy patches
    for patch_name in ["combined.diff", "harness.diff"]:
        src = merge_dir / patch_name
        if src.exists():
            shutil.copy2(src, patches_dir / patch_name)
            logger.info("Copied %s (%d bytes)", patch_name, src.stat().st_size)
        else:
            logger.warning("Patch not found: %s", src)

    copied_seed_candidates = copy_seed_candidates(merge_dir, seeds_dir)
    logger.info("Copied %d seed candidate testcases", copied_seed_candidates)

    # 10. Collect crash lines by running PoCs against the merged binary
    summary["_merge_dir"] = str(merge_dir)
    crash_lines = collect_crash_lines_from_image(bench_dir, summary, fuzz_target)
    logger.info("Found crash lines for %d/%d bugs", len(crash_lines), len(summary["results"]))

    # 11. Generate bug metadata (with crash lines)
    bug_meta = generate_bug_metadata(summary, crash_lines)
    meta_path = bench_dir / "bug_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(bug_meta, f, indent=2)
    logger.info("Generated bug_metadata.json (%d bugs, %d with crash lines)",
                len(bug_meta["bugs"]), len(crash_lines))

    # 12. Generate sample experiment config
    config = generate_experiment_config(output_base, benchmark_name)
    (output_base / "experiment_config.yaml").write_text(config)

    # Summary
    logger.info("=" * 60)
    logger.info("Benchmark generated: %s", bench_dir)
    logger.info("  Bugs: %d total (%d triggered at merge time)",
                len(summary["results"]),
                sum(1 for v in summary["results"].values() if v))
    logger.info("  Dispatch bytes: %d", dispatch_bytes)
    logger.info("  Crash lines: %d/%d bugs",
                len(crash_lines), len(summary["results"]))
    bugs_missing = [b for b in summary["results"] if b not in crash_lines]
    if bugs_missing:
        logger.info("  Missing crash lines: %s", bugs_missing)

    # ------------------------------------------------------------------
    # 13. Build with FuzzBench
    # ------------------------------------------------------------------
    if args.fuzzer:
        fuzzbench_dir = _resolve_fuzzbench_dir(args.fuzzbench_dir, bench_dir)
        if not fuzzbench_dir:
            logger.error("Cannot find FuzzBench directory. Use --fuzzbench-dir.")
            sys.exit(1)

        failed = []
        for fuzzer in args.fuzzer:
            if not _fuzzbench_build(fuzzbench_dir, fuzzer, benchmark_name):
                failed.append(fuzzer)
        if failed:
            logger.error("Failed fuzzers: %s", " ".join(failed))
            sys.exit(1)

    else:
        logger.info("")
        logger.info("Next steps:")
        logger.info("  1. Copy %s into fuzzbench/benchmarks/", benchmark_name)
        logger.info("  2. cd fuzzbench && make build-afl-%s", benchmark_name)
        logger.info("  3. make test-run-afl-%s", benchmark_name)


def _resolve_fuzzbench_dir(explicit_path: str | None, bench_dir: Path) -> Path | None:
    """Find the FuzzBench root directory."""
    if explicit_path:
        p = Path(explicit_path)
        if p.is_dir():
            return p
        return None

    # Try to infer: bench_dir is typically fuzzbench/benchmarks/{name}
    candidate = bench_dir.parent.parent  # fuzzbench/
    if (candidate / "Makefile").exists() and (candidate / "docker").is_dir():
        return candidate

    # Fallback: PROJECT_ROOT/fuzzbench
    candidate = PROJECT_ROOT / "fuzzbench"
    if (candidate / "Makefile").exists():
        return candidate

    return None


def _fuzzbench_build(fuzzbench_dir: Path, fuzzer: str, benchmark: str):
    """Run 'make build-{fuzzer}-{benchmark}' in the FuzzBench directory."""
    target = f"build-{fuzzer}-{benchmark}"
    logger.info("Building: make %s (in %s)", target, fuzzbench_dir)
    result = subprocess.run(
        ["make", target],
        cwd=fuzzbench_dir,
    )
    if result.returncode != 0:
        logger.error("Build failed for %s-%s (exit %d)", fuzzer, benchmark, result.returncode)
        return False
    logger.info("Build OK: %s-%s", fuzzer, benchmark)
    return True


if __name__ == "__main__":
    main()
