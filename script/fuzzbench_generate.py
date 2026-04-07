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


def read_summary(merge_dir: Path) -> dict:
    summary_path = merge_dir / "summary.json"
    with open(summary_path) as f:
        return json.load(f)


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
    # Format: "2021-03-14 10:30:00 +0100" → ISO 8601
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


def generate_dockerfile(project: str, oss_fuzz_dir: Path, builder_digest: str,
                        dispatch_bytes: int, no_canary: bool = False) -> str:
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

    # Add COPY for patches and seeds before the final COPY build.sh line
    # We insert our COPY commands before 'COPY build.sh'
    copy_lines = [
        "# Bug transplant patches and seeds",
        "COPY patches/ /src/patches/",
        "COPY seeds/ /src/seeds/",
    ]
    if not no_canary:
        copy_lines.append("COPY monitor/ /src/monitor/")
    patch_lines = "\n".join(copy_lines)

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


def generate_build_sh(project: str, target_commit: str, fuzz_target: str,
                      oss_fuzz_dir: Path, dispatch_bytes: int,
                      no_canary: bool = False) -> str:
    """Generate build.sh that checks out the target commit, applies patches, and builds."""
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
    dispatch_hex = "".join([r"\x00"] * dispatch_bytes)

    build_sh = f"""#!/bin/bash -eu
# Generated by fuzzbench_generate.py for bug transplant evaluation

cd /src/{project}

# Checkout target commit
git checkout {target_commit}

# Apply transplanted bug patches + dispatch harness
if ! git apply --check /src/patches/combined.diff 2>/dev/null; then
    echo "Trying git apply --3way for combined.diff..."
    git apply --3way /src/patches/combined.diff
else
    git apply /src/patches/combined.diff
fi

if ! git apply --check /src/patches/harness.diff 2>/dev/null; then
    echo "Trying git apply --3way for harness.diff..."
    git apply --3way /src/patches/harness.diff
else
    git apply /src/patches/harness.diff
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

    # Canary integration: copy files, patch CMake, instrument harness
    if not no_canary:
        build_sh += f"""
# --- Canary instrumentation ---
# Copy canary library to project root (alongside __bug_dispatch.c/h)
cp /src/patches/bug_canary.c /src/patches/bug_canary.h /src/{project}/

# Add bug_canary.c to CMake build alongside __bug_dispatch.c
if [ -f tests/fuzz/CMakeLists.txt ]; then
    sed -i '/set(BUG_DISPATCH_SOURCE/a set(BUG_CANARY_SOURCE ${{PROJECT_SOURCE_DIR}}/bug_canary.c)' tests/fuzz/CMakeLists.txt
    sed -i 's/${{BUG_DISPATCH_SOURCE}})/${{BUG_DISPATCH_SOURCE}} ${{BUG_CANARY_SOURCE}})/' tests/fuzz/CMakeLists.txt
    # Link -lrt for shm_open
    if grep -q 'target_link_libraries' tests/fuzz/CMakeLists.txt; then
        sed -i '/target_link_libraries/s/)/ rt)/' tests/fuzz/CMakeLists.txt
    else
        sed -i '/add_executable.*BUG_CANARY/a \\    target_link_libraries(${{target}} rt)' tests/fuzz/CMakeLists.txt
    fi
fi

# Add canary include and reach logging to all harness files
for f in tests/fuzz/fuzz_*.c; do
    [ -f "$f" ] || continue
    # Add include after __bug_dispatch.h
    sed -i '/#include "__bug_dispatch.h"/a #include "bug_canary.h"' "$f"
    # Add canary reach logging after dispatch bytes are consumed
    sed -i '/size -= __BUG_DISPATCH_BYTES;/a \\  for(int _ci=0;_ci<__BUG_DISPATCH_BYTES;_ci++) for(int _cj=0;_cj<8;_cj++) if(__bug_dispatch[_ci]&(1<<_cj)) bug_canary_log(_ci*8+_cj,0);' "$f"
done
"""

    # Patch cmake to disable tests/benchmarks (they fail because __bug_dispatch
    # is only linked into fuzz targets, not the main library)
    original_build_patched = original_build
    if "cmake" in original_build_patched and "-DBUILD_TESTS" not in original_build_patched:
        original_build_patched = original_build_patched.replace(
            "-DBUILD_FUZZERS=ON",
            "-DBUILD_FUZZERS=ON -DBUILD_TESTS=OFF -DBUILD_BENCHMARKS=OFF -DBUILD_EXAMPLES=OFF",
        )

    build_sh += f"""
# --- Original build commands ---
{original_build_patched}

# --- Seed corpus: prepend dispatch bytes to original seeds ---
# FuzzBench uses $OUT/{{fuzz_target}}_seed_corpus.zip as initial corpus.
# We need to prepend {dispatch_bytes} zero dispatch bytes to all original seeds
# so the fuzzer starts with the default (unpatched) code path.
mkdir -p /tmp/seeds_dispatch

# Prepend dispatch bytes to any existing seed corpus files
if [ -f "$OUT/{fuzz_target}_seed_corpus.zip" ]; then
    mkdir -p /tmp/original_seeds
    unzip -q -o "$OUT/{fuzz_target}_seed_corpus.zip" -d /tmp/original_seeds 2>/dev/null || true
    for f in /tmp/original_seeds/*; do
        [ -f "$f" ] && printf '{dispatch_hex}' | cat - "$f" > "/tmp/seeds_dispatch/$(basename "$f")"
    done
fi

# Add dispatch-modified PoCs from our seeds directory
if [ -d /src/seeds ]; then
    for f in /src/seeds/testcase-*; do
        [ -f "$f" ] && cp "$f" /tmp/seeds_dispatch/
    done
fi

# Re-package seed corpus with dispatch-prefixed seeds
if ls /tmp/seeds_dispatch/* 1>/dev/null 2>&1; then
    zip -j -q "$OUT/{fuzz_target}_seed_corpus.zip" /tmp/seeds_dispatch/*
fi
"""
    return build_sh


def generate_benchmark_yaml(project: str, fuzz_target: str, target_commit: str,
                            commit_date: str) -> str:
    """Generate benchmark.yaml content."""
    return f"""project: {project}
fuzz_target: {fuzz_target}
commit: {target_commit}
commit_date: {commit_date}
"""


def _dispatch_value_to_canary_index(dispatch_value: int) -> int:
    """Convert dispatch_value to canary array index (bit position).

    dispatch_value is a power of 2: the bit position is the canary index.
    Returns -1 for local bugs (dispatch_value=0).
    """
    if dispatch_value == 0:
        return -1
    idx = 0
    v = dispatch_value
    while v > 1:
        v >>= 1
        idx += 1
    return idx


def generate_bug_metadata(summary: dict) -> dict:
    """Generate bug metadata for post-experiment triage."""
    dispatch_state = summary["dispatch_state"]
    bugs = {}
    for bug_id, bit_value in dispatch_state["poc_bytes"].items():
        canary_index = _dispatch_value_to_canary_index(bit_value)
        bugs[bug_id] = {
            "dispatch_value": bit_value,
            "canary_index": canary_index,
            "triggered": summary["results"].get(bug_id, False),
        }
    return {
        "project": summary["project"],
        "target_commit": summary["target_commit"],
        "dispatch_bytes": dispatch_state["dispatch_bytes"],
        "total_bugs": len(summary["results"]),
        "bugs": bugs,
    }


def copy_seeds(merge_dir: Path, seeds_dir: Path):
    """Copy dispatch-modified testcases (the -patched variants) as seeds."""
    testcases_dir = merge_dir / "testcases"
    if not testcases_dir.exists():
        logger.warning("No testcases directory in %s", merge_dir)
        return 0

    count = 0
    for f in sorted(testcases_dir.iterdir()):
        if f.name.endswith("-patched"):
            # Strip -patched suffix for the seed name
            dest_name = f.name[: -len("-patched")]
            shutil.copy2(f, seeds_dir / dest_name)
            count += 1
    return count


def generate_canary_header(summary: dict) -> str:
    """Generate bug_canary.h — Magma-style canary header."""
    num_bugs = len(summary["results"])
    return f"""#ifndef BUG_CANARY_H
#define BUG_CANARY_H

#include <stdint.h>

#define BUG_CANARY_NUM_BUGS {num_bugs}
#define BUG_CANARY_SHM_NAME "/bug_canary"

struct bug_canary {{
    uint64_t reached;
    uint64_t triggered;
    uint64_t timestamp_first_reached;
    uint64_t timestamp_first_triggered;
}};

struct bug_canary_shm {{
    volatile uint8_t faulty;
    struct bug_canary canaries[BUG_CANARY_NUM_BUGS];
}};

/* Call at dispatch block entry (reached) and fault site (triggered).
 * Uses bitwise ops only — no implicit branches for coverage-guided fuzzers. */
void bug_canary_log(int bug_id, int trigger_condition);

/* Initialize shared memory region. Call once at program startup. */
void bug_canary_init(void);

#endif /* BUG_CANARY_H */
"""


def generate_canary_source(summary: dict) -> str:
    """Generate bug_canary.c — Magma-style canary implementation."""
    return """#include "bug_canary.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

static struct bug_canary_shm *shm = NULL;

static uint64_t time_monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

__attribute__((constructor))
void bug_canary_init(void) {
    if (shm) return;

    int fd = shm_open(BUG_CANARY_SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (fd < 0) return;

    size_t sz = sizeof(struct bug_canary_shm);
    if (ftruncate(fd, sz) < 0) {
        close(fd);
        return;
    }
    shm = (struct bug_canary_shm *)mmap(NULL, sz,
        PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);

    if (shm == MAP_FAILED) {
        shm = NULL;
        return;
    }
}

void bug_canary_log(int bug_id, int trigger_condition) {
    if (!shm) return;
    if (bug_id < 0 || bug_id >= BUG_CANARY_NUM_BUGS) return;

    volatile struct bug_canary *c = &shm->canaries[bug_id];
    volatile uint8_t *faulty = &shm->faulty;

    /* Magma-style always-evaluate with bitwise ops only.
     * No implicit branches — coverage-guided fuzzers cannot detect canary. */
    uint64_t not_faulty = 1 & (*faulty ^ 1);
    c->reached   += not_faulty;
    c->triggered += (uint64_t)(trigger_condition != 0) & not_faulty;
    *faulty = *faulty | (uint8_t)(trigger_condition != 0);

    /* Record first-reach/trigger timestamps */
    uint64_t now = time_monotonic_ms();
    if (c->timestamp_first_reached == 0)
        c->timestamp_first_reached = now;
    if ((trigger_condition != 0) && c->timestamp_first_triggered == 0)
        c->timestamp_first_triggered = now;
}
"""


def generate_experiment_config(output_dir: Path, benchmark_name: str) -> str:
    """Generate a sample local experiment config."""
    return f"""# FuzzBench local experiment config
# Generated by fuzzbench_generate.py

trials: 3
max_total_time: 86400  # 24 hours per trial

local_experiment: true
experiment_filestore: /tmp/fuzzbench-data
report_filestore: /tmp/fuzzbench-reports
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
    parser.add_argument("--output-dir", required=True,
                        help="Output directory for generated benchmark(s)")
    parser.add_argument("--oss-fuzz-dir", default=str(OSS_FUZZ_DIR),
                        help="Path to local oss-fuzz checkout")
    parser.add_argument("--builder-digest",
                        help="Override base-builder digest (e.g., sha256:abc...)")
    parser.add_argument("--benchmark-name",
                        help="Custom benchmark name (default: {project}_transplant_{target})")
    parser.add_argument("--no-canary", action="store_true",
                        help="Skip canary instrumentation files")
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

    # 2. Read oss-fuzz commit from CSV
    oss_fuzz_commit = read_oss_fuzz_commit(build_csv, project, target_commit)
    logger.info("OSS-Fuzz commit: %s", oss_fuzz_commit)

    # 3. Checkout oss-fuzz at the right commit
    checkout_oss_fuzz(oss_fuzz_dir, oss_fuzz_commit)
    commit_date = get_oss_fuzz_commit_date(oss_fuzz_dir, oss_fuzz_commit)
    logger.info("Commit date: %s", commit_date)

    # 4. Get builder digest
    builder_digest = get_builder_digest(oss_fuzz_dir, oss_fuzz_commit, args.builder_digest)
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
    dockerfile = generate_dockerfile(project, oss_fuzz_dir, builder_digest, dispatch_bytes,
                                     no_canary=args.no_canary)
    (bench_dir / "Dockerfile").write_text(dockerfile)
    logger.info("Generated Dockerfile")

    # 7. Generate build.sh
    build_sh = generate_build_sh(project, target_commit, fuzz_target,
                                 oss_fuzz_dir, dispatch_bytes,
                                 no_canary=args.no_canary)
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

    # 10. Copy seeds (dispatch-modified testcases)
    seed_count = copy_seeds(merge_dir, seeds_dir)
    logger.info("Copied %d dispatch-modified testcases as seeds", seed_count)

    # 11. Generate bug metadata
    bug_meta = generate_bug_metadata(summary)
    meta_path = bench_dir / "bug_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(bug_meta, f, indent=2)
    logger.info("Generated bug_metadata.json (%d bugs)", len(bug_meta["bugs"]))

    # 12. Generate canary files and monitor
    if not args.no_canary:
        canary_h = generate_canary_header(summary)
        canary_c = generate_canary_source(summary)
        (patches_dir / "bug_canary.h").write_text(canary_h)
        (patches_dir / "bug_canary.c").write_text(canary_c)
        logger.info("Generated canary library (bug_canary.c/h)")

        # Copy monitor script and metadata into monitor/ directory
        monitor_dir = bench_dir / "monitor"
        monitor_dir.mkdir(exist_ok=True)
        monitor_src = SCRIPT_DIR / "bug_monitor.py"
        if monitor_src.exists():
            shutil.copy2(monitor_src, monitor_dir / "bug_monitor.py")
            # Also copy bug_metadata.json into monitor/ for self-contained use
            shutil.copy2(meta_path, monitor_dir / "bug_metadata.json")
            logger.info("Copied bug_monitor.py + metadata to monitor/")
        else:
            logger.warning("bug_monitor.py not found at %s", monitor_src)

    # 13. Generate sample experiment config
    config = generate_experiment_config(output_base, benchmark_name)
    (output_base / "experiment_config.yaml").write_text(config)

    # Summary
    logger.info("=" * 60)
    logger.info("Benchmark generated: %s", bench_dir)
    logger.info("  Bugs: %d total (%d triggered at merge time)",
                len(summary["results"]),
                sum(1 for v in summary["results"].values() if v))
    logger.info("  Dispatch bytes: %d", dispatch_bytes)
    logger.info("  Seeds: %d", seed_count)
    logger.info("")
    logger.info("Next steps:")
    logger.info("  1. Copy %s into fuzzbench/benchmarks/", benchmark_name)
    logger.info("  2. cd fuzzbench && make build-afl-%s", benchmark_name)
    logger.info("  3. make test-run-afl-%s", benchmark_name)


if __name__ == "__main__":
    main()
