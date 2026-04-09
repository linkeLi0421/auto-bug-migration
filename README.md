# OSS-Fuzz Bug Transplant

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/linkeLi0421/auto-bug-migration)

Automated bug transplant pipeline for OSS-Fuzz projects. Given a project with historical bugs, the system transplants bug-triggering conditions from old commits into the current codebase, producing a single version that triggers all bugs simultaneously.

## How it works

1. **Batch transplant** -- For each bug, a code agent (Claude Code or Codex) runs inside an OSS-Fuzz Docker container. It reads the crash stack and function trace, identifies what prevents the bug from triggering, and either reverts code changes or patches the testcase binary. A shared CLAUDE.md accumulates project knowledge across bugs.
2. **Merge** -- Per-bug diffs are applied incrementally. Testcase-only transplants (no code change, only patched testcase) are registered directly. Conflicts between overlapping diffs are resolved by a code agent. After each step, all previously-applied bugs are verified for regressions.
3. **Dispatch wrapping** -- When merging causes regressions, a bitmask-based dispatch mechanism gates each bug's code changes so they can coexist. Each bug gets a bit in `__bug_dispatch[]`; the fuzzer reads the dispatch byte from the first byte of the test input.

## Quick start

```bash
# 1. Setup
source script/setenv.sh
export ANTHROPIC_API_KEY=...

# 2. See what bugs need transplanting (dry run)
python3 script/bug_transplant_batch.py ~/log/c-blosc2.csv \
  --bug_info $BUGINFO_PATH \
  --build_csv ~/log/c-blosc2_builds.csv \
  --target c-blosc2 --dry-run

# 3. Run batch transplant (shared container, CLAUDE.md accumulates knowledge)
sudo -E python3 script/bug_transplant_batch.py ~/log/c-blosc2.csv \
  --bug_info $BUGINFO_PATH \
  --build_csv ~/log/c-blosc2_builds.csv \
  --testcases-dir ~/oss-fuzz-for-select/pocs/tmp/ \
  --target c-blosc2 --resume --keep-containers

# 4. Offline dispatch-wrap and merge all per-bug diffs into one version
sudo -E python3 script/bug_transplant_merge_offline.py \
  --summary data/bug_transplant/batch_c-blosc2_79e921d9/summary.json \
  --bug_info $BUGINFO_PATH \
  --target c-blosc2 \
  --build_csv ~/log/c-blosc2_builds.csv
```

**Output:**
```
RESULT:  18 / 21 bugs triggering

  Local bugs:           9/10 verified
  Transplanted bugs:    9/11 triggering
  Combined diff:        data/bug_transplant/merge_c-blosc2_79e921d9/combined.diff
  Testcases:            data/bug_transplant/merge_c-blosc2_79e921d9/testcases/
```

## Transplant results

Each bug produces artifacts in `data/bug_transplant/<project>_<bug_id>/`:

| File | Description |
|---|---|
| `bug_transplant.diff` | Code patch (empty for testcase-only transplants) |
| `testcase-<bug_id>` | Modified testcase (if the agent patched the binary input) |
| `transplant_crash.txt` | Verified crash output |
| `minimize_output.txt` | Minimization agent output |
| `claude_output.txt` | Agent summary |
| `conversation.jsonl` | Full agent conversation for debugging |
| `bug_transplant.impossible` | Reason if agent declared transplant infeasible |

## Offline dispatch wrapping

When bugs need to coexist in a single binary but their code changes conflict,
use `dispatch_wrap_offline.md` to wrap each bug's patch with dispatch gating:

```bash
# Each bug gets a bit. The fuzzer reads __bug_dispatch[] from the first
# byte of the test input.

# Example: wrap OSV-2021-21's patch with bit 0
claude -p "$(cat script/prompts/dispatch_wrap_offline.md | sed \
  -e 's/{project}/c-blosc2/g' \
  -e 's/{bug_id}/OSV-2021-21/g' \
  -e 's/{dispatch_bit}/0/g' \
  -e 's/{dispatch_byte}/0/g' \
  -e 's/{dispatch_value}/1/g' \
  -e 's|{patch_path}|data/bug_transplant/c-blosc2_OSV-2021-21/bug_transplant.diff|g' \
  -e 's|{testcase_path}|/work/testcase-OSV-2021-21|g' \
  -e 's|{output_testcase_path}|/work/testcase-OSV-2021-21|g')"
```

### Dispatch mechanism

Every runtime code change is wrapped in an if/else:
```c
#include "__bug_dispatch.h"

if (__bug_dispatch[0] & (1 << 0)) {
    // Bug's version (from the patch)
} else {
    // Original version (before the patch)
}
```

Macro changes use ternary:
```c
#define LIMIT ((__bug_dispatch[0] & (1 << 0)) ? 4096 : 4080)
```

Testcases get the dispatch byte prepended:
```python
d = open('testcase-OSV-2021-21', 'rb').read()
open('testcase-OSV-2021-21', 'wb').write(bytes([1]) + d)  # bit 0 = value 1
```

## Repository structure

| Path | Purpose |
|---|---|
| `script/bug_transplant.py` | Single-bug transplant launcher (runs code agent in Docker) |
| `script/bug_transplant_batch.py` | Batch orchestrator (shared container, CLAUDE.md memory) |
| `script/bug_transplant_merge_offline.py` | Offline dispatch-wrap and merge per-bug diffs + testcase-only bugs |
| `script/fuzzbench_generate.py` | Generate FuzzBench benchmark from merge output |
| `script/fuzzbench_run.py` | Build and run FuzzBench benchmark, collect artifacts for triage |
| `script/fuzzbench_triage.py` | Post-experiment triage (crashes + coverage → bug timeline CSV) |
| `script/prompts/bug_transplant.md` | Transplant prompt (testcase patching, crash verification) |
| `script/prompts/bug_transplant_memory.md` | CLAUDE.md template for shared knowledge |
| `script/prompts/minimize_patch.md` | Patch minimization prompt |
| `script/prompts/dispatch_wrap_offline.md` | Offline dispatch wrapping prompt |
| `script/prompts/regression_dispatch.md` | Online regression dispatch (used during merge) |
| `script/prompts/conflict_resolve_dispatch.md` | Conflict resolution with dispatch branches |
| `script/prompts/self_trigger_dispatch.md` | Unblock bugs blocked by previous patches |
| `script/prompts/harness_dispatch.md` | Modify fuzz harness for dispatch byte consumption |
| `script/fuzz_helper.py` | Docker-based build/fuzz/reproduce/trace operations |
| `script/buildAndtest.py` | Generate CSV files across commit ranges |
| `data/feedback_bug_transplant.md` | Bug transplant methodology reference |
| `evaluation_bug_discovery_rate.md` | Evaluation plan: Magma-style bug discovery rate measurement |

## FuzzBench evaluation

After merging, evaluate how well different fuzzers discover the transplanted bugs using [FuzzBench](https://github.com/google/fuzzbench):

```bash
# Generate benchmark and build for aflplusplus
sudo -E python3 script/fuzzbench_generate.py \
  --merge-dir data/merge_offline_opensc_6903aebf \
  --build-csv data/opensc_builds.csv \
  --fuzz-target fuzz_pkcs15_reader \
  --output-dir fuzzbench/benchmarks \
  --merge-container bug-merge-opensc \
  --fuzzer aflplusplus

# Run a full 24h experiment with fuzzbench_run.py
sudo -E python3 script/fuzzbench_run.py opensc_transplant_fuzz_pkcs15_reader \
  --fuzzer aflplusplus \
  --experiment-name transplant-opensc-24h \
  --run-time 86400
```

### `fuzzbench_generate.py` flags

| Flag | Description |
|---|---|
| `--merge-dir` | Path to merge output directory (contains summary.json) |
| `--build-csv` | Builds CSV mapping commits to OSS-Fuzz Docker images |
| `--fuzz-target` | Fuzz target binary name |
| `--output-dir` | Output directory (default: `fuzzbench/benchmarks/`) |
| `--merge-container` | Running merge container name -- commits it as a Docker image and uses as Dockerfile base for identical build environment |
| `--fuzzer <name> [...]` | Build the benchmark for these fuzzers after generation |
| `--benchmark-name` | Custom benchmark name (default: `{project}_transplant_{target}`) |
| `--use-current-oss-fuzz-checkout` | Use current local oss-fuzz state instead of checking out from builds.csv |
| `--builder-digest` | Override base-builder image digest |

### Running experiments (`fuzzbench_run.py`)

Once the benchmark is generated, run a full FuzzBench experiment (fuzzing + coverage measurement + crash collection):

```bash
# 24h experiment with aflplusplus, 3 trials
sudo -E python3 script/fuzzbench_run.py opensc_transplant_fuzz_pkcs15_reader \
  --fuzzer aflplusplus \
  --experiment-name transplant-opensc-24h \
  --run-time 86400

# Multiple fuzzers, 5 trials, custom output directory
sudo -E python3 script/fuzzbench_run.py opensc_transplant_fuzz_pkcs15_reader \
  --fuzzer aflplusplus libfuzzer \
  --experiment-name transplant-opensc-5t \
  --trials 5 --run-time 86400 \
  --output-dir /tmp/fuzzbench-data
```

| Flag | Description |
|---|---|
| `benchmark` | Benchmark name (positional) |
| `--fuzzer <name> [...]` | Fuzzer(s) to evaluate |
| `--experiment-name` | Name for this experiment (required) |
| `--run-time <seconds>` | Fuzzing duration per trial (default: 86400 = 24h) |
| `--trials <n>` | Number of trials per fuzzer (default: 3) |
| `--output-dir` | Base directory for experiment data (default: `/tmp/fuzzbench-data`) |

This uses FuzzBench's full infrastructure (`run_experiment.py`), which handles building, fuzzing, periodic corpus snapshots, coverage measurement, and crash collection.

### Triage (`fuzzbench_triage.py`)

After the experiment completes, triage which bugs were reached and triggered:

```bash
python3 script/fuzzbench_triage.py \
  --experiment-dir /tmp/fuzzbench-data/transplant-opensc-24h \
  --bug-metadata fuzzbench/benchmarks/opensc_transplant_fuzz_pkcs15_reader/bug_metadata.json \
  --benchmark opensc_transplant_fuzz_pkcs15_reader \
  --output results.csv
```

This produces:
- **results.csv** -- Per-bug discovery timeline (fuzzer, trial, bug_id, time_first_reached, time_first_triggered)
- **results_bug_report.json** -- Detailed per-bug report with crash locations and discovery status
- **results_bug_report.txt** -- Human-readable summary table

A bug is **reached** when its crash line (from `bug_metadata.json`) appears in FuzzBench's coverage snapshots. A bug is **triggered** when a crash file contains the matching dispatch bytes.

### Manual step-by-step workflow

```bash
# 1. Generate benchmark only
python3 script/fuzzbench_generate.py \
  --merge-dir data/merge_offline_c-blosc2_79e921d9 \
  --build-csv data/c-blosc2_builds.csv \
  --fuzz-target decompress_frame_fuzzer \
  --output-dir fuzzbench/benchmarks

# 2. Build and run via make
cd fuzzbench
make build-aflplusplus-c-blosc2_transplant_decompress_frame_fuzzer
make test-run-aflplusplus-c-blosc2_transplant_decompress_frame_fuzzer

# 3. Or run a full FuzzBench experiment
PYTHONPATH=. python3 experiment/run_experiment.py \
  --experiment-config benchmarks/experiment_config.yaml \
  --benchmarks c-blosc2_transplant_decompress_frame_fuzzer \
  --fuzzers afl aflplusplus honggfuzz libfuzzer \
  --experiment-name transplant-cblosc2-24h

# 4. Triage results (after experiment completes)
python3 script/fuzzbench_triage.py \
  --experiment-dir /tmp/fuzzbench-data/transplant-cblosc2-24h \
  --bug-metadata benchmarks/c-blosc2_transplant_decompress_frame_fuzzer/bug_metadata.json \
  --output results.csv
```

### What the generator produces

- **Dockerfile** -- When `--merge-container` is used, the image is based on the committed merge container for identical build environment. Otherwise, pinned to the exact base-builder digest used during merging.
- **build.sh** -- Checks out the target commit, applies combined.diff + harness.diff, and compiles with ASAN (`type: bug` benchmark)
- **benchmark.yaml** -- With `type: bug` so FuzzBench enables ASAN at build time and sets `ASAN_OPTIONS` (including `detect_stack_use_after_return=1`) at runtime
- **No PoC seeds** -- fuzzers must discover bugs independently; only the project's original seed corpus is used (with dispatch zero bytes prepended)
- **bug_metadata.json** -- Maps each bug to its dispatch bit and crash line (file:line from ASAN/UBSAN output), collected by replaying PoCs with `-runs=10`

The triage script determines bug discovery using two signals: **triggered** = crash with matching dispatch bytes; **reached** = bug's crash line covered in FuzzBench coverage snapshots. This works uniformly for both transplanted and local bugs (see `evaluation_bug_discovery_rate.md`).

## Requirements

- Python 3.10+
- Docker
- Claude Code CLI (`npm install -g @anthropic-ai/claude-code`) and/or Codex CLI
- `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY` for Codex)
- OSS-Fuzz project images (built automatically)

## Pipeline details

### Step 1: Batch transplant (`bug_transplant_batch.py`)

Reads CSV/JSON data:
- `~/log/<project>.csv` -- commit x bug status matrix
- `osv_testcases_summary.json` -- fuzzer name, sanitizer, crash type per bug
- `~/log/<project>_builds.csv` -- commit to Docker image mapping

**Shared container mode** (sequential): One Docker container is reused for all bugs.
Each bug gets a fresh agent session but reads the same CLAUDE.md which accumulates
target-commit knowledge (code structure, validation checks, input format).

For each bug:
1. Collects crash log and function trace (via `fuzz_helper.py`)
2. Agent reads crash stack, diffs buggy vs target, identifies blocking changes
3. Either reverts code (produces diff) or patches testcase binary (testcase-only)
4. Post-verification: rebuilds with official `compile`, verifies crash matches original stack
5. Saves diff + testcase + conversation JSONL
6. Agent may declare `IMPOSSIBLE` if the bug depends on external library version changes

**Key flags:**
- `--dry-run` -- show plan without executing
- `--resume` -- skip already-completed bugs
- `--bug_id OSV-XXXX` -- process single bug
- `--skip-collect` -- skip crash/trace collection
- `--keep-containers` -- keep Docker containers for debugging
- `--agent claude|codex` -- select code agent

### Step 2: Offline merge (`bug_transplant_merge_offline.py`)

Two-phase dispatch-wrap and merge:
1. **Phase 1 -- Wrap**: Each per-bug diff is independently wrapped with dispatch gating on clean source. Each bug gets a bit in `__bug_dispatch[]`; local bugs and testcase-only bugs get `0x00`.
2. **Phase 2 -- Merge**: All wrapped diffs are merged into one codebase via code agent. Since each bug uses a different bit, they don't interfere at runtime.
3. The harness is modified once to read `__bug_dispatch[]` from the first byte(s) of each testcase. Each PoC gets its dispatch bit prepended.
4. Verifies all bugs at baseline and after final merge.

**Key flags:**
- `--dry-run` -- show dispatch bit assignments
- `--keep-container` -- keep container alive for debugging
- `--build_csv` -- use historical Docker image (`--runner-image auto`)

### Bug transplant methodology

The code agent follows a pragmatic approach:

| Strategy | When | Example |
|---|---|---|
| **Revert code** | Direct bug fix or validation check blocks the crash path | Remove bounds check, revert `calloc` to `malloc` |
| **Patch testcase** | Input format changed between commits | Patch header bytes with `dd`/`printf` to match new format |
| **Both** | Format change + code fix | Patch testcase for new header, revert validation check |
| **Impossible** | Bug depends on vendored library version | Different zstd/zlib version at target vs buggy commit |

## Data collection

```bash
# Collect crash log
sudo -E python3 script/fuzz_helper.py collect_crash <project> <fuzzer> \
  --commit <buggy_sha> --testcases $TESTCASES --test_input testcase-OSV-XXXX

# Collect function trace
sudo -E python3 script/fuzz_helper.py collect_trace <project> <fuzzer> \
  --commit <buggy_sha> --testcases $TESTCASES --test_input testcase-OSV-XXXX

# Build at specific commit
sudo -E python3 script/fuzz_helper.py build_version --commit <sha> \
  --build_csv ~/log/<project>_builds.csv <project>

# Reproduce a bug
sudo -E python3 script/fuzz_helper.py reproduce <project> <fuzzer> \
  $TESTCASES/testcase-OSV-XXXX -e ASAN_OPTIONS=detect_leaks=0
```

## Contributing

Pull requests and bug reports are welcome.
