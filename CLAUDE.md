# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository implements automated fuzzing workflows for OSS-Fuzz projects. The system transplants bug-triggering conditions from old (buggy) commits into current code versions, then merges all per-bug patches into a single version that triggers all bugs simultaneously.

`bug_transplant_batch.py` iterates over bugs, `bug_transplant.py` runs a code agent (Claude Code or Codex) inside an OSS-Fuzz Docker container to semantically transplant each bug, and `bug_transplant_merge.py` merges per-bug diffs into one version with conflict resolution.

## Key Commands

### Environment setup
```bash
source script/setenv.sh
```
Sets: `TESTCASES`, `REPO_PATH`, `BUGINFO_PATH`, `ANTHROPIC_API_KEY`

### Bug Transplant via Code Agent

#### Step 1: Batch transplant (one agent session per bug)
```bash
# Dry run — see what would execute
python3 script/bug_transplant_batch.py ~/log/<project>.csv \
  --bug_info osv_testcases_summary.json \
  --build_csv ~/log/<project>_builds.csv \
  --target <project> --dry-run

# Run all bugs
sudo -E python3 script/bug_transplant_batch.py ~/log/<project>.csv \
  --bug_info osv_testcases_summary.json \
  --build_csv ~/log/<project>_builds.csv \
  --target <project>

# Single bug, skip data collection, keep container for debugging
sudo -E python3 script/bug_transplant_batch.py ~/log/<project>.csv \
  --bug_info osv_testcases_summary.json \
  --build_csv ~/log/<project>_builds.csv \
  --target <project> --bug_id OSV-XXXX --skip-collect --keep-containers

# Resume after interruption (skips completed bugs)
sudo -E python3 script/bug_transplant_batch.py ~/log/<project>.csv \
  --bug_info osv_testcases_summary.json \
  --build_csv ~/log/<project>_builds.csv \
  --target <project> --resume
```

#### Step 2: Merge per-bug diffs into one version
```bash
# Dry run — show merge order and detect file conflicts
python3 script/bug_transplant_merge.py \
  --summary data/bug_transplant/batch_<project>_<commit>/summary.json \
  --bug_info osv_testcases_summary.json \
  --target <project> \
  --local-bugs OSV-XXXX OSV-YYYY --dry-run

# Run merge with conflict resolution
sudo -E python3 script/bug_transplant_merge.py \
  --summary data/bug_transplant/batch_<project>_<commit>/summary.json \
  --bug_info osv_testcases_summary.json \
  --target <project> \
  --local-bugs OSV-XXXX OSV-YYYY
```

#### Single bug (standalone)
```bash
sudo -E python3 script/bug_transplant.py <project> \
  --buggy-commit <sha> --target-commit <sha> \
  --bug-id OSV-XXXX --fuzzer-name <fuzzer> \
  --testcase testcase-OSV-XXXX --skip-collect
```

### Data Collection
```bash
# Collect crash log
sudo -E python3 script/fuzz_helper.py collect_crash <project> <fuzzer> \
  --commit <buggy_sha> --testcases $TESTCASES --test_input testcase-OSV-XXXX

# Collect function trace
sudo -E python3 script/fuzz_helper.py collect_trace <project> <fuzzer> \
  --commit <buggy_sha> --testcases $TESTCASES --test_input testcase-OSV-XXXX

# Build at a specific commit
sudo -E python3 script/fuzz_helper.py build_version --commit <sha> \
  --build_csv ~/log/<project>_builds.csv <project>

# Reproduce a bug
sudo -E python3 script/fuzz_helper.py reproduce <project> <fuzzer> \
  $TESTCASES/testcase-OSV-XXXX -e ASAN_OPTIONS=detect_leaks=0
```


## Architecture

### Pipeline (top-down)

1. **`script/bug_transplant_batch.py`**: Batch orchestrator. Reads CSV/JSON data, selects target commit, resolves per-bug metadata (fuzzer, sanitizer, testcase), calls `bug_transplant.py` per bug. Outputs per-bug diffs to `data/bug_transplant/<project>_<bug_id>/`.

2. **`script/bug_transplant.py`**: Single-bug launcher. Builds an agent-layered Docker image (Claude Code or Codex, via `--agent` flag) on OSS-Fuzz project image, starts persistent container, runs the agent with transplant prompt. The agent reads crash stack + trace, identifies bug fixes, surgically reverts them, minimizes the patch.

3. **`script/bug_transplant_merge.py`**: Merge orchestrator. Applies per-bug diffs incrementally, builds ASAN + UBSAN in the main container, verifies all bugs after each step, resolves conflicts via code agent (Claude Code or Codex), outputs combined diff.

4. **`script/bug_transplant_prompt.md`**: Prompt template with the transplant methodology (categorize changes as A/B/C, iterative apply, mandatory minimization).

5. **`script/bug_transplant_claude.md`**: CLAUDE.md mounted inside the container for persistent agent guidance.

6. **`script/prompts/`**: Agent prompt templates used by the merge orchestrator. Loaded at runtime via `_load_prompt()` with variable substitution:
   - `harness_dispatch.md` — Modify fuzz harness to consume dispatch byte from input
   - `conflict_resolve_dispatch.md` — Resolve merge conflicts using dispatch branches (whole-patch dispatch)
   - `regression_dispatch.md` — Wrap a newly-applied patch in dispatch to fix regressions
   - `self_trigger_dispatch.md` — Unblock a bug blocked by previously-applied patches

### Data Infrastructure (shared)

- **`script/fuzz_helper.py`**: Docker-based build/fuzz/reproduce/trace operations. Supports `--runner-image auto` for historical Docker image pinning.
- **`script/buildAndtest.py`**: Generates CSV files by building/testing across commit ranges.
- **`script/symbolizer.py`**, **`script/read_func_trace.py`**, **`script/compare_trace.py`**: Trace collection and analysis.
- **`script/monitor_crash.py`**: Crash detection and stack extraction.

## Key Concepts

### Bug Transplant Methodology
Changes between buggy and current versions fall into three categories:
- **A) Direct bug fixes** (revert `calloc`→`malloc`, remove `memset`, etc.) — **MUST revert**
- **B) New validation checks** that reject the testcase before reaching the bug — **MUST remove**
- **C) Refactoring/unrelated changes** — **LEAVE ALONE**

Category B is most commonly missed. After triggering, minimize via single-change elimination.
See `data/feedback_bug_transplant.md` for the full methodology with examples.

### Sanitizer Builds
The merge script builds with ASAN and UBSAN in the main container. MSAN support was removed to simplify the merge flow (MSAN taints system libraries and required ephemeral containers).

### Environment Setup
`source script/setenv.sh` sets:
- `TESTCASES`: Directory containing PoC testcase files
- `REPO_PATH`: Git repo directory for target projects
- `BUGINFO_PATH`: Path to `osv_testcases_summary.json`
- `ANTHROPIC_API_KEY`: Required for Claude Code agent (or `OPENAI_API_KEY` for Codex)

### Data Sources
- **`~/log/<project>.csv`**: Commit x bug status matrix (from `buildAndtest.py`)
- **`osv_testcases_summary.json`**: Per-bug metadata (fuzzer, sanitizer, crash type)
- **`~/log/<project>_builds.csv`**: Commit → OSS-Fuzz Docker image mapping

### Artifacts
- Per-bug: `data/bug_transplant/<project>_<bug_id>/bug_transplant.diff`
- Batch: `data/bug_transplant/batch_<project>_<commit>/summary.json`
- Merge: `data/bug_transplant/merge_<project>_<commit>/combined.diff`
- Traces: `data/target_trace-<commit>-<testcase>.txt`
- Crash logs: `data/crash/target_crash-<commit>-<testcase>.txt`
