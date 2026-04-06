# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository implements automated fuzzing workflows for OSS-Fuzz projects. The system transplants bug-triggering conditions from old (buggy) commits into current code versions, then merges all per-bug patches into a single version that triggers all bugs simultaneously.

`bug_transplant_batch.py` iterates over bugs, `bug_transplant.py` runs Codex inside an OSS-Fuzz Docker container to semantically transplant each bug, and `bug_transplant_merge_offline.py` wraps each patch with dispatch gating and merges them into one version.

## Key Commands

### Environment setup
```bash
source script/setenv.sh
```
Sets: `TESTCASES`, `REPO_PATH`, `BUGINFO_PATH`, `OPENAI_API_KEY`

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

#### Step 2: Offline dispatch-wrap and merge
```bash
# Dry run — show dispatch bit assignments
python3 script/bug_transplant_merge_offline.py \
  --summary data/bug_transplant/batch_<project>_<commit>/summary.json \
  --bug_info osv_testcases_summary.json \
  --target <project> --dry-run

# Run offline merge (wrap + merge + verify)
sudo -E python3 script/bug_transplant_merge_offline.py \
  --summary data/bug_transplant/batch_<project>_<commit>/summary.json \
  --bug_info osv_testcases_summary.json \
  --build_csv ~/log/<project>_builds.csv \
  --target <project>
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

1. **`script/bug_transplant_batch.py`**: Batch orchestrator. Reads CSV/JSON data, selects target commit, resolves per-bug metadata (fuzzer, sanitizer, testcase), calls `bug_transplant.py` per bug in a shared container. Outputs per-bug diffs to `data/bug_transplant/<project>_<bug_id>/`.

2. **`script/bug_transplant.py`**: Single-bug launcher. Builds a Codex-layered Docker image on the OSS-Fuzz project image, starts persistent container, runs Codex with the transplant prompt. The agent reads crash stack + trace + fix hint diff, identifies what blocks the crash path, surgically reverts fixes or patches the testcase. After success, a post-agent verification confirms the crash with official `compile`, then a **separate minimization agent** reduces the diff to the minimal set of changes.

3. **`script/bug_transplant_merge_offline.py`**: Offline merge. Pre-assigns dispatch bits to each bug, wraps each patch independently with dispatch gating on clean source (Phase 1), then merges all wrapped diffs via code agent (Phase 2). Verifies all bugs and outputs combined diff + dispatch-tagged testcases.

4. **`script/prompts/bug_transplant.md`**: Transplant prompt template with the methodology (test PoC on target, patch testcase binary for format changes, diff the crash path, identify what blocks the bug, verify both directions).

5. **`script/prompts/minimize_patch.md`**: Minimization prompt for the second agent pass (per-file elimination, then per-hunk within required files).

6. **`script/prompts/`**: Agent prompt templates. Loaded at runtime via `_load_prompt()` with variable substitution:
   - `dispatch_wrap_offline.md` — Wrap a single patch with dispatch gating (used per-bug in Phase 1)
   - `merge_wrapped_patches.md` — Merge all dispatch-wrapped patches into one codebase (Phase 2)
   - `harness_dispatch.md` — Modify fuzz harness to consume dispatch byte from input
   - `conflict_resolve_dispatch.md` — Resolve conflicts using dispatch branches
   - `bug_transplant_memory.md` — AGENTS.md template for shared knowledge seeding

### Data Infrastructure (shared)

- **`script/fuzz_helper.py`**: Docker-based build/fuzz/reproduce/trace operations. Supports `--runner-image auto` for historical Docker image pinning.
- **`script/buildAndtest.py`**: Generates CSV files by building/testing across commit ranges.
- **`script/symbolizer.py`**, **`script/read_func_trace.py`**, **`script/compare_trace.py`**: Trace collection and analysis.
- **`script/monitor_crash.py`**: Crash detection and stack extraction.

## Key Concepts

### Bug Transplant Methodology
The agent follows an iterative test/diagnose/patch loop:
1. Test the PoC on the target commit — observe what happens
2. If testcase is rejected early (format/parsing changed), patch the testcase binary with `xxd`/`dd`/`printf` rather than reverting code
3. Diff the crash path — read fix hint diff, then `git diff` on specific files from the crash stack
4. Identify what concretely blocks the crash path — may not be a single "fix" commit, could be incidental validation or refactoring
5. Verify both directions — crash WITH changes, no crash WITHOUT

When the input format changed between commits, **patch the testcase binary** rather than reverting format definitions in code.

After triggering, minimize via single-change elimination (per-file, then per-hunk).
See `data/feedback_bug_transplant.md` for the full methodology with examples.

### Two-Phase Agent Approach
Each bug runs two sequential Codex agent sessions inside the same container:
1. **Transplant agent** (`bug_transplant.md`): diagnose and apply changes to trigger the bug
2. **Minimize agent** (`minimize_patch.md`): reduce the diff to the minimal necessary set

Between the two, post-agent verification rebuilds with official `compile` and compares the crash stack against the original to confirm it's the same vulnerability.

### Offline Dispatch Merge
Each bug with a code diff gets a dispatch bit pre-assigned. The merge has two phases:
1. **Phase 1 — Wrap**: Each patch is independently wrapped with `if (__bug_dispatch[B] & (1<<N))` gating on clean source. Both old and new code are preserved.
2. **Phase 2 — Merge**: All wrapped diffs are merged into one codebase via code agent. Since each bug uses a different bit, they don't interfere at runtime.

The harness is modified once to read `__bug_dispatch[]` from the first byte(s) of each testcase. Each PoC gets its dispatch bit prepended. Local bugs and testcase-only bugs get `0x00`.

### Environment Setup
`source script/setenv.sh` sets:
- `TESTCASES`: Directory containing PoC testcase files
- `REPO_PATH`: Git repo directory for target projects
- `BUGINFO_PATH`: Path to `osv_testcases_summary.json`
- `OPENAI_API_KEY`: Required for Codex agent

### Data Sources
- **`~/log/<project>.csv`**: Commit x bug status matrix (from `buildAndtest.py`)
- **`osv_testcases_summary.json`**: Per-bug metadata (fuzzer, sanitizer, crash type)
- **`~/log/<project>_builds.csv`**: Commit → OSS-Fuzz Docker image mapping

### Artifacts
- Per-bug: `data/bug_transplant/<project>_<bug_id>/bug_transplant.diff`
- Batch: `data/bug_transplant/batch_<project>_<commit>/summary.json`
- Merge: `data/bug_transplant/merge_offline_<project>_<commit>/combined.diff`
- Traces: `data/target_trace-<commit>-<testcase>.txt`
- Crash logs: `data/crash/target_crash-<commit>-<testcase>.txt`
- Fix hints: `data/patch_diffs/fix_hint-<commit>-<testcase>.diff`
