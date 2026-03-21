# OSS-Fuzz Bug Transplant

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/linkeLi0421/auto-bug-migration)

Automated bug transplant pipeline for OSS-Fuzz projects. Given a project with historical bugs, the system transplants bug-triggering conditions from old commits into the current codebase, producing a single version that triggers all bugs simultaneously.

## How it works

1. **Batch transplant** — For each bug, Claude Code runs inside an OSS-Fuzz Docker container. It reads the crash stack and function trace, identifies what code changes fixed the bug, surgically reverts those changes, and minimizes the patch.
2. **Merge** — Per-bug diffs are applied incrementally. Conflicts between overlapping diffs are resolved automatically by Claude Code. After each step, all previously-applied bugs are verified for regressions.

## Quick start

```bash
# 1. Setup
source script/setenv.sh
export ANTHROPIC_API_KEY=...

# 2. See what bugs need transplanting (dry run)
python3 script/bug_transplant_batch.py ~/log/wavpack.csv \
  --bug_info $BUGINFO_PATH \
  --build_csv ~/log/wavpack_builds.csv \
  --target wavpack --dry-run

# 3. Run batch transplant (one Claude Code session per bug)
sudo -E python3 script/bug_transplant_batch.py ~/log/wavpack.csv \
  --bug_info $BUGINFO_PATH \
  --build_csv ~/log/wavpack_builds.csv \
  --target wavpack

# 4. Merge all per-bug diffs into one version
sudo -E python3 script/bug_transplant_merge.py \
  --summary data/bug_transplant/batch_wavpack_0b99613e/summary.json \
  --bug_info $BUGINFO_PATH \
  --target wavpack \
  --local-bugs OSV-2025-105 OSV-2025-107 OSV-2025-108 OSV-2025-127
```

**Output:**
```
RESULT:  8 / 8 bugs triggering

  Local bugs:           4/4 verified
  Transplanted bugs:    4/4 triggering
  Combined diff:        data/bug_transplant/merge_wavpack_0b99613e/combined.diff
```

## Repository structure

| Directory | Purpose |
|---|---|
| `script/bug_transplant.py` | Single-bug transplant launcher (runs Claude Code in Docker) |
| `script/bug_transplant_batch.py` | Batch orchestrator (iterates all bugs for a project) |
| `script/bug_transplant_merge.py` | Merge per-bug diffs + verify + resolve conflicts |
| `script/bug_transplant_prompt.md` | Prompt template for Claude Code transplant task |
| `script/bug_transplant_claude.md` | CLAUDE.md mounted inside the container |
| `script/fuzz_helper.py` | Docker-based build/fuzz/reproduce/trace operations |
| `script/buildAndtest.py` | Generate CSV files across commit ranges |
| `data/feedback_bug_transplant.md` | Bug transplant methodology (categorize, revert, minimize) |
| `script/react_agent/` | Legacy ReAct agent pipeline (being replaced) |
| `script/revert_patch_test.py` | Legacy end-to-end orchestrator |
| `Function_instrument/` | Trace instrumentation library |
| `oss-fuzz/` | OSS-Fuzz framework checkout |

## Requirements

- Python 3.10+
- Docker
- Claude Code CLI (`npm install -g @anthropic-ai/claude-code`)
- `ANTHROPIC_API_KEY` environment variable
- OSS-Fuzz project images (built automatically)

## Pipeline details

### Step 1: Batch transplant (`bug_transplant_batch.py`)

Reads the same CSV/JSON data as the legacy pipeline:
- `~/log/<project>.csv` — commit x bug status matrix
- `osv_testcases_summary.json` — fuzzer name, sanitizer, crash type per bug
- `~/log/<project>_builds.csv` — commit → Docker image mapping

For each bug needing transplant:
1. Collects crash log and function trace (via `fuzz_helper.py`)
2. Builds a Claude Code Docker image layered on the project image
3. Starts a container at the target commit
4. Claude Code: reads crash stack → diffs buggy vs current → categorizes changes → reverts bug fixes → removes validation blockers → builds → tests → minimizes
5. Saves `bug_transplant.diff`

**Key flags:**
- `--dry-run` — show plan without executing
- `--resume` — skip already-completed bugs
- `--bug_id OSV-XXXX` — process single bug
- `--skip-collect` — skip crash/trace collection
- `--keep-containers` — keep Docker containers for debugging
- `--jobs N` — parallel execution

### Step 2: Merge (`bug_transplant_merge.py`)

Merges per-bug diffs incrementally:
1. Orders diffs by independence (fewest file overlaps first)
2. Builds per-sanitizer (ASAN in main container, MSAN/UBSAN in ephemeral containers)
3. For each diff:
   - `git apply --check` → clean apply
   - Conflict → `git apply --3way` (3-way merge)
   - Still fails → Claude Code resolves manually
4. After each apply: verify ALL previous bugs still trigger
5. Outputs combined diff

**Key flags:**
- `--local-bugs OSV-XXXX ...` — bugs already triggering at target commit
- `--dry-run` — show merge order and potential conflicts
- `--keep-container` — keep container alive for debugging

### Bug transplant methodology

Claude Code follows a semantic approach (not mechanical function copy):

| Category | Action | Example |
|---|---|---|
| **A) Direct bug fixes** | **REVERT** | `malloc`→`calloc`, added `memset`, added bounds check |
| **B) New validation checks** | **REMOVE** | Input validation that rejects testcase before reaching bug |
| **C) Refactoring/unrelated** | **LEAVE ALONE** | API renames, threading support, code reorganization |

After triggering, minimize via single-change elimination. See `data/feedback_bug_transplant.md`.

## Data collection

Crash/trace data is collected before the transplant step:

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

## Legacy pipeline

The original pipeline uses a LangGraph ReAct agent with OpenAI models:

```bash
# End-to-end (generates patches, fixes build errors via LLM, verifies)
sudo -E python3 script/revert_patch_test.py ~/log/<project>.csv \
  --bug_info osv_testcases_summary.json \
  --build_csv ~/log/<project>_builds.csv \
  --target <project> --auto-select-images
```

This pipeline is being replaced by the Claude Code approach. Key differences:

| | Legacy (ReAct agent) | New (Claude Code) |
|---|---|---|
| Agent | LangGraph + OpenAI | Claude Code CLI |
| Approach | Mechanical function copy | Semantic (categorize, revert, minimize) |
| Patch format | Pickle bundles (`.patch2`) | Plain `git diff` |
| Build fixing | LLM tool loop per hunk | Claude Code edits files directly |
| Merge | Compatibility graph + cliques | Incremental apply + regression check |
| Conflict resolution | Detected but not resolved | Claude Code resolves automatically |

## Contributing

Pull requests and bug reports are welcome.
