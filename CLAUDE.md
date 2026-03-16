# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository implements automated fuzzing workflows for OSS-Fuzz projects. The system selectively migrates bug-triggering code between versions of C/C++ projects, using an LLM-based ReAct agent to fix compilation failures that arise from the migration.

The end-to-end pipeline is: `revert_patch_test.py` generates revert patches from bug-introducing commits, calls `multi_agent.py` (which fans out to `agent_langgraph.py` per hunk) to iteratively fix build errors via LLM-generated override diffs, then verifies the patched code still triggers the original bug.

## Key Commands

### Install dependencies
```bash
python3 -m pip install -r script/react_agent/requirements.txt
```

### Run tests
```bash
# Main agent regression tests (offline, fast)
bash script/react_agent/test_langgraph_agent.sh

# Multi-agent orchestration tests (offline)
bash script/react_agent/test_multi_agent.sh

# Migration tools tests (patch bundle loading, error parsing)
bash script/migration_tools/test_migration_tools.sh

# Symbol tools smoke test (KB indexing, source resolution)
bash script/react_agent/test_symbol_tools.sh
```

All test scripts are self-contained bash scripts that embed Python tests via heredocs. They run offline without API calls or Docker.

### Run the agent (offline stub mode)
```bash
python3 script/react_agent/agent_langgraph.py --model stub --tools fake --max-steps 3 <artifact_dir>
```

### Run the agent (real mode with OpenAI)
```bash
export OPENAI_API_KEY=...
python3 script/react_agent/agent_langgraph.py \
  --model openai --tools real --max-steps 8 --error-scope patch <artifact_dir> \
  --patch-path data/tmp_patch/<project>.patch2 \
  --ossfuzz-project <project> --ossfuzz-commit <sha> \
  --openai-model gpt-5-mini
```

### Multi-hunk agent (one agent per patch key)
```bash
python3 script/react_agent/multi_agent.py <build_log> \
  --patch-path data/tmp_patch/<project>.patch2 \
  --model openai --tools real --max-steps 8 --jobs 4
```

### End-to-end pipeline
```bash
source script/setenv.sh
sudo -E python3 script/revert_patch_test.py ~/log/<project>.csv \
  --bug_info osv_testcases_summary.json \
  --build_csv ~/log/<project>_builds.csv \
  --target <project> --auto-select-images

# Optional flags:
#   --target-commit <sha>     Override target commit (default: latest in CSV)
#   --crash-stack-only        Only revert functions from crash stack (not full trace)
#   --bug_id <id>             Process a single bug
#   --buggy_commit <sha>      Process a single buggy commit
```

### List available agent tools
```bash
python3 script/react_agent/agent_langgraph.py --list-tools --output-format json-pretty
```

### Debug LLM I/O
```bash
# Print full request/response to stderr
python3 script/react_agent/agent_langgraph.py --debug-llm ...

# Also write llm_call_XXXX_{request,response}.json files
python3 script/react_agent/agent_langgraph.py --debug-llm-dir <dir> ...
```

## Architecture

### Pipeline Layers (top-down)

1. **`script/revert_patch_test.py`** (~3200 lines): End-to-end orchestrator. For each bug: generates revert patches, calls `multi_agent.py` in rounds to fix build errors, merges overrides, verifies crash reproduction. Caches results to `data/patches/<target>_patches.pkl.gz`.

2. **`script/react_agent/multi_agent.py`** (~1260 lines): Groups build errors by `patch_key`, spawns one `agent_langgraph.py` subprocess per hunk (with `--jobs N` parallelism). Selects best override diff per hunk, writes merged patch bundle, optionally runs a final combined OSS-Fuzz build. Artifacts go to `data/react_agent_artifacts/multi_<run_id>/`.

3. **`script/react_agent/agent_langgraph.py`**: Single-hunk ReAct agent loop. Constructs prompts (via `prompting.py`), calls LLM (via `models.py`), dispatches tool calls (via `tools/runner.py`), applies guardrails. Iterates until the hunk is fixed or budget exhausted.

### Tools (`script/react_agent/tools/`)

- **`registry.py`** + **`runner.py`**: Tool spec registry and execution dispatcher.
- **`ossfuzz_tools.py`**: OSS-Fuzz Docker build/test integration (`ossfuzz_apply_patch_and_test`).
- **`extra_patch_tools.py`**: Patch bundle manipulation (`list_patch_bundle`, `get_patch`, `search_patches`, `get_error_patch_context`, `make_error_patch_override`).
- **`symbol_tools.py`**: Symbol/code inspection via static analysis KB (`search_definition`, `read_file_context`).
- **`migration_tools.py`**: Linker error mapping to patch bundles.

### Migration Tools (`script/migration_tools/`)

Core patch processing library imported by the agent tools:
- **`tools.py`**: Error parsing, patch extraction, context lookup, override diff generation.
- **`patch_bundle.py`**: Pickle-based patch bundle I/O with allowlist security checks.
- **`build_errors.py`**: Compiler/linker error detection patterns.
- **`types.py`**: Data classes (`PatchInfo`, `FunctionLocation`).

### Static Analysis KB (`script/react_agent/core/`)

- **`kb_index.py`**: `KbIndex` loads `*_analysis.json` from V1/V2 directories into in-memory indices for symbol lookup.
- **`source_manager.py`**: `SourceManager` resolves `/src/...` JSON paths to local checkouts and reads code by extent.

### Fuzzing Infrastructure

- **`script/fuzz_helper.py`**: Docker-based build/fuzz/reproduce/trace operations. Supports `--runner-image auto --commit-date <timestamp>` for historical Docker image pinning via `prepare_repository()`.
- **`script/buildAndtest.py`**: Orchestrates builds/tests across commit ranges. Contains `BASE_BUILDER_IMAGES` and `BASE_RUNNER_IMAGES` lists with historical Docker image digests (2019-2022).

## Key Concepts

### Patch Bundle Format
Patch bundles (`*.patch2`) are pickled dictionaries keyed by `patch_key`. In patch-aware runs:
- Build-log locations `/src/...:line` refer to migrated code
- Patch bundles use `git apply --reverse` semantics: `-` lines become **additions**
- Override diffs rewrite specific function slices within hunks

### Patch-Aware Workflow (Agent Tool Order)
`parse_build_errors` → `get_error_patch_context` → `read_artifact` (BASE slice) → `make_error_patch_override` → `ossfuzz_apply_patch_and_test`

### Error Scope Modes
- `--error-scope first`: Process only the first error
- `--error-scope patch`: Group errors by patch_key and process all errors for a hunk

### Error Types and Hunk Status
- **Compiler errors**: `file:line:col: error:` patterns. Determine hunk "fixed" status.
- **Linker errors**: `undefined reference to` patterns. Grouped by patch_key alongside compiler errors.
- **Hunk fixed**: All **original** compiler errors (matching `target_errors` messages) in the active patch_key are resolved. New errors at the same lines but with different messages are tracked separately (`new_errors_in_active_patch_key`) and do not block the "fixed" verdict.

### Pre-Build Batch Fix
Before forcing `ossfuzz_apply_patch_and_test`, the agent checks `grouped_errors` for all undeclared identifier errors (matching `_UNDECLARED_SYMBOL_RE`) not yet handled by `make_extra_patch_override`. It forces `make_extra_patch_override` for each unfixed symbol before building. This allows fixing multiple undeclared identifiers in a single build pass, even with `ossfuzz-loop-max=1`.

### Environment Setup
`source script/setenv.sh` sets paths used by `revert_patch_test.py`:
- `REPO_PATH`, `V1_REPO_PATH`, `V2_REPO_PATH`: Git checkout directories for target project
- `TESTCASES`: Directory containing PoC testcase files
- `OPENAI_API_KEY`: Required for LLM agent
- `REACT_AGENT_JOBS`: Parallel agent count (default 4)

### Other Environment Variables
- `REACT_AGENT_ARTIFACT_ROOT`: Custom artifact directory root
- `REACT_AGENT_PATCH_ALLOWED_ROOTS`: Colon-separated allowed patch bundle directories
- `REACT_AGENT_PROMPT_DEBUG=1`: Show prompt section names in output
- `REACT_AGENT_TIMEOUT`: Per-agent subprocess timeout in seconds (default 1800)

### Artifacts
- Single-agent: `data/react_agent_artifacts/<run_id>/`
- Multi-agent: `data/react_agent_artifacts/multi_<run_id>/<patch_key>/` plus `summary.json` and `progress.json`
- Pipeline cache: `data/patches/<target>_patches.pkl.gz`

## Related Files

- `script/react_agent/AGENTS.md`: Detailed development notes and implementation details
- `script/react_agent/tasks/TASKS.md`: Completed and in-progress development tasks
- `script/react_agent/README.md`: Usage examples and CLI reference
