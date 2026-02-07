# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository implements automated fuzzing workflows for OSS-Fuzz projects. The core component is a LangGraph-based ReAct agent (`script/react_agent/`) that triages build errors against patch bundles and iteratively produces override diffs to fix compilation failures during code migration.

## Configurable Docker Images

The fuzzing helper (`script/fuzz_helper.py`) supports configurable base-runner and base-builder Docker images for reproducibility across different time periods.

### Usage
```bash
# Auto-select image based on commit date
python3 script/fuzz_helper.py reproduce myproject fuzzer testcase.bin \
  --runner-image auto --commit-date 1630000000

# Specify custom image digest
python3 script/fuzz_helper.py build_version myproject \
  --commit abc123 --runner-image sha256:859b694f...

# Works with: reproduce, build_version, collect_trace, collect_crash
```

### Image Selection
- `--runner-image auto --commit-date <timestamp>`: Automatically selects appropriate base-builder/base-runner images based on commit timestamp (imports `buildAndtest.py::get_base_builder_for_date()` and `get_base_runner_for_date()`)
- `--runner-image sha256:...`: Uses specified digest for both builder and runner
- No arguments: Uses OSS-Fuzz Dockerfile defaults (no pinning)

### Available Images
See `script/buildAndtest.py` for `BASE_BUILDER_IMAGES` and `BASE_RUNNER_IMAGES` lists with historical Docker image digests from 2019-2022.

### Implementation Details
- **`fuzz_helper.py`**: Handles all Docker image pinning via `prepare_repository()`. Accepts `--runner-image` and `--commit-date` CLI arguments.
- **`buildAndtest.py`**: Orchestrates builds/tests across commit ranges. Delegates image pinning to `fuzz_helper.py` by passing `--runner-image auto --commit-date <timestamp>` options. Also removes `--depth 1` from Dockerfiles to ensure full git history is available for bisection.

## Key Commands

### Install dependencies
```bash
python3 -m pip install -r script/react_agent/requirements.txt
```

### Run tests
```bash
# Main agent regression tests (offline, fast)
bash script/react_agent/test_langgraph_agent.sh

# Migration tools tests
bash script/migration_tools/test_migration_tools.sh

# Symbol tools smoke test
bash script/react_agent/test_symbol_tools.sh
```

### Run the agent (offline stub mode)
```bash
python3 script/react_agent/agent_langgraph.py --model stub --tools fake --max-steps 3 <artifact_dir>
```

### Run the agent (real mode with OpenAI)
```bash
export OPENAI_API_KEY=...
export OPENAI_MODEL=gpt-5-mini
python3 script/react_agent/agent_langgraph.py \
  --model openai --tools real --max-steps 8 --error-scope patch <artifact_dir> \
  --patch-path data/tmp_patch/<project>.patch2 \
  --ossfuzz-project <project> --ossfuzz-commit <sha>
```

### Multi-hunk agent (one agent per patch key)
```bash
python3 script/react_agent/multi_agent.py <artifact_dir> \
  --patch-path data/tmp_patch/<project>.patch2 \
  --model openai --tools real --max-steps 8
```

### List available tools
```bash
python3 script/react_agent/agent_langgraph.py --list-tools --output-format json-pretty
```

## Architecture

### Agent System (`script/react_agent/`)

- **`agent_langgraph.py`**: Main agent loop with prompt construction, guardrails, and ReAct orchestration. Entry point for single-hunk triage.
- **`multi_agent.py`**: Orchestrates multiple agent instances (one per patch_key/hunk). Handles error grouping, fan-out, and final combined patch generation.
- **`prompting.py`**: Dynamic system prompt assembly based on error context (loads fragments from `prompts/`).
- **`models.py`**: LLM abstraction layer (OpenAI, stub, etc.).

### Tools (`script/react_agent/tools/`)

- **`registry.py`**: Tool specification registry.
- **`runner.py`**: Tool execution dispatcher.
- **`ossfuzz_tools.py`**: OSS-Fuzz Docker build/test integration.
- **`extra_patch_tools.py`**: Patch bundle manipulation (list, get, search, override).
- **`symbol_tools.py`**: Symbol/code inspection via static analysis KB.
- **`migration_tools.py`**: Linker error mapping to patch bundles.

### Static Analysis KB (`script/react_agent/core/`)

- **`kb_index.py`**: `KbIndex` loads `*_analysis.json` from V1/V2 into in-memory indices for symbol lookup.
- **`source_manager.py`**: `SourceManager` resolves JSON paths to local checkouts and reads code by extent.

### Patch Bundle Format

Patch bundles (`*.patch2`) are pickled dictionaries keyed by `patch_key`. They store per-hunk patch entries. In patch-aware runs:
- Build-log locations `/src/...:line` refer to migrated code
- Patch bundles use `git apply --reverse` semantics: `-` lines become **additions**
- Override diffs rewrite specific function slices within hunks

### Artifacts

Agent outputs (diffs, logs, observations) go to `data/react_agent_artifacts/<run_id>/` or `data/react_agent_artifacts/multi_<run_id>/<patch_key>/`.

## Key Concepts

### Error Scope Modes
- `--error-scope first`: Process only the first error
- `--error-scope patch`: Group errors by patch_key and process all errors for a hunk

### Error Types and Hunk Status
- **Compiler errors**: Detected via `file:line:col: error:` patterns. These determine hunk "fixed" status.
- **Linker errors**: Detected via `undefined reference to` patterns. These are grouped by patch_key alongside compiler errors.
- **Hunk fixed**: A hunk is marked "fixed" when all **compiler errors** in the active patch_key are resolved.

### Patch-Aware Workflow
Recommended tool order: `parse_build_errors` → `get_error_patch_context` → `read_artifact` (BASE slice) → `make_error_patch_override` → `ossfuzz_apply_patch_and_test`

### Environment Variables
- `OPENAI_API_KEY`: API key for OpenAI models
- `OPENAI_MODEL`: Model name (e.g., `gpt-5-mini`)
- `REACT_AGENT_ARTIFACT_ROOT`: Custom artifact directory root
- `REACT_AGENT_PATCH_ALLOWED_ROOTS`: Colon-separated paths for allowed patch bundle directories
- `REACT_AGENT_PROMPT_DEBUG=1`: Show prompt section names in output

## Related Files

- `script/react_agent/AGENTS.md`: Detailed development notes and implementation details
- `script/react_agent/tasks/TASKS.md`: Completed and in-progress development tasks
- `script/react_agent/README.md`: Usage examples and CLI reference
