# react_agent tooling

Python tooling for exploring libclang JSON analysis output across two versions of a C/C++ codebase (V1 → V2).

## Core library

- `script/react_agent/core/kb_index.py`: `KbIndex` loads `*_analysis.json` from V1 and V2 into in-memory indices.
- `script/react_agent/core/source_manager.py`: `SourceManager` resolves JSON paths to local checkouts and reads code segments by extent.
- `script/react_agent/tools/symbol_tools.py`: `AgentTools` implements symbol/code tools used by the agent.
- `script/react_agent/agent_tools.py`: compatibility shim (re-exports `KbIndex`, `SourceManager`, `AgentTools`).

## Quick start (manual test)

Use the smoke-test CLI:
```bash
python3 script/react_agent/tests/tool_cli.py -h
python3 script/react_agent/tests/tool_cli.py <symbol-or-usr> --v1-json-dir ... --v2-json-dir ... --v1-src ... --v2-src ...
```

See `script/react_agent/tests/README.md` for a concrete run log and example commands.

## Build-log parsing utilities

`script/react_agent/build_log.py` provides:

- `load_build_log(path_or_stdin)`
- `find_first_fatal(build_log)`
- `iter_compiler_errors(build_log, limit=..., snippet_lines=...)`

## LLM + LangGraph agent

`script/react_agent/agent_langgraph.py` is an LLM-driven agent loop that can call:

- Symbol/code tools:
  - `inspect_symbol(symbol_name)`
  - `read_file_context(file_path, line_number, context, version)`
  - `search_definition(symbol_name, version)` (use `version=v1|v2`)
  - `search_definition_in_v1(symbol_name)` (deprecated alias)
  - `search_text(query, version, limit?, file_glob?)` (macro/typedef fallback when clang JSON has no result)
- Patch-bundle tools (read-only, from `data/tmp_patch/*.patch2`):
  - `list_patch_bundle(patch_path, filter_file?, filter_patch_type?, limit?)`
  - `get_patch(patch_path, patch_key, include_text?, max_lines?)`
  - `search_patches(patch_path, query, limit?)`
  - `get_error_patch(patch_path, file_path, line_number)`
  - `get_error_patch_context(patch_path, file_path, line_number, error_text?, context_lines?, max_total_lines?)`
  - `get_error_v1_function_code(patch_path, file_path, line_number, max_lines?, max_chars?)`
  - `make_error_function_patch(patch_path, file_path, line_number, new_func_code, context_lines?, max_lines?, max_chars?)`
  - `parse_build_errors(build_log_path?|build_log_text?)`

All agent-callable tool specs + dispatch live under `script/react_agent/tools/`.

Install dependencies:
```bash
python3 -m pip install -r script/react_agent/requirements.txt
```

Offline (no network) stub run:
```bash
python3 script/react_agent/agent_langgraph.py --model stub --tools fake --max-steps 3 tmp1
bash script/react_agent/test_langgraph_agent.sh
```

Real tools + OpenAI (requires network + API key):
```bash
export OPENAI_API_KEY=...
export OPENAI_MODEL=gpt-5-mini
export OPENAI_MAX_TOKENS=4000  # bump if you see empty/invalid JSON responses

# Patch-aware triage (recommended when the build log is from migrated code)
python3 script/react_agent/agent_langgraph.py \
  --model openai --tools real --max-steps 4 tmp1 \
  --patch-path data/tmp_patch/libxml2.patch2 \
  --v1-json-dir /path/to/v1/json --v2-json-dir /path/to/v2/json \
  --v1-src /path/to/v1/src --v2-src /path/to/v2/src

# Patch-scope triage: group all errors that map to the same patch key
python3 script/react_agent/agent_langgraph.py \
  --model openai --tools real --max-steps 6 --error-scope patch --max-errors 50 tmp1 \
  --patch-path data/tmp_patch/libxml2.patch2 \
  --v1-json-dir /path/to/v1/json --v2-json-dir /path/to/v2/json \
  --v1-src /path/to/v1/src --v2-src /path/to/v2/src
```

Patch bundle path notes:

- `--error-scope patch` requires `--patch-path` (or `REACT_AGENT_PATCH_PATH`).
- If `--patch-path` is omitted and `--v2-src` is provided, the agent will try to infer `data/tmp_patch/<v2-src-basename>.patch2` if it exists.
- For safety, patch bundles are only readable from `data/tmp_patch/` by default; to allow other directories, set `REACT_AGENT_PATCH_ALLOWED_ROOTS` (colon-separated like `PATH`).

Output format:

- Default: `--output-format auto` (prints human-friendly text when stdout is a TTY; otherwise prints JSON)
- Force JSON: `--output-format json` or `--output-format json-pretty`

List tools:
```bash
python3 script/react_agent/agent_langgraph.py --list-tools
python3 script/react_agent/agent_langgraph.py --list-tools --output-format json-pretty
```
