# react_agent tooling

Python tooling for exploring libclang JSON analysis output across two versions of a C/C++ codebase (V1 → V2).

## Core library

- `script/react_agent/agent_tools.py`:
  - `KbIndex`: loads `*_analysis.json` files from V1 and V2 into in-memory indices.
  - `SourceManager`: resolves JSON file paths to local checkouts and reads code segments by extent.
  - `AgentTools`: convenience wrapper to fetch “V1 vs V2” code for a symbol.

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

## LLM + LangGraph agent

`script/react_agent/agent_langgraph.py` is an LLM-driven agent loop that can call:

- Symbol/code tools:
  - `inspect_symbol(symbol_name)`
  - `read_file_context(file_path, line_number, context, version)`
  - `search_definition(symbol_name, version)` (use `version=v1|v2`)
  - `search_definition_in_v1(symbol_name)` (deprecated alias)
- Patch-bundle tools (read-only, from `data/tmp_patch/*.patch2`):
  - `list_patch_bundle(patch_path, filter_file?, filter_patch_type?, limit?)`
  - `get_patch(patch_path, patch_key, include_text?, max_lines?)`
  - `search_patches(patch_path, query, limit?)`
  - `get_error_patch(patch_path, file_path, line_number)`
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
python3 script/react_agent/agent_langgraph.py \
  --model openai --tools real --max-steps 4 tmp1 \
  --v1-json-dir /path/to/v1/json --v2-json-dir /path/to/v2/json \
  --v1-src /path/to/v1/src --v2-src /path/to/v2/src
```

Output format:

- Default: `--output-format auto` (prints human-friendly text when stdout is a TTY; otherwise prints JSON)
- Force JSON: `--output-format json` or `--output-format json-pretty`

List tools:
```bash
python3 script/react_agent/agent_langgraph.py --list-tools
python3 script/react_agent/agent_langgraph.py --list-tools --output-format json-pretty
```
