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
- `iter_compiler_errors(build_log, snippet_lines=...)`

## LLM + LangGraph agent

`script/react_agent/agent_langgraph.py` is an LLM-driven agent loop that can call:

- Symbol/code tools:
  - `read_artifact(artifact_path, start_line?, max_lines?, query?, context_lines?, max_chars?)`
  - `read_file_context(file_path, line_number, context, version)`
  - `search_definition(symbol_name, version)` (use `version=v1|v2`)
  - `kb_search_symbols(symbols, version, kinds?, limit_per_symbol?)` (KB lookup for macros/types/functions; includes `MACRO_DEFINITION`)
- OSS-Fuzz Docker testing (opt-in):
  - `ossfuzz_apply_patch_and_test(project, commit, patch_path, patch_override_paths?, build_csv?, sanitizer?, architecture?, engine?, fuzz_target?, run_fuzzer_seconds?, timeout_seconds?, use_sudo?)`
  - It writes a merged `.diff` file (bundle + overrides) under the artifact directory and uses it as the OSS-Fuzz `--patch` input.
- Patch-bundle tools (read-only, from `data/tmp_patch/*.patch2`):
  - `list_patch_bundle(patch_path, filter_file?, filter_patch_type?, limit?)`
  - `get_patch(patch_path, patch_key, include_text?, max_lines?)`
  - `search_patches(patch_path, query, limit?)`
  - `get_error_patch_context(patch_path, file_path, line_number, error_text?, context_lines?, max_total_lines?)`
    - Includes `patch_minus_code` (all `-` lines in the hunk), `error_func_code` (mapped `-` slice for the error function), and macro-token hints like `macro_tokens_not_defined_in_slice`.
  - `make_error_patch_override(patch_path, file_path, line_number, new_func_code, context_lines?, max_lines?, max_chars?)` (rewrites the mapped patch slice by replacing its `-` lines)
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
  --model openai --tools real --max-steps 8 --error-scope patch tmp1 \
  --patch-path data/tmp_patch/libxml2.patch2 \
  --ossfuzz-project libxml2 --ossfuzz-commit <git-sha> \
  --v1-json-dir /path/to/v1/json --v2-json-dir /path/to/v2/json \
  --v1-src /path/to/v1/src --v2-src /path/to/v2/src

# Patch-scope triage for a specific hunk (patch_key)
python3 script/react_agent/agent_langgraph.py \
  --model openai --tools real --max-steps 8 --error-scope patch --focus-patch-key <patch_key> tmp1 \
  --patch-path data/tmp_patch/libxml2.patch2 \
  --ossfuzz-project libxml2 --ossfuzz-commit <git-sha> \
  --v1-json-dir /path/to/v1/json --v2-json-dir /path/to/v2/json \
  --v1-src /path/to/v1/src --v2-src /path/to/v2/src
```

Debugging LLM I/O:

- `--debug-llm` prints the full request `messages` and parsed `response` to stderr.
- `--debug-llm-dir <dir>` also writes `llm_call_XXXX_request.json` / `llm_call_XXXX_response.json`.
- If the parsed `response` is empty, the response dump includes `response_debug` with raw HTTP JSON (`raw_body`) and basic metadata (status/content-type/finish_reason) to help diagnose provider-side empty outputs.

## Multi-hunk driver (one agent per patch_key)

`script/react_agent/multi_agent.py` parses a build log, maps errors to patch hunks (`patch_key`), and runs one patch-scope
agent per hunk. By default it writes only `summary.json` (no stdout); use `--output-format json-pretty` if you want it to
print the report.

```bash
python3 script/react_agent/multi_agent.py tmp1 \
  --patch-path data/tmp_patch/libxml2.patch2 \
  --ossfuzz-project libxml2 --ossfuzz-commit <git-sha> \
  --model openai --tools real --max-steps 8 \
  --v1-json-dir /path/to/v1/json --v2-json-dir /path/to/v2/json \
  --v1-src /path/to/v1/src --v2-src /path/to/v2/src
```

Notes:
- Limit fan-out: `--max-groups 10`
- Run only specific hunks: `--only-patch-keys p1,p2,p3`
- Retry a failing hunk from a clean slate: `--max-restarts-per-hunk 1`
- Run one final OSS-Fuzz build/check_build with *all* hunks’ overrides:
  - `--final-ossfuzz-test auto` (default): only when all hunks are `fixed` and `--tools real`
  - `--final-ossfuzz-test always`: run regardless of per-hunk status (still requires `--tools real`)
  - `--final-ossfuzz-test never`: skip
- Multi-run artifacts: `data/react_agent_artifacts/multi_<run_id>/<patch_key>/` plus a top-level `summary.json`

Final combined overrides:

- `multi_agent.py` selects the “latest” override diff per hunk (prefers `agent_stdout.json.next_step`’s `Override diff: ...`,
  otherwise picks the newest `make_error_patch_override_patch_text*.diff` file), and sorts hunks bottom-up using the
  patch bundle’s `new_start_line` (same ordering as `script/revert_patch_test.py`).
- It also writes a combined debug artifact: `data/react_agent_artifacts/multi_<run_id>/combined_override_diffs.diff`.
- If `--final-ossfuzz-test` runs, its results and log paths are recorded under `final_ossfuzz_test` in `summary.json`.

Patch bundle path notes:

- `--error-scope patch` requires `--patch-path` (or `REACT_AGENT_PATCH_PATH`).
- If `--patch-path` is omitted and `--v2-src` is provided, the agent will try to infer `data/tmp_patch/<v2-src-basename>.patch2` if it exists.
- For safety, patch bundles are only readable from `data/tmp_patch/` by default; to allow other directories, set `REACT_AGENT_PATCH_ALLOWED_ROOTS` (colon-separated like `PATH`).

Artifacts (reduce prompt/output size):

- Patch-related tool outputs (diff excerpts / patch slices containing V1-origin `-` lines / generated patches) are persisted under `data/react_agent_artifacts/<patch_key>/` when `patch_key` is known (patch-aware runs). Otherwise they use `data/react_agent_artifacts/<run_id>/`.
- By default, files are overwritten by name within the `patch_key` directory (no `.1`, `.2`, ... accumulation). When `--auto-ossfuzz-loop` is enabled, the agent preserves per-iteration artifacts by allocating unique filenames instead of overwriting.
- Tool observations replace large fields with `{artifact_path, sha256, bytes, lines}`.
- Configure with:
  - `REACT_AGENT_ARTIFACT_ROOT=/path/to/root` to change the base root while still using `<patch_key>/` or `<run_id>/`
  - `--no-artifacts` to disable

Output format:

- Default: `--output-format auto` (prints human-friendly text when stdout is a TTY; otherwise prints JSON)
- Force JSON: `--output-format json` or `--output-format json-pretty`
- When `--auto-ossfuzz-loop` is enabled, the agent may trim internal prompt context between iterations, but the final output still reports the full tool-step history for the whole run.

List tools:
```bash
python3 script/react_agent/agent_langgraph.py --list-tools
python3 script/react_agent/agent_langgraph.py --list-tools --output-format json-pretty
```
