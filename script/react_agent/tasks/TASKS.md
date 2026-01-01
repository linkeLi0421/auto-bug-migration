# Tasks — Tool extraction from `revert_patch_test.py`

## Goal

Extract a **small, high-value, read-only tool surface** from `script/revert_patch_test.py` so an LLM agent can:

- inspect the generated patch bundle (`data/tmp_patch/*.patch2`)
- locate which patch hunk corresponds to a build error location (e.g. `get_error_patch`)
- parse compiler/build errors into structured data

Non-goal: expose the entire rule-based pipeline to the LLM (no git operations, no patch application, no fuzz runs by default).

## Key artifact: patch bundle (`*.patch2`)

`script/revert_patch_test.py` persists a patch dictionary to:

- `data/tmp_patch/<target>.patch2` (example: `data/tmp_patch/libxml2.patch2`)

This file is a **Python pickle** of `{patch_key: PatchInfo}` created via `save_patches_pickle(...)`.

Constraints to handle:

- Pickles are unsafe to load from arbitrary paths: tools must restrict file locations (e.g. only `data/tmp_patch/`) and use a restricted unpickler.
- Current pickles may reference `__main__.PatchInfo` (when `revert_patch_test.py` ran as a script), so loaders must be backward-compatible.

## Proposed tool surface (curated)

Patch-bundle introspection:

- `list_patch_bundle({patch_path, filter_file?, filter_patch_type?, limit?})` → patch summaries (key/file/types/signatures/line ranges)
- `get_patch({patch_path, patch_key, include_text?, max_lines?})` → one patch’s metadata (and optionally its diff text)
- `search_patches({patch_path, query, limit?})` → match by key/file/signature/patch_type

Error-to-patch mapping:

- `get_error_patch({patch_path, file_path, line_number})` → best patch key for that location + best old signature + (optional) indices for “recreated function” hunks

Build-log parsing:

- `parse_build_errors({build_log_text|build_log_path})` → structured output based on `handle_build_error(...)`:
  - undeclared identifiers/types
  - undeclared/conflicting functions
  - missing struct members (+ 2-line context)
  - too-few/many-args and type-mismatch function call blocks
  - incomplete type errors (+ forward-decl note when available)

## AgentTools ergonomics (v1/v2 symmetry)

Current issue: the agent tool surface has a V1-only helper (`search_definition_in_v1`). We also need to retrieve definitions from V2.

Recommendation: prefer **one** tool with a `version` argument (less tool sprawl, simpler prompting), and keep the old V1-only tool as a deprecated alias for compatibility.

Proposed tool:

- `search_definition({symbol_name, version})` where `version` is `v1|v2`

Back-compat:

- keep `search_definition_in_v1({symbol_name})` but implement it as a thin wrapper calling `search_definition(..., version="v1")`

## Tasks

### 1) Extract stable types (PatchInfo, FunctionLocation)

- [ ] Move `PatchInfo` + `FunctionLocation` into a small importable module (e.g. `script/migration_tools/types.py`).
- [ ] Update `script/revert_patch_test.py` to import these types instead of defining them inline (future pickles won’t reference `__main__`).
- [ ] Keep backward compatibility in loaders for existing `__main__.PatchInfo` pickles.

### 2) Implement safe patch-bundle loader

- [ ] Add `script/migration_tools/patch_bundle.py`:
  - restricted unpickler (allow only basic builtins + the known dataclasses)
  - optional auto-detection of gzip (`.gz`) vs raw pickle
  - path allowlist (default: only `data/tmp_patch/`)
- [ ] Provide a normalized in-memory representation:
  - `patches: dict[str, PatchInfo]`
  - helper indexes: by file, by signature, by patch_type

### 3) Implement the curated tools (pure/read-only)

- [ ] Add `script/migration_tools/tools.py` implementing the tool surface above.
- [ ] Re-implement/adapt `get_error_patch` so it works from only `{patch_path, file_path, line_number}`:
  - derive `patch_key_list` deterministically (e.g. `new_start_line` descending, then key)
  - handle both `file.c` and `/src/.../file.c` forms
  - treat `_extra_...` patches specially (optional)

### 4) Wire into the LLM agent (but keep it optional)

- [ ] Add tool specs to `script/react_agent/tools_wrapper.py` and dispatch in `ToolRunner`.
- [ ] Update `script/react_agent/agent_langgraph.py` prompt/tool registry to include the new tools.
- [ ] Enforce output-size limits (truncate patch text; return summaries by default).

### 5) Add `search_definition(..., version)`

- [ ] Update `script/react_agent/agent_tools.py`:
  - add `search_definition(symbol_name, version="v1")`
  - keep `search_definition_in_v1` as an alias (mark deprecated in docstring)
- [ ] Update `script/react_agent/tools_wrapper.py`:
  - add `search_definition` to `TOOL_SPECS` + `ALLOWED_TOOLS`
  - dispatch in `ToolRunner.call` with validation for `version in {"v1","v2"}`
- [ ] Update `script/react_agent/models.py` stub behavior to use `search_definition` (version-aware) instead of the V1-only tool.
- [ ] Update `script/react_agent/test_langgraph_agent.sh` allowlist to include `search_definition` (keep the old one allowed during transition).
- [ ] Update docs/examples if needed (`script/react_agent/README.md` and `--list-tools` output).

### 6) Tests + fixtures

- [ ] Add a tiny synthetic patch-bundle fixture (small pickle) under `script/migration_tools/fixtures/`.
- [ ] Add tests validating:
  - loader backward compatibility with `__main__.PatchInfo`
  - `get_error_patch` returns stable results for a known file/line
  - outputs are JSON-serializable and bounded in size

## Success criteria

- [ ] `python3 script/react_agent/agent_langgraph.py --list-tools` lists the new migration tools.
- [ ] Running `get_error_patch` against `data/tmp_patch/libxml2.patch2` returns a patch key + signature for an error location from `tmp1`.
- [ ] No tool can load pickles from outside the allowed patch directory by default.
- [ ] `search_definition` can retrieve code from both V1 and V2 via `version=v1|v2`.
