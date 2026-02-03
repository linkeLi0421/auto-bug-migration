# react_agent: Development Notes (AGENTS.md)

## What This Directory Contains
This directory implements a langgraph-based ReAct agent that triages OSS-Fuzz build errors against a **patch bundle**
and iteratively produces override diffs to fix compilation failures.

Key files:

- `script/react_agent/agent_langgraph.py`: main agent loop + prompt + guardrails.
- `script/react_agent/agent_tools.py`: compatibility shim (re-exports `KbIndex`, `SourceManager`, `AgentTools`).
- `script/react_agent/tools/`: tool registry + runner + OSS-Fuzz + artifact helpers.
- `script/react_agent/test_langgraph_agent.sh`: offline regression tests (fast).

Plans live in `script/react_agent/tasks/TASKS.md`.

## Static Analysis KB (V1/V2 JSON)
The agent can query libclang-produced JSON for V1/V2 symbol definitions and locations.

### Input Data Format
The input is a directory of JSON files (`*_analysis.json`). You can check example in `data/libxml2-e11519`
Each JSON file contains a list of dictionaries. The structure of a single entry is strictly based on this schema:

```jsonc
{
  "kind": "FUNCTION_DECL",  // or STRUCT_DECL, TYPEDEF_DECL, etc.
  "spelling": "my_function",
  "usr": "c:@F@my_function",
  "location": {
    "file": "/src/path/to/file.c",
    "line": 10,
    "column": 5
  },
  "extent": {
    "start": { "file": "/src/path/to/file.c", "line": 10, "column": 1 },
    "end":   { "file": "/src/path/to/file.c", "line": 25, "column": 1 }
  },
  // If it's a struct, it might have basic field info if captured
  // If it's a function, it might contain callee info embedded as children nodes
}
```

### Implementation Notes (KB + Source Reader)
Historically, this repo used a 3-class split (KbIndex / SourceManager / AgentTools). The codebase still follows
that conceptually, but the agent-facing tools are now exposed via `search_definition` / `read_file_context` and deterministic patch tools.

1. Class: KbIndex (The Knowledge Base)
Goal: Aggregate scattered JSON files into an efficient in-memory index.

__init__(self, v1_root_dir, v2_root_dir):

Recursively find all *.json files in both directories.

Parse them and build a lookup table: self.index[usr] = { 'v1': [nodes], 'v2': [nodes] }.

Also maintain a name-based index: self.name_index[spelling] = ... (handle name collisions by prioritizing definitions over declarations).

Note: The file paths in JSON might start with /src/ or #include <.... Store them as-is; the SourceManager will handle the resolution.

query_symbol(self, name_or_usr):

Accepts a symbol name or a USR string.

Returns a dict: {'v1': node, 'v2': node}.

If multiple definitions exist, prioritize the one where kind ends in _DEFI or is_definition is implicit.

get_callers_callees(self, name, version='v1'):

Finds the function definition node.

Iterates through its children (if your JSON structure captured CALL_EXPR or DECL_REF_EXPR) to return a list of dependencies.

2. Class: SourceManager (The File Reader)
Goal: Map the abstract JSON paths to the local filesystem and read code.

__init__(self, local_v1_path, local_v2_path):

local_v1_path: The real path on your disk where Version 1 code resides.

local_v2_path: The real path on your disk where Version 2 code resides.

_resolve_path(self, json_path, version):

Logic:

If json_path starts with /src, strip it and append to the corresponding local_vX_path.

If json_path looks like #include <foo.h>, try to find foo.h in the include directories of the local repo.

Return the absolute OS path.

get_code_segment(self, file_path, start_line, end_line, version):

Reads the file.

Returns the string content between start_line and end_line.

Handle encoding errors (use errors='replace').

get_function_code(self, kb_node, version):

Convenience wrapper. extract start.line and end.line from kb_node['extent'] and call get_code_segment.

3. Class: AgentTools (The Interface)
Goal: High-level tools that the ReAct agent will call.

inspect_symbol(self, symbol_name):

Uses KbIndex to find the symbol in V1 and V2.

Uses SourceManager to fetch the source code for both.

Returns a formatted string:

Plaintext

=== Version 1 ===
File: ...
Code:
... code ...

Note: the agent-facing tool set now prefers `search_definition(symbol_name, version=v1|v2)` and does not expose `inspect_symbol` as a tool.

=== Version 2 ===
Status: [Missing / Changed / Same]
File: ...
Code:
... code ...

## Implementation Details
Use pathlib for path manipulation.

Assume the JSON files might contain duplicates; the KbIndex must handle this gracefully.

Include docstrings for all methods.

## Patch-Aware Workflow (Patch Bundles)
Patch bundles (`*.patch2`) store per-hunk patch entries keyed by `patch_key`. In patch-aware runs:

- Build-log locations `/src/...:line` refer to the migrated code; use patch tools to map them back into the bundle.
- Patch bundles are applied via `git apply --reverse`: in these diffs, `-` lines become **additions**.
- Recommended tool order:
  - `parse_build_errors` → `get_error_patch_context` → (KB/source inspection) → `read_artifact` (BASE slice)
  - then `make_error_patch_override` → `ossfuzz_apply_patch_and_test`

### Merged/Tail Hunks (Function-by-Function)
Some patch hunks contain multiple merged/tail functions. The agent groups errors by `old_signature` and focuses on one
function group per round. The active group is shown in the prompt header as:

- `Active function (old_signature): ...`

### `make_error_patch_override` Rules (Critical)
When generating an override diff:

- `new_func_code` MUST be derived from the latest BASE slice (the most recent `read_artifact` output).
- In merged/tail hunks, `new_func_code` MUST rewrite ONLY the mapped slice for the **active** function group.
  Do NOT paste the entire patch/hunk, and do NOT include unified-diff headers (`diff --git`, `@@`, `---/+++`).
- `patch_text` returned by `make_error_patch_override` must never be truncated (it becomes an applyable override diff artifact).

### Symbol Lookup Gotcha
`search_definition` is not a struct-field lookup. Do not call it on member names like `nsdb` or expressions like `ctxt->nsdb`.
Instead: call `search_definition(symbol_name="struct <Name>", version="v1")` and `search_definition(..., version="v2")`,
then inspect the returned struct body (fields, nesting, `#if` guards) to infer the correct field mapping.

## Tests
- `bash script/react_agent/test_langgraph_agent.sh`
- `bash script/migration_tools/test_migration_tools.sh`

## Multi-agent (multi-hunk) notes

- `script/react_agent/multi_agent.py` writes per-hunk artifacts under `data/react_agent_artifacts/multi_<run_id>/<patch_key>/` and a top-level `summary.json`.
- Default output is quiet (no stdout). Use `--output-format json-pretty` if you want the full report on stdout.
- To produce one “final patch” test run across all hunks, use `--final-ossfuzz-test auto|always` (requires `--tools real`); results are stored under `final_ossfuzz_test` in `summary.json`.
