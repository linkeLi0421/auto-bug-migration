# Tasks

Archived plans live in `script/react_agent/tasks/TASKS_*.md`. This file tracks the current active items.

## Plan: Fix `_extra_*` insertion order (use AST insert anchors; avoid “unknown type name”)
Context: Some multi-agent runs hit ordering issues like:
`/src/libxml2/parserInternals.c:93:1: error: unknown type name 'xmlParserNsData'`
because declarations inserted into `_extra_*` hunks can end up after prototypes that reference them. The current
“insert-after-includes” heuristic is sensitive to the include/preprocessor region. To stabilize, switch the insertion
anchor selection to an AST-derived line number approach (like `get_patch_insert_line_number(...)` in
`script/revert_patch_test.py`) when analysis JSON is available.

- [x] Repro from artifacts: confirm `xmlParserNsData` is referenced before its typedef in `_extra_parserInternals.c`.
- [x] Implement AST-based anchor selection for new `_extra_*` skeletons:
  - Reuse V2 `*_analysis.json` function extents to choose an insertion line (start.line of selected function).
  - Default: if no anchor func_sig is provided, insert before the first function definition (smallest start line).
  - Optional: override the anchor with `REACT_AGENT_EXTRA_SKELETON_ANCHOR_FUNC_SIG` (signature match, ignore arg types).
  - Fallback: keep `_find_file_scope_insertion_index` when analysis JSON is unavailable.
- [x] Decide anchor policy:
  - Default is before the first function.
  - Override with `REACT_AGENT_EXTRA_SKELETON_ANCHOR_FUNC_SIG` when a specific stable function is preferred.
- [x] Add regression coverage: ensure skeleton insertion anchor uses the AST-derived line number when V2 analysis JSON exists.
- [ ] Re-run `script/react_agent/multi_agent.py` on the failing run and confirm ordering-related “unknown type name” errors are gone.

## Plan: Insert new `_extra_*` hunks before the first function
Context: Some files have multiple nearby hunks that touch the include/attribute region; anchoring the synthesized
`_extra_*` skeleton at EOF or after a function can create overlapping hunks and context drift (“patch does not apply”).
Instead, anchor the new `_extra_*` skeleton **before the first function definition** in the file.

- [x] Define the rule: “before the first function definition” means `insert_line = first_func_extent.start.line` from V2 `*_analysis.json`.
- [x] Implement anchor selection:
  - Use V2 `KbIndex.file_index["v2"][basename]` to find the minimum `extent.start.line` among `FUNCTION_DEFI`/`CXX_METHOD`/`FUNCTION_TEMPLATE` nodes in that file.
  - When found, build the skeleton hunk context starting at that line (so the insertions land above the first function).
  - Fallback when no function defs or no JSON: keep `_find_file_scope_insertion_index` (after preprocessor/comments).
- [x] Add regression coverage in `script/react_agent/test_langgraph_agent.sh`:
  - V2 file with `#include` then a first function at a known line.
  - Assert the synthesized `_extra_*` hunk header uses that function-start line (not EOF, not after-includes).
- [ ] Re-run `script/react_agent/multi_agent.py` on a failing multi-run and confirm the merged patch applies cleanly (no context drift between adjacent hunks).
