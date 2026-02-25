# Plan: Better Follow-up Fix Support for Functions Inserted Into `_extra_*` Hunks

## Goal
Enable reliable multi-step fixing when a function inserted into an `_extra_*` hunk still fails to compile, so `get_error_patch_context` and `make_error_patch_override` target the correct function slice instead of a broad contiguous block.

## Why
- Current `_extra_*` entries often have empty `hiden_func_dict` metadata.
- Mapping can collapse to a nearest contiguous `-` run, which may cover multiple inserted functions.
- Follow-up `make_error_patch_override` then rewrites too much, causing unstable iterations.

## Implementation Plan
- [x] Add `_extra_*` function boundary inference in `script/migration_tools/tools.py`:
  - parse minus-side function definition starts from unified-diff hunk body;
  - produce temporary `hiden_func_dict`-compatible offsets when metadata is absent.

- [x] Use inferred offsets in `_get_error_patch_from_bundle(...)` for `_extra_*` hunks:
  - when `patch.hiden_func_dict` is empty and patch is `Extra`, derive boundaries from patch text;
  - pick function slice by nearest hit index and next function start, not whole minus block.

- [x] Ensure rewrite flow remains stable after edits:
  - mapping after `make_error_patch_override` must still resolve to the correct function in rewritten `_extra_*` text.

- [x] Add regressions in `script/react_agent/test_langgraph_agent.sh`:
  - `_extra_*` hunk with two inserted function definitions; error in second function maps to second only;
  - `make_error_patch_override` rewrites only the selected function slice.

## Acceptance Criteria
- [x] `get_error_patch_context` on `_extra_*` function errors returns function-local `error_func_code`.
- [x] `make_error_patch_override` on `_extra_*` rewrites only the intended inserted function.
- [x] Existing non-`_extra_*` mapping behavior is unchanged.
- [x] `bash script/react_agent/test_langgraph_agent.sh` passes.
