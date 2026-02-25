# Plan: Relocate Header `__revert_*` Function Definitions To Caller `.c` Before First `add_context`

## Goal
Before the first `add_context(...)` call in `apply_and_test_patches` (`script/revert_patch_test.py:2981`), detect recreated function-definition patches that target header files (e.g. `sam_internal.h`) and relocate those definitions into a caller source-file hunk.

Required policy from user:
- Keep original generation behavior unchanged up to this stage.
- Do relocation just before first `add_context`.
- If multiple callsites exist, choose the callsite with the smallest line number.

## Where to hook
In `apply_and_test_patches(...)`:
- Current flow:
  1. `patch_patcher(...)`
  2. `add_patch_for_trace_funcs(...)`
  3. `llvm_fuzzer_test_one_input_patch_update(...)`
  4. sort keys
  5. `add_context(...)`
- New relocation step should run between (3) and (4), so `add_context` sees final patch layout.

## Proposed helper
Add a helper (new function), e.g.:
- `_relocate_header_revert_function_defs(diff_results, patch_key_list, commit_id) -> List[str]`

It returns an updated `patch_key_list` (or mutates in place and returns it).

## Candidate detection logic
For each key in `patch_key_list`, treat patch as relocation candidate iff:
- `patch.file_path_new` is a header (`.h`, `.hh`, `.hpp`, `.hxx`)
- patch text contains a removed function-definition block line matching:
  - `-static ... __revert_<commit>_<name>(...) {`
  - or `-static inline ... __revert_<commit>_<name>(...) {`
- block is a real definition (`{ ... }`), not prototype.

Implementation detail:
- Reuse/introduce parser for removed function block extraction from unified diff body:
  - find start line with `__revert_*(` and `{`
  - track brace depth on removed lines until block end.

## Callsite discovery logic
For each extracted symbol `__revert_<commit>_<name>`:
- scan all other patches in `patch_key_list` (non-header preferred) for occurrences of `__revert_<commit>_<name>(`.
- compute actual line number of each occurrence in the hunk:
  - parse `@@ -old_start,old_len +new_start,new_len @@`
  - walk hunk body and maintain `new_line` counter:
    - `' '`: `new_line += 1`
    - `'+'`: `new_line += 1`
    - `'-'`: no increment
  - since these patches are reverse-applied and we care about migrated code additions, prioritize hits on `'-'` lines, but accept any line type if needed.
- choose the global smallest line number among all hits.

If no callsite found:
- do nothing for this symbol (leave header definition patch unchanged).

## Relocation target and anchor
Given selected callsite:
- target file: callsite patch file (`patch.file_path_new`, normalized).
- insertion line:
  1. `target_patch.new_function_start_line` if available and > 0
  2. else the chosen callsite line number

User requirement interpreted:
- “just before the function that calls them” => prefer `new_function_start_line`.
- “if more than one callsites, choose smallest line number” => choose earliest callsite first.

## Patch rewrite strategy
For each relocated symbol:
1. Create a new synthetic patch in target `.c`:
   - header:
     - `diff --git a/<target> b/<target>`
     - `--- a/<target>`
     - `+++ b/<target>`
   - hunk:
     - `@@ -<insert_line>,<N> +<insert_line>,0 @@`
     - removed lines = extracted function-definition block (`-...`)
2. Create `PatchInfo` for synthetic patch:
   - `file_path_old/new = target file`
   - `patch_type` should include `Recreated function` and function-body markers.
   - start/end lines set consistently with existing artificial patch style.
3. Remove original header-definition patch key from `patch_key_list` **if** all extracted defs in that patch were relocated.
4. Keep any non-definition content in original header patch:
   - if candidate patch contains only definition block, drop key fully.
   - if mixed content exists, rewrite candidate patch text to remove moved block and keep remaining lines.

## Ordering and safety
After relocation pass:
- dedupe `patch_key_list`
- sort by `diff_results[key].new_start_line` descending (same existing behavior)
- continue with `add_context(...)`.

Safety guards:
- Never relocate into header file.
- Never relocate if target insertion line invalid (`<= 0`).
- If target patch file path is `/dev/null`, skip.
- If synthetic patch text hashes to an existing key, reuse key.

## Logging
Add explicit logs:
- candidate found in header
- symbol and chosen target file/line
- whether relocation succeeded or skipped (with reason)
- keys removed/added

## Validation plan
1. Re-run OSV-2023-1370 flow.
2. Verify output diff:
   - `sam_internal.h` no longer contains `-static inline void __revert_..._nibble2base(...) {`
   - one `.c` patch contains relocated `__revert_..._nibble2base` definition.
3. Verify chosen target corresponds to smallest-line callsite.
4. Ensure `add_context` still succeeds with relocated synthetic patch.

## Non-goals
- Do not change original patch generation behavior before this relocation step.
- Do not alter enum/type relocation behavior.
- Do not modify react-agent override logic in this task.

