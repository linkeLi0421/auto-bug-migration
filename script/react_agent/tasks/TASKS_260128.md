# TASKS

## 2026-01-28: Fix linker error mapping in _summarize_target_error_status

**Problem:** After OSS-Fuzz test, the agent shows "Active function fixed: unknown" for linker errors instead of properly determining if the error is fixed.

**Root Cause:** In `_summarize_target_error_status()`:
1. `mapping_for_error()` skipped errors with `line_number <= 0` (line 697: `if not (state.patch_path and fp and ln > 0): return {}`)
2. Linker errors have `line=0`, so they couldn't be mapped to patch_keys
3. `patch_key_for_error()` only supported compiler error mapping, not linker error mapping
4. The matching logic didn't handle linker errors (which have `function` instead of `line`)

**Solution:** Add linker error mapping support:
1. Add `mapping_for_linker_error()` function that uses `_get_link_error_patch_from_bundle` with function name
2. Modify `patch_key_for_error()` to accept `function_name` and `is_linker` parameters
3. Update all matching logic to check `kind == "linker"` and use appropriate mapping

**Tasks:**
- [x] Add `_ensure_bundle_loaded()` helper to share bundle loading between mapping functions
- [x] Add `linker_mapping_cache` for caching linker error mappings
- [x] Add `mapping_for_linker_error(file_path, function_name)` function
- [x] Modify `patch_key_for_error()` to accept linker error parameters
- [x] Update "active_old_signature" matching block (lines 780-849) to handle linker errors
- [x] Update general target matching block (lines 851-900) to handle linker errors

**Changes Made:**
- Refactored bundle loading into `_ensure_bundle_loaded()` helper
- Import `_get_link_error_patch_from_bundle` alongside `_get_error_patch_from_bundle`
- Added `mapping_for_linker_error()` that uses function name for mapping
- Modified `patch_key_for_error()` signature to `(file_path, line_number, function_name="", is_linker=False)`
- Updated both matching loops to:
  - Check `is_linker` from `err.get("kind")` field
  - Use appropriate mapping function based on error type
  - Include `function` and `kind` fields in result dicts

**Testing:** All tests pass.

---

## 2026-01-28: Fix OSS-Fuzz tool output not being read as artifacts

**Problem:** Two issues with `ossfuzz_apply_patch_and_test`:
1. Merged diff stored at artifact root instead of under patch_key directory
2. "Missing OSS-Fuzz tool output" error even when build log exists

**Root Cause:**
1. `ossfuzz_apply_patch_and_test` was returning raw build output text in `build_output` and `check_build_output` fields
2. But `_read_ossfuzz_logs()` and `_ossfuzz_artifact_path()` expected artifact references with `artifact_path` fields
3. When raw text was passed as a "path", file reading would fail

**Solution:** Modify `ossfuzz_apply_patch_and_test` to:
1. Write build outputs to artifact files (`.log`) under the same directory as the merged patch
2. Return artifact reference dicts instead of raw text

**Tasks:**
- [x] Import `ArtifactStore` in `ossfuzz_tools.py`
- [x] Write build, check_build, and run_fuzzer outputs as artifact files
- [x] Return artifact reference dicts (with `artifact_path`, `sha256`, `bytes`, `lines`)

**Changes Made:**
- Added `from artifacts import ArtifactStore` import
- Modified `ossfuzz_apply_patch_and_test` return section to:
  - Use `ArtifactStore` with the merged patch's parent directory
  - Write `ossfuzz_apply_patch_and_test_build_output.log`
  - Write `ossfuzz_apply_patch_and_test_check_build_output.log`
  - Optionally write `ossfuzz_apply_patch_and_test_run_fuzzer_output.log`
  - Return `.to_dict()` artifact references instead of raw text

**Testing:** All tests pass.

---

## 2026-01-28: Teach agent to check _extra_* patches for indirect symbol references in linker errors

**Problem:** When fixing linker errors like `undefined reference to 'defaultHandlers'`, the agent only checks the function code. But if the function doesn't directly use `defaultHandlers`, the agent can't find the reference. The symbol might be referenced indirectly through a variable declared in the `_extra_*` patch for the same file.

**Example:**
- Linker error: `undefined reference to 'defaultHandlers'` in function `__revert_e11519_xmlLookupCharEncodingHandler`
- The function uses `xmlLatin1Handler`, not `defaultHandlers` directly
- But `_extra_encoding.c` has: `static const xmlCharEncodingHandler *xmlLatin1Handler = &defaultHandlers[4];`
- Fix: Modify the FUNCTION code to replace `xmlLatin1Handler` with NULL using `make_link_error_patch_override`

**Solution:**
1. Add guidance to the linker error prompt (`system_linker_error.txt`) to check `_extra_*` patches
2. Guide agent to modify function code (NOT the `_extra_*` patch) to avoid indirect references
3. Fix `_prepare_next_patch_scope_iteration_after_ossfuzz` to handle linker errors (was skipping them because `line=0`)

**Tasks:**
- [x] Update `prompts/system_linker_error.txt` with guidance for checking _extra_* patches
- [x] Guide agent to use `make_link_error_patch_override` to modify function code (not `make_extra_patch_override`)
- [x] Fix `_prepare_next_patch_scope_iteration_after_ossfuzz` to handle linker errors

**Changes Made:**
1. Added section to `system_linker_error.txt` explaining:
   - How to identify indirect symbol references in `_extra_*` patches
   - To modify the FUNCTION code using `make_link_error_patch_override` (e.g., replace `xmlLatin1Handler` with NULL)
   - NOT to use `make_extra_patch_override` (blocked by guardrail for `_extra_*` errors)
2. Fixed `_prepare_next_patch_scope_iteration_after_ossfuzz()` to:
   - Import `_get_link_error_patch_from_bundle` in addition to `_get_error_patch_from_bundle`
   - Check `is_linker` based on `kind` field
   - Use function name for linker error mapping instead of line number
   - This allows the auto-loop to continue when linker errors remain in the active patch_key

**Testing:** All tests pass.

---

## 2026-01-28: Auto-call ossfuzz_apply_patch_and_test after make_link_error_patch_override

**Problem:** After `make_link_error_patch_override` completes, the LLM has to decide to call `ossfuzz_apply_patch_and_test`. This wastes a model turn since the action is always required.

**Root Cause:** In the `tool_node` handler for `make_link_error_patch_override` (line 5721), `st.patch_generated` was not being set to `True`, unlike the handler for `make_error_patch_override` (line 5572).

The `llm_node` has auto-call logic at line 4494: `if st.patch_generated and not st.ossfuzz_test_attempted:` which automatically triggers `ossfuzz_apply_patch_and_test`. But since `patch_generated` wasn't set for linker error patches, this auto-call was skipped.

**Solution:** Add `st.patch_generated = True` in the `make_link_error_patch_override` handler.

**Tasks:**
- [x] Add `st.patch_generated = True` after successful `make_link_error_patch_override`

**Changes Made:**
- Added `st.patch_generated = True` at line 5722 in the `make_link_error_patch_override` handler

**Testing:** All tests in `test_langgraph_agent.sh` pass.

---

## 2026-01-28: Fix target error status detection for linker errors

**Problem:** When processing linker errors, the agent cannot properly detect if the target linker error was fixed because `_summarize_target_error_status()` only parses compiler errors with `iter_compiler_errors()`, not linker errors.

**Root Cause:** In `agent_langgraph.py`, `_summarize_target_error_status()` at lines 649-656 only called:
```python
combined_errors.extend(iter_compiler_errors(build_text, snippet_lines=0))
combined_errors.extend(iter_compiler_errors(check_text, snippet_lines=0))
```

This means linker errors are never included in `combined_errors`, so the matching logic cannot determine if a target linker error was fixed or still present.

**Solution:** Add `iter_linker_errors()` calls alongside `iter_compiler_errors()` to include both compiler and linker errors in the combined list.

**Tasks:**
- [x] Add `iter_linker_errors()` calls in `_summarize_target_error_status()` for both build_text and check_text

**Changes Made:**
- Modified `_summarize_target_error_status()` (lines 651-656) to also call `iter_linker_errors()` after `iter_compiler_errors()` for both build and check logs

**Testing:** Run `test_langgraph_agent.sh` to verify no regressions.

---

## 2026-01-28: Fix merged patch artifacts stored outside patch_key folder for linker errors

**Problem:** When processing linker errors, the merged patch (`ossfuzz_merged_*.diff`) is being stored at the artifact root (e.g., `data/react_agent_artifacts/ossfuzz_merged_libxml2_f0fd1b.diff`) instead of under the patch_key subdirectory (e.g., `data/react_agent_artifacts/517319253357/ossfuzz_merged_libxml2_f0fd1b.diff`).

**Root Cause:** In `agent_langgraph.py`, the `_PATCH_TOOLS_WITH_PATCH_PATH` set controls which tools automatically get `patch_path` filled from `st.patch_path`. Currently it includes:
- `list_patch_bundle`, `get_patch`, `search_patches`
- `get_error_patch`, `get_error_patch_context`
- `make_extra_patch_override`, `make_error_patch_override`

But it does NOT include:
- `get_link_error_patch` (linker error mapping)
- `get_link_error_patch_context` (linker error context)
- `make_link_error_patch_override` (linker error patch generation)
- `ossfuzz_apply_patch_and_test` (OSS-Fuzz build/test)

When these tools are called without the updated `patch_path` from `st.patch_path`, they may use the original bundle path (at artifact root), and `merge_patch_bundle_with_overrides` cannot infer the patch_key directory to nest the output.

**Solution:** Add the missing tools to `_PATCH_TOOLS_WITH_PATCH_PATH`:
1. `get_link_error_patch`
2. `get_link_error_patch_context`
3. `make_link_error_patch_override`
4. `ossfuzz_apply_patch_and_test`

**Tasks:**
- [x] Add missing tools to `_PATCH_TOOLS_WITH_PATCH_PATH` in `agent_langgraph.py`
- [x] Verify linker error artifact paths are now nested under patch_key directories

**Changes Made:**
- Added `get_link_error_patch`, `get_link_error_patch_context`, `make_link_error_patch_override`, and `ossfuzz_apply_patch_and_test` to `_PATCH_TOOLS_WITH_PATCH_PATH` at line 1171 of `agent_langgraph.py`

**Testing:** All tests in `test_langgraph_agent.sh` pass.

---

## 2026-01-28: Linker error snippet shows all errors instead of just the active one

**Problem:** When handling linker errors with `--focus-patch-key`, the "Log context:" in the prompt shows ALL linker errors from the build log, not just the one for the focused patch_key. For example, focusing on `517319253357` (parser.c/xmlSkipBlankChars) still shows errors from threads.c, encoding.c, error.o, etc.

**Root Cause:** In `build_log.py:iter_linker_errors()`, the `make_snippet()` function uses `ctx_n` (snippet_lines) to include lines AFTER the error. Since linker errors appear consecutively in the log with no separation, `snippet_lines=10` captures the next 10+ lines which include other unrelated linker errors.

**Solution:** Modify `make_snippet()` to stop including lines when it encounters another "undefined reference" or "in function" line for a DIFFERENT function. The snippet should only include context for the specific linker error, not subsequent errors.

**Tasks:**
- [x] Update `make_snippet()` in `build_log.py` to truncate at the next linker error
- [x] Test with a build log containing multiple consecutive linker errors

**Changes Made:**
- Modified `make_snippet()` in `build_log.py` to stop extending the snippet when it encounters:
  - A new "in function" line for a different function
  - A new "undefined reference" line
- Now each linker error snippet only contains context for that specific error, not subsequent errors

**Testing:** All tests pass. Verified with sample build log:
- Before: snippet_lines=10 would include 10+ lines including other errors
- After: snippets are properly truncated at the next error (2-3 lines each)

---
