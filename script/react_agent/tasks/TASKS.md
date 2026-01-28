# TASKS

## 2026-01-28: Guide agent to use search_definition before adding extern declarations

**Problem:** When the agent encounters an undeclared identifier in an `_extra_*` hunk (e.g., `defaultHandlers`), it blindly adds an `extern` declaration without understanding what the symbol is. For complex V1-only data structures like `defaultHandlers[]` which references other V1 symbols, this just moves the problem from a compiler error to a linker error.

**Example:**
- Error: `use of undeclared identifier 'defaultHandlers'` in `_extra_encoding.c`
- Agent incorrectly added: `extern const xmlCharEncodingHandler *defaultHandlers[];`
- This causes a linker error later because `defaultHandlers` is a V1-only array

**Root Cause:** The guidance in `system_undeclared_symbol.txt` didn't instruct the agent to investigate the symbol definition before deciding how to handle it.

**Solution:** Updated `system_undeclared_symbol.txt` to:
1. Guide agent to FIRST use `search_definition(symbol_name="X", version="v1")` to understand what the symbol is
2. For complex V1 data structures that can't be migrated, remove the reference rather than add an extern
3. Added specific guidance for `_extra_*` hunks to remove lines that reference unmigrateable V1 symbols

**Tasks:**
- [x] Update undeclared symbol guidance to use search_definition first
- [x] Add guidance for handling complex V1 data structures in `_extra_*` hunks
- [x] Test changes don't break existing functionality

**Changes Made:**
- Modified `prompts/system_undeclared_symbol.txt`:
  - Added instruction to use `search_definition` before making decisions
  - Added warning that complex V1 data structures will cause linker errors
  - Added specific guidance for `_extra_*` hunks to remove unmigrateable references
  - Added example with `defaultHandlers` and `xmlLatin1Handler`

**Testing:** All tests pass.

---

## 2026-01-28: Fix patch_key inference for safe-ified directory names

**Problem:** When `ossfuzz_apply_patch_and_test` tries to infer the patch_key from the override file path, it fails if the directory name is safe-ified (special characters replaced with underscores).

**Example:**
- patch_key: `fuzz/fuzz.cfuzz/fuzz.c-70,1+70,1`
- Safe directory name: `fuzz_fuzz.cfuzz_fuzz.c-70_1_70_1`
- Error: `ValueError: Could not infer patch_key for override patch file. Put override artifacts under a directory named <patch_key> ...`

**Root Cause:** `_infer_patch_key_from_path()` only checked if the directory name exactly matched a patch_key. It didn't account for the safe-ified directory names created by `multi_agent.py` using `_safe_patch_key_dirname()`.

**Solution:** Build a reverse mapping from safe-ified names to original patch_keys and check both the original and safe-ified forms when inferring.

**Tasks:**
- [x] Update `_infer_patch_key_from_path()` to handle safe-ified directory names
- [x] Update `_infer_primary_patch_key_from_path()` similarly
- [x] Test changes don't break existing functionality

**Changes Made:**
- Modified `tools/ossfuzz_tools.py`:
  - `_infer_patch_key_from_path()`: Added reverse mapping from `_safe_filename(patch_key)` to original patch_key
  - `_infer_primary_patch_key_from_path()`: Same fix for consistency

**Testing:** All tests pass.

---

## 2026-01-28: Fix agent incorrectly removing __revert_* function calls

**Problem:** When the agent encounters an undeclared `__revert_*` function (e.g., `__revert_e11519_xmlHashCreate`), it incorrectly removes the function call and replaces it with the original function name.

**Example:**
- Error: `call to undeclared function '__revert_e11519_xmlHashCreate'`
- Agent incorrectly replaced: `__revert_e11519_xmlHashCreate(8)` → `xmlHashCreate(8)`
- This is wrong - the `__revert_*` function IS correct and just needs a declaration

**Root Cause:** The guidance in `system_undeclared_symbol.txt` only said to remove functions NOT starting with `__revert_`, but didn't explicitly say to ADD declarations for functions that DO start with `__revert_`.

**Solution:** Added explicit guidance for `__revert_*` functions:
1. Functions starting with `__revert_` are migration-generated wrappers that SHOULD be used
2. Do NOT remove or replace calls to `__revert_*` functions
3. Use `make_extra_patch_override(symbol_name="__revert_e11519_xmlHashCreate", version="v1")` to add the declaration

**Tasks:**
- [x] Add explicit guidance for handling `__revert_*` function declarations
- [x] Test changes don't break existing functionality

**Changes Made:**
- Modified `prompts/system_undeclared_symbol.txt`:
  - Added section for functions STARTING with `__revert_`
  - Explicitly stated these functions should NOT be removed
  - Added instruction to use `make_extra_patch_override` to add the declaration

**Testing:** All tests pass.

---

## 2026-01-28: Fix duplicate artifact directories for patch_keys with slashes

**Problem:** When a patch_key contains slashes (e.g., `fuzz/fuzz.cfuzz/fuzz.c-70,1+70,1`), two directories are created:
1. `fuzz_fuzz.cfuzz_fuzz.c-70_1_70_1/` - correct safe-ified directory from multi_agent.py
2. `fuzz/fuzz.cfuzz/fuzz.c-70,1+70,1/` - nested directories from ossfuzz_tools.py

**Root Cause:** In `merge_patch_bundle_with_overrides()` and `merge_patch_bundle_with_overrides_pickle()`, when creating output directories:
```python
out_dir = (allow_root / inferred_key).resolve()
```
The `inferred_key` contains slashes, which creates nested directories instead of a single safe-ified directory.

**Solution:** Use `_safe_filename(inferred_key)` when building the output directory path.

**Tasks:**
- [x] Fix `merge_patch_bundle_with_overrides()` to use safe directory name
- [x] Fix `merge_patch_bundle_with_overrides_pickle()` to use safe directory name
- [x] Test changes don't break existing functionality

**Changes Made:**
- Modified `tools/ossfuzz_tools.py`:
  - Line 810: `out_dir = (allow_root / _safe_filename(inferred_key)).resolve()`
  - Line 1003: Same fix for consistency

**Testing:** All tests pass.

---
