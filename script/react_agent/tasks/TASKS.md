# TASKS

## 2026-01-28: Linker Error Detection in OSS-Fuzz Verdict (COMPLETED)

**Problem:** After agent generates a patch and runs ossfuzz_apply_patch_and_test, the verdict logic (`_summarize_active_patch_key_status`) only checks for compiler errors, not linker errors. If linker errors remain (like `undefined reference to '__revert_e11519_xmlGlobalInitMutexUnlock'`), the agent reports "Active function fixed: unknown" instead of detecting the remaining error.

**Root Cause:** `_iter_ossfuzz_compiler_errors` only called `iter_compiler_errors`, not `iter_linker_errors`. Additionally, the status function skipped errors with `line <= 0` (which linker errors have).

**Changes Made:**
- [x] Updated `_iter_ossfuzz_compiler_errors` to also call `iter_linker_errors` and collect linker errors with `kind="linker"` (~lines 1511-1548)
- [x] Updated `_summarize_active_patch_key_status` to handle linker errors using `_get_link_error_patch_from_bundle` for mapping (~lines 1609-1660)
- [x] Linker errors are now properly mapped to patch_keys and counted in `remaining_in_active_patch_key`

**Testing:** All tests in `test_langgraph_agent.sh` pass.

---

## 2026-01-28: Linker Error Initialization in agent_langgraph.py (COMPLETED)

**Problem:** When agent_langgraph.py is started with a linker error (undefined reference) as the target, the initialization code only calls `iter_compiler_errors()` and does not process linker errors.

**Solution:** Added `iter_linker_errors()` processing in the `cfg.error_scope == "patch"` initialization block, mirroring `multi_agent.py`'s `_group_errors_by_patch_key()`.

**Changes Made:**
- [x] Added `iter_linker_errors` to the import from `build_log` (line 24)
- [x] Added linker error loop after compiler error loop (~lines 5938-5958)
- [x] Added import of `get_link_error_patch` from `tools.migration_tools` (~line 5916)
- [x] Added fallback for linker errors (line_number=0) to extract func indices from grouped_errors (~lines 6025-6037)

**Testing:** All tests in `test_langgraph_agent.sh` pass.

---

## 2026-01-27: Dynamic Error Queue Refresh (multi_agent)

- [x] Add `--refresh-error-queue {auto,always,never}` to `script/react_agent/multi_agent.py` (enable when `--tools real` and `--jobs 1`).
- [x] After each fixed hunk, merge accumulated override diffs into a new `*.patch2`, re-run OSS-Fuzz build, and re-parse compiler errors to discover newly-unblocked patch_keys.
- [x] Keep writing `progress.json` snapshots during the run (so refreshed queue progress is visible/resumable).

## 2026-01-27: Handle Linker Undefined References (react_agent)

- [x] Parse link-time errors like `undefined reference to \`symbol'` from OSS-Fuzz build output (capture object + function when available, e.g. `encoding.c:(.text.<func>+0x..)`).
- [x] Add patch-bundle mapping for link errors without `file:line` (best-effort locate the owning patch_key + function slice by `file` + `function` name in the patch bundle).
- [x] Extend patch tools so the agent can rewrite the mapped slice for link errors (either by adding a new tool or by adding an alternate mapping mode to `get_error_patch_context`/`make_error_patch_override`).
- [x] Update agent loop to treat link errors as actionable "missing symbol" problems (try v2 replacement symbol via `search_definition`, otherwise minimize by removing/guarding the call).
- [x] Add regression fixtures/tests for linker errors (at least: `encoding.c:(.text.__revert_...): undefined reference to \`defaultHandlers'`).
- [x] Update `multi_agent.py` to include linker errors in `_group_errors_by_patch_key()` and `_error_type_priority()`.
