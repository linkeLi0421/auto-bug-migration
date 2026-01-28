# TASKS

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
