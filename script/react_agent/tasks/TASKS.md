# TASKS

## Never truncate `make_error_patch_override` output (full override diff must be valid)

### Context / Repro

- In `log/agent_log/tmp1.log`, `make_error_patch_override` returned `patch_text_truncated=true`, which produced a truncated
  override diff artifact and led to patch-apply failures / corrupt merged patches.
- The override diff artifact must always contain the *full* unified diff for the patch_key; truncation is only useful
  for previews, not for the actual patch file.

### Plan

- [x] Update `script/migration_tools/tools.py:make_error_patch_override` to always return the full `patch_text` (ignore `max_lines`/`max_chars` for the diff itself).
- [x] Keep `old_func_code` bounded (it’s only for debugging), but ensure `patch_text_truncated` is always `False` and `patch_text_lines_returned == patch_text_lines_total`.
- [x] Add a regression test in `script/migration_tools/test_migration_tools.sh` that calls `make_error_patch_override` with absurdly small `max_lines/max_chars` and asserts the returned diff is still complete/valid.
- [x] Run `bash script/migration_tools/test_migration_tools.sh` and `bash script/react_agent/test_langgraph_agent.sh`.

## Clarify `make_error_patch_override.new_func_code` (function-by-function mode)

### Context / Goal

- In merged/tail hunk mode, the agent now iterates **per function** (`active_old_signature`).
- The model sometimes treats `make_error_patch_override.new_func_code` as “rewrite the whole patch/hunk” and emits code for multiple functions (or even diff-ish content).
- Desired behavior: for a given round, `new_func_code` is **only** the full C definition of the **active** function; other functions will be handled in later rounds.

### Plan

- [x] Update the system prompt + tool description to explicitly state: in merged/tail hunks, `make_error_patch_override.new_func_code` must rewrite only the mapped slice for the active function (no other functions; no unified-diff headers).
- [x] Add an agent-side guardrail for `make_error_patch_override` in function mode that rejects multi-function / diff-like `new_func_code` and forces a retry scoped to the active slice.
- [x] Add a regression test in `script/react_agent/test_langgraph_agent.sh` for the new guardrail (multi-function input should trigger; single-function should pass).
- [x] Run `bash script/react_agent/test_langgraph_agent.sh` (and any other relevant tests).
