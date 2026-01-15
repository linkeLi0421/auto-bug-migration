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

## Fix merged/tail auto-loop mis-attribution (keep `hiden_func_dict` + line mapping in sync)

### Problem

- In merged/tail hunks, after the first override changes function length, subsequent OSS-Fuzz errors are mapped to the wrong function because we update `patch_text` (override diff) but do **not** persist the corresponding `hiden_func_dict` / line-range metadata.
- This causes the next error (e.g., `xmlParserNsLookup`) to be treated as part of the previous function (e.g., `xmlParserNsPush`).

### Plan

- [x] Persist an **effective patch bundle** after each `make_error_patch_override`: copy the current `*.patch2` bundle and replace only the active `patch_key` entry with the returned `patch_text` + updated metadata.
- [x] Update the effective entry’s metadata fields (`hiden_func_dict`, `old_start_line/old_end_line/new_start_line/new_end_line`) by re-parsing the rewritten unified diff.
- [x] Switch the auto-loop to use the **patch bundle’s** `patch_text` as the source-of-truth for the next BASE slice (no longer require `patch_override_paths` to exist).
- [x] Add a regression test that simulates a merged/tail hunk rewrite that changes slice length and asserts subsequent error→function mapping stays correct.
- [x] Run `bash script/react_agent/test_langgraph_agent.sh` and any relevant migration tool tests.

## Post-OSS-Fuzz output: refresh function groups + show patch_key for “Next top errors”

### Problem

- After an OSS-Fuzz run where the active function/patch_key is fixed, the final output still prints the *old* “Current function groups” from the start of the run (stale).
- “Next top errors” may come from a *different* patch hunk, but the log doesn’t show which `patch_key` those errors map to.

### Plan

- [x] After `ossfuzz_apply_patch_and_test`, refresh `state.function_groups` from the latest OSS-Fuzz build logs (use `patch_key_verdict.function_groups`), even when we are about to stop (no auto-loop).
- [x] Print `patch_key` next to each “Next top errors” entry (or group them by patch_key) so it’s obvious when they’re from another hunk.
- [x] Update text rendering so “Current function groups (0)” is shown when the active patch_key is clean (avoid hiding the section when the list is empty).
- [x] Add a small regression test for the “0 groups” rendering and patch_key-annotated next errors.
- [x] Run `bash script/react_agent/test_langgraph_agent.sh`.

## Store effective `*.patch2` under per-hunk artifacts dir

### Goal

- When we persist the “effective” patch bundle after `make_error_patch_override`, store it under the same per-hunk
  artifacts directory as other outputs (e.g. `data/react_agent_artifacts/<patch_key>/...`) instead of `data/tmp_patch/...`.

### Plan

- [x] Change `_write_effective_patch_bundle` to write to `state.artifacts_dir` when available (fallback: default artifact root).
- [x] Ensure `migration_tools.patch_bundle.DEFAULT_ALLOWED_ROOTS` includes `data/react_agent_artifacts` so the agent/tools can reload the effective bundle without extra env vars.
- [x] Update regression tests and run `bash script/react_agent/test_langgraph_agent.sh`.

## Auto-loop v2: restart patch-scope triage each round (use latest OSS-Fuzz logs + effective bundle)

### Problem

- First round (function fix + OSS-Fuzz test) works.
- Next round often fails because we keep too much stale state and we skip the normal “first round” workflow
  (`get_error_patch_context` → BASE slice → `make_error_patch_override`). This can leave stale `active_file_path/line_number`
  and other mapping state, causing the next function/error to be patched incorrectly.

### Goal

- After each OSS-Fuzz run, if there are still errors for the active `patch_key`, **clear context** and restart the triage loop
  as if it were a fresh run:
  - input patch bundle = the newly written effective `*.patch2`
  - input build log = the last OSS-Fuzz build output
  - first tool call in the new round should be `get_error_patch_context`

### Plan

- [x] In `_prepare_next_patch_scope_iteration_after_ossfuzz`, stop using `loop_base_slice_*` extraction for subsequent rounds.
- [x] Instead: pick the next error (still within `active_patch_key`, still grouped by function for merged/tail hunks),
  set `state.error_line/snippet/grouped_errors/active_old_signature`, and reset stale per-round state.
- [x] Clear `state.steps` (keep `step_history`) and clear `loop_base_func_code_artifact_path` so prereq tools run again.
- [x] Force a `get_error_patch_context` tool call for the new round using the latest error location + the effective bundle path.
- [x] Add a regression test that ensures after a round transition, `active_file_path/line_number` reflect the new error (not the previous one).
- [x] Run `bash script/react_agent/test_langgraph_agent.sh`.
