# Tasks

## React agent (patch-scope)
- [x] Clarify OSS-Fuzz verdict output: distinguish active-function vs patch_key status.
- [x] Show remaining error count per active patch_key (especially when auto-loop is disabled or hits the loop limit).
- [x] Verify auto-loop continues within `--focus-patch-key` until the patch_key has 0 mapped compiler errors.

## Plan: Fix premature “patch_key clean” when only `_extra_*` overrides exist
Context: `log/agent_log/tmp1.log` shows `Grouped errors (103)` in patch_key `92116236229`, but the run stops after generating only an `_extra_parser.c` override and reports `Remaining errors in active patch_key 92116236229: 0`.

- [x] Reproduce locally from the existing artifacts (`data/react_agent_artifacts/92116236229/*`) and confirm:
  - `ossfuzz_apply_patch_and_test_build_output.log` still contains errors mapping to `92116236229`.
  - `_summarize_active_patch_key_status` returns `remaining_in_active_patch_key > 0` when mapping uses the correct patch text for `92116236229`.
  - The live agent run returns `0` due to wrong override overlay during mapping.
- [x] Fix `_load_effective_patch_bundle_for_mapping` override selection:
  - Do not “guess” the active override by matching any ancestor directory named like the active patch_key (this matches `.../<active_key>/_extra_*/...` and misattributes `_extra_*` diffs).
  - Infer override patch_key using the bundle’s known `patch_keys` (same approach as `ossfuzz_tools._infer_patch_key_from_path`) and only overlay when `inferred_key == active_key`.
  - Keep `patch_override_by_key` as the primary source of truth.
- [x] Add a regression test:
  - `patch_override_paths` contains only `.../<active_key>/_extra_parser.c/override__extra_parser.c.diff`.
  - Ensure mapping for errors in `.../parser.c:99xx` still resolves to `patch_key == <active_key>` and not “clean”.
- [ ] Improve final output for easier diagnosis:
  - Print why auto-loop did/didn’t continue (e.g., remaining count, mapping_error, and which override diff (if any) was overlaid for the active patch_key).

## Plan: Restart on OpenAI HTTP 5xx/429 (not just timeouts)
Context: `log/agent_log/tmp1.log` ends with `next_step: OpenAI HTTPError: 502 Bad Gateway ... cloudflare` and then `thought: Agent error.` without any `[agent_langgraph] transient error ... retrying ...` message.

- [ ] Confirm the retry gate is the classifier:
  - `_run_langgraph_with_retries` is enabled (default `--max-agent-retries` is non-zero).
  - `_is_transient_agent_error` returns false for `ModelError("OpenAI HTTPError: 502 ...")` (and/or its `urllib.error.HTTPError` cause), so the exception is re-raised and the agent stops.
- [ ] Expand transient error detection in `script/react_agent/agent_langgraph.py:_is_transient_agent_error`:
  - Treat `urllib.error.HTTPError` with `code >= 500` as transient (and likely `429` as transient).
  - Preserve non-retriable errors (e.g., 401/403 auth, 400 invalid request) as fatal to avoid infinite loops.
  - If the HTTP status is only present in a `ModelError` string, parse it as a fallback.
- [ ] Add a regression test for retry classification:
  - `ModelError(...)` chained from `urllib.error.HTTPError(502, ...)` returns `True`.
  - `ModelError(...)` chained from `urllib.error.HTTPError(401, ...)` returns `False`.
- [ ] Update CLI/help text for `--max-agent-retries` to reflect that it covers transient HTTP failures (5xx/429) in addition to timeouts, and log why a failure is/ isn’t considered transient.

## Plan: Gate merged/tail prompt by patch_type (only show for merged hunks)
Context: `log/agent_log/tmp2.log` shows the assembled system prompt includes `Merged/tail hunks (function-by-function)` even when the target patch hunk isn’t a merged hunk. We only want that fragment when the patch metadata indicates a merged hunk.

- [x] Confirm the patch metadata for the active `patch_key`:
  - Load the patch bundle and verify `patch_type` for the active patch_key does/doesn’t contain “Merged”.
  - Cross-check with `list_patch_bundle(filter_patch_type=...)` behavior.
- [x] Plumb `patch_type` into prompt context:
  - Capture `patch_type` for the selected `patch_key` when starting the run and store it in agent state.
  - Ensure auto-loop updates don’t accidentally change the patch_type for the pinned patch_key.
- [x] Update prompt assembly:
  - Always include mapped-slice rewrite rules when using `make_error_patch_override` on a function.
  - Only include the `Merged/tail hunks (function-by-function)` fragment when `patch_type` contains “merged”.
- [x] Add a small regression check:
  - Given `active_patch_types={"Recreated function"}` → merged/tail fragment not included.
  - Given `active_patch_types={"Merged functions"}` → merged/tail fragment included.
