## Current Plan (unarchived)

- [x] Stop forcing `read_file_context(context=80)` in macro-lookup guardrail (`script/react_agent/agent_langgraph.py`); keep forcing only `kb_search_symbols` (v2 → v1).
- [x] Update the system prompt (`script/react_agent/agent_langgraph.py`) to remove “context=80” and instruct the model to choose an appropriate context window (large enough to include full `#if/#endif` blocks when needed).
- [x] Update `script/react_agent/test_langgraph_agent.sh` to remove assumptions about `context=80` and add a small unit test ensuring the runtime doesn’t inject a fixed context value.
- [x] If the LLM returns empty `message.content` and `--debug-llm` is enabled, dump raw HTTP JSON (`response_debug.raw_body`) and metadata in `llm_call_XXXX_response.json` (`script/react_agent/models.py`, `script/react_agent/agent_langgraph.py`).

- [x] Patch-scope multi-error loop: don’t stop after the first `make_error_patch_override` + `ossfuzz_apply_patch_and_test` if `target_errors` still remain (e.g., `unknown type name 'xmlHashedString'` in `log/agent_log/tmp2.log`). Continue iterating until fixed or a configurable run limit is hit.
- [x] Make the follow-up iteration actionable: after an OSS-Fuzz run, surface the remaining target errors (and top non-target errors) back into the next LLM prompt and/or set `state.error_line` to the next remaining error so the model doesn’t tunnel on the first one.
- [x] Ensure iterative rewrites don’t lose previous fixes: when a second override is generated for the same `patch_key`, replace the prior override path and base subsequent `new_func_code` edits on the most recent BASE slice (the last applied `new_func_code`, not the original V1 slice).
- [x] Tests: add a stub-mode regression test that simulates “fix first error → still has remaining target error” and asserts the agent continues (when enabled) instead of finalizing immediately after the first OSS-Fuzz test.
