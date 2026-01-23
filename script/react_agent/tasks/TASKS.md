# Tasks

## Plan: When guardrails reject `make_error_patch_override`, keep repair prompts minimal
Context: When a `make_error_patch_override` tool call is rejected by our guardrails (e.g. multi-function body, function rename, incomplete body), the next-round repair call (e.g. `override_function_scope_repair`) currently reuses `repair_messages = list(messages)`. This drags the original patch-scope “Build log path … Patch-scope active error … Log context …” blob into the repair prompt, even though the repair is only about fixing the tool call format/scope.

- [x] Identify all guardrail-driven repair paths that call `_complete(..., label="override_*_repair")` and currently reuse the full `messages` history.
- [x] Change repair prompt construction to exclude the initial patch-scope build-error message(s):
  - Build `repair_messages` from scratch (or filter `messages`) so the repair LLM sees only:
    - the system prompt,
    - minimal state (patch_path, patch_key, file_path, line_number, active_old_signature, patch_type),
    - the most relevant tool observation(s) needed to craft the corrected tool call (e.g. `get_error_patch_context` artifact paths),
    - the rejected tool JSON and the guardrail feedback text.
- [x] Add a regression test that inspects logged repair prompts and asserts they do NOT contain strings like `Build log path:` / `Patch-scope active error:` / `Log context:`.
- [ ] Validate the repair still succeeds without the dropped context (ensure we still pass enough BASE-slice references for the model to rewrite `new_func_code` correctly).
- [x] Model selection: when a guardrail triggers a repair round, run the repair `_complete(...)` with a stronger default model (`gpt-5.2`) regardless of the user-selected `--openai-model`; keep the user-selected model for all non-repair turns.
