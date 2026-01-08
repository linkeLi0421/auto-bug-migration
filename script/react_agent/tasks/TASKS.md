## Next: Reduce tool duplication (your idea): `get_error_patch_context` -> `get_error_v1_code_slice` -> `make_error_patch_override`

### Goal

Keep `get_error_patch_context`, but stop passing `(patch_path, file_path, line_number)` into *both* tools.
Instead, treat `get_error_patch_context` as the single “error → hunk mapping” step, and feed its output directly into
`get_error_v1_code_slice` (extract V1-origin `-` lines + macro hints). Keep `make_error_patch_override` unchanged.

Keep `read_artifact` for now (still useful for reading offloaded hunks/slices/patches), but this flow should make it *less necessary*
for routine cases by keeping each tool output small and hunk-scoped.

### Plan

- [x] Define a stable “mapped hunk context” object produced by `get_error_patch_context`, e.g.:
  - `patch_path`, `patch_key`, `file_path`, `line_number`
  - `func_start_index`, `func_end_index`, `old_signature`
  - optional: `pre_patch_file_path`, `pre_patch_line_number`, `mapping_note`
  - optional: `excerpt` (single-hunk excerpt; small by construction)

- [x] Change `get_error_v1_code_slice` inputs to accept the mapped context (primary path), not raw location:
  - new args: `excerpt` (object from `get_error_patch_context.excerpt`, containing `artifact_path`) as the primary path
    - `get_error_v1_code_slice(excerpt={artifact_path: ...})` reads only the single-hunk excerpt and extracts `-` lines + macro hints
    - keep location-based `(patch_path, file_path, line_number)` as a fallback (backward compatible)
  - keep old `(patch_path, file_path, line_number)` temporarily for backward compatibility, but mark as deprecated in descriptions.
  - implementation: do **not** re-run mapping when context is provided; just slice the patch text by indices and extract `-` lines.

- [ ] Make `get_error_patch_context` hunk-scoped and small:
  - ensure `excerpt` is the *single* relevant hunk/slice (not a large file-wide window)
  - keep artifact offloading behavior in the runtime, but the default “inline” output should be safe to include in prompts

- [x] Update the agent workflow + prompt:
  - patch-scope: `parse_build_errors` → `get_error_patch_context` → `get_error_v1_code_slice(context=...)` → (optional `search_*`) →
    `make_error_patch_override(patch_path, file_path, line_number, new_func_code, ...)` → `ossfuzz_apply_patch_and_test`
  - explicitly tell the model: “do not call get_error_v1_code_slice with patch_path/file_path/line_number when context is available”

- [x] Update tests/docs:
  - `script/react_agent/test_langgraph_agent.sh`: assert the patch-scope path uses `get_error_patch_context` then context-based calls
  - `script/migration_tools/test_migration_tools.sh`: add fixtures exercising the context-based APIs
  - `script/react_agent/README.md`: update tool signatures + examples

- [ ] Re-evaluate `read_artifact` after the refactor:
  - keep it if we still offload big artifacts (full patch_text, long excerpts, OSS-Fuzz logs)
  - only consider removal if all tool outputs stay reliably small (unlikely with real patches/logs)

## Next: Macro dependency fixes should be source-driven (no guessing)

Problem (seen in `log/agent_log/tmp.log`): when `get_error_v1_code_slice.macro_tokens_not_defined_in_slice` contains tokens like
`EMPTY_ICONV`/`EMPTY_UCONV`, the agent may insert placeholder `#define EMPTY_ICONV` / `#define EMPTY_UCONV` without actually locating
their real definitions in V1/V2 source. We want the fix to be general and tool-driven: read the source, then decide the new code.

### Plan

- [x] Prompt guardrail: “don’t invent macro definitions”
  - If the patch override introduces any `#define <TOKEN>` for a token that was missing, the agent MUST first:
    - `search_text(query=\"#define <TOKEN>\", version=\"v2\")` then `search_text(..., version=\"v1\")`
    - `read_file_context(...)` around the best match to capture the full `#if/#endif` block
  - If neither V1 nor V2 defines the token, do NOT add a dummy `#define`; instead remove/replace the token in the macro body (or adapt
    to the V2 initializer shape) and state that decision explicitly.

- [x] Add a general “macro dependency resolution” recipe to the system prompt (not MAKE_HANDLER-specific):
  1) Identify the failing macro name from the build snippet (`expanded from macro 'X'`) and collect missing tokens from
     `macro_tokens_not_defined_in_slice`.
  2) For the top 1–3 missing tokens, locate definitions via `search_text` (v2 first, then v1) and confirm via `read_file_context`.
  3) Copy/adapt the smallest correct macro block into the override slice (include required `#if/#else` guards).
  4) Only then call `make_error_patch_override`.

- [x] Add a regression test that enforces “tool evidence before defines”:
  - `script/react_agent/test_langgraph_agent.sh` unit-tests the guardrail helper to ensure an attempted `#define EMPTY_ICONV` triggers a forced `search_text` first.
  - (Future) expand to an end-to-end patch-scope fixture asserting `search_text` + `read_file_context` occur before override generation.

## Next: Macro resolution must fall back to V1 when V2 misses

Problem (seen in `log/agent_log/tmp.log`): for tokens like `EMPTY_ICONV` / `EMPTY_UCONV`, the agent may search V2 only, not find them, and then:
- either stop early, or
- “give up” and remove the tokens without confirming whether V1 defines them.

We want a consistent policy:
- If token is missing in V2: search V1.
- If token exists in V1: prefer using V1’s definition (copy/adapt the guarded `#define` block).
- If token exists in neither: then (and only then) remove/replace the token usage.

### Plan

- [x] Strengthen prompt rules for missing macro tokens:
  - Always search in this order: `search_text(query=\"#define TOKEN\", version=\"v2\")` → if no matches, `search_text(..., version=\"v1\")`.
  - Never use a bare `search_text(query=\"TOKEN\")` for macro-definition lookup; it’s too noisy and misses the intended `#define`.
  - If V1 defines TOKEN but V2 doesn’t, prefer copying the V1 `#define` block into the override slice (do not invent a stub).

- [x] Make the runtime macro guardrail explicitly enforce V1 fallback:
  - If V2 search returns 0 matches for `#define TOKEN`, automatically schedule the V1 search next (without model choice).
  - If both searches return 0 matches, set a guardrail flag like `macro_lookup.not_found=True` and inject a short instruction into the prompt:
    “TOKEN not defined in V1/V2; remove/replace TOKEN usage instead of defining it.”

- [ ] Add an end-to-end regression fixture for the fallback behavior:
  - Provide a tiny v1/v2 source tree fixture where:
    - V2 does *not* define `EMPTY_ICONV`, but V1 does (with guards).
  - Assert the agent calls `search_text` in v2 then v1, then `read_file_context` on the V1 match, before producing an override.

## Next: Remove patch-generation truncation limits (avoid accidental code deletion)

Problem (seen in `log/agent_log/tmp.log` / `_extra_parser.c`): `make_error_patch_override` replaces the entire mapped `-` slice.
If the agent/model only sees a truncated slice (or the model’s response is truncated), it will emit an incomplete `new_func_code`,
silently deleting the missing tail lines (e.g., trailing `static ...` prototypes).

### Plan

- [x] Remove small hard caps in `read_artifact`:
  - Support `max_lines=0` meaning “read all remaining lines”.
  - Support `max_chars=0` meaning “no char truncation”.
  - Raise/remove the current internal clamps (800 lines / 200k chars) so full patch slices can be read in one call.

- [x] Remove the extra prompt-compaction truncation for `read_artifact` outputs:
  - `_compact_observation_for_prompt` currently truncates all strings to ~12k chars; this can cut off patch slices even when `read_artifact` returned them.
  - Special-case `read_artifact` so its `output.text` is not compacted (or is compacted using a much higher cap, respecting `max_chars=0`).

- [x] Change the forced pre-patch `read_artifact` call to request full slice content:
  - Use `start_line=1`, `query=\"\"`, `context_lines=0`, `max_lines=0`, `max_chars=0` when reading `get_error_v1_code_slice.func_code` artifacts.

- [x] Add a small regression test:
  - Create a synthetic artifact file >12k chars and ensure `read_artifact(max_chars=0)` + prompt compaction keeps the full text.
