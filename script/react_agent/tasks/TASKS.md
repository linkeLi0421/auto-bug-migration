## Next: Policy — don’t change V2 type definitions (adapt V1 code instead)

### Problem

In patch-scope runs, the agent may propose “fixes” that **edit V2 data structure definitions**
(e.g. adding fields back into a shared `struct` in a public header).

This is usually a bad migration strategy because:
- V2 types are used by many other call sites and invariants/ABI expectations may differ.
- Adding/reordering fields can silently break unrelated code or tests.
- The goal is typically to adapt **V1-origin usage** to the **V2 API/semantics**, not to retrofit V2 back to V1.

Example from the current libxml2 run: suggesting “Option A: add `nbWarnings`/`nbErrors` to `struct _xmlParserCtxt`”.

### Goal

Make the agent default to a safe migration policy:
- **Do not propose editing V2 type definitions** (struct/typedef/enum) in shared/public headers.
- Prefer “usage adaptation”: update the migrated (V1-origin) code to use V2’s existing fields/APIs/behavior.
- If a V2 type edit seems required, flag it for human review instead of proposing it.

### Plan

1) Update agent policy (system prompt)
- [x] Add an explicit rule: **never suggest modifying V2 type definitions**; treat V2 types as authoritative.
- [x] For “missing struct member” errors, require a “V2 adaptation” approach:
  - check V1 vs V2 definitions,
  - then search for V2 replacement mechanisms (API/field rename/centralized error object),
  - propose localized code changes (in the migrated function/module) rather than editing the struct.

2) Add an output guardrail
- [x] Add a lightweight “final output rewrite” step: if the model suggests editing V2 type definitions, ask it to rewrite the final decision to a V2-usage-adaptation plan.
- [x] Add a small denylist detector for type-edit suggestions (e.g. “add field to struct”, “edit header”, “modify struct definition”).

3) Success criteria
- [x] Running the libxml2 command in patch-scope mode produces a final suggestion that **does not** include “add fields to struct _xmlParserCtxt / include/libxml/parser.h”.
- [x] For missing-member errors, the final `next_step` proposes **usage adaptation** (rename/replace/remove field usage, or use an existing V2 error-tracking API), and states that V2 type edits are out-of-policy and require human review.


## Next: Tool — extract the V1-origin function code from the patch bundle

### Problem

When we decide to adapt V1-origin usage to V2 semantics, the agent needs to see the **V1 function code** that was migrated/removed/recreated by the patch.

In many cases the build error line numbers refer to **post-migration** code, so reading `--v2-src` by raw `file:line` is misleading. The patch bundle already contains the relevant function body; we should extract it in a bounded way.

The extraction logic already exists in the rule-based pipeline:
- `script/revert_patch_test.py:2768` maps `file:line` → `(patch_key, old_signature, func_start_index, func_end_index)`
- `script/revert_patch_test.py:2776` reconstructs the V1 function by taking the `-` lines from that slice of the unified diff.

### Goal

Add a read-only tool so the agent can request:
- the V1-origin function body (from `-` lines in the patch hunk slice),
- along with the patch key + old signature that ties it back to the migration context,
- with bounded output (line/char limits).

### Tasks

1) Implement the extraction helper in `migration_tools`
- [x] Add a function tool (suggested name: `get_error_v1_function_code`) that accepts:
  - `patch_path`, `file_path`, `line_number`
  - optional: `max_lines` / `max_chars`
- [x] Reuse the existing `get_error_patch(patch_path, file_path, line_number)` result to obtain:
  - `patch_key`, `old_signature`, `func_start_index`, `func_end_index`
- [x] Reconstruct V1 function code using the revert logic:
  - `patch_lines = patch.patch_text.splitlines()[4:]`
  - `func_code = "\n".join(l[1:] for l in patch_lines[func_start_index:func_end_index] if l.startswith("-"))`
- [x] Return a structured result:
  - `patch_key`, `old_signature`, `file_path`, `line_number`
  - `func_code` (bounded + `truncated` flag)
  - `note` when extraction isn’t available (no patch match / indices missing)

2) Expose it as a react_agent tool
- [x] Add the tool to `script/react_agent/tools/registry.py` (`TOOL_SPECS` + `ToolName`) with clear args/description.
- [x] Wire it into `script/react_agent/tools/migration_tools.py` and `script/react_agent/tools/runner.py`.
- [x] Keep the same patch-path allowlist behavior (`REACT_AGENT_PATCH_ALLOWED_ROOTS`).

3) Teach the agent when to call it
- [x] Update the system prompt: when proposing “V2 usage adaptation” for a patch-scoped error, call `get_error_v1_function_code` early to read the V1-origin function body (instead of suggesting V2 type edits).
- [x] Update the stub-model heuristic + tests so the intended tool ordering is exercised.

### Success criteria

- [x] On the libxml2 `nbWarnings/nbErrors` example, the agent fetches the V1-origin function code from the patch bundle before proposing a fix.
- [x] The final output proposes a V2-usage-adaptation change (not a V2 struct edit) and references evidence from the extracted V1 function body.


## Next: Tool — generate a function-replacement patch (reverse of `get_error_v1_function_code`)

### Problem

We can extract the V1-origin function body from the patch bundle (`get_error_v1_function_code`), but after the model proposes a replacement function that compiles against V2, we currently have no tool to turn that into an actionable patch.

### Goal

Add a read-only tool that, given `(patch_path, file_path, line_number)` and a `new_func_code` string, returns a unified diff that replaces the mapped V1-origin function definition with the provided replacement.

Constraints:
- Use `get_error_patch` mapping + bundle text; do not read arbitrary source trees.
- Return patch text only; do not apply/write patches to the filesystem by default.
- Keep output bounded (line/char limits + truncation flags).

### Tasks

1) Implement patch generator in `migration_tools`
- [ ] Add a tool (suggested name: `make_error_function_patch`) that accepts:
  - `patch_path`, `file_path`, `line_number`, `new_func_code`
  - optional: `max_lines` / `max_chars` / `context_lines`
- [ ] Reuse `get_error_patch(patch_path, file_path, line_number)` to resolve:
  - `patch_key`, `old_signature`, `func_start_index`, `func_end_index`
- [ ] Reconstruct the exact “old” function text from the mapped slice (same extraction as `get_error_v1_function_code`).
- [ ] Build a single-file unified diff that replaces the old function with `new_func_code`:
  - header `diff --git a/<file> b/<file>` + `---/+++`
  - hunk header `@@ -start,old_len +start,new_len @@` (prefer `patch.old_function_start_line` when available; fallback to parsed hunk start)
  - removed lines from extracted old function (`-...`)
  - added lines from `new_func_code` splitlines (`+...`)
- [ ] Return a structured result:
  - `patch_key`, `file_path`, `line_number`, `old_signature`
  - `old_func_code` (bounded) + `old_func_code_truncated`
  - `patch_text` (bounded) + `patch_text_truncated`
  - `note` for missing mapping/slice indices, and basic validation errors (e.g., empty `new_func_code`)

2) Expose it as a react_agent tool
- [ ] Add to `script/react_agent/tools/registry.py` (`ToolName` + `TOOL_SPECS`) with a clear description.
- [ ] Wire it into `script/react_agent/tools/migration_tools.py` + `script/react_agent/tools/runner.py`.
- [ ] Keep the existing patch-path allowlist behavior (`REACT_AGENT_PATCH_ALLOWED_ROOTS`).

3) Teach the agent to output patches (not just code)
- [ ] Update the system prompt: after drafting replacement function code, call `make_error_function_patch` and include the returned unified diff in the final output.
- [ ] Make it explicit this patch targets the code that produced the build errors (the side that contains the V1-origin `__revert_*` function), and does not touch V2 type definitions.

4) Tests / success criteria
- [ ] Add a unit test that generates a replacement patch for the libxml2 `xmlVRaiseError` example and verifies:
  - patch header targets `error.c`
  - patch includes both `-` (old) and `+` (new) blocks
  - applying the diff to the extracted old function code with `script/utils.py:apply_unified_diff_to_string` yields the replacement code
- [ ] In a patch-scope run, the agent can produce a ready-to-apply diff patch as its `next_step` when it proposes a function-body fix.
