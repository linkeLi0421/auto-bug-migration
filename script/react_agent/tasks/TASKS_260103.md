## Next: Patch-scope + cross-version struct-member triage

### Problem

In patch-scope mode, the build error often refers to **code migrated from V1**, but the agent can “solve” it by only looking at **V2** definitions (because the compile error happens in the migrated codebase).

Example: `no member named 'nbWarnings' in 'struct _xmlParserCtxt'`

To correctly migrate/fix the V1-origin code, the agent should confirm:

1) Does the member exist in **V1**’s definition of the struct?
2) If missing in V2, was it **removed** or **renamed/moved**?

Without the V1 check, the agent wastes steps and can’t propose the correct migration edit.

### Goal

For `missing_struct_member` errors (and similar “API drift” errors) in patch-scope triage:

- always compare the relevant type definition in **V1 vs V2**
- produce a concrete migration hint (rename/remove/replace field usage)
- reduce tool calls / steps by fetching the right definitions early

### Plan

This is the same workflow as `script/openai/handle_struct_use.py`, but driven by the agent + existing tools:

1) Use patch-first triage to locate the migrated (V1-origin) code in the patch hunk.
2) For each `no member named 'X' in 'struct Y'` error, fetch `struct Y` in **both V1 and V2**.
3) Compare V1 vs V2 struct definitions to infer a field mapping (rename/remove/replace).
4) Only after that, consider `search_text` as a fallback (e.g. to find renamed fields elsewhere).

### Tasks

1) Detect and summarize struct-member errors in patch-scope mode
- [x] In patch-scope mode, extract `missing_struct_members` from the grouped error block via `parse_build_errors`.
- [x] Add a compact summary to the initial prompt header: `[{struct: "...", members: ["...", ...]}]` (deduped + bounded).

2) Enforce “check V1 too” tool ordering
- [x] Update the system prompt policy: for `missing_struct_member`, do `get_error_patch_context` then `search_definition(struct, v1)` and `search_definition(struct, v2)` before any `search_text`.
- [x] Update the stub model heuristic so patch-scope missing-member fixtures reliably exercise the same ordering in tests.

3) Make the agent’s reasoning “struct-diff first”
- [x] Add a prompt rule: treat the failing code as **V1-origin** (from the patch), so V1 struct semantics matter; avoid concluding “deleted field” without checking V1.
- [x] When multiple members are missing in the same struct (e.g. `nbWarnings`, `nbErrors`), fetch each struct definition once per version and reuse it for all members.

4) Tests
- [x] Add a patch-scope fixture log with multiple “no member named” errors on the same struct and patch key.
- [x] Extend `script/react_agent/test_langgraph_agent.sh` to assert the tool order includes both `search_definition(..., version="v1")` and `search_definition(..., version="v2")` before `search_text`.

### Success criteria

- [ ] On the libxml2 example (`nbWarnings` / `nbErrors` in `struct _xmlParserCtxt`), the agent fetches `struct _xmlParserCtxt` in **both** V1 and V2 during the first few steps.
- [ ] The final output explicitly states whether the missing member existed in V1, and whether it is renamed/removed in V2 (with a concrete migration hint).


## Next: Make `read_file_context` patch-safe (use pre-patch line numbers)

### Problem

`read_file_context(file_path, line_number, version=...)` reads from the **raw V1/V2 checkout roots** (`--v1-src` / `--v2-src`).

In patch-aware runs, the build log’s `/src/...:line:col` locations usually refer to the **patched build tree**, so passing those line numbers directly into `read_file_context` returns misleading source context.

### Goal

Allow `read_file_context` (and any future “read source by file:line” tools) to be used safely by ensuring:

- the `file:line` comes from **pre-patch** sources (KB extents or a patch mapping), not from the build log directly
- patch hunks remain the primary way to view **patched** code context

### Tasks

1) Add a pre-patch location mapping to patch tools
- [x] Extend `get_error_patch_context` to optionally return a best-effort mapping for the error location:
  - `pre_patch_file_path` (repo-relative, suitable for `read_file_context`)
  - `pre_patch_line_number` (int) or `null` if unmappable (e.g. added-only lines)
  - `mapping_note` explaining why/when mapping is unavailable

2) Update agent policy (prompt + stub behavior)
- [x] Replace the current “don’t use `read_file_context`” wording with:
  - “Only call `read_file_context` using line numbers from KB results (`search_definition` / `inspect_symbol`) or the `pre_patch_*` mapping from patch tools.”
  - “Never call `read_file_context` with raw build-log `/src/...:line` numbers.”

3) Tests
- [x] Add/adjust a patch-aware fixture where the error line can be mapped, and assert that any `read_file_context` call uses `pre_patch_line_number` (not the build-log line).

### Success criteria

- [ ] In patch-aware mode, the agent never calls `read_file_context` with the raw build-log line number; it either uses `pre_patch_line_number` (when available) or uses KB-derived locations.
