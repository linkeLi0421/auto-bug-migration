# Tasks

Archived plans live in `script/react_agent/tasks/TASKS_*.md`. This file tracks the current active items.

## Plan: Multi-agent must merge multiple `_extra_*` overrides for the same patch_key (no last-write-wins)
Context: In multi-agent runs, multiple independent hunks can each generate an override for the same shared `_extra_*` patch_key (e.g. `_extra_hash.c`). Today our merge path treats overrides as `dict[patch_key] -> patch_text`, so later overrides silently overwrite earlier ones. This can drop required extra definitions/macros from the final merged bundle/diff (example: only `.../_extra_hash.c/make_extra_patch_override_patch_text_hash.c_xmlHashFindEntry.*.diff` ends up included, but `.../_extra_hash.c/make_extra_patch_override_patch_text_hash.c_MAX_HASH_SIZE.*.diff` is missing).

- [x] Repro + confirm: multi-run `_extra_hash.c` has multiple independent overrides; final merge only kept one due to last-write-wins.
- [x] Decide merge semantics for duplicates:
  - For `_extra_*`: combine all override diffs for the same patch_key (stable order) so the final patch contains the union.
  - For non-`_extra_*`: duplicates should be unexpected; either keep last with a warning or hard-fail.
- [x] Update `script/react_agent/tools/ossfuzz_tools.py`:
  - `write_patch_bundle_with_overrides()` accepts multiple override files per patch_key; `_extra_*` keys are merged by unioning inserted `-` lines.
  - `merge_patch_bundle_with_overrides()` mirrors this so a merged unified diff can be produced from multiple `_extra_*` override files.
  - Deterministic ordering: sort override files by path before merging; de-dup by exact line match.
- [x] Add a regression test in `script/react_agent/test_langgraph_agent.sh`:
  - Provide two override diff files for the same `_extra_*` patch_key with distinct content.
  - Assert the merged unified diff contains both.
  - Assert the merged patch bundle stores a combined `patch_text` that retains both.
- [x] Naming/traceability: prefer per-hunk `override_*.diff` artifacts (nested under `<origin_patch_key>/_extra_*/`) when collecting overrides, rather than `make_extra_patch_override_patch_text_*` (named by symbol) from the shared `_extra_*` directory.
- [x] (Nice-to-have) Emit a concise log/summary entry when combining N overrides for a single `_extra_*` key (helps diagnose missing-extra regressions).

### Status (2026-01-25)
- Implemented override collection + `_extra_*` merge semantics in `script/react_agent/multi_agent.py` and `script/react_agent/tools/ossfuzz_tools.py`.
- Added regression coverage in `script/react_agent/test_langgraph_agent.sh` and verified it passes locally.

## Plan: Do not use make_extra_patch_override for `unknown type name` errors inside `_extra_*` hunks
Context: For `error: unknown type name 'X'`, the agent often tries `make_extra_patch_override(symbol_name=X)` to add a file-scope decl/type into the file’s `_extra_*` hunk. This is usually correct when the error originates in a normal patch hunk. But when the error itself maps to an `_extra_*` hunk, repeatedly extending `_extra_*` can hide the real V1→V2 mismatch and create cascaded/incorrect insertions. In that case, we should inspect the existing `_extra_*` patch content and rewrite/fix it directly.

- [x] Update prompt guidance (`script/react_agent/prompts/system_undeclared_symbol.txt`) to explicitly avoid make_extra_patch_override when active patch_key starts with `_extra_`.
- [x] Add a guardrail in `script/react_agent/agent_langgraph.py`:
  - If decision is `make_extra_patch_override` AND active patch_key is `_extra_*` AND active error is “unknown type name”, force `read_artifact` of the `_extra_*` slice and then force `make_error_patch_override` (reuse pending_patch + force_patch_after_read).
- [x] Add/adjust regression coverage in `script/react_agent/test_langgraph_agent.sh`.

## Plan: `_extra_*` merge must preserve multi-line insert blocks (avoid stray fragments like a lone `int`)
Context: Our current `_extra_*` merge strategy unions individual inserted `-` lines across override diffs. This breaks when two agents insert overlapping multi-line declarations with shared lines. Example from `data/react_agent_artifacts/multi_20260125_045052_2071583_6db821ff`:
- `.../833780948167/_extra_hash.c/override__extra_hash.c.1.diff` inserts:
  - `int` + `__revert_e11519_xmlHashGrow(...);` (split across lines)
- `.../218853945220/_extra_hash.c/override__extra_hash.c.5.diff` inserts:
  - `static int` + `__revert_e11519_xmlHashGrow(...);`
The line-union merge keeps `__revert_e11519_xmlHashGrow(...);` once, but still inserts the missing `int` line, producing a malformed stray `-int` in the merged output (`.../ossfuzz_merged_libxml2_f0fd1b.diff` around line ~5580).

- [x] Repro in a minimal fixture: two override diffs with overlapping multi-line prototypes (shared name line, different return-type line).
- [x] Update `_extra_*` merge semantics (in `script/react_agent/tools/ossfuzz_tools.py`) from “union of lines” to “union of blocks”:
  - Parse each override diff’s first hunk body into inserted blocks (split on blank `-` lines) and merge whole blocks (atomic), never partial lines.
  - De-dup blocks by semantic key when possible:
    - function prototype blocks: key by function name (prefer a `static` prototype if any variant is `static` to avoid “static follows non-static” issues)
    - `#define`: key by macro name
    - `typedef`/tag blocks: key by declared type name/tag
    - fallback: key by exact block text
- [x] Add a deterministic “sanity check” on merged `_extra_*` hunks to catch merge corruption (e.g., lone `int` / `unsigned` / `static int` lines, incomplete prototypes).
- [x] (Optional, gated) If the sanity check fails, call an LLM “merge repair” pass to rewrite just the `_extra_*` hunk insertions into a coherent set of declarations/macros (config/env guarded; default deterministic-only).
- [x] Add regression test(s) in `script/react_agent/test_langgraph_agent.sh` ensuring:
  - merged `_extra_*` output does not contain stray fragments
  - exactly one coherent prototype exists for the duplicated function name
