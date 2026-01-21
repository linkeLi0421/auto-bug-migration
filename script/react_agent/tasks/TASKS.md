[x] Fix `make_extra_patch_override` false “already present” for type names used only in prototypes
  - Context: `_symbol_defined_in_extra_hunk` currently treats whole-identifier matches on `;`-terminated prototype lines as “defined”, so a type name like `xmlHashedString` mentioned only in prototypes can block inserting its `typedef` (real repro: libxml2 `parser.c` / `_extra_parser.c`).
  - [x] Reproduce from real artifact: `_extra_parser.c` contains `xmlHashedString` only in a prototype (no typedef), but tool returns “already present”.
  - [x] Tighten `_symbol_defined_in_extra_hunk` so “defined” means an actual declaration/definition:
    - [x] Don’t treat type names appearing inside function prototypes/param lists as “defined”.
    - [x] Don’t treat `struct TAG *p;` / `struct TAG;` as a tag definition (require `{` or `{` on next inserted line).
  - [x] Ensure type insertions are ordered correctly:
    - [x] When inserting `typedef`/tag bodies, prepend them before existing prototypes/macros in the `_extra_*` hunk so later prototypes can use the type.
  - [x] Add regression tests:
    - [x] `_symbol_defined_in_extra_hunk` returns false for `xmlHashedString` mentioned only in prototypes.
    - [x] Type insertions are prepended before existing `-` blocks in the extra hunk.
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh` and `bash script/react_agent/test_multi_agent.sh`.
  - [x] Post reminder to `#report`.

[x] Stabilize `make_error_patch_override`: avoid bulk renaming `__revert_*` helpers to unprefixed symbols
  - Context: models sometimes “normalize” calls like `__revert_<hash>_foo(...)` to `foo(...)` while fixing an unrelated error, which can introduce new missing-prototype/ABI/behavior issues and makes the patch-scope loop unstable.
  - [x] Add an agent-side guardrail: when rewriting from a BASE slice, reject overrides that drop multiple `__revert_*` identifiers from the baseline (retry with minimal edits).
  - [x] Update `system_patch_scope` prompt to explicitly: keep existing `__revert_*` symbols unless directly required by the active diagnostic (prefer `make_extra_patch_override` for prototypes).
  - [x] Add regression test: dropping 2+ `__revert_*` names triggers the guardrail.
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh` and `bash script/react_agent/test_multi_agent.sh`.
  - [x] Post reminder to `#report`.

[x] Stabilize `make_error_patch_override`: reject placeholder/short `new_func_code` that omits large parts of the BASE slice
  - Context: LLMs sometimes emit “the rest is unchanged …” placeholders or output only a partial function body, which deletes the omitted lines from the patch slice and causes cascading failures.
  - [x] Tighten the base-preservation guardrail to catch large shrink even when the tail is present (line-count ratio).
  - [x] Update `system_patch_scope` prompt: no placeholders/ellipsis; always paste the full BASE slice and apply minimal edits.
  - [x] Add regression test for “short but includes tail” scenario.
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh` and `bash script/react_agent/test_multi_agent.sh`.
  - [x] Post reminder to `#report`.

[ ] Stabilize missing-struct-member handling: focus one member at a time
  - Context: patch-scope runs can include multiple missing-member diagnostics for the same struct within a single function group; unioning them in the prompt encourages broad edits and increases guardrail trips.
  - [ ] Summarize only the active missing member (no union across grouped errors).
  - [ ] Wire into patch-scope state init + auto-loop state refresh.
  - [ ] Update `system_patch_scope` prompt guidance for missing-member errors.
  - [ ] Add regression test.
  - [ ] Run `bash script/react_agent/test_langgraph_agent.sh` and `bash script/react_agent/test_multi_agent.sh`.
  - [ ] Post reminder to `#report`.
