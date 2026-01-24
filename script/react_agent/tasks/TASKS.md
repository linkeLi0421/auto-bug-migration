# Tasks

Archived plans live in `script/react_agent/tasks/TASKS_*.md`. This file tracks the current active items.

## Plan: Multi-agent must merge multiple `_extra_*` overrides for the same patch_key (no last-write-wins)
Context: In multi-agent runs, multiple independent hunks can each generate an override for the same shared `_extra_*` patch_key (e.g. `_extra_hash.c`). Today our merge path treats overrides as `dict[patch_key] -> patch_text`, so later overrides silently overwrite earlier ones. This can drop required extra definitions/macros from the final merged bundle/diff (example: only `.../_extra_hash.c/make_extra_patch_override_patch_text_hash.c_xmlHashFindEntry.*.diff` ends up included, but `.../_extra_hash.c/make_extra_patch_override_patch_text_hash.c_MAX_HASH_SIZE.*.diff` is missing).

- [ ] Repro + confirm: pick a multi-run artifacts dir with 2+ override diffs under the same `_extra_*` patch_key and show the merged bundle only contains one of them.
- [ ] Decide merge semantics for duplicates:
  - For `_extra_*`: combine all override diffs for the same patch_key (stable order) so the final patch contains the union.
  - For non-`_extra_*`: duplicates should be unexpected; either keep last with a warning or hard-fail.
- [ ] Update `script/react_agent/tools/ossfuzz_tools.py`:
  - In `write_patch_bundle_with_overrides()`, accept multiple override files per patch_key instead of last-write-wins.
  - In `merge_patch_bundle_with_overrides()`, ensure the merged unified diff includes all `_extra_*` override diffs (not just one).
  - Make ordering deterministic (e.g., sort by path; optionally honor numeric suffixes) and optionally de-dup identical override texts by hash.
- [ ] Add a regression test in `script/react_agent/test_langgraph_agent.sh`:
  - Provide two override diff files for the same `_extra_*` patch_key with distinct content.
  - Assert the merged unified diff contains both.
  - Assert the merged patch bundle stores a combined `patch_text` that retains both.
- [ ] (Nice-to-have) Emit a concise log/summary entry when combining N overrides for a single `_extra_*` key (helps diagnose missing-extra regressions).
