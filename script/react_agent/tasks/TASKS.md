## Next: Auto-verify whether the target error is fixed after OSS-Fuzz test

### Problem

In `log/agent_log/tmp.log`, the agent ends with “Review OSS-Fuzz logs in artifacts…”, but it doesn’t clearly answer whether the *original target error(s)* are still present after `ossfuzz_apply_patch_and_test` (which ran `build_version` + `check_build`).

We want an automatic “did we fix it?” check, without manually opening logs.

### Goal

After `ossfuzz_apply_patch_and_test`, automatically parse the resulting OSS-Fuzz logs (artifact-backed) and report:

- whether the original error signature(s) are gone **for the original patch hunk key**
- if not fixed, the remaining matching errors
- if fixed but build still fails, the new top errors (next triage target)

### Plan / Tasks

- [x] Capture the “target error” at the beginning of a patch-scope run:
  - store normalized `(patch_key, msg)` as `state.target_errors` (optionally with `file` for display).
  - for grouped errors, store all unique missing-member error patterns for that `patch_key`.
- [x] After `ossfuzz_apply_patch_and_test`, parse logs automatically:
  - use the existing error parsing helpers (`script/react_agent/build_log.py:iter_compiler_errors` and/or `parse_build_errors`) to extract compiler error lines from:
    - `ossfuzz_apply_patch_and_test.build_output` (artifact)
    - `ossfuzz_apply_patch_and_test.check_build_output` (artifact)
  - return a compact result: `matched_target_errors`, `other_errors[:N]`.
- [x] Update the agent final output to include an explicit verdict:
  - `Target error fixed: yes/no`
  - if `no`: include the remaining matching errors **mapped to the same `patch_key` as the target** (bounded)
  - if `yes`: include the next top compiler errors (bounded, regardless of patch key)
  - include artifact paths to the full build/check_build logs.
- [x] Add non-Docker tests:
  - feed synthetic `check_build_output`/`build_output` strings to the parser and assert **patch-key-based** target matching works.
  - ensure outputs are bounded and stable.

### Success criteria

- [x] For runs like `log/agent_log/tmp.log`, the final summary explicitly states whether the missing-member error is fixed.
- [x] The agent no longer requires manual log browsing to confirm the target error’s status.

## Next: `search_definition` should follow typedef extents to real struct bodies

### Problem

In `log/agent_log/tmp.log`, `search_definition(symbol_name="struct _xmlHashTable", version="v2")` only returns the typedef:

- primary: `typedef struct _xmlHashTable xmlHashTable;`
- related: still points at the typedef line, not the real struct body

But the KB entry includes a `type_ref.typedef_extent` pointing to the actual definition range (e.g. `hash.c:68-76`). The tool should surface that as the “real definition”, even when `type_ref.underlying` is `NO_DECL_FOUND`.

### Goal

For typedef-to-struct patterns, `search_definition` prints:

- the typedef (alias) site
- the underlying struct body when it is reachable via `type_ref.typedef_extent` (or other KB-provided extents)

### Plan / Tasks

- [x] Add a helper to materialize “virtual nodes” from KB nested extents:
  - if a node has `type_ref.typedef_extent`, emit a synthetic candidate node whose `extent` is that `typedef_extent` (and `kind` like `STRUCT_DECL` with a `__reason` such as `type_ref.typedef_extent`).
  - do the same for any other nested extents we rely on (keep it minimal; start with `typedef_extent`).
- [x] Update `KbIndex.related_definition_candidates(...)` (or `AgentTools.search_definition`) to include these synthetic candidates so ranking can prefer the real body over forward decl/typedef.
- [x] Add a regression test for `_xmlHashTable` (v2) that asserts the output includes the `hash.c:<start>-<end>` struct snippet (not just the typedef line).
- [x] Ensure the output remains bounded and doesn’t introduce `...[truncated]` markers in the `search_definition` tool output.

### Success criteria

- [x] Running `search_definition("struct _xmlHashTable", version="v2")` shows the actual struct body (via `typedef_extent`) in addition to the typedef alias.
