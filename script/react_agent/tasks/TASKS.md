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

## Next: Parallelize patch-scope fixing across multiple hunks

### Problem

Right now the agent solves only the **first** error group (typically the first/most common `patch_key` group). In practice, OSS-Fuzz builds often fail with **multiple independent patch hunks** (different `patch_key`s), and we want to triage/fix them in parallel and then decide which fix(es) to apply.

### Goal

Given a build log (or OSS-Fuzz build/check_build artifacts), automatically:

1. parse compiler errors
2. map each error to a `patch_key` (hunk key) using the patch bundle
3. group by `patch_key` and pick one representative “primary” error line per group
4. run **one ReAct agent per group** (separately) and collect their results for review

The user reviews the per-hunk agent outputs and decides next actions (apply only certain overrides, rerun OSS-Fuzz, iterate, etc.).

### Plan / Tasks

- [x] Add a new driver command that fans out per-hunk agents (no auto-apply):
  - new CLI entry (recommended): `script/react_agent/multi_agent.py` or a new `--mode multi` in `agent_langgraph.py`.
  - inputs: `--patch-path`, `--build-log` (or `--ossfuzz-artifacts`), `--v1-json-dir`, `--v2-json-dir`, `--v1-src`, `--v2-src`.
  - outputs: one JSON/text report plus per-hunk artifact dirs.
- [x] Error parsing + grouping pipeline:
  - reuse `script/react_agent/build_log.py:iter_compiler_errors` to extract `(file,line,col,msg,raw)` from build/check_build logs.
  - load patch bundle via `script/migration_tools/patch_bundle.py:load_patch_bundle` (respect `REACT_AGENT_PATCH_ALLOWED_ROOTS`).
  - map each error to `patch_key` with `migration_tools.tools._get_error_patch_from_bundle(...)`.
  - group errors by `patch_key`; drop unmapped errors into `patch_key=None` group.
  - select a stable representative per group (e.g. first error in file/line order).
- [x] Per-hunk agent invocation:
  - for each `patch_key` group, call the existing agent with `--error-scope patch` but override its `state.error_line`/`state.grouped_errors` to that group.
  - ensure each sub-agent writes to its own artifact dir: `data/react_agent_artifacts/<parent_run>/<patch_key>/...`.
  - enforce the existing “must OSS-Fuzz test after generating a patch” policy **within each sub-agent**, but do not automatically merge/apply across groups unless user requests.
- [x] Aggregate reporting:
  - produce a summary table: `patch_key`, primary error, `Target error fixed`, whether an override diff was generated, and artifact paths.
  - keep the report bounded and easy to scan in text mode; save full details to artifacts.
- [x] Add tests (non-Docker):
  - synthetic build log with 2 different patch keys and verify grouping + stable representative selection.
  - smoke test that the driver produces N sub-runs and a top-level summary.

### Success criteria

- [x] One command produces per-hunk agent results for all patch keys found in the build logs.
- [x] No automatic “apply everything”; user can choose which overrides to keep/merge.
- [x] The workflow scales to dozens of hunks while keeping console output bounded (details offloaded to artifacts).

## Maintenance: Remove `inspect_symbol` tool

- [x] Remove `inspect_symbol` from the agent-facing tool registry; use `search_definition(..., version=v1|v2)` instead.
- [x] Update stub model/tooling/docs/tests to avoid emitting or expecting `inspect_symbol` tool calls.

## Next: Multi-agent artifact directory normalization (avoid duplicate `_foo` vs `foo` dirs)

### Problem

Some patch keys can start with punctuation (e.g. `_extra_encoding.c`). The agent’s artifact directory logic normalizes
patch keys (strips leading `._-`) when creating per-`patch_key` artifact folders, but `multi_agent.py` previously used the
raw `patch_key` as a directory name for `agent_cmd.txt`/`agent_stdout.json`. This can produce two directories for the same
hunk within one multi-agent run:

- `.../_extra_encoding.c/` (multi_agent’s raw directory)
- `.../extra_encoding.c/` (agent’s normalized artifact directory)

### Plan / Tasks

- [x] Make `multi_agent.py` write per-hunk artifacts into the same normalized directory name as the agent (safe filename).
- [x] Add `patch_key_dirname` to the multi-agent summary for clarity/debugging.
- [x] Add/adjust a non-Docker test to ensure the summary always includes `patch_key_dirname`.
