[x] make_extra_patch_override: create `_extra_*` hunk when missing
  - [x] If the patch bundle has no `_extra_*` entry for `file_path`, synthesize a new patch_key (default `_extra_<basename>`) and a minimal unified-diff skeleton anchored after the file’s preprocessor/header region.
  - [x] agent_langgraph: allow `_write_effective_patch_bundle` to *add* a new patch_key (create a `PatchInfo`) when applying an override diff for `_extra_*`.
  - [x] ossfuzz_tools: allow `merge_patch_bundle_with_overrides` + `write_patch_bundle_with_overrides` to accept override diffs under a new `_extra_*` patch_key (create a `PatchInfo` instead of erroring).
  - [x] search_definition: coerce invalid `version=` args (e.g. commit hashes) to `v1|v2` and record `version_raw` (and update prompt text to only use `v1|v2`).
  - [x] Add regression tests for:
    - [x] creating a brand-new `_extra_*` entry (bundle initially has none)
    - [x] search_definition version coercion
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh` and `bash script/react_agent/test_multi_agent.sh`.
  - [x] Post reminder to `#report`.

[x] make_extra_patch_override: don’t fail when KB file paths aren’t in v1-src checkout
  - [x] Diagnose failure mode: KB has nodes for the symbol (e.g. `xmlHashedString` in `include/private/dict.h`) but `SourceManager` can’t read the referenced file from the configured `--v1-src` working tree.
  - [x] Add a `SourceManager` fallback to read missing files from git objects (e.g. `git show <commit>:<path>`) using per-version commit hints.
  - [x] Infer commit hints from `--v1-json-dir/--v2-json-dir` basenames (e.g. `libxml2-e11519` → `e11519`) and/or `--ossfuzz-commit` and plumb them to `SourceManager` via env vars.
  - [x] Improve `make_extra_patch_override` failure notes: if KB nodes exist but source extraction failed, include the missing file path + hint about `--v1-src` mismatch / commit-hint env vars.
  - [x] Add regression test: KB node points at a file missing in the working tree but present in a git commit (ensures `xmlHashedString` can be extracted deterministically).
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh` and `bash script/react_agent/test_multi_agent.sh`.
  - [x] Post reminder to `#report`.

[x] SourceManager: prefer commit-hint `git show` even when the file exists (fix wrong extents on mismatched checkouts)
  - [x] Reproduce: KB extent points at `include/libxml/parser.h:175` (typedef), but the configured `--v1-src` worktree has different content at that line (tool inserts a comment like `* The parser context.`).
  - [x] Update `SourceManager.get_code_segment(...)` to try `git show $REACT_AGENT_V{1,2}_SRC_COMMIT:<path>` first when the env hint is set (fallback to reading the working tree only if `git show` fails).
  - [x] Add regression test that simulates an “existing file but wrong revision” worktree (two commits with different line-175 content) and asserts `make_extra_patch_override` inserts the correct typedef line.
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh`.
  - [x] Post reminder to `#report`.

[x] make_extra_patch_override: upgrade forward typedefs to full tag definitions
  - [x] Detect “forward typedef” already present in `_extra_*` hunks (e.g. `typedef struct TAG Name;`) and treat it as incomplete for field-access use cases.
  - [x] When called again for the same symbol, locate the tag body in KB (`STRUCT_DECL|UNION_DECL|ENUM_DECL`) and insert `struct TAG { ... };` (don’t no-op).
  - [x] Avoid duplication if the tag definition is already present in the extra hunk.
  - [x] Add regression test: start with an `_extra_*` hunk containing only the typedef; second `make_extra_patch_override` call inserts the struct body.
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh`.
  - [x] Post reminder to `#report`.

[x] Incomplete-type guardrail: force `_extra_*` type definitions (avoid semantic no-op rewrites)
  - [x] Detect incomplete-type diagnostics (e.g. “incomplete definition of type …”, “sizeof to an incomplete type …”) and extract the type name.
  - [x] Before allowing `make_error_patch_override`, force `make_extra_patch_override(symbol_name=<type>)` (allow up to 2 attempts per type to support “typedef then tag body” upgrade).
  - [x] Update `prompts/system_patch_scope.txt` to tell the model to fix incomplete types via `make_extra_patch_override`, not by removing field access / sizeof usage.
  - [x] Add regression test for the new guardrail.
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh`.
  - [x] Post reminder to `#report`.

[x] Handle `-Wmissing-prototypes` warnings (`no previous prototype for function ...`)
  - [x] Extend `build_log.iter_compiler_errors` to include `warning: no previous prototype for function '...'` diagnostics.
  - [x] Add a patch-scope guardrail: when the current diagnostic is missing-prototype, force `make_extra_patch_override(symbol_name=<function>)` (prototype insertion) before allowing function rewrites.
  - [x] Apply a deterministic within-hunk ordering: prioritize warnings (missing-prototype/implicit-decl) before errors when selecting the next `grouped_errors[0]` (both initial patch-scope grouping and auto-loop).
  - [x] Add regression tests:
    - [x] build_log warning parsing includes `no previous prototype ...`
    - [x] guardrail triggers and produces `make_extra_patch_override` for missing-prototype warning
    - [x] ordering: warnings are selected before errors in patch-scope grouping
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh`.
  - [x] Post reminder to `#report`.
