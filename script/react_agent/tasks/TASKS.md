# TASKS

## Patch-apply failures must not be treated as “fixed”

### Context / Repro

- In some OSS-Fuzz runs the generated override diff is invalid, so `git apply` fails with e.g.:
  - `error: corrupt patch at line 402`
  - Example log: `data/react_agent_artifacts/tail-parser.c-xmlParse3986DecOctet_/ossfuzz_apply_patch_and_test_build_output.6.log`
- Today the agent often decides “target error fixed” just because the target compiler errors from that hunk are no longer present in the build log.
- When the patch fails to apply, the build may succeed on the unmodified source tree, so the target errors “disappear” even though nothing was fixed.

### Root cause (current behavior)

- `script/fuzz_helper.py` uses `git apply ... --reverse /patch;` without `set -e` / return-code checking, so patch-apply failures don’t fail `build_version`.
- `script/react_agent/agent_langgraph.py:_summarize_target_error_status` only parses `file:line:col: error:` style compiler errors (`script/react_agent/build_log.py:iter_compiler_errors`) and ignores patch-apply failures like `error: corrupt patch at line N`.

## Plan

- [x] Confirm failure mode in `ossfuzz_apply_patch_and_test_build_output.6.log` and locate where it’s missed (verdict logic + fuzz_helper patch apply).
- [ ] Add a dedicated “patch apply failure” detector (regex) for OSS-Fuzz logs:
  - `error: corrupt patch at line`
  - `error: patch failed:`
  - `error: .*: patch does not apply`
  - `patch: ****` (malformed patch)
  - Keep it separate from compiler error parsing (these lines have no `file:line:col`).
- [ ] Wire patch-apply failure detection into OSS-Fuzz verdicts:
  - In `script/react_agent/agent_langgraph.py:_summarize_target_error_status`, if patch-apply failure is seen in build log, return `status=failed` with `reason` + `hint`, and never claim `fixed=yes`.
  - Do the same for patch-scope reporting (`_summarize_active_patch_key_status`) so multi-agent summaries clearly show “patch did not apply”.
- [ ] Make `build_version` fail fast when patch application fails:
  - In `script/fuzz_helper.py:build_version`, add `set -euo pipefail` (or at minimum check `git apply` return code) so patch failures propagate as non-zero exit.
  - Optional: run `git apply --check ... --reverse /patch` before applying, to produce clearer diagnostics while preserving the worktree.
- [ ] Belt-and-suspenders in the tool layer:
  - In `script/react_agent/tools/ossfuzz_tools.py:ossfuzz_apply_patch_and_test`, scan `build_output` text for patch-apply failures and expose `patch_apply_ok` / `patch_apply_error` in the tool output (even if `returncode==0` due to legacy behavior).
- [ ] Update the agent loop behavior on patch-apply failure:
  - Treat as a hard failure for the current override diff (don’t advance to “next error”).
  - Next step guidance should explicitly say: “override diff is corrupt / doesn’t apply; regenerate `make_error_patch_override` output (ensure unified-diff header + valid hunk).”
- [ ] Add regression tests:
  - In `script/react_agent/test_langgraph_agent.sh`, feed a fake build log artifact containing `error: corrupt patch at line 402` and assert verdict is `status=failed` (not `fixed=yes`).
  - Ensure final output includes the reason and the log artifact path.
