## Multi-agent: store merged patch under patch_key + clarify `--max-groups` vs hunks fixed

### Goals

- When running via `script/react_agent/multi_agent.py`, store `merged_patch_file_path` inside the per-hunk artifacts dir:
  `data/react_agent_artifacts/multi_<run_id>/<patch_key>/...`
- Make it obvious why `--max-groups N` can yield `< N` fixed hunks (or even `< N` groups selected).

### Plan

- [x] `ossfuzz_tools.merge_patch_bundle_with_overrides`: when `patch_override_paths` is empty, infer `patch_key` from `patch_path` location (if the bundle lives under `<artifact_root>/<patch_key>/...`) and write `merged_patch_file_path` under that patch_key folder.
- [x] Add a regression test (non-Docker) that verifies the merged patch file is written under the inferred `<patch_key>/` directory even with zero override paths.
- [x] `multi_agent.py`: add explicit selection fields to `summary.json` (`max_groups_requested`, groups found/selected after filters) and add a short `task_status_counts` + `not_fixed` list so it’s clear why `hunks_fixed != groups_selected`.
- [x] Update `script/react_agent/test_multi_agent.sh` assertions for the new summary fields.
- [x] Run `bash script/react_agent/test_multi_agent.sh` and `bash script/react_agent/test_langgraph_agent.sh`.

## Multi-agent: restart a hunk when not fixed

### Goal

- In `script/react_agent/multi_agent.py`, if a per-hunk agent run ends with `task_status != fixed`, delete that hunk’s artifact directory and re-run the agent from scratch, up to a configurable limit.

### Plan

- [x] Add `--max-restarts-per-hunk` (default 0) to `multi_agent.py`.
- [x] Implement per-hunk retry loop: if final status is not `fixed`, `rm -rf <artifacts_root>/<patch_key>/` and rerun (up to `1 + max_restarts_per_hunk` total attempts).
- [x] Record restart metadata in `summary.json` and per-result fields (`attempts`, `restarts_attempted`, `attempt_history`), while keeping only the final attempt’s on-disk artifacts.
- [x] Add regression coverage in `script/react_agent/test_multi_agent.sh` (enable restarts and assert `attempts==2` when a hunk is not fixed).
- [x] Run `bash script/react_agent/test_multi_agent.sh`.

## OSS-Fuzz verdict: avoid “fixed” when build failed without compiler errors

### Problem

- Some OSS-Fuzz failures don’t produce `file:line:col: error:` compiler diagnostics (e.g. `cp: cannot create ... /out/...`).
- The agent currently treats “no parsed compiler errors” as “fixed”, which is wrong when `ossfuzz_apply_patch_and_test` actually failed.

### Plan

- [x] In `agent_langgraph.py`, treat OSS-Fuzz run as `failed` when `build_ok`/`check_build_ok` is `False` and no compiler errors were parsed (also respect `patch_apply_ok=False` even if logs don’t match known patterns).
- [x] Wire this into both `ossfuzz_verdict` (`_summarize_target_error_status`) and `patch_key_verdict` (`_summarize_active_patch_key_status` / `_iter_ossfuzz_compiler_errors`) so multi-agent won’t mark the hunk as fixed.
- [x] Add regression test coverage for a non-compiler failure line (e.g. `cp: cannot create regular file '/out/llvm-symbolizer'`).
- [x] Run `bash script/react_agent/test_langgraph_agent.sh`.

## Multi-agent: final merged patch + final OSS-Fuzz test

### Goal

- After `multi_agent.py` finishes all patch_key hunks, collect each hunk’s final `make_error_patch_override_patch_text*.diff` and run a single OSS-Fuzz build/check_build using the combined overrides.

### Plan

- [x] Add `--final-ossfuzz-test {auto,always,never}` to `multi_agent.py` (default `auto`).
- [x] After all hunks complete, find the latest override diff per hunk (prefer the path referenced in `agent_stdout.json.next_step`, else pick the highest-version `make_error_patch_override_patch_text*.diff` in the hunk artifacts dir).
- [x] Write a debug artifact `combined_override_diffs.diff` under `data/react_agent_artifacts/multi_<run_id>/` that concatenates all per-hunk override diffs.
- [x] If enabled (`auto`: only when all hunks are `fixed` and `--tools real`), run `ossfuzz_apply_patch_and_test` with `patch_override_paths=[...]` and store final build/check_build outputs as artifact files; record `final_ossfuzz_test` in `summary.json`.
- [x] Add a non-Docker regression test that validates “latest override diff selection” behavior (e.g. `.8.diff` beats `.diff`).
- [x] Run `bash script/react_agent/test_multi_agent.sh` (and `bash script/react_agent/test_langgraph_agent.sh` if needed).

## Multi-agent: sort combined override diffs (and clarify purpose)

### Problem

- `combined_override_diffs.diff` is a debug artifact that concatenates per-hunk override diffs; today it is written in “agent run order” (roughly by error-count ranking), which can be confusing and can make patch application harder to reason about.

### Goal

- Keep `combined_override_diffs.diff` (useful for debugging), but:
  - sort hunks the same way as `script/revert_patch_test.py` (by `new_start_line` descending, i.e. bottom-up),
  - clarify in `summary.json`/docs that it is overrides-only (not the full merged patch).

### Plan

- [x] Sort per-hunk override diffs by patch bundle order (`PatchInfo.new_start_line` descending) before writing `combined_override_diffs.diff`.
- [x] Record extra metadata in `final_ossfuzz_test` explaining what `combined_override_diffs.diff` is and what file to use for the full patch (`merged_patch_file_path`).
- [x] Add a regression test for the sorted override selection order.
- [x] Run `bash script/react_agent/test_multi_agent.sh`.

## Concurrency: serialize OSS-Fuzz tests

### Problem

- Concurrent agent runs share `oss-fuzz/` state (`oss-fuzz/build/out/...`, `oss-fuzz/build/work/...`, and sometimes `git checkout` inside `oss-fuzz/`), causing test runs to clobber each other.

### Goal

- Keep multi-agent concurrency for reasoning/patch generation, but ensure only one `ossfuzz_apply_patch_and_test` runs at a time (other agents wait).

### Plan

- [x] Add a cross-process file lock around `ossfuzz_apply_patch_and_test` (covers `build_version`, `check_build`, and optional `run_fuzzer`).
- [x] Use a stable repo-local lock file path (e.g. `data/react_agent_locks/ossfuzz_apply_patch_and_test.lock`) with an env override.
- [x] Emit a short stderr message when waiting for the lock (avoid stdout).
- [x] Add a small non-Docker regression test that two subprocesses contend for the lock and serialize.
- [x] Run `bash script/react_agent/test_multi_agent.sh`.
