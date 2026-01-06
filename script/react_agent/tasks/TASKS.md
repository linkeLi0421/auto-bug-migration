## Next: Store artifacts under `patch_key/` (overwrite by filename)

### Problem

Artifacts are currently stored under `data/react_agent_artifacts/<run_id>/...`. This makes it hard to compare runs for the **same patch**, and repeated runs create many near-duplicate artifact directories.

I want artifacts to be grouped by `patch_key`:

- `data/react_agent_artifacts/<patch_key>/...`
- If an artifact file with the same name already exists in that folder, delete/overwrite it (no `.1`, `.2`, ... accumulation).

### Goal

When `patch_key` is known (patch-aware runs), persist artifacts under `data/react_agent_artifacts/<patch_key>/` and overwrite existing filenames.

Fallback behavior:
- If `patch_key` is unavailable, keep the current run-id directory behavior.
- If `--artifact-dir` or `REACT_AGENT_ARTIFACT_DIR` is provided, respect it (no forced patch_key rewrite).

### Plan / Tasks

- [x] Reorder `script/react_agent/agent_langgraph.py` so `patch_key` is computed before calling `resolve_artifact_dir(...)`.
- [x] Update `script/react_agent/artifacts.py`:
  - [x] Extend `resolve_artifact_dir(...)` to accept `patch_key` and choose `data/react_agent_artifacts/<patch_key>/` by default when available.
  - [x] Add an “overwrite mode” for patch-key artifact dirs: if the target path exists, delete it before writing.
  - [x] Keep filename sanitization for `patch_key` and artifact names (no path traversal).
- [x] Update any docs/tests that assume `<run_id>` directories (e.g. `script/react_agent/README.md`, `script/react_agent/test_langgraph_agent.sh`).

### Success criteria

- [x] Running the same patch-scope command twice reuses `data/react_agent_artifacts/<patch_key>/` and overwrites artifact files (no numeric suffixes).
- [x] `read_artifact` continues to work with the new directory layout.


## Next: Tool to apply patch + test in OSS-Fuzz Docker (reuse `revert_patch_test.py` flow)

### Problem

Today the agent can generate an updated patch bundle diff, but it cannot validate it end-to-end (apply + build/test) in the real OSS-Fuzz Docker environment.

### Goal

Add a new tool that:

1) materializes a patch text to a real patch file,
2) applies it and runs build/test in OSS-Fuzz Docker,
3) stores full logs as artifacts and returns only a compact summary to the model.

This should reuse the existing implementation/approach in `script/revert_patch_test.py` (which calls `script/fuzz_helper.py build_version` and optionally `infra/helper.py check_build`).

### Plan / Tasks

- [x] Define the tool API and guardrails:
  - [x] Name: `ossfuzz_apply_patch_and_test`.
  - [x] Args: `project`, `commit`, `patch_path`, optional `patch_override_paths`, `sanitizer`, `architecture`, `engine`, `build_csv`, `fuzz_target`.
  - [x] Enabled by default (no opt-in guard); may require `sudo` depending on Docker setup (`--ossfuzz-use-sudo`).
  - [x] Timeouts + bounded outputs (logs are artifact-backed in agent runs).
- [x] Implement the tool by reusing existing code paths:
  - [x] Build via `script/fuzz_helper.py build_version` (same as `script/revert_patch_test.py`).
  - [x] Validate via `oss-fuzz/infra/helper.py check_build` (same underlying `check_build` as `script/fuzzer_correct_test.py`).
- [x] Wire the tool into the agent runtime:
  - [x] Add to `script/react_agent/tools/registry.py` and `script/react_agent/tools/runner.py`.
  - [x] Add documentation in `script/react_agent/README.md`.
- [x] Add tests (non-Docker):
  - [x] Registry + guardrail sanity checks in `script/react_agent/test_langgraph_agent.sh`.

### Success criteria

- [ ] With opt-in enabled, the tool successfully runs the OSS-Fuzz build/test workflow and reports pass/fail without dumping large logs into the prompt.


## Next: Update `ossfuzz_apply_patch_and_test` to consume patch bundle + override patch files (no `patch_text`)

### Problem

`ossfuzz_apply_patch_and_test` currently accepts `patch_text`, which is large and should not be passed through the model/tool call arguments.

Instead, I want the tool to take:

1) `patch_path`: the tmp_patch bundle path (same meaning as agent `--patch-path`, i.e. `*.patch2`)
2) `patch_override_paths`: a list of `*.diff` file paths produced by tools like `make_error_function_patch`

Then the tool should write a final merged `.diff` patch file for OSS-Fuzz:

- Start from all patches in `patch_path`
- If an override patch exists for a `patch_key`, replace that patch’s text with the override’s text
- Save the merged patch file to disk and use it as the `--patch` input for `script/fuzz_helper.py build_version`

### Plan / Tasks

- [x] Update tool signature and specs:
  - [x] Remove `patch_text` and `patch_file_path` from `ossfuzz_apply_patch_and_test` tool args/spec.
  - [x] Add `patch_path` (bundle `*.patch2`) and `patch_override_paths` (`list[string]`).
  - [x] Update `script/react_agent/tools/registry.py` + `script/react_agent/tools/runner.py` validations.
- [x] Implement merge logic inside the tool:
  - [x] Load the patch bundle with `script/migration_tools/patch_bundle.py::load_patch_bundle` (respect `REACT_AGENT_PATCH_ALLOWED_ROOTS`).
  - [x] For each override path:
    - [x] Read diff text from file (must be under artifact root allowlist).
    - [x] Infer `patch_key` from the override path (a parent directory name matches a real `patch_key` in the bundle, e.g. `.../react_agent_artifacts/<patch_key>/...`).
    - [x] Replace the patch text for that `patch_key` in the merged output.
  - [x] Write the merged patch file (joined diffs) to an artifact-root `.diff` file, overwriting any existing file with the same name.
  - [x] Use this merged patch file as the `--patch` argument for `script/fuzz_helper.py build_version`.
- [x] Update outputs:
  - [x] Return `merged_patch_file_path` (string) instead of returning patch text.
  - [x] Keep build/check_build logs artifact-backed (no large logs in prompt).
- [x] Update docs/tests:
  - [x] Update `script/react_agent/README.md` to describe the new args and workflow.
  - [x] Add a non-Docker unit test that builds a merged diff from the sample bundle + a synthetic override under `<patch_key>/`.

### Success criteria

- [x] The tool call payload never includes patch text; it only passes file paths.
- [x] The merged `.diff` file uses override patches when provided and otherwise falls back to the bundle’s original patch text.


## Next: Make the agent test the generated patch before stopping

### Problem

In the current run (`tmp`), the agent stops immediately after `make_error_function_patch`:

- it generates a patch override diff (artifact),
- then the runtime forces `final` (“Generated a patch; stop after patch generation.”),
- so the agent never validates the patch in OSS-Fuzz Docker.

### Goal

The agent should ALWAYS test the patch in OSS-Fuzz after generating it (no opt-in / no skipping):

1) generate the patch override via `make_error_function_patch`,
2) call `ossfuzz_apply_patch_and_test` using:
   - `patch_path` = the bundle path (`--patch-path`)
   - `patch_override_paths` = the override diff artifact path(s) from `make_error_function_patch`
3) only then return `final`, including a short test summary + artifact paths to logs.

### Plan / Tasks

- [x] Add agent CLI/config for OSS-Fuzz testing:
  - [x] `--ossfuzz-project`, `--ossfuzz-commit`
  - [x] optional: `--ossfuzz-build-csv`, `--ossfuzz-sanitizer`, `--ossfuzz-arch`, `--ossfuzz-engine`, `--ossfuzz-fuzz-target`, `--ossfuzz-use-sudo`
  - [x] include these values in the initial prompt header so the model can call the tool without guessing.
  - [x] if required OSS-Fuzz args are missing, fail fast (don’t allow a run that can generate a patch but cannot test it).
  - [x] remove the opt-in env guard (`REACT_AGENT_ENABLE_OSSFUZZ`) so testing can’t be skipped by configuration.
- [x] Track the generated override diff path(s) in agent state:
  - [x] after `make_error_function_patch`, store `patch_text.artifact_path` into `state.patch_override_paths`.
  - [x] keep only the latest override per `patch_key` (or just keep the last one for the current `patch_key` run).
- [x] Update runtime guardrails / phase rules:
  - [x] replace “stop after patch generation” with mandatory testing:
    - [x] after a successful `make_error_function_patch`, force one more tool call `ossfuzz_apply_patch_and_test`, then `final`.
  - [x] add a new guardrail: don’t accept `final` unless `ossfuzz_apply_patch_and_test` has been called after `make_error_function_patch`.
  - [x] update step budgeting: require enough remaining steps for `read_artifact -> make_error_function_patch -> ossfuzz_apply_patch_and_test`.
- [x] Prompt updates:
  - [x] add a system-prompt rule: after generating a patch, ALWAYS call `ossfuzz_apply_patch_and_test` before returning `final`.
  - [x] model should pass override diff paths directly (do NOT call `read_artifact` just to read the diff).
- [x] Tests (non-Docker):
  - [x] extend stub-mode tests to assert mandatory ordering:
    - [x] `... make_error_function_patch -> ossfuzz_apply_patch_and_test -> final`
  - [x] remove/replace any tests that assume OSS-Fuzz testing is optional.

### Success criteria

- [x] A patch-scope run ends with an OSS-Fuzz test attempt (logs saved as artifacts) instead of stopping right after patch generation.


## Next: Remove all error-count limits (no `--max-errors`, no internal caps)

### Problem

`--max-errors` forces callers to pick an arbitrary limit and complicates the CLI. Previously, `iter_compiler_errors(...)` also capped the number of collected errors.

### Goal

Remove `--max-errors` / `REACT_AGENT_MAX_ERRORS` and remove any internal caps on how many errors are parsed from the build log.

### Plan / Tasks

- [x] Remove `--max-errors` and `REACT_AGENT_MAX_ERRORS` from `script/react_agent/agent_langgraph.py`.
- [x] Update `script/react_agent/build_log.py` to remove `limit` and stop capping/breaking by error count.
- [x] Update callsites to use the new `iter_compiler_errors(...)` signature.
- [x] Update docs/tests that reference `--max-errors` (e.g. `script/react_agent/README.md`, `script/react_agent/test_langgraph_agent.sh`).

### Success criteria

- [x] The agent runs without any `--max-errors` flag.
- [x] Patch-scope runs still group multiple errors when present.
- [x] The agent never truncates the number of parsed errors due to an internal cap.
