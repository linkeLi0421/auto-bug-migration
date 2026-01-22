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

[x] Stabilize missing-struct-member handling: focus one member at a time
  - Context: patch-scope runs can include multiple missing-member diagnostics for the same struct within a single function group; unioning them in the prompt encourages broad edits and increases guardrail trips.
  - [x] Summarize only the active missing member (no union across grouped errors).
  - [x] Wire into patch-scope state init + auto-loop state refresh.
  - [x] Update `system_patch_scope` prompt guidance for missing-member errors.
  - [x] Add regression test.
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh` and `bash script/react_agent/test_multi_agent.sh`.
  - [x] Post reminder to `#report`.

[ ] Fix `multi_agent.py` crash when `patch_text` is a unified diff string (Errno 36: file name too long)
  - Context: `_extract_override_diffs_from_agent_stdout_steps()` currently calls `normalize_path(patch_text)` when `patch_text` is a string. In some “no change” tool outputs, `patch_text` is the *full diff text* (starts with `diff --git ...`), so `Path(...).is_file()` attempts to `stat()` a huge “filename” and crashes.
  - [x] Reproduce with a minimal `agent_stdout.json` payload where `steps[*].observation.output.patch_text` is a unified diff string (no `artifact_path`).
  - [x] Harden `normalize_path`:
    - [x] Reject obviously-not-a-path strings (contains `\n`, starts with `diff --git`, overly long).
    - [x] Wrap `path.resolve()` / `path.is_file()` in `try/except OSError` and return `""` on failure.
  - [x] Tighten `maybe_add` parsing:
    - [x] When `patch_text` is a string, only treat it as an override artifact path if it “looks like a path” (single-line, reasonable length); otherwise skip it.
  - [x] Add regression coverage to `script/react_agent/test_multi_agent.sh` ensuring the unified-diff-string case does not throw and does not produce an override path.

[x] Multi-agent resume support: restart without redoing fixed hunks
  - Context: long multi-agent runs can fail transiently (e.g. `read operation timed out`) and it’s expensive to restart from the beginning.
  - [x] Add `--resume-from` to `script/react_agent/multi_agent.py` to reuse an existing `multi_<run_id>` artifacts root (or its `progress.json`/`summary.json`).
  - [x] Skip patch_keys whose prior `task_status` is `fixed`; rerun the rest.
  - [x] Write `progress.json` checkpoints after each completed hunk so partial runs can be resumed.
  - [x] Add regression coverage in `script/react_agent/test_multi_agent.sh`.

[x] Single-agent restart on transient timeouts (agent_langgraph)
  - Context: single-agent runs can fail with transient network/LLM errors like `Result: next_step: The read operation timed out` and currently exit with `thought: Agent error.`
  - [x] Add `--max-agent-retries` and `--agent-retry-backoff-sec` to `script/react_agent/agent_langgraph.py`.
  - [x] Retry LangGraph execution in-process when the exception chain indicates a timeout (`urllib.error.URLError` / `socket.timeout` / “timed out” text).
  - [x] Add regression coverage in `script/react_agent/test_langgraph_agent.sh` with a flaky model that times out once, then succeeds.
