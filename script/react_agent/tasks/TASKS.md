# Auto-loop: preserve and print *all* steps

## Goal
In `--auto-ossfuzz-loop` runs we intentionally trim `state.steps` (prompt context) between iterations, but the final report should still include **all tool steps across the whole run**, not just the last iteration.

## Tasks
- [x] Define the output contract for “all steps” vs “prompt steps” (what goes in `final["steps"]`, and whether we add a separate field).
- [x] Add `AgentState.step_history` (or similar) that accumulates all `{decision, observation}` entries across iterations.
- [x] Seed `step_history` from any pre-populated `state.steps` at the start of `_run_langgraph` (tests/resumed runs).
- [x] Update `tool_node` to append each new step to both `state.steps` and `state.step_history`.
- [x] Keep the auto-loop trim (`state.steps = state.steps[-1:]`) but never drop `step_history`; optionally add a loop-boundary marker for readability.
- [x] Update all “final” payload construction sites to emit the full step history (including early-exit finals).
- [x] Update `_render_final_text()` to label the section clearly (e.g., “Steps (full run)”) and keep output bounded via existing artifact refs.
- [x] Update regression tests: assert forbidden tools weren’t called in later iterations via `FakeRunner.calls` (not by scanning rendered steps).
- [x] Update regression tests: assert final rendered output includes steps from before the trim (first OSS-Fuzz run + later loop steps).
- [x] Update `script/react_agent/README.md` to document step-history output behavior (and any new fields/flags).

## Done criteria
- The final `--output-format text` output includes every tool step across all auto-loop iterations (even though `state.steps` is trimmed for prompting).
- The auto-loop still drops prompt context between iterations.
- Tests pass: `bash script/react_agent/test_langgraph_agent.sh`.
