# Step retry with failure feedback

## Problem

Currently the merge loop (commit 724bd06aa) is a flat `for` loop. When a
step fails — build error, self-trigger failure, or regression — the code
either reverts and skips (self-trigger) or just records the regression and
moves on. The agent never gets a second chance with knowledge of what went
wrong.

## Goal

After each failure type, revert to the pre-step snapshot, then re-run the
entire step with feedback telling the agent:
- What it did in the previous attempt (the git diff it produced)
- What went wrong (build error, which bug didn't trigger, which bugs regressed)

Allow up to 1 retry per step (configurable via `_MAX_RETRIES = 1`).

## Design

### Loop structure

Wrap the step body in a `while True` loop inside the existing `for` loop.
On retry, revert source + dispatch_state to pre-step snapshot, then
re-enter the loop with feedback.

```python
for i, bd in enumerate(ordered):
    _save_source_snapshot(container, project)
    dispatch_state_before_step = copy.deepcopy(dispatch_state)
    step_feedback = None
    retry_count = 0

    while True:  # retry loop
        if retry_count > 0:
            dispatch_state = copy.deepcopy(dispatch_state_before_step)
            _revert_and_rebuild(container, project, ...)

        step = { ... }
        # ... apply, build, verify, regression check ...

        if should_retry:
            step_feedback = _build_feedback(...)
            retry_count += 1
            continue

        break  # done with this step
```

### Three failure points that trigger retry

#### 1. Build failure (after conflict resolution)

Only retry if the step used agent conflict resolution (`method == "conflict"`),
since clean/3way applies don't involve agent decisions.

Feedback includes:
- The last 20 lines of build error output
- Which bug was being applied
- Instruction to make a smaller, more localized edit

#### 2. Self-trigger failure

After the bug's patch is applied (and optional dispatch attempted), the
bug still doesn't crash. Retry the whole step.

Feedback includes:
- The expected crash (top app stack frame from crash log)
- Which previously-applied bugs may be blocking
- The current git diff (what the agent produced)
- Instruction to re-read the standalone patch and preserve its full semantics

#### 3. Regression failure

The new bug triggers, but previously-working bugs stopped. Retry the whole
step (even after dispatch was attempted and failed to fix all regressions).

Feedback includes:
- Which bugs regressed (bug IDs + their crash types)
- The current git diff (what the agent produced)
- Instruction to keep new bug semantics while preserving the code paths
  the regressed bugs need

### Feedback plumbing

Add a `feedback: str | None` parameter to three agent-calling functions:
- `resolve_conflict_with_agent()` — append feedback to the conflict prompt
- `resolve_self_trigger_with_dispatch()` — append feedback to the self-trigger prompt
- `resolve_with_dispatch()` — append feedback to the regression dispatch prompt

When `feedback` is set, append it to the prompt:

```python
if feedback:
    prompt += (
        "\n\nFeedback from a previous failed attempt on this step:\n"
        f"{feedback.strip()}\n"
    )
```

### Feedback builder functions

```python
def _build_step_feedback(
    failure_type: str,      # "build", "self_trigger", "regression"
    bug_id: str,
    container: str,
    project: str,
    crash_log: str | None,
    build_output: str | None,
    regressed_bugs: list[str] | None,
    applied_bugs: list[str],
) -> str:
```

This function captures the current `git diff` from the container (what the
agent produced) and formats a concise summary:

```
Previous attempt for {bug_id} failed.

What you changed (git diff):
  {diff_stat}          # e.g. "blosc2.c: +15 -8, frame.c: +3 -2"

Result: {failure description}
  - build: "Build failed. Last 20 lines: ..."
  - self_trigger: "Bug {bug_id} did not crash. Expected top frame: {frame}."
  - regression: "These bugs stopped triggering: OSV-2021-XXX, OSV-2021-YYY"

Guidance:
  - {failure-specific instruction}
```

Keep it short — the agent already has the full prompt context.

### What stays the same

- `_save_source_snapshot()` is called once per step (before the while loop),
  not on each retry
- `dispatch_state_before_step` is a deepcopy saved before the while loop
- On retry, both source and dispatch_state are restored to pre-step state
- The same diff is re-applied from scratch on each retry
- If retry also fails, the step falls through to the existing
  revert/skip/record logic

## Files changed

- `script/bug_transplant_merge.py`:
  - Add `import copy` (for `dispatch_state_before_step = copy.deepcopy(...)`)
  - Add `_MAX_RETRIES = 1` constant
  - Add `_build_step_feedback()` helper
  - Add `feedback` parameter to `resolve_conflict_with_agent()`,
    `resolve_self_trigger_with_dispatch()`, `resolve_with_dispatch()`
  - Restructure step body into `while True` retry loop
  - Pass `step_feedback` into agent-calling functions on retry
