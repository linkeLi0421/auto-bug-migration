# Improve retry feedback: diagnostic over boilerplate

## Problem

Current retry feedback gives the agent symptoms (what failed) but not
diagnosis (why it failed). The result is 6 retries that oscillate
between "self-trigger fails" and "regression" without converging,
because the agent lacks the information to pinpoint the blocker.

Current feedback structure:
```
What you changed: (git diff --stat — file-level, no specifics)
Result: (symptom — "did not crash" or "bugs X,Y stopped triggering")
Guidance: (static boilerplate — same 4 lines every retry)
```

## Goal

Replace generic feedback with targeted diagnostic information that
tells the agent WHERE the problem is, not just WHAT happened.

## Changes

### 1. Self-trigger failure: identify the blocker

Currently: "Bug didn't crash. Expected top frame: zfp_getcell."

Better: show which previously-applied patches touch the same functions
as the failing bug's crash path, so the agent knows which code to
dispatch.

```python
def _diagnose_self_trigger_failure(
    container, project, bug_id, crash_log, applied_bugs_data,
):
    """Identify which previous patches likely block the testcase."""
    # Get the crash path functions from the crash log
    crash_funcs = set(_extract_stack_from_file(crash_log))

    # For each previously applied bug, check if its patch touches
    # functions in the crash path
    blockers = []
    for pb in applied_bugs_data:
        pb_diff = Path(pb["diff_path"]).read_text(errors="replace")
        # Extract function names from diff context lines (@@...@@)
        diff_funcs = set(re.findall(r'@@.*@@\s*(\w+)', pb_diff))
        overlap = crash_funcs & diff_funcs
        if overlap:
            blockers.append((pb["bug_id"], overlap))

    return blockers
```

Feedback becomes:
```
Result: Bug OSV-2022-511 did not crash.
Expected crash path: zfp_getcell → blosc_d → blosc_run_decompression_with_context

Likely blockers (previous patches that touch crash-path functions):
  - OSV-2023-51: touches blosc_run_decompression_with_context (2 hunks)
  - OSV-2021-639: touches blosc_d (3 hunks)

Action: dispatch the changes from these bugs in the listed functions.
```

### 2. Regression failure: pinpoint the conflicting hunks

Currently: "These bugs stopped triggering: OSV-2021-897, OSV-2021-639"

Better: for each regressed bug, run its testcase and capture the
actual output (crash vs clean exit), plus identify which files the
agent changed that overlap with the regressed bug's patch.

```python
def _diagnose_regression(
    container, project, bug_id, regressed_bugs_data,
):
    """For each regressed bug, identify what the agent broke."""
    diag = []
    for rb in regressed_bugs_data:
        # Run regressed bug's testcase to see current behavior
        _, output = _exec_capture(
            container,
            f"/out/address/{rb['fuzzer']} /work/{rb['testcase']} 2>&1 | tail -5",
            timeout=30,
        )
        # Find which files the agent changed that overlap with
        # the regressed bug's patch
        rb_files = files_in_diff(rb["diff_path"])
        _, agent_diff = _exec_capture(
            container, f"cd /src/{project} && git diff --name-only",
        )
        agent_files = set(agent_diff.strip().splitlines())
        overlap = rb_files & agent_files
        diag.append({
            "bug_id": rb["bug_id"],
            "behavior": output.strip()[-200:] if output else "unknown",
            "conflicting_files": overlap,
        })
    return diag
```

Feedback becomes:
```
Result: 2 bugs regressed.

OSV-2021-897:
  Now: exits cleanly (was: crash in ZSTD_decompressBlock_internal)
  Your changes to zstd_decompress.c overlap with this bug's patch.
  → Wrap your changes to zstd_decompress.c in dispatch branches.

OSV-2021-639:
  Now: exits cleanly (was: crash in blosc_d)
  Your changes to blosc2.c overlap with this bug's patch.
  → Wrap your changes to blosc2.c that touch blosc_d() in dispatch.
```

### 3. Drop the static boilerplate

Remove the repeated "Re-read the standalone patch" / "wrap ALL of them"
lines. The base prompt already contains these instructions. Repeating
them dilutes the diagnostic signal.

### 4. Drop the raw diff dump

Remove `_capture_dispatch_diff()` from the feedback. The agent already
has `git diff` access. The 80-line diff dump adds noise and inflates
the prompt. Replace with the targeted diagnostic from points 1-2.

### 5. Keep it short

Target: feedback section under 20 lines. Current a1 feedback: 120 lines.
Most of that is the raw diff dump and fuzzer boilerplate output. Cut both.

## Implementation

### New helper functions

```python
def _diagnose_self_trigger_failure(container, project, bug_id,
                                    crash_log, applied_bugs_data) -> str
def _diagnose_regression(container, project, bug_id,
                          regressed_bugs_data) -> str
```

### Modified function

`_build_step_feedback()` — replace the three failure-type branches with
calls to the new diagnostic helpers. Remove `_capture_dispatch_diff()`
call and static guidance lines.

## Files changed

- `script/bug_transplant_merge.py`:
  - Add `_diagnose_self_trigger_failure()`
  - Add `_diagnose_regression()`
  - Rewrite `_build_step_feedback()` to use diagnostics
  - Remove `_capture_dispatch_diff()` (or keep for prompt save only)
