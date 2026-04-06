# Bug Transplant Task

You are inside an OSS-Fuzz Docker container for project **{project}**.

## Goal

Bug **{bug_id}** reproduced at old commit `{buggy_commit}`.
The source in `/src/{project}` is now at newer commit `{target_commit}`, where the bug has been fixed.

Your task is to make the old testcase at `/work/{testcase_name}` crash again in the current tree by undoing the fix or any added guard that prevents the testcase from reaching the bug.

Target result (a crash is valid if ALL hold):
- same sanitizer class as the original crash (e.g. both heap-buffer-overflow)
- same access direction (both READ, or both WRITE)
- same code area (same source file, or direct caller/callee in same subsystem)
- at least one function from the original stack appears anywhere in the new stack
  (check the full chain including callers and the allocating function, not just top frames)

## Files

- `/data/crash/target_crash-{buggy_short}-{testcase_name}.txt` — original crash log
- `/data/target_trace-{buggy_short}-{testcase_name}.txt` — trace/call path from buggy commit
- `/work/{testcase_name}` — PoC input
- `/src/{project}` — current fixed source tree

## Allowed commands

```bash
# Build the project (inside container)
sudo -E compile

# Run the fuzzer with PoC to check if bug triggers
/out/{fuzzer_name} /work/{testcase_name}

# Quick build-and-test one-liner
sudo -E compile 2>&1 | tail -5 && /out/{fuzzer_name} /work/{testcase_name} 2>&1 | grep -E "SUMMARY|ERROR|Executed|WARNING"
```

## Methodology (follow this exactly)

### Step 1: Understand the bug
- Read the crash stack file to identify: crash type (e.g. heap-buffer-overflow,
  use-of-uninitialized-value), the crashing function, and the full call chain.
- Note the testcase file path (it's binary fuzzer input).

### Step 2: Identify what changed
- `git log --oneline {buggy_commit}..{target_commit} --reverse -- <affected_files>`
  to find commits that changed relevant files.
- `git diff {buggy_commit} {target_commit} -- <file>` for each file in the crash
  trace to see ALL changes.
- Read the function trace to understand the execution path and call graph.

### Step 3: Categorize changes (THIS IS THE KEY STEP)
Changes between buggy and current versions fall into three categories:

| Category | Action | Example |
|---|---|---|
| **A) Direct bug fixes** | **REVERT** | `malloc` -> `calloc`, added `memset`, added bounds check |
| **B) New validation/safety checks** | **REMOVE** | Input validation that rejects testcase before reaching bug |
| **C) Refactoring/unrelated** | **LEAVE ALONE** | API renames, code reorganization, threading support |

**Category B is the most commonly missed** -- new input validation added after
the buggy commit that rejects the testcase before it reaches the vulnerable
code path.

### Step 4: Apply changes iteratively
- Start with the most obvious fix revert (e.g. removing `memset`, reverting
  `calloc` -> `malloc`).
- Build and test after EACH change.
- If the crash doesn't reproduce, look for NEW VALIDATION CHECKS added after
  the buggy commit that reject the input before reaching the vulnerable code.

### Step 5: Verify bug triggers
- Run `/out/{fuzzer_name} /work/{testcase_name}`.
- Compare output with the original crash: same crash type, same crashing
  function, same call chain pattern.

Use `git stash` to save state and `git checkout -- <file>` to selectively
revert individual files during testing.

### Step 7: Save the result
```bash
cd /src/{project}
git diff > /out/bug_transplant.diff
```

## Rules

- NEVER build with make/gcc/cmake — only `sudo -E compile`.
- Build and test after every change.
