# Bug Transplant Task

You are inside an OSS-Fuzz Docker container for project **{project}**.

## Objective

Bug **{bug_id}** is triggered at buggy commit `{buggy_commit}` using testcase
`/work/{testcase_name}`. The source at `/src/{project}` is currently at target
commit `{target_commit}`.

Your job: modify the current version's code so the **same bug** is triggered
by the same testcase.

## Available data

| File | Description |
|---|---|
| `/data/crash/target_crash-{buggy_short}-{testcase_name}.txt` | Crash stack from buggy commit |
| `/data/target_trace-{buggy_short}-{testcase_name}.txt` | Function trace + call relations from buggy commit |
| `/work/{testcase_name}` | PoC testcase (binary fuzzer input) |
| `/src/{project}` | Source code (at target commit `{target_commit}`) |

## Build and test commands

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

### Step 6: Minimize the patch (MANDATORY before delivering)
After getting the bug to trigger, minimize using single-change elimination:

1. Start with all N changes applied (bug triggers).
2. For each change i (from 1 to N):
   - Revert ONLY change i (keep all others).
   - Build and test:
     `sudo -E compile 2>&1 | tail -3 && /out/{fuzzer_name} /work/{testcase_name} 2>&1 | grep -E "SUMMARY|Executed|WARNING"`
   - If bug still triggers -> change i is **unnecessary**, remove it permanently.
   - If bug stops triggering -> change i is **required**, re-apply it.
3. Final verification: confirm the minimal set still triggers the bug.

Use `git stash` to save state and `git checkout -- <file>` to selectively
revert individual files during testing.

### Step 7: Save the result
```bash
cd /src/{project}
git diff > /out/bug_transplant.diff
```

Report which changes were required and why, which were eliminated and why.

## Common fix patterns to revert

| Fix Pattern | Revert Action |
|---|---|
| `memset(buffer, 0, size)` added | Remove the memset |
| `malloc` -> `calloc` | Change back to `malloc` |
| New bounds check: `if (x > limit) return FALSE` | Remove the check |
| Added `NULL` checks | May need to remove if they prevent reaching the bug |

## Rules
- Do NOT change the bug-triggering logic -- only revert fixes and remove blockers.
- Start MINIMAL: crash-stack functions only. Escalate to callees only if needed.
- Build and test after EVERY change -- do not batch.
- **ALWAYS use `sudo -E compile` to build.** NEVER build manually with make, gcc,
  clang, cmake, or any other command. NEVER create your own fuzz target binaries.
  Only test with `/out/{fuzzer_name}` produced by `sudo -E compile`. Manual builds
  produce different binaries and bugs that trigger with them may NOT trigger with
  the official build.
- Always minimize before delivering.
- Save final diff to `/out/bug_transplant.diff`.
