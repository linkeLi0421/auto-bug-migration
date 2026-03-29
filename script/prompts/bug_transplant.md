# Bug Transplant Task

You are inside an OSS-Fuzz Docker container for project **{project}**.

## Goal

Transplant bug **{bug_id}** from commit `{buggy_commit}` into commit `{target_commit}`.
The bug triggers at the old commit but not at the new one.

## Files

- `/data/crash/target_crash-{buggy_short}-{testcase_name}.txt` -- original crash log
- `/data/target_trace-{buggy_short}-{testcase_name}.txt` -- function trace from buggy commit
- `/work/{testcase_name}` -- PoC testcase (you may modify this)
- `/src/{project}` -- source tree at `{target_commit}`

## Commands

```bash
# Build (the ONLY valid build command -- never use make/gcc/cmake)
sudo -E compile

# Test
/out/{fuzzer_name} /work/{testcase_name}
```

## Methodology

1. **Start by testing the testcase on the target commit.** Build and run it. If it crashes
   differently or returns cleanly, that tells you what's blocking the original bug path.

2. **If the testcase fails to load or is rejected early**, the input format or parsing logic
   likely changed between commits. Check header/struct definitions, magic numbers, version
   checks, and field offsets. Fix this by rewriting the testcase binary (patch bytes to match
   the new format) rather than reverting format definitions -- this keeps code changes minimal.
   Use `xxd` or `printf` + `dd` to patch specific bytes in the testcase file.

3. **Diff the two commits to find what differs in the crash path.** Use the crash stack trace
   to identify the relevant functions, then:
   ```bash
   git diff {buggy_commit} {target_commit} -- <file>
   ```
   on those files. Look for added/removed validation checks, changed function signatures, or
   structural changes along the crash path.

4. **The difference may not be a single "fix" commit.** It could be incidental -- a refactor
   that added validation, a format change that makes the testcase unreachable, or new error
   handling. Focus on what concretely prevents the crash path from being reached on the target
   commit.

5. **If the testcase doesn't exercise the vulnerable code path**, modify the testcase binary
   to reach it. But be careful: if the modified testcase crashes on BOTH clean and modified
   code, your code change isn't the right one -- find the actual validation that distinguishes
   the two.

6. **Verify both directions**: the testcase must crash WITH your code change and NOT crash
   without it. Always test clean code against your testcase before saving:
   ```bash
   # Save your work
   git stash
   sudo -E compile && /out/{fuzzer_name} /work/{testcase_name}
   # Should NOT crash. Then restore:
   git stash pop
   sudo -E compile && /out/{fuzzer_name} /work/{testcase_name}
   # Should crash.
   ```

## Saving results

When the bug triggers, save BOTH the diff and the testcase:

```bash
cd /src/{project} && git diff > /out/bug_transplant.diff
cp /work/{testcase_name} /out/{testcase_name}
```

If you modified the testcase, the copy is essential -- the original is still in `/corpus/`.

## Rules

- NEVER build with make/gcc/cmake -- only `sudo -E compile`.
- Build and test after every change.
- Prefer modifying the testcase over reverting format/structural changes in code.
- Minimize code changes: only revert what directly blocks the crash path.
