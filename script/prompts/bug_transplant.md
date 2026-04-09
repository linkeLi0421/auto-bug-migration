# Bug Transplant Task

You are inside an OSS-Fuzz Docker container for project **{project}**.

**IMPORTANT: Start by reading AGENTS.md** (`{agents_md}`). It contains shared
knowledge from previous bug transplant sessions -- format changes, validation checks,
testcase patching recipes. Use it to avoid rediscovering things.

## Goal

Transplant bug **{bug_id}** from commit `{buggy_commit}` into commit `{target_commit}`.
The bug triggers at the old commit but not at the new one.

## Files

- `/data/crash/target_crash-{buggy_short}-{testcase_name}.txt` -- original crash log
- `/data/target_trace-{buggy_short}-{testcase_name}.txt` -- function trace from buggy commit{fix_diff_line}
- `/work/{testcase_name}` -- PoC testcase (you may modify this)
- `{source_dir}` -- source tree at `{target_commit}`
- `{agents_md}` -- shared knowledge (read first, update when done)

## Commands

```bash
# Build (the ONLY valid build command -- never use make/gcc/cmake)
# IMPORTANT: always delete the fuzzer binary before compile to force re-link.
# Autotools/cmake may not re-link the fuzzer when only a library source changes.
find {source_dir} -name '{fuzzer_name}' -type f -executable -delete
rm -f /out/{fuzzer_name}
compile

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

3. **Find what differs in the crash path.**{adjacent_commit_hint}
   Use the crash stack trace to identify the relevant functions. You can also get the diff
   between the two commits for specific files using:
   ```bash
   git diff {buggy_commit} {target_commit} -- <file>
   ```
   Look for added/removed validation checks, changed function signatures, or
   structural changes along the crash path.

4. **The difference may not be a single "fix" commit.** It could be incidental -- a refactor
   that added validation, a format change that makes the testcase unreachable, or new error
   handling. Focus on what concretely prevents the crash path from being reached on the target
   commit.

   If a fix-hint diff is available, treat it as a clue only. Do not assume it is the full fix
   or that reverting it is sufficient. You still need to inspect the surrounding target code,
   testcase reachability, and any unrelated validation or format changes that block the bug path.

5. **If the testcase doesn't exercise the vulnerable code path**, sometimes the fuzzer input
   format change between target commit and buggy commit. If the input header change, may try
   to update the input. And do not change other parts of the testcase too much. 

   Before concluding the path is unreachable, try to localize where execution stops on the target.
   Use minimal runtime instrumentation or temporary logging if needed to determine whether the PoC
   reaches header parsing, slice parsing, decode, concealment, display, or other relevant stages.

6. **Verify both directions**: the testcase must crash WITH your code change and NOT crash
   without it. The crash must be the same vulnerability -- but it does NOT need an identical
   stack trace. A crash is a valid match if ALL of these hold:
   - **Same sanitizer class** (e.g. both `AddressSanitizer: heap-buffer-overflow`)
   - **Same access direction** (both READ, or both WRITE)
   - **Same code area**: crash is in the same source file, or in a direct caller/callee
     within the same subsystem
   - **Overlapping call chain**: at least one function from the original stack appears
     anywhere in the new stack (not just the top frames -- check the full chain including
     callers and the allocating function)

   Code refactoring between commits can shift the exact crash point within the same
   vulnerable path. What matters is that the same underlying vulnerability is exercised,
   not that the crash is on the exact same line.

   Always test clean code against your testcase before saving:
   ```bash
   # Save your work
   git stash
   find {source_dir} -name '{fuzzer_name}' -type f -executable -delete
   rm -f /out/{fuzzer_name}
   compile && /out/{fuzzer_name} /work/{testcase_name}
   # Should NOT crash. Then restore:
   git stash pop
   find {source_dir} -name '{fuzzer_name}' -type f -executable -delete
   rm -f /out/{fuzzer_name}
   compile && /out/{fuzzer_name} /work/{testcase_name}
   # Should crash.
   ```

## Early exit if impossible

Use `IMPOSSIBLE` sparingly. It is for cases where you have concrete evidence that reproducing the
same bug would require changes outside the project-shipped code, or would require replacing the
PoC with a substantially different synthesized input rather than adapting the provided testcase.

Do NOT declare `IMPOSSIBLE` merely because:
- the fix-hint diff did not work
- one revert attempt failed
- the testcase is rejected before parsing without first investigating why
- the target needs testcase byte/header adjustments
- the blocking change appears to be a broader refactor inside project code

Before writing `IMPOSSIBLE`, confirm all of the following:
- you tested the original testcase on the unmodified target
- you inspected the relevant crash-path code and at least some surrounding diffs, not just the fix hint
- if the testcase is rejected early, you investigated whether minimal testcase adaptation can restore reachability
- you gathered concrete evidence for where execution stops on the target

If you determine the bug truly cannot be reintroduced under those constraints, write a specific one-line reason.
Make it concrete enough that someone can tell:
- where the original testcase stopped on the target
- what testcase/code adaptation you tried
- what final blocker remained after those attempts

Preferred pattern:

```text
IMPOSSIBLE: original PoC stops at <stage>; after trying <adaptation>, it reaches <later stage or same stage> but still fails to reproduce because <final blocker>.
```

```bash
echo "IMPOSSIBLE: <one-line reason>" > /out/bug_transplant.impossible
```

Only stop early when the evidence shows the root cause is genuinely outside any reasonable
project-code transplant or minimal testcase adaptation.

## Saving results

When the bug triggers, save BOTH the diff and the testcase:

```bash
cd {source_dir} && git diff > /out/bug_transplant.diff
cp /work/{testcase_name} /out/{testcase_name}
```

If you modified the testcase, the copy is essential -- the original is still in `/corpus/`.

## Update shared knowledge

After finishing (success or failure), update `{agents_md}` with any
discoveries about the **target commit** that would help future bug transplants:

- Target code structure (header layout, key structs, field offsets at the target commit)
- Validation checks in the target code (function name, file, what they check)
- Input format the target code expects (byte order, magic numbers, required fields)
- Build notes (quirks, workarounds)

Do NOT save information about the buggy commit or old-vs-new comparisons -- each bug
comes from a different buggy commit so those details are not reusable.
Only save what is true about the target commit's code.

## Rules

- NEVER build with make/gcc/cmake -- only `compile`.
- Build and test after every change.
