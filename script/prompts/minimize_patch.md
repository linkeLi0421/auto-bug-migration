# Patch Minimization

You are inside an OSS-Fuzz Docker container for project **{project}**.

## Goal

Bug **{bug_id}** triggers with the current diff applied. Your job is to
remove unnecessary changes until only the minimal set remains.

The unminimized diff: `git diff` (already applied in `{source_dir}`)
Testcase: `/work/{testcase_name}` (may have been modified from original)
Crash log for reference: `/data/crash/target_crash-{buggy_short}-{testcase_name}.txt`

## Commands

```bash
# IMPORTANT: always delete fuzzer binaries before compile to force re-link.
# Autotools/cmake may not re-link the fuzzer when only a library source changes.
find {source_dir} -name '{fuzzer_name}' -type f -executable -delete
rm -f /out/{fuzzer_name}
compile
/out/{fuzzer_name} /work/{testcase_name}
```

## Method

1. Run `git diff --stat` to list all changed files.
2. For each file, try reverting it:
   `git checkout {target_commit} -- <file>`
   Then delete fuzzer binaries, build and test.
   - If the bug still triggers → that file was unnecessary, keep it reverted.
   - If the bug stops or build fails → re-apply: `git checkout HEAD -- <file>`
3. For files that are required, try minimizing within the file:
   look at each hunk and try reverting individual changes.
4. Run the final set 3 times to confirm the crash is stable.
5. Save:
   ```bash
   cd {source_dir} && git diff > /out/bug_transplant.diff
   cp /work/{testcase_name} /out/{testcase_name}
   ```

## Rules

- NEVER build with make/gcc/cmake — only `compile`.
- ALWAYS delete the fuzzer binary before compile (`rm -f /out/{fuzzer_name}`)
  to force re-linking. The build system may have broken dependency tracking.
- Build and test after every revert.
- Do not spawn subagents.
- If the crash is flaky (triggers 2/3 times), keep the change — do not
  remove it just because one run passed.
