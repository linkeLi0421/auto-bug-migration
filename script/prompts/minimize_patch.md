# Patch Minimization

You are inside an OSS-Fuzz Docker container for project **{project}**.

## Goal

Bug **{bug_id}** triggers with the current diff applied. Your job is to
remove unnecessary changes until only the minimal set remains **while still
triggering the same bug**, not just *any* sanitizer crash.

The unminimized diff: `git diff` (already applied in `{source_dir}`)
Testcase: `/work/{testcase_name}` (may have been modified from original)
Reference crash log: `/data/crash/target_crash-{buggy_short}-{testcase_name}.txt`

## Equivalence oracle (read this carefully)

A revert is only safe if the resulting crash is **the same bug** as the
reference. Use the helper script after every revert:

```bash
/out/{fuzzer_name} /work/{testcase_name} > /tmp/last_run.txt 2>&1
python3 /script/check_crash_match.py \
    /data/crash/target_crash-{buggy_short}-{testcase_name}.txt \
    /tmp/last_run.txt
echo "exit=$?"
```

Interpret the exit code:

- **0 (PASS)** — candidate has a sanitizer SUMMARY *and* its project-code
  stack overlaps the reference (shared function or source file). The revert
  is safe; keep it.
- **0 (PASS with class drift)** — same project stack, different sanitizer
  class (e.g. `heap-buffer-overflow` ↔ `undefined-behavior`). Same code site
  caught by different instrumentation; still safe to keep the revert.
- **1 (FAIL)** — either no sanitizer crash, or a sanitizer crash whose
  stack does **not** overlap the reference. The change you just reverted
  was load-bearing for *the original bug*; re-apply it
  (`git checkout HEAD -- <file>`) even though the candidate "still crashes."

**This is the key rule.** A simpler patch that produces a different crash
(stack-overflow from new recursion, an out-of-bounds in a different
function, etc.) is NOT an acceptable minimization — it has replaced the
original bug with one of your own creation.

## Build commands

```bash
# IMPORTANT: always delete fuzzer binaries before compile to force re-link.
# Autotools/cmake may not re-link the fuzzer when only a library source changes.
find {source_dir} -name '{fuzzer_name}' -type f -executable -delete
rm -f /out/{fuzzer_name}
compile
```

## Method

1. Run `git diff --stat` to list all changed files.
2. Run the unminimized binary once and confirm `check_crash_match.py` exits 0
   (this validates the reference and your build flow before any revert).
3. **Per-file pass.** For each changed file, try reverting it whole:
   ```bash
   git checkout {target_commit} -- <file>
   find {source_dir} -name '{fuzzer_name}' -type f -executable -delete
   rm -f /out/{fuzzer_name}
   compile
   /out/{fuzzer_name} /work/{testcase_name} > /tmp/last_run.txt 2>&1
   python3 /script/check_crash_match.py \
       /data/crash/target_crash-{buggy_short}-{testcase_name}.txt \
       /tmp/last_run.txt
   ```
   - exit 0 → that file was unnecessary, keep it reverted.
   - exit 1 → re-apply: `git checkout HEAD -- <file>` and continue.
   - The build failed → re-apply: `git checkout HEAD -- <file>`.
4. **Per-hunk pass.** For files that are required, try reverting individual
   hunks the same way (use `git checkout -p` or split the hunk by hand).
   Same oracle: PASS keeps the revert, FAIL re-applies it.
5. **Final stability check.** Run the minimized binary 3 times and require
   `check_crash_match.py` exit 0 on **all three runs**. If only 2/3 pass,
   the crash you've left behind is flaky — re-apply something from the
   most recent revert and try a less aggressive reduction.
6. Save:
   ```bash
   cd {source_dir} && git diff > /out/bug_transplant.diff
   cp /work/{testcase_name} /out/{testcase_name}
   ```

## Rules

- NEVER build with make/gcc/cmake — only `compile`.
- ALWAYS delete the fuzzer binary before compile (`rm -f /out/{fuzzer_name}`)
  to force re-linking. The build system may have broken dependency tracking.
- Build and run `check_crash_match.py` after every revert. Do NOT trust
  "the testcase still crashes" — verify it crashes with the *same* bug.
- A revert that makes the binary crash with a *different* bug (e.g. you
  collapsed a multi-condition guard into a one-liner and the simpler form
  causes infinite recursion → stack-overflow) is a regression, not a
  minimization. Re-apply it.
- Do not spawn subagents.
- If the crash is flaky (PASSes 2/3 times), keep the change — do not
  remove it just because one run passed.
