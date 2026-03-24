# CLAUDE.md -- Bug Transplant Container

You are inside an OSS-Fuzz Docker container. Your task is to transplant a bug
from an old commit into the current version of the code.

## Environment

- **Source code**: `/src/<project>/` (git repo at target commit)
- **Build command**: `sudo -E compile` (builds the project with sanitizers)
- **Fuzzer binaries**: `/out/<fuzzer_name>` (after successful build)
- **Testcase**: `/work/<testcase_name>` (binary PoC input)
- **Crash data**: `/data/crash/` (crash stack from buggy commit)
- **Trace data**: `/data/` (function traces from buggy commit)
- **Output**: Save final diff to `/out/bug_transplant.diff`

## Key commands

```bash
# Build
sudo -E compile

# Test if bug triggers
/out/<fuzzer_name> /work/<testcase_name>

# Quick check
sudo -E compile 2>&1 | tail -5 && /out/<fuzzer_name> /work/<testcase_name> 2>&1 | grep -E "SUMMARY|ERROR|Executed"

# See what changed between commits
git diff <buggy_commit> <target_commit> -- <file>
git log --oneline <buggy_commit>..<target_commit> -- <file>

# Save result
git diff > /out/bug_transplant.diff
```

## Rules

1. **Categorize before reverting**: Every change between buggy and current is either
   (A) a direct bug fix, (B) a new validation check blocking the testcase, or
   (C) unrelated refactoring. Only revert A and B.

2. **Build after every change**: Never batch multiple changes without testing.

3. **ALWAYS use `sudo -E compile` to build**: NEVER build manually with make, gcc,
   clang, or cmake. The only valid build command is `sudo -E compile`. NEVER
   create your own build commands or compile fuzz targets by hand. The official
   build produces different binaries than manual builds — a bug that triggers
   with a hand-built binary may NOT trigger with the official build. Test with
   `/out/<fuzzer_name>`, never with binaries you built yourself.

4. **Look for validation checks**: If the obvious revert doesn't trigger the bug,
   look for NEW input validation added after the buggy commit. This is the most
   commonly missed category.

5. **Minimize**: After the bug triggers, do single-change elimination to find the
   minimal diff. Use `git stash` and `git checkout -- <file>` to test each change.

6. **Preserve current API**: Do not blindly copy old function bodies. Only revert
   the specific lines that fixed the bug or block the testcase.

7. **Save diff**: Always `git diff > /out/bug_transplant.diff` at the end.
