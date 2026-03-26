# Regression Dispatch

Wrap a newly-applied patch in dispatch branches to fix regressions.

## Prompt

I am merging multiple bug transplant patches into project {project}.

After applying the patch for bug {bug_id}, these previously-working
bugs stopped triggering: {regressed_ids}

I need you to wrap ALL code changes from {bug_id}'s patch in
dispatch branches so both sides can coexist in the same binary.

Available patches:
{patch_list}

For EVERY change this patch makes to the source code, wrap it:

    #include "__bug_dispatch.h"
    if (__bug_dispatch[{dispatch_byte}] & (1 << {dispatch_bit})) {{
        // {bug_id}'s version of the code (from the patch)
    }} else {{
        // Original code (before the patch, needed by regressed bugs)
    }}

The header is at /src/{project}/__bug_dispatch.h.

IMPORTANT — Bug ownership markers:
The source code contains comment markers that identify which code
belongs to which previously-applied bug:

    //BUG_START OSV-XXXX
    ... code for that bug ...
    //BUG_END OSV-XXXX

You MUST NOT modify, move, or wrap code between these markers.
That code belongs to a previous bug and must stay exactly as-is.
Only wrap code from {bug_id} (the newly-applied bug) in dispatch
branches. When wrapping, place dispatch branches OUTSIDE the
marked regions, never inside them.

Rules:
- Read the patch file to see ALL hunks
- For each hunk, find where it was applied in the current source
- Wrap the changed lines in a dispatch branch
- The else branch must contain the ORIGINAL code (before {bug_id}'s
  changes), not the current code
- If a hunk moves code (removes from one place, adds to another),
  BOTH the removal site and the addition site need dispatch branches
- Do NOT skip any hunk — wrap them ALL
- An unnecessary dispatch branch is harmless; a missing one loses
  a bug

After making changes, run: sudo -E compile
If there are build errors, fix them.
