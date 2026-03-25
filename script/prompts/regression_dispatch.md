# Regression Dispatch

Wrap a newly-applied patch in dispatch branches to fix regressions.

## Prompt

I am merging multiple bug transplant patches into project {project}.

After applying the patch for bug {bug_id}, these previously-working
bugs stopped triggering: {regressed_ids}

I need you to wrap ALL code changes from {bug_id}'s patch in
dispatch branches so both sides can coexist in the same binary.

The patch for {bug_id}: /tmp/patch_{bug_id}.diff

For EVERY change this patch makes — additions, modifications,
AND deletions — wrap it in a dispatch branch:

    #include "__bug_dispatch.h"

    For added/modified lines:
    if (__bug_dispatch & (1 << {dispatch_bit})) {{
        // {bug_id}'s version of the code (from the patch)
    }} else {{
        // Original code (before the patch, needed by regressed bugs)
    }}

    For deleted lines — do NOT just leave them deleted:
    if (__bug_dispatch & (1 << {dispatch_bit})) {{
        // Empty — lines removed by {bug_id}'s patch
    }} else {{
        // Original lines restored (needed by regressed bugs)
        <put the deleted lines here>
    }}

The header is at /src/{project}/__bug_dispatch.h.

IMPORTANT — Bug ownership markers:
The source code contains comment markers that identify which code
belongs to which previously-applied bug:

    //BUG_START OSV-XXXX
    ... code for that bug ...
    //BUG_END OSV-XXXX

You may wrap a marked region inside a dispatch else-branch to
preserve it, but you MUST NOT modify the code between the markers.

Rules:
- Read the patch file to see ALL hunks
- For each hunk, find where it was applied in the current source
- Wrap ALL changes in dispatch branches (additions AND deletions)
- The else branch must contain the ORIGINAL code (before {bug_id}'s
  changes), not the current code
- If a hunk moves code (removes from one place, adds to another),
  BOTH the removal site and the addition site need dispatch branches
- Do NOT skip any hunk — wrap them ALL
- An unnecessary dispatch branch is harmless; a missing one loses
  a bug
- SKIP dispatch for compile-time constructs that cannot be wrapped
  in runtime if/else: #define, #undef, #include, struct/union/enum
  definitions, global variable declarations, function signature
  changes. Leave these as-is.

After making changes, run: sudo -E compile
If there are build errors, fix them.
