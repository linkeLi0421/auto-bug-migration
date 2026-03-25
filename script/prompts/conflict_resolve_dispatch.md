# Conflict Resolution with Dispatch Branches

Resolve merge conflicts by adding the smallest dispatch needed.

## Prompt

I am merging multiple bug transplant patches into project {project}.

The following bugs have already been applied successfully: {applied_list}

I need to apply the patch at /tmp/{diff_name} for bug {bug_id}, but it
has merge conflicts with the current state of the code.

The conflicting previously-applied bug(s) and their patches:
{conflict_desc}

Both patches are minimized (every hunk is necessary). You MUST
preserve the bug-triggering logic from BOTH patches.

IMPORTANT — Bug ownership markers:
The source code contains comment markers that identify which code
belongs to which previously-applied bug:

    //BUG_START OSV-XXXX
    ... code for that bug ...
    //BUG_END OSV-XXXX

You MUST NOT modify, move, or wrap code between these markers.
That code belongs to a previous bug and must stay exactly as-is.
Only add NEW code for bug {bug_id} outside these marked regions.
If {bug_id}'s patch needs to change the same lines as a marked
region, add {bug_id}'s version separately and use a dispatch
branch to select between them at runtime.

Strategy:
1. Read the patch file /tmp/{diff_name} to see ALL changes.
2. For each change, apply it to the current code. Where the new
   patch and existing code disagree on the same lines, wrap it
   in a dispatch branch:

   #include "__bug_dispatch.h"
   if (__bug_dispatch & (1 << {dispatch_bit})) {{
       // Code from bug {bug_id}'s patch
   }} else {{
       // Existing code (from previously-applied bugs)
   }}

   The header is at /src/{project}/__bug_dispatch.h.

3. If a hunk can be applied without conflicting with existing
   changes, apply it directly (no dispatch needed for that hunk).
4. Keep dispatch regions as small as possible. Do NOT dispatch
   unrelated hunks or whole files just for consistency.
5. Prefer one flat dispatch branch over nested dispatch branches.
   Do NOT put a new dispatch branch inside an existing one unless
   a second independent conflict is strictly necessary.
6. For deletions: if the deleted code is still needed by a
   previously-applied bug, preserve it in the else-branch;
   otherwise apply the deletion directly.
7. SKIP runtime dispatch for compile-time-only constructs such as
   #define/#undef/#include, type definitions, global declarations,
   and function signature changes. Apply those directly or keep
   the existing version.
8. After adding your code, wrap it with markers:
   //BUG_START {bug_id}
   ... your new code ...
   //BUG_END {bug_id}

After making changes, run: sudo -E compile
If there are build errors, fix them.

At the VERY END of your output, write exactly one of these tokens
on its own line:
  DISPATCH_USED   — if you created any dispatch branches
  NO_DISPATCH     — if you applied all changes without branching
