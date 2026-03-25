# Conflict Resolution with Dispatch Branches

Resolve merge conflicts by dispatching the ENTIRE patch.

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

You may wrap a marked region inside a dispatch else-branch to
preserve it for that bug's testcase, but you MUST NOT modify
the code between the markers.

Strategy — dispatch the ENTIRE patch:
1. Read the patch file /tmp/{diff_name} to see ALL hunks.
2. Wrap EVERY hunk in a dispatch branch — not just the
   conflicting ones. When any part of a patch conflicts,
   the entire patch must be dispatched for consistency.

   #include "__bug_dispatch.h"

   For hunks that ADD and/or MODIFY lines:
   if (__bug_dispatch & (1 << {dispatch_bit})) {{
       // {bug_id}'s version (the "+" lines from the patch)
   }} else {{
       // Original code (the "-" lines or current code)
   }}

   For hunks that only DELETE lines — the deletion must also
   be conditional. Do NOT just delete the lines. Instead:
   if (__bug_dispatch & (1 << {dispatch_bit})) {{
       // Empty — lines removed by {bug_id}'s patch
   }} else {{
       // Original lines preserved for other bugs
       <the deleted lines go here>
   }}

   The header is at /src/{project}/__bug_dispatch.h.

3. When in doubt, use a dispatch branch. An unnecessary branch
   is harmless; a missing one loses a bug.
4. SKIP dispatch for changes that cannot be runtime-conditional:
   - #define / #undef / #include preprocessor directives
   - struct/union/enum type definitions
   - global variable declarations or type changes
   - function signature changes (return type, parameters)
   These are compile-time constructs — wrapping them in
   if/else would not compile. Leave them as-is (apply
   directly from the patch or keep the existing version).
5. After adding your code, wrap it with markers:
   //BUG_START {bug_id}
   ... your new code ...
   //BUG_END {bug_id}

After making changes, run: sudo -E compile
If there are build errors, fix them.

At the VERY END of your output, write exactly one of these tokens
on its own line:
  DISPATCH_USED   — if you created any dispatch branches
  NO_DISPATCH     — if you applied all changes without branching
