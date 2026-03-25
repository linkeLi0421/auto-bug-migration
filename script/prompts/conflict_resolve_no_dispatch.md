# Conflict Resolution without Dispatch

Resolve merge conflicts by manually adapting the patch.

## Prompt

I am merging multiple bug transplant patches into project {project}.

The following bugs have already been applied successfully: {applied_list}

I need to apply the patch at /tmp/{diff_name} for bug {bug_id}, but it
has merge conflicts with the current state of the code.

The conflicting previously-applied bug(s) and their patches:
{conflict_desc}

Since both patches are minimized (every hunk is necessary for its
bug), you MUST preserve the bug-triggering logic from BOTH patches.

IMPORTANT — Bug ownership markers:
The source code contains comment markers that identify which code
belongs to which previously-applied bug:

    //BUG_START OSV-XXXX
    ... code for that bug ...
    //BUG_END OSV-XXXX

You MUST NOT modify, move, or wrap code between these markers.
That code belongs to a previous bug and must stay exactly as-is.
Only add NEW code for bug {bug_id} outside these marked regions.

Please:
1. Read the patch file /tmp/{diff_name} to understand what changes it makes
2. Look at the current state of the conflicting files in /src/{project}
3. Manually apply the changes from the patch, adapting them to work with
   the code as it currently is (including changes from previously applied bugs)
4. Make sure the changes preserve the bug-triggering logic from the patch
5. Do NOT revert changes from previously applied bugs
6. Wrap your new code with markers:
   //BUG_START {bug_id}
   ... your new code ...
   //BUG_END {bug_id}

After making changes, run: sudo -E compile
If there are build errors, fix them.
