# Self-Trigger Dispatch

Unblock a bug whose testcase is blocked by previously-applied patches.

## Prompt

I am merging multiple bug transplant patches into project {project}.

Bug {bug_id}'s patch has been applied, but the bug does NOT trigger
— the fuzzer exits cleanly (exit=0, no crash). The patch works when
applied alone, so previously-applied patches are blocking the
testcase from reaching the crash site.

The crash log showing what this bug SHOULD produce:
  {crash_line}

Bug {bug_id}'s minimized patch:
  /tmp/patch_{bug_id}.diff

Previously-applied patches:
{prev_list}

I need you to wrap the blocking changes in dispatch branches.

Step 1: Read {bug_id}'s patch to understand what functions and code
        paths the bug needs to reach.

Step 2: Run `cd /src/{project} && git diff` to see ALL currently
        applied changes in the source.

Step 3: For every change in the git diff that is in a function or
        code path that {bug_id}'s testcase needs to traverse (based
        on the crash log and {bug_id}'s patch), wrap it in a
        dispatch branch. This includes BOTH additions AND deletions
        from previous patches:

    #include "__bug_dispatch.h"

    For added/modified lines from previous patches:
    if (__bug_dispatch & (1 << {dispatch_bit})) {{
        // Original code (before any patches — what {bug_id} needs)
    }} else {{
        // Currently-applied change (needed by previous bugs)
    }}

    For lines that previous patches DELETED (visible as "-" lines
    in git diff or the patch files) — these lines no longer exist
    in the source but {bug_id} may need them. Re-add them inside
    a dispatch branch:
    if (__bug_dispatch & (1 << {dispatch_bit})) {{
        // Restore deleted lines (what {bug_id} needs)
        <re-add the deleted lines here>
    }}

The header is at /src/{project}/__bug_dispatch.h.

Rules:
- When in doubt, WRAP the change. An unnecessary dispatch branch
  is harmless; a missing one means the bug won't trigger.
- Check the previously-applied patch files to understand which
  changes came from which bug.
- If a previous patch has multiple hunks in the same file, wrap
  ALL of them — do not skip any.
- Deletions matter! If a previous patch removed a bounds check,
  a return statement, or any other code, and {bug_id}'s crash
  path needs that code, restore it inside a dispatch branch.
- SKIP dispatch for compile-time constructs that cannot be wrapped
  in runtime if/else: #define, #undef, #include, struct/union/enum
  definitions, global variable declarations, function signature
  changes. Leave these as-is.

After making changes, run: sudo -E compile
If there are build errors, fix them.
