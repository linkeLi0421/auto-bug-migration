# Self-Trigger Unblock

Unblock a bug whose testcase is blocked by previously-applied patches.

## Prompt

I am merging multiple bug transplant patches into project {project}.

Bug {bug_id}'s patch has been applied, but the bug does NOT trigger
— the fuzzer exits cleanly (exit=0, no crash). The patch works when
applied alone, so previously-applied patches are blocking the
testcase from reaching the crash site.

The crash log showing what this bug SHOULD produce:
  {crash_line}

Bug {bug_id}'s original minimized patch (what works in isolation):
  /tmp/patch_{bug_id}.diff

Previously-applied patches:
{prev_list}

Your goal: make {bug_id}'s testcase trigger the crash shown above,
without breaking any previously-applied bugs.

Step 1: Read {bug_id}'s patch to understand ALL changes it needs
        — struct/type definitions, macro definitions, code changes
        in every function it touches.

Step 2: Run `cd /src/{project} && git diff` to see the current
        state of the source (all previously-applied patches).

Step 3: Compare the patch against the current state. Identify:
        a) Parts of {bug_id}'s patch that are MISSING from the
           current code (e.g. struct field additions, changes in
           functions that no previous patch touched). Apply these
           directly — they don't conflict with anything.
        b) Places where a previous patch changed code that
           {bug_id}'s testcase needs to traverse, blocking it
           from reaching the crash site.

Step 4: For blocking changes found in (b), you have a runtime
        dispatch mechanism available. It lets the fuzzer select
        different code paths per-bug via a byte in the test input:

    #include "__bug_dispatch.h"
    if (__bug_dispatch & (1 << {dispatch_bit})) {{
        // Code path that {bug_id} needs
    }} else {{
        // Currently-applied code (needed by previous bugs)
    }}

    The header is at /src/{project}/__bug_dispatch.h.

    Use dispatch ONLY where a previous patch's change actually
    blocks {bug_id}'s testcase. Do NOT dispatch struct/type
    definitions, macros, or other compile-time constructs — apply
    those directly.

After making changes, run: sudo -E compile
If there are build errors, fix them.
