# Merge Dispatch-Wrapped Patches

You are inside an OSS-Fuzz Docker container for project **{project}**.
The source at `/src/{project}` is at commit `{target_commit}` with dispatch
infrastructure already set up (`__bug_dispatch.h`, `__bug_dispatch.c`,
the fuzz harness modified to read dispatch bytes, and
`__bug_dispatch.h` copied into the harness source directory).

## Task

Apply ALL of the following dispatch-wrapped patches to the source code.
Each patch was independently created on a clean source tree, so they may
have textual conflicts where multiple patches modify the same file.

Your job is to merge them all into one coherent codebase where:
- Every patch's changes are present
- Dispatch if/else blocks from different patches coexist (they use different bits)
- `#include "__bug_dispatch.h"` appears once per file (not duplicated)
- The code compiles with `sudo -E compile`

## Patches

{patch_list}

## Rules

- Read each patch file carefully before applying
- Apply patches one at a time, resolving conflicts as you go
- When two patches modify the same line, keep BOTH dispatch branches
  (they use different bits so they don't interfere)
- If a patch adds `#include "__bug_dispatch.h"` and it already exists, skip the duplicate
- Build after applying all patches: `sudo -E compile`
- If build fails, fix the errors (usually missing includes or duplicate definitions)
- Do NOT modify the dispatch logic — keep the exact if/else conditions from each patch
