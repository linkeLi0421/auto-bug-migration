# Merge Dispatch-Wrapped Patches

You are inside an OSS-Fuzz Docker container for project **{project}**.
The source at `{source_dir}` is at commit `{target_commit}` with dispatch
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
- The code compiles with `compile`

## Patches

{patch_list}

## Rules

- Read each patch file carefully before applying
- Apply patches one at a time, resolving conflicts as you go
- When two patches modify the same line, keep BOTH dispatch branches
  (they use different bits so they don't interfere)
- If a patch adds `#include "__bug_dispatch.h"` and it already exists, skip the duplicate
- Build after applying all patches: `compile`
- If build fails, fix the errors (usually missing includes or duplicate definitions)
- Do NOT modify the dispatch logic — keep the exact if/else conditions from each patch

## CRITICAL — use mechanical `git apply` for every patch

Each patch is a unified diff whose hunk headers already encode the
exact anchor:

    @@ -<old_line>,<n> +<new_line>,<m> @@ <function_signature>

Do **not** re-locate a hunk by searching for similar-looking code.
Large codebases contain several functions with nearly duplicate
snippets (for example in libredwg, `dxf_tables_read` and
`dxf_blocks_read` both contain
`free(dxfname); if (idx != dwg->num_objects) obj->dxfname = NULL;
 return DWG_ERR_INVALIDDWG;`). Choosing the wrong copy silently breaks
the bug: the dispatch bit is wired, the build passes, but the crash
path is never gated.

For each `wrapped_<bug>.diff` in `{patch_list}`, apply it mechanically:

    cd {source_dir}
    git apply --3way --whitespace=nowarn /tmp/wrapped_<bug>.diff

`git apply --3way` honors the hunk's line number, context, and the
`index <sha>..<sha>` pre-image blob recorded in the diff. It will not
misroute a hunk across function boundaries even when the earlier
patches have shifted line numbers around the anchor.

If `git apply --3way` succeeds with no conflict markers, move on — do
**not** "improve" the result, do **not** re-factor, do **not** inline
helpers. The wrap is already correct; any rewrite is a chance to lose
it.

If `git apply --3way` reports a real conflict (overlapping edits with a
previously applied patch), resolve *only* the `<<<<<<<` / `=======` /
`>>>>>>>` markers it produced:
- Keep BOTH dispatch branches (they use different bits).
- Do not move code out of the conflict region.
- Do not rename / extract helpers to "clean up."

Only after every patch is in via `git apply --3way` (or
conflict-resolved in place), run `compile`. If build fails, fix the
minimum necessary — usually a missing include or duplicate
definition — without touching dispatch gates.
