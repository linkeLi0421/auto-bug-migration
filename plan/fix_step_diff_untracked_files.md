# Fix step diffs to include untracked source files

## Problem

Multiple places use `git diff` to capture source state, but `git diff`
only includes **tracked** files. When a transplant patch creates a new
file (e.g. `blosc/zfp-getcell.c` from OSV-2022-511), `git apply`
creates it as an untracked file and `git diff` silently omits it.

This breaks three things:
1. **Step diffs** — `_save_step_diff()` produces incomplete snapshots.
   Resume via `--start-step` fails because the new file is missing.
2. **Combined diff** — the final `combined.diff` export (line ~2244)
   also uses `git diff`, so the deliverable is incomplete too.
3. **Source snapshot** — `_save_source_snapshot()` works around this
   with a separate tar of untracked files, but that's a parallel
   mechanism that doesn't help step diffs or combined diff.

## Root cause

`git diff` ignores untracked files. The separate tar sidecar in
`_save_source_snapshot` is a workaround that only helps rollback.

## Fix: `git add -N` before every `git diff`

`git add --intent-to-add` (or `-N`) marks untracked files in the
index without staging their content. After that, `git diff` shows
them as new files (full content as additions). This fixes all three
use sites with one consistent pattern — no tar sidecar needed.

### Helper function

```python
def _stage_untracked_source(container: str, project: str) -> None:
    """Mark untracked source files as intent-to-add so git diff includes them."""
    _exec_capture(
        container,
        f"cd /src/{project} && "
        f"git ls-files --others --exclude-standard "
        f"'*.c' '*.h' '*.cc' '*.cpp' '*.cxx' '*.hpp' '*.hh' '*.hxx' "
        f"| xargs -r git add -N",
    )
```

### Call sites

1. **`_save_step_diff()`** — call `_stage_untracked_source()` before
   `git diff`. The saved step diff will now include new file content.

2. **Combined diff export** (line ~2244) — call
   `_stage_untracked_source()` before `git diff -- {file_args}`.
   `combined.diff` will now include new files.

3. **`_save_source_snapshot()`** — call `_stage_untracked_source()`
   before `git diff > /tmp/_snap.diff`. This replaces the separate
   tar mechanism. The snapshot diff alone is now sufficient for
   rollback; the tar of untracked files can be removed.

4. **`_revert_and_rebuild()`** — the `git checkout -- .` +
   `git apply /tmp/_snap.diff` path now works for new files too,
   because the snapshot diff includes them. Remove the
   `tar xf /tmp/_snap_untracked.tar` step.

5. **Resume path** — `git apply /tmp/_resume.diff` on a step diff
   that includes new files just works. No tar sidecar needed.

### Why this is safe

- `git add -N` does NOT stage file content. `git status` shows the
  files as "new file" with unstaged changes. `git diff` shows them
  as full additions. `git checkout -- .` removes them (restores to
  the empty intent-to-add state, then they can be cleaned).
- After `git checkout -- .`, intent-to-add entries leave empty files.
  `git apply` of the snapshot diff overwrites them with correct
  content. Files not in the diff get cleaned by the checkout.
- `git apply` of a diff that creates a new file (`--- /dev/null`)
  works correctly whether or not the file already exists as an
  empty intent-to-add placeholder.

### One caveat

After `git checkout -- .`, intent-to-add files remain as empty
tracked entries. Need to run `git reset` after checkout to clear
them before applying the snapshot diff. Updated revert sequence:

```python
_exec_capture(container, f"cd /src/{project} && git checkout -- . 2>&1")
_exec_capture(container, f"cd /src/{project} && git reset 2>&1")
_exec_capture(container, f"cd /src/{project} && git clean -fd 2>&1")
_exec_capture(container, f"cd /src/{project} && git apply --allow-empty /tmp/_snap.diff 2>&1")
```

`git reset` unstages the intent-to-add entries. `git clean -fd`
removes any leftover untracked files. Then `git apply` creates
only the files that belong in the snapshot.

## Files changed

- `script/bug_transplant_merge.py`:
  - Add `_stage_untracked_source()` helper
  - `_save_step_diff()` — call helper before `git diff`
  - `_save_source_snapshot()` — call helper before `git diff`,
    remove the tar mechanism
  - `_revert_and_rebuild()` — add `git reset` + `git clean -fd`
    after `git checkout -- .`, remove tar restore
  - Combined diff export — call helper before `git diff`
