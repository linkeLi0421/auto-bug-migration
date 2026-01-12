# Auto-loop: preserve per-iteration artifacts (no overwrites)

## Problem
In multi-agent/patch-scope runs with `--auto-ossfuzz-loop`, each new loop iteration overwrites prior artifacts inside the patch_key directory (e.g.:
`make_error_patch_override_patch_text_*.diff`, `ossfuzz_apply_patch_and_test_*_output.log`, and `ossfuzz_merged_*.diff`).

This makes debugging hard and also breaks the meaning of older `step_history` entries (their `artifact_path` can end up pointing at a file whose contents are from a later loop).

## Goal
Keep *every* iteration’s patch + OSS-Fuzz logs + merged patch diff so older steps remain reproducible:
- Each loop iteration produces new artifact files (no overwrite).
- Earlier `steps`/`step_history` artifact refs still exist and match what the agent saw at that time.
- The latest artifacts are still easy to find (optional: keep a stable “latest” copy/symlink).

## Plan
- [x] Reproduce and enumerate exactly which files get overwritten in a real auto-loop run (patch_text, build/check logs, merged patch, etc.).
- [x] Choose preservation strategy (and document the choice in-code):
  - [x] Option A: stop using `overwrite=True` for patch_key artifact stores (or only when `--auto-ossfuzz-loop` is enabled) so `ArtifactStore` auto-allocates `*.1`, `*.2`, … instead of unlinking.
  - [ ] Option B: write artifacts under per-loop subdirectories like `<patch_key>/loop_001/…` and optionally maintain `<patch_key>/latest/…` pointing at the newest.
- [x] Preserve offloaded tool outputs (build/check logs + override patch_text):
  - [x] Make `offload_patch_output()` write unique filenames per tool call (via disabling overwrite, or by adding a per-call suffix such as `loop_{ossfuzz_runs_attempted}` / `step_{n}`).
  - [x] Ensure `state.patch_override_paths[-1]` always points at the *new* patch_text artifact for the current loop.
- [x] Preserve merged patch output (`ossfuzz_merged_*.diff`) inside `merge_patch_bundle_with_overrides()` (avoid unlinking + reuse; allocate unique name per loop or when the destination exists).
- [x] Keep patch_key inference working for override artifacts (must remain somewhere under `<multi_run_root>/<patch_key>/...`).
- [x] Add regression coverage:
  - [x] Auto-loop scenario that triggers multiple `make_error_patch_override` + `ossfuzz_apply_patch_and_test` calls.
  - [x] Assert multiple versions of `make_error_patch_override_patch_text_*.diff` and `ossfuzz_apply_patch_and_test_*_output.log` exist after the run.
  - [x] Assert older step entries’ `artifact_path` files still exist and differ across iterations.
- [x] Update docs briefly (how to locate per-loop artifacts; how many are retained; any new flag/env var).

---

# get_error_patch_context: excerpt flags + full-hunk retrieval for tail/merged patches

## Problem
In some tail/merged-function hunks (example: `tail-parser.c-xmlParse3986DecOctet_`), `get_error_patch_context` returns an excerpt diff whose hunk header still shows the original length (e.g. `@@ -15487,1389 +15487,3 @@`), but the excerpt file contains only a subset of the hunk. The tool output currently reports `excerpt_truncated=false`, which is confusing because the excerpt clearly does not contain the full hunk.

## Why This Happens (Root Cause)
- `get_error_patch_context` is designed to return a *small excerpt* around the mapped slice (`func_start_index`/`func_end_index`) plus `context_lines`, not the full patch/hunk.
- `excerpt_truncated` currently only means “was the computed excerpt window clipped by `max_total_lines`”, not “does the excerpt include the full hunk/patch”.
- The tool caps `context_lines` (≤100) and `max_total_lines` (≤500), so even very large CLI requests (e.g. `context_lines=200`, `max_total_lines=4000`) will not return the full 1000+ line hunk.
- The excerpt preserves the original unified-diff hunk header (from the full patch), so the header line counts don’t match the excerpt length (the excerpt is not intended to be an applyable diff).

## Plan
- [x] Update `get_error_patch_context` to always return the *entire* unified-diff hunk that contains the mapped slice (not a windowed excerpt), regardless of hunk size:
  - [x] Compute the hunk boundaries in `patch.patch_text` (from the `diff --git` header line to the next `@@`/`diff --git`/EOF) and return that full span.
  - [x] Include the file-level diff header (`diff --git`/`---`/`+++`) so the excerpt is applyable on its own.
  - [x] Keep writing it to artifacts (so the JSON stays small); ensure it’s safe to read back with `read_artifact`.
  - [x] Remove/relax the hard caps (`context_lines<=100`, `max_total_lines<=500`) for this tool, since hunk size should not force partial output.
  - [x] Keep `patch_text_lines_total` for the full patch, and add explicit `hunk_lines_total` + `hunk_line_range` to avoid ambiguity.
- [x] Clarify tool semantics in output:
  - [x] Keep `excerpt_truncated` for back-compat, but redefine it to mean “returned hunk text was truncated by a safety limit” (should be `false` for normal tail hunks).
  - [x] Add `excerpt_note` stating “excerpt is a full hunk” and that hunk headers match returned content.
- [ ] Update the agent’s prompt/heuristics for tail/merged patches to request full patch text when “helper function duplication” triage is required.
- [x] Add regression coverage using a tail/merged-function fixture:
  - [x] Assert `get_error_patch_context` returns the entire hunk for a 1000+ line tail patch (no partial excerpt).
  - [x] Assert the returned hunk header counts match the returned hunk body length (or at least that the excerpt includes all `-` lines for the hunk).

---

# get_error_v1_code_slice: unbounded output + excerpt-only extraction

## Problem
- `get_error_v1_code_slice` output is currently truncated because the tool runner supplies default `max_lines`/`max_chars` even when the underlying implementation supports “0 = unlimited”.
- The agent calls `get_error_v1_code_slice` using `patch_path/file_path/line_number` (and not the `get_error_patch_context.excerpt` artifact), which can produce confusing/“random” slices for tail/merged-function hunks.

## Goal
- Make `get_error_v1_code_slice` deterministic and simple: read the unified-diff excerpt artifact from `get_error_patch_context`, extract only the V1-origin `-` lines, and return that as `func_code`.
- Eliminate silent truncation knobs (`max_lines`/`max_chars`) from the tool surface across the project; rely on artifacts + `read_artifact` for bounded inspection instead.

## Plan
- [x] Update agent flow to feed the excerpt artifact into `get_error_v1_code_slice`:
  - [x] In `_next_patch_prereq_tool`, after `get_error_patch_context`, locate the last `get_error_patch_context.excerpt.artifact_path` and call `get_error_v1_code_slice(excerpt={artifact_path: ...})`.
  - [x] Stop passing `patch_path/file_path/line_number` + `max_lines/max_chars` in that prereq tool call (keep `patch_path` only if needed for metadata).
  - [x] Keep auto-loop behavior unchanged: if `loop_base_func_code_artifact_path` exists, do not call either `get_error_patch_context` or `get_error_v1_code_slice`.
- [x] Simplify `get_error_v1_code_slice` implementation/contract:
  - [x] Make `excerpt` required (or strongly preferred) and clearly mark the legacy `patch_path/file_path/line_number` path as deprecated (with an explicit `note`/`warning` field).
  - [x] Extract V1-origin code by parsing the excerpt diff and collecting only hunk-body `-...` lines (excluding `---` file headers and `\\ No newline...` markers).
  - [x] Keep macro-token analysis (`defined_macros`, `macro_tokens_not_defined_in_slice`) based on the extracted `-` lines.
