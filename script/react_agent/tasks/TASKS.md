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
