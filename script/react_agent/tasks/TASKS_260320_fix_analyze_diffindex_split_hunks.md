# TASKS

## 2026-03-20: Fix analyze_diffindex splitting same-function changes into separate PatchInfo entries

**Bug:** `patch/OSV-2020-1006_0b99613e..._patches_round0.diff` fails to build with
`fuzzer.cc:157: error: unterminated conditional directive` pointing at an orphaned
`#ifdef __cplusplus`.

**Reproducer:** wavpack OSV-2020-1006, buggy commit `348ff60b`, target `0b99613e`.

### Root cause

`analyze_diffindex()` in `revert_patch_test.py:1479` processes the raw `git diff V1 V2`
output. For `fuzzing/fuzzer.cc`, the V1→V2 diff has a single git diff hunk covering the
`LLVMFuzzerTestOneInput` function signature change:

```
@@ -119,20 +119,26 @@        (approximate — one contiguous git hunk)
     raw_push_back_byte, ...
 };

-extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
-    static long long times_called, opens, seeks, samples_decoded, ...
 static long long debug_log_mask = -1;

 #ifdef __cplusplus
+extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
+#else
+int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
+#endif
+{
+    static long long times_called, opens, seeks, tag_writes, ...
+    int flags = ...
     WavpackRawContext raw_wv;
     WavpackContext *wpc;
     char error [80];
     int num_chans, bps, mode, qmode;
-#else                                     ← V1-only: removed in V2
-    ... (duplicate C declarations)        ← V1-only: removed in V2
-#endif                                    ← V1-only: removed in V2
     int32_t total_samples;
```

`analyze_diffindex` runs two passes on this hunk:

1. **V2 pass** (line 1533): Clips to V2 function extent via `extract_revert_patch(h, 125, 133, 'new')`.
   Only captures the `+` lines. Produces: `@@ -121,0 +125,8 @@` (zero old lines, 8 new lines).

2. **V1 pass** (line 1617): Clips to V1 function extent via `extract_revert_patch(h, 120, 127, 'old')`.
   Only captures the `-` lines. Produces: `@@ -120,2 +122,0 @@` (2 old lines, zero new lines).

3. **Merge check** (line 1689): Checks if V1 entry overlaps V2 entry. They DON'T overlap
   sufficiently (V2 entry has `old_end=121`, V1 entry has `old_start=120`; new ranges barely touch).
   Result: **two separate PatchInfo entries** for the same function change.

**Neither entry includes the context lines** (`#ifdef __cplusplus`, `#else`/`#endif`).
The context lines (including the `#else`/`#endif` removal at V1 ~131-133) are
stripped out because `extract_revert_patch` only captures lines within the clipped range.

Later, `patch_patcher` reconstructs a full hunk from these stripped entries. It re-reads
the V2 source to add context around the change lines. But the reconstructed hunk only extends
to the nearby context — it picks up `#ifdef __cplusplus` (V2 line 124) as trailing context
but does NOT reach V1's `#else`/`#endif` removal (V1 lines ~131-133), which falls in the
gap between the first and second fuzzer.cc PatchInfo entries.

After `patch -R` reverse-applies the round0 diff, the gap between hunks retains V2 content
(variable declarations without `#endif`), leaving `#ifdef __cplusplus` unmatched.

### Cached evidence

Raw `analyze_diffindex` output (cached at `data/diff/revert_patch_OSV-2020-1006_...`):
```
fuzzing/fuzzer.ccfuzzing/fuzzer.cc-120,2+122,0   ← V1 pass: only 2 removed lines
fuzzing/fuzzer.ccfuzzing/fuzzer.cc-121,0+125,8   ← V2 pass: only 8 added lines
fuzzing/fuzzer.ccfuzzing/fuzzer.cc-131,5+142,8   ← next hunk (gap: old lines 123-130)
```

Final `wavpack.patch2` (after `patch_patcher`):
```
fuzzing/fuzzer.ccfuzzing/fuzzer.cc-121,0+125,8   ← merged, but old_end=130, missing #endif
fuzzing/fuzzer.ccfuzzing/fuzzer.cc-131,5+142,8   ← gap between these two has the lost #endif
```

### The bug (two levels)

**Level 1 — `extract_revert_patch` strips all context:**
`extract_revert_patch(h, begin, end, 'new')` and `extract_revert_patch(h, begin, end, 'old')`
only emit lines where the target cursor is in `[begin, end]`. Context lines, `-` lines
(for 'new' mode), and `+` lines (for 'old' mode) outside this range are silently dropped.
This means the V1 `#else`/`#endif` removal (a `-` line at V1 ~131, which is within the
same git hunk) is dropped by the V2 pass, and the V2 `#ifdef __cplusplus`/`#else`/`#endif`
addition (a `+` line at V2 ~125-128) is dropped by the V1 pass.

**Level 2 — Merge fails for split function changes:**
The V1-pass and V2-pass entries for the same function signature change end up as separate
PatchInfo entries because their old/new line ranges barely overlap. The merge check at
line 1689 requires `max(old_start_i, old_line_start) <= min(old_end_i, old_line_cursor)`
— but the V2 entry has `old_end=121` (no old lines captured) and the V1 entry has
`old_start=120`, making the overlap check marginal at best.

### Proposed fix

**Option A — Merge same-function PatchInfo entries after both passes (recommended):**

After the V1 pass completes (line ~1731), add a post-processing step:

1. Group all PatchInfo entries by `(file_path_new, function_signature)` where the signature
   matches either `old_signature` or `new_signature`.
2. For each group with >1 entry for the same function, sort by `old_start_line`.
3. If adjacent entries have a gap (entry[i].old_end < entry[i+1].old_start), merge them:
   - Re-extract from the original git hunk using `extract_revert_patch(h, merged_start, merged_end, 'both')`
     where `merged_start = min(all old_starts)` and `merged_end = max(all old_ends)`.
   - This captures the full change range including any `-` lines in the gap.
4. Replace the separate entries with the single merged entry.

**Key insight:** The original git diff hunk `h` contains all the information (including the
`#else`/`#endif` removal). We just need to extract the full range instead of clipping to
narrow sub-ranges.

**Implementation notes:**
- The original hunk `h` is available during both passes but is not stored. Either:
  (a) Store it alongside the PatchInfo for post-processing, or
  (b) Perform the merge DURING the V1 pass when overlapping entries are detected
      (extend the existing merge logic at line 1671-1699 to also check for same-function
       entries from different git hunks).
- When merging, use `version='both'` to capture both `-` and `+` lines in the full range.
- Reconstruct `patch_text` with proper `@@ @@` header for the merged range.

**Option B — Extend extract_revert_patch to include paired preprocessor directives:**

After extracting lines, scan the result for unbalanced `#ifdef`/`#if`/`#ifndef` directives.
For each unmatched opening directive, extend `line_end` to include the matching `#endif`.
For each unmatched `#endif`, extend `line_start` to include the matching `#ifdef`.

This is more targeted but fragile — it only fixes the preprocessor symptom, not the general
problem of split function changes losing intermediate changes.

**Option C — Use `version='both'` in the V2 pass:**

Change line 1587 from:
```python
sub_patch, ... = extract_revert_patch(h, diff_result_begin, diff_result_end, 'new')
```
to:
```python
sub_patch, ... = extract_revert_patch(h, diff_result_begin, diff_result_end, 'both')
```

This would capture both `+` and `-` lines in the function's extent during the first pass,
potentially avoiding the split. However, `begin` and `end` are still clipped to the function
extent's intersection with the hunk's change range, so intermediate `-` lines might still
be missed if they fall outside `[begin, end]`.

### Tasks

- [x] Reproduce: load cached `data/diff/revert_patch_OSV-2020-1006_*` and confirm the split entries
- [x] Implement fix: relax merge condition in V1 pass (Option A variant — inline during V1 pass)
  - [x] Add same-function adjacency fallback when strict overlap check fails (line 1696)
  - [x] Uses existing merge codepath: `extract_revert_patch(h, merged_start, merged_end, 'both')`
  - [x] No need to store hunk `h` separately — already available in the V1 pass loop
- [ ] Verify: re-run `analyze_diffindex` on wavpack diff and confirm single merged entry for `LLVMFuzzerTestOneInput`
- [ ] Verify: regenerate round0 diff and confirm `#ifdef __cplusplus` / `#endif` are both present
- [ ] Test: run `bash script/react_agent/test_langgraph_agent.sh` (no regressions)
- [x] Test: run `bash script/migration_tools/test_migration_tools.sh` (no regressions)

### Files to modify

- `script/revert_patch_test.py`: `analyze_diffindex()` (line 1479) — add post-merge step
- `script/revert_patch_test.py`: `extract_revert_patch()` (line 1389) — possibly extend for balance checking
