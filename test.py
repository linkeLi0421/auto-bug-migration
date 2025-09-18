import re

_HUNK_RE = re.compile(r'^@@ -(?P<old_start>\d+)(?:,(?P<old_len>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_len>\d+))? @@')

def apply_unified_diff_to_string(original_text: str, diff_text: str, *, reverse: bool=False) -> str:
    """
    Apply a unified diff (for one file) to original_text and return the patched text.
    Set reverse=True to apply the diff in reverse (i.e., "unpatch").

    Limitations:
      - Assumes hunks are for a single file (ignores ---/+++ headers).
      - Ignores lines like '\\ No newline at end of file'.
    """
    orig_lines = original_text.splitlines(keepends=True)
    out_lines = []
    i = 0  # index into orig_lines

    lines = diff_text.splitlines(keepends=False)
    idx = 0

    # Skip optional file headers
    while idx < len(lines) and (lines[idx].startswith('---') or lines[idx].startswith('+++')):
        idx += 1

    while idx < len(lines):
        m = _HUNK_RE.match(lines[idx])
        if not m:
            # Non-hunk line (blank or metadata) — skip
            idx += 1
            continue

        old_start = int(m.group('old_start'))
        old_len   = int(m.group('old_len') or '0')
        # new_* not needed for application logic, but parsed for completeness
        idx += 1

        # Copy unchanged region before this hunk
        hunk_pos = old_start - 1  # unified diff is 1-based
        if hunk_pos < i or hunk_pos > len(orig_lines):
            raise ValueError(f'Hunk context out of range (want old line {old_start}, have i={i}, n={len(orig_lines)})')
        out_lines.extend(orig_lines[i:hunk_pos])
        i = hunk_pos

        # Apply hunk body
        while idx < len(lines) and not lines[idx].startswith('@@ '):
            line = lines[idx]
            if not line or line.startswith('\\ No newline at end of file'):
                idx += 1
                continue

            tag = line[0]
            payload = line[1:] + '\n' if (line.endswith('\n') is False and tag in ' +-') else line[1:]  # best effort

            # If reversing, swap + and -
            if reverse:
                tag = {'+': '-', '-': '+', ' ': ' '}.get(tag, tag)

            if tag == ' ':
                # context line: must match original
                if i >= len(orig_lines):
                    raise ValueError('Context extends past end of original')
                if orig_lines[i] != payload:
                    # If you want fuzzy matching, relax this check
                    raise ValueError('Context mismatch while applying hunk')
                out_lines.append(orig_lines[i])
                i += 1
            elif tag == '-':
                # deletion: original line must match; do not copy to output
                if i >= len(orig_lines):
                    raise ValueError('Deletion extends past end of original')
                if orig_lines[i] != payload:
                    raise ValueError('Deletion mismatch while applying hunk')
                i += 1
            elif tag == '+':
                # insertion: write payload; do not advance i
                out_lines.append(payload)
            else:
                raise ValueError(f'Unexpected hunk line tag: {tag!r}')
            idx += 1

    # Copy any remaining original lines after last hunk
    out_lines.extend(orig_lines[i:])
    return ''.join(out_lines)


orig = """#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <blosc2.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int32_t i = 0, dsize = 0;
  int32_t nchunk = 0;

  blosc2_init();
  blosc2_set_nthreads(1);

  /* Create a super-chunk backed by an in-memory frame */
  blosc2_schunk* schunk = blosc2_schunk_from_buffer((uint8_t *) data, (int64_t)size, false);
  if (schunk == NULL) {
    blosc2_destroy();
    return 0;
  }
  /* Don't allow address sanitizer to allocate more than INT32_MAX */
  if (schunk->nbytes >= INT32_MAX) {
    blosc2_schunk_free(schunk);
    blosc2_destroy();
    return 0;
  }
  /* Decompress data */
  uint8_t *uncompressed_data = (uint8_t *)malloc((size_t)schunk->nbytes+1);
  if (uncompressed_data != NULL) {
    for (i = 0, nchunk = 0; nchunk < schunk->nchunks-1; nchunk++) {
      dsize = blosc2_schunk_decompress_chunk(schunk, nchunk, uncompressed_data + i, schunk->chunksize);
      if (dsize < 0) {
        printf("Decompression error.  Error code: %d\n", dsize);
        break;
      }
      i += dsize;
    }

    free(uncompressed_data);
  }

  blosc2_schunk_free(schunk);
  blosc2_destroy();
  return 0;
}

#ifdef __cplusplus
}
#endif
"""

udiff = """diff --git a/tests/fuzz/fuzz_decompress_frame.c b/tests/fuzz/fuzz_decompress_frame.c
--- a/tests/fuzz/fuzz_decompress_frame.c
+++ b/tests/fuzz/fuzz_decompress_frame.c
@@ -16,7 +16,7 @@
   blosc2_set_nthreads(1);
 
   /* Create a super-chunk backed by an in-memory frame */
-  blosc2_schunk* schunk = __revert_54a733_blosc2_schunk_from_buffer((uint8_t *) data, (int64_t)size, false);
+  blosc2_schunk* schunk = blosc2_schunk_from_buffer((uint8_t *) data, (int64_t)size, false);
   if (schunk == NULL) {
     blosc2_destroy();
     return 0;
"""

# To reverse:
patched = apply_unified_diff_to_string(orig, udiff, reverse=True)
print(patched)
