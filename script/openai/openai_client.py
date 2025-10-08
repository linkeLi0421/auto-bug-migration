import os
from openai import OpenAI
import re
import difflib

# Initialize the client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def generate_diff(old_code, new_code, filename="file.c", start_line_old=1, start_line_new=1):
    """
    Generate a unified diff text (a patch) between two code versions for a single function.
    The caller provides the function source for old_code and new_code and the file-line
    numbers where each function version starts (start_line_old / start_line_new).
    The returned patch is ready to be applied (contains ---/+++ headers and @@ hunks
    with correct absolute line numbers).

    Args:
        old_code: string containing the old version of the function
        new_code: string containing the new version of the function
        filename: path displayed in diff header (used in a/... and b/...)
        start_line_old: 1-based line number in the file where the old function starts
        start_line_new: 1-based line number in the file where the new function starts

    Returns:
        Unified diff text (str). Returns an empty string when there are no changes.
    """
    old_lines = old_code.rstrip("\n").splitlines()
    new_lines = new_code.rstrip("\n").splitlines()

    # difflib.unified_diff uses 1-based line numbers relative to the sequences passed.
    # We'll compute the diff for the function text and then shift the hunk start
    # numbers by (start_line - 1) to get absolute file line numbers.
    diff_iter = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        fromfiledate="",
        tofiledate="",
        lineterm="",
        n=3,  # context lines
    )

    diff_text = "\n".join(diff_iter)
    if not diff_text:
        return ""  # no changes

    # Adjust the @@ -old_start,old_count +new_start,new_count @@ to absolute line numbers
    diff_text = adjust_diff_start_lines(diff_text, start_line_old, start_line_new)
    return diff_text


def adjust_diff_start_lines(diff_text, old_start, new_start):
    """
    Adjust all @@ -a,b +c,d @@ hunk headers in diff_text by adding (old_start-1)
    to 'a' and (new_start-1) to 'c'.

    This preserves the hunk sizes (b and d) emitted by difflib, but relocates
    the hunk to the proper absolute file lines.
    """
    def repl(match):
        # match groups: full numbers strings like "1,7" and "1,7"
        old_range = match.group(1)  # e.g. "1,7"
        new_range = match.group(2)  # e.g. "1,8"

        # Parse old start/count
        old_parts = old_range.split(",")
        old_a = int(old_parts[0])
        old_b = int(old_parts[1]) if len(old_parts) > 1 else 1

        # Parse new start/count
        new_parts = new_range.split(",")
        new_c = int(new_parts[0])
        new_d = int(new_parts[1]) if len(new_parts) > 1 else 1

        # Shift starts to absolute lines (caller provided 1-based start_line)
        abs_old_a = old_a + (old_start - 1)
        abs_new_c = new_c + (new_start - 1)

        return f"@@ -{abs_old_a},{old_b} +{abs_new_c},{new_d} @@"

    # Replace all hunk header occurrences. This will preserve other parts of the diff.
    adjusted = re.sub(r"@@ -(\d+,\d+) \+(\d+,\d+) @@", repl, diff_text)
    return adjusted


def extract_code(text):
    blocks = re.findall(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL)
    return "\n\n".join(blocks).strip() if blocks else text.strip()


def solve_code_migration(error_message, data_structure, source_code, model="gpt-4o"):
    """
    Solve code migration problems using OpenAI API
    
    Args:
        error_message: The compilation error message
        data_structure: The relevant data structure definition
        source_code: The source code causing the error
        model: OpenAI model to use (default: gpt-4o)
    
    Returns:
        The AI's response with the solution
    """
    
    prompt = f"""I am transplanting a function from version A to version B. However, in version B I got a compilation error:

{error_message}

Related data structure is:
{data_structure}

Related source code is:
{source_code}

Please fix only the function code to resolve the compilation error.
Output only the corrected C function (no struct definitions, no explanations, no comments).
Wrap it in ```c ... ``` so I can parse it easily.
"""
    
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are an expert C programmer who fixes compilation errors. Respond only with code when asked."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_completion_tokens=2000
        )
        raw = response.choices[0].message.content
        return extract_code(raw)
    except Exception as e:
        return f"Error calling OpenAI API: {str(e)}"


# Example usage
if __name__ == "__main__":
    error_msg = """/src/c-blosc2/blosc/frame.c:478:28: error: no member named 'sdata' in 'blosc2_frame'
  478 |   uint8_t* framep = frame->sdata;
      |                     ~~~~~  ^/src/c-blosc2/blosc/frame.c:485:14: error: no member named 'sdata' in 'blosc2_frame'
  485 |   if (frame->sdata == NULL) {
      |       ~~~~~  ^/src/c-blosc2/blosc/frame.c:488:16: error: no member named 'eframe' in 'blosc2_frame'
  488 |     if (frame->eframe) {
      |         ~~~~~  ^"""

    struct_def = """typedef struct {
  char* urlpath;
  uint8_t* cframe;
  bool avoid_cframe_free;
  uint8_t* coffsets;
  int64_t len;
  int64_t maxlen;
  uint32_t trailer_len;
  bool sframe;
} blosc2_frame;"""

    code = """int __revert_1a42fc_get_header_info(blosc2_frame *frame, int32_t *header_len, int64_t *frame_len, int64_t *nbytes,
                    int64_t *cbytes, int32_t *chunksize, int32_t *nchunks, int32_t *typesize,
                    uint8_t *compcode, uint8_t *clevel, uint8_t *filters, uint8_t *filters_meta) {
  uint8_t* framep = frame->sdata;
  uint8_t header[FRAME_HEADER_MINLEN];

  if (frame->len <= 0) {
    return -1;
  }

  if (frame->sdata == NULL) {
    size_t rbytes = 0;
    FILE* fp = NULL;
    if (frame->eframe) {
      char* eframe_name = malloc(strlen(frame->urlpath) + strlen("/chunks.b2frame") + 1);
      sprintf(eframe_name, "%s/chunks.b2frame", frame->urlpath);
      fp = fopen(eframe_name, "rb");
      free(eframe_name);
    }
    else {
      fp = fopen(frame->urlpath, "rb");
    }
    if (fp != NULL) {
      rbytes = fread(header, 1, FRAME_HEADER_MINLEN, fp);
      fclose(fp);
    }
    (void) rbytes;
    if (rbytes != FRAME_HEADER_MINLEN) {
      return -1;
    }
    framep = header;
  }

  // Fetch some internal lengths
  __revert_1a42fc_swap_store(header_len, framep + FRAME_HEADER_LEN, sizeof(*header_len));
  __revert_1a42fc_swap_store(frame_len, framep + FRAME_LEN, sizeof(*frame_len));
  __revert_1a42fc_swap_store(nbytes, framep + FRAME_NBYTES, sizeof(*nbytes));
  __revert_1a42fc_swap_store(cbytes, framep + FRAME_CBYTES, sizeof(*cbytes));
  __revert_1a42fc_swap_store(chunksize, framep + FRAME_CHUNKSIZE, sizeof(*chunksize));
  if (typesize != NULL) {
    __revert_1a42fc_swap_store(typesize, framep + FRAME_TYPESIZE, sizeof(*typesize));
  }

  if (*header_len <= 0 || *header_len > *frame_len) {
    BLOSC_TRACE_ERROR("Header length is invalid or exceeds length of the frame.");
    return -1;
  }

  // Codecs
  uint8_t frame_codecs = framep[FRAME_CODECS];
  if (clevel != NULL) {
    *clevel = frame_codecs >> 4u;
  }
  if (compcode != NULL) {
    *compcode = frame_codecs & 0xFu;
  }

  // Filters
  if (filters != NULL && filters_meta != NULL) {
    uint8_t nfilters = framep[FRAME_FILTER_PIPELINE];
    if (nfilters > BLOSC2_MAX_FILTERS) {
      BLOSC_TRACE_ERROR("The number of filters in frame header are too large for Blosc2.");
      return -1;
    }
    uint8_t *filters_ = framep + FRAME_FILTER_PIPELINE + 1;
    uint8_t *filters_meta_ = framep + FRAME_FILTER_PIPELINE + 1 + FRAME_FILTER_PIPELINE_MAX;
    for (int i = 0; i < nfilters; i++) {
      filters[i] = filters_[i];
      filters_meta[i] = filters_meta_[i];
    }
  }

  if (*nbytes > 0 && *chunksize > 0) {
    // We can compute the number of chunks only when the frame has actual data
    *nchunks = (int32_t) (*nbytes / *chunksize);
    if (*nbytes % *chunksize > 0) {
      if (*nchunks == INT32_MAX) {
        BLOSC_TRACE_ERROR("Number of chunks exceeds maximum allowed.");
        return -1;
      }
      *nchunks += 1;
    }

    // Sanity check for compressed sizes
    if ((*cbytes < 0) || ((int64_t)*nchunks * *chunksize < *nbytes)) {
      BLOSC_TRACE_ERROR("Invalid compressed size in frame header.");
      return -1;
    }
  } else {
    *nchunks = 0;
  }

  return 0;
}"""

    solution = '''blosc2_frame* blosc2_frame_from_sframe(uint8_t *sframe, int64_t len, bool copy) {
  const uint8_t* header = sframe;
  int64_t frame_len;
  if (len < FRAME_HEADER_MINLEN) {
    return NULL;
  }
  swap_store(&frame_len, header + FRAME_LEN, sizeof(frame_len));
  if (frame_len != len) {
    return NULL;
  }
  blosc2_frame* frame = calloc(1, sizeof(blosc2_frame));
  frame->len = frame_len;
  const uint8_t* trailer = sframe + frame_len - FRAME_TRAILER_MINLEN;
  int trailer_offset = FRAME_TRAILER_MINLEN - FRAME_TRAILER_LEN_OFFSET;
  if (trailer[trailer_offset - 1] != 0xce) {
    free(frame);
    return NULL;
  }
  uint32_t trailer_len;
  swap_store(&trailer_len, trailer + trailer_offset, sizeof(trailer_len));
  frame->trailer_len = trailer_len;
  if (copy) {
    frame->cframe = malloc((size_t)len);
    memcpy(frame->cframe, sframe, (size_t)len);
  } else {
    frame->cframe = sframe;
    frame->avoid_cframe_free = true;
  }
  return frame;
}'''

    print("Querying OpenAI API...")
    solution = solve_code_migration(error_msg, struct_def, code)
    print("\n" + "="*80)
    print("SOLUTION:")
    print("="*80)
    print(solution)
    print(generate_diff(code, solution, filename="frame.c", start_line_old=470, start_line_new=470))
