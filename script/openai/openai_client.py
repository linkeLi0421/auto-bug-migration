import os
from openai import OpenAI
import re
import difflib

# Initialize the client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def generate_diff(old_code, new_code, filename="file.c", start_line_old=1, start_line_new=1):
    """
    Generate a unified diff text between two code versions.
    
    Args:
        old_code: string (old version)
        new_code: string (new version)
        filename: path displayed in diff header
        start_line_old: starting line number for the old version
        start_line_new: starting line number for the new version
    Returns:
        Unified diff text (str)
    """
    old_lines = old_code.strip().splitlines()
    new_lines = new_code.strip().splitlines()

    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        fromfiledate="",
        tofiledate="",
        lineterm="",
        n=3,  # context lines
        # difflib doesn’t have direct start-line control, so we manually fix that next
    )

    diff_text = "\n".join(diff)
    # Adjust line numbers manually (difflib always starts from 1)
    diff_text = adjust_diff_start_lines(diff_text, start_line_old, start_line_new)
    return diff_text


def adjust_diff_start_lines(diff_text, old_start, new_start):
    """
    Adjust the @@ -x,y +x,y @@ lines in a unified diff
    to custom starting line numbers.
    """
    import re
    def repl(match):
        old_range = match.group(1)
        new_range = match.group(2)

        # Replace starting lines but preserve line counts
        old_parts = old_range.split(",")
        new_parts = new_range.split(",")
        old_len = old_parts[1] if len(old_parts) > 1 else ""
        new_len = new_parts[1] if len(new_parts) > 1 else ""

        return f"@@ -{old_start},{old_len} +{new_start},{new_len} @@"
    return re.sub(r"@@ -(\d+,\d+) \+(\d+,\d+) @@", repl, diff_text)


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
    error_msg = """/src/c-blosc2/blosc/frame.c:3650:12: error: no member named 'sdata' in 'blosc2_frame'
 3650 |     frame->sdata = malloc((size_t)len);
      |     ~~~~~  ^"""

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

    code = """blosc2_frame* blosc2_frame_from_sframe(uint8_t *sframe, int64_t len, bool copy) {
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
    frame->sdata = malloc((size_t)len);
    memcpy(frame->sdata, sframe, (size_t)len);
  } else {
    frame->sdata = sframe;
    frame->avoid_sdata_free = true;
  }
  return frame;
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
    # solution = solve_code_migration(error_msg, struct_def, code)
    print("\n" + "="*80)
    print("SOLUTION:")
    print("="*80)
    print(solution)
    print(generate_diff(code, solution))
