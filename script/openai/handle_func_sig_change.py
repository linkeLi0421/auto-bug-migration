import os
from openai import OpenAI
import re

# Initialize the client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def extract_code(text):
    blocks = re.findall(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL)
    return "\n\n".join(blocks).strip() if blocks else text.strip()


def handle_func_sig_change(error_message, caller_defA, callee_defA, callee_defB, model="gpt-5-mini"):
    """
    Handle function signature change problems using OpenAI API
    
    Args:
        error_message: The compilation error message
        caller_defA: The relevant caller function definition in version A
        callee_defA: The relevant callee function definition in version A
        callee_defB: The relevant callee function definition in version B
        model: OpenAI model to use (default: gpt-4o)
    
    Returns:
        The AI's response with the solution
    """
    
    prompt = f"""In my project, code around the caller function or the definition of the caller function {caller_defA} calls a callee function {callee_defA} in older version, and got a compilation error:
{error_message}. This is because the definition of the callee function is changed to {callee_defB}.
Please fix only the caller function code to resolve the compilation error.
Output only the caller function definition (no callee function definitions, no explanations, no comments).
Wrap it in ```c ... ``` so I can parse it easily.
"""
    
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are an expert C programmer who fixes compilation errors. Respond only with code when asked."},
                {"role": "user", "content": prompt}
            ],
        max_completion_tokens=4096,
        )
        raw = response.choices[0].message.content
        return extract_code(raw)
    except Exception as e:
        return f"Error calling OpenAI API: {str(e)}"


# Example usage

if __name__ == '__main__':
    error_msg = '''/src/c-blosc2/blosc/frame.c:2503:65: error: too few arguments to function call, expected 5, have 4
 2503 |   int64_t offset = get_coffset(frame, header_len, cbytes, nchunk);
      |                    ~~~~~~~~~~~                                  ^'''

    caller_defA = '''int frame_get_lazychunk(blosc2_frame *frame, int nchunk, uint8_t **chunk, bool *needs_free) {
  int32_t header_len;
  int64_t frame_len;
  int64_t nbytes;
  int64_t cbytes;
  int32_t chunksize;
  int32_t nchunks;

  *chunk = NULL;
  *needs_free = false;
  int ret = get_header_info(frame, &header_len, &frame_len, &nbytes, &cbytes, &chunksize, &nchunks,
                            NULL, NULL, NULL, NULL, NULL);
  if (ret < 0) {
    BLOSC_TRACE_ERROR("Unable to get meta info from frame.");
    return -1;
  }

  if (nchunk >= nchunks) {
    BLOSC_TRACE_ERROR("nchunk ('%d') exceeds the number of chunks "
                      "('%d') in frame.", nchunk, nchunks);
    return -2;
  }

  // Get the offset to nchunk
  int64_t offset = get_coffset(frame, header_len, cbytes, nchunk);

  size_t lazychunk_cbytes = 0;
  if (frame->sdata == NULL) {
    // TODO: make this portable across different endianness
    // Get info for building a lazy chunk
    size_t chunk_nbytes;
    size_t chunk_cbytes;
    size_t chunk_blocksize;
    uint8_t header[BLOSC_MIN_HEADER_LENGTH];
    FILE* fp = NULL;
    if (frame->eframe) {
      // The chunk is not in the frame
      char* chunkpath = malloc(strlen(frame->urlpath) + 1 + 8 + strlen(".chunk") + 1);
      sprintf(chunkpath, "%s/%08X.chunk", frame->urlpath, offset);
      fp = fopen(chunkpath, "rb");
      free(chunkpath);
    }
    else {
      fp = fopen(frame->urlpath, "rb");
      fseek(fp, header_len + offset, SEEK_SET);
    }
    size_t rbytes = fread(header, 1, BLOSC_MIN_HEADER_LENGTH, fp);
    if (rbytes != BLOSC_MIN_HEADER_LENGTH) {
      BLOSC_TRACE_ERROR("Cannot read the header for chunk in the fileframe.");
      fclose(fp);
      return -5;
    }
    blosc_cbuffer_sizes(header, &chunk_nbytes, &chunk_cbytes, &chunk_blocksize);
    size_t nblocks = chunk_nbytes / chunk_blocksize;
    size_t leftover_block = chunk_nbytes % chunk_blocksize;
    nblocks = leftover_block ? nblocks + 1 : nblocks;
    // Allocate space for lazy chunk (cbytes + trailer)
    size_t trailer_len = sizeof(int32_t) + sizeof(int64_t) + nblocks * sizeof(int32_t);
    lazychunk_cbytes = chunk_cbytes + trailer_len;
    *chunk = malloc(lazychunk_cbytes);
    *needs_free = true;
    // Read just the full header and bstarts section too (lazy partial length)
    if (frame->eframe) {
      fseek(fp, 0, SEEK_SET);
    }
    else {
      fseek(fp, header_len + offset, SEEK_SET);
    }
    size_t lazy_partial_len = BLOSC_EXTENDED_HEADER_LENGTH + nblocks * sizeof(int32_t);
    rbytes = fread(*chunk, 1, lazy_partial_len, fp);
    fclose(fp);
    if (rbytes != lazy_partial_len) {
      BLOSC_TRACE_ERROR("Cannot read the (lazy) chunk out of the fileframe.");
      return -6;
    }

    // Mark chunk as lazy
    uint8_t* blosc2_flags = *chunk + BLOSC2_CHUNK_BLOSC2_FLAGS;
    *blosc2_flags |= 0x08U;

    // Add the trailer (currently, nchunk + offset + block_csizes)
    *(int32_t*)(*chunk + chunk_cbytes) = nchunk;
    *(int64_t*)(*chunk + chunk_cbytes + sizeof(int32_t)) = header_len + offset;

    int32_t* block_csizes = malloc(nblocks * sizeof(int32_t));

    int memcpyed = *(*chunk + BLOSC2_CHUNK_FLAGS) & (uint8_t)BLOSC_MEMCPYED;
    if (memcpyed) {
      // When memcpyed the blocksizes are trivial to compute
      for (int i = 0; i < (int)nblocks; i++) {
        block_csizes[i] = (int)chunk_blocksize;
      }
    }
    else {
      // In regular, compressed chunks, we need to sort the bstarts (they can be out
      // of order because of multi-threading), and get a reverse index too.
      memcpy(block_csizes, *chunk + BLOSC_EXTENDED_HEADER_LENGTH, nblocks * sizeof(int32_t));
      // Helper structure to keep track of original indexes
      struct csize_idx *csize_idx = malloc(nblocks * sizeof(struct csize_idx));
      for (int n = 0; n < (int)nblocks; n++) {
        csize_idx[n].val = block_csizes[n];
        csize_idx[n].idx = n;
      }
      qsort(csize_idx, nblocks, sizeof(struct csize_idx), &sort_offset);
      // Compute the actual csizes
      int idx;
      for (int n = 0; n < (int)nblocks - 1; n++) {
        idx = csize_idx[n].idx;
        block_csizes[idx] = csize_idx[n + 1].val - csize_idx[n].val;
      }
      idx = csize_idx[nblocks - 1].idx;
      block_csizes[idx] = (int)chunk_cbytes - csize_idx[nblocks - 1].val;
      free(csize_idx);
    }
    // Copy the csizes at the end of the trailer
    void *trailer_csizes = *chunk + lazychunk_cbytes - nblocks * sizeof(int32_t);
    memcpy(trailer_csizes, block_csizes, nblocks * sizeof(int32_t));
    free(block_csizes);
  } else {
    // The chunk is in memory and just one pointer away
    *chunk = frame->sdata + header_len + offset;
    lazychunk_cbytes = sw32_(*chunk + BLOSC2_CHUNK_CBYTES);
  }

  return (int)lazychunk_cbytes;
}'''

    callee_defA = '''int64_t get_coffset(blosc2_frame* frame, int32_t header_len, int64_t cbytes, int32_t nchunk) {
  // Get the offset to nchunk
  int64_t offset;
  uint8_t *coffsets = get_coffsets(frame, header_len, cbytes, NULL);
  if (coffsets == NULL) {
    BLOSC_TRACE_ERROR("Cannot get the offset for chunk %d for the frame.", nchunk);
    return -3;
  }

  int rc = blosc_getitem(coffsets, nchunk, 1, &offset);
  if (rc < 0) {
    size_t nbytes_, cbytes_, blocksize_;
    blosc_cbuffer_sizes(coffsets, &nbytes_, &cbytes_, &blocksize_);
    BLOSC_TRACE_ERROR("Problems retrieving a chunk offset.");
    return -4;
  }
  return offset;
}'''

    callee_defB = ''''int get_coffset(blosc2_frame_s* frame, int32_t header_len, int64_t cbytes, int32_t nchunk, int64_t *offset) {
  int32_t off_cbytes;
  // Get the offset to nchunk
  uint8_t *coffsets = get_coffsets(frame, header_len, cbytes, &off_cbytes);
  if (coffsets == NULL) {
    BLOSC_TRACE_ERROR("Cannot get the offset for chunk %d for the frame.", nchunk);
    return BLOSC2_ERROR_DATA;
  }

  // Get the 64-bit offset
  int rc = blosc2_getitem(coffsets, off_cbytes, nchunk, 1, offset, (int32_t)sizeof(int64_t));
  if (rc < 0) {
    BLOSC_TRACE_ERROR("Problems retrieving a chunk offset.");
  } else if (*offset > frame->len) {
    BLOSC_TRACE_ERROR("Cannot read chunk %d outside of frame boundary.", nchunk);
    rc = BLOSC2_ERROR_READ_BUFFER;
  }

  return rc;
}'''
    fixed_code = handle_func_sig_change(error_msg, caller_defA, callee_defA, callee_defB)
    print("--- AI Generated Output ---")
    print(fixed_code)

    