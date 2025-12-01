import os
from openai import OpenAI
import re

# Initialize the client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def extract_code(text):
    blocks = re.findall(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL)
    return "\n\n".join(blocks).strip() if blocks else text.strip()


def handle_renaming_patch_sig_change(error_message: str, caller_code: str, callee_codes: str, model: str = "gpt-5.1"):
    """
    Use an LLM to fix compilation errors caused by function signature changes.
    
    Args:
        error_message: The compiler error text (e.g. "too many arguments...")
        caller_code: The full caller function definition (the part to fix)
        callee_codes: The full definitions of callee functions (new version)
        model: Model name
    
    Returns:
        The updated caller function, as C code in a code block.
    """

    prompt = f"""
You are an expert C systems programmer. You must FIX a compilation error
caused by a callee function's signature changing.

You will receive:
1. CALLER CODE — the function that must be updated
2. CALLEE CODES — definitions of callee functions (new version)
3. ERROR MESSAGE — the compiler error

========================  CRITICAL RULES  ========================

1. ONLY modify the caller function.
   - Do NOT modify callee definitions.
   - Do NOT invent new fields, macros, or struct members.
   - Change ONLY the call site(s) that directly appear in the error.

2. Follow the new callee function signature exactly.
   - If parameters were removed → delete them from the call.
   - If parameters were added → use an existing variable if available,
     otherwise use NULL or 0.
   - Do NOT restructure logic beyond fixing the call.

3. Do NOT rename variables, change indentation, change comments,
   or alter unrelated lines.

4. You MUST return ONLY the corrected caller function.
   - Wrap the answer in a ```c ... ``` block.
   - No explanations. No extra text.

===============================================================

--- CALLER CODE ---
{caller_code}

--- CALLEE CODES ---
{callee_codes}

--- ERROR MESSAGE ---
{error_message}

Now fix the caller function so it compiles using the NEW signature.
Return ONLY the updated caller code inside:

```c
// code here
"""

    try:
      response = client.chat.completions.create(
          model=model,
          messages=[
              {
                  "role": "system",
                  "content": (
                      "You are an expert C programmer. "
                      "Rewrite only the caller function as requested. "
                      "No explanations."
                  ),
              },
              {"role": "user", "content": prompt},
          ],
          temperature=0,
      )
      raw = response.choices[0].message.content
      return extract_code(raw)

    except Exception as e:
        return f"Error calling OpenAI API: {str(e)}"


def handle_func_sig_change(error_message, caller_defA, callee_defA, callee_defB, model="gpt-5.1"):
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
    
    # Extract specific error lines and function calls
    # Create a more targeted prompt
    prompt = f"""Fix ONLY the specific function calls that are causing compilation errors.

CRITICAL INSTRUCTIONS:
1. DO NOT modify any function calls starting with "__revert_" unless they are explicitly mentioned in the error
2. DO NOT change any other lines or function calls not mentioned in the error message
3. DO NOT redeclare existing variables; reuse them if already defined in the function

ERROR MESSAGE:
{error_message}

FUNCTION TO FIX:
{caller_defA}

OLD FUNCTION SIGNATURES (version A):
{callee_defA}

NEW FUNCTION SIGNATURES (version B):
{callee_defB}

REQUIREMENTS:
- Only fix the exact function calls on ERROR MESSAGE
- Keep all other code exactly the same
- Do not modify __revert_ prefixed function calls unless they appear in the error
- Return the complete corrected function code
- Wrap your response in ```c ... ```
"""
    
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are an expert C programmer who fixes compilation errors. You MUST follow the specific line requirements and only change what is explicitly requested."}, 
                {"role": "user", "content": prompt}
            ],
        temperature=0,  # Lower temperature for more precise following of instructions
        )
        raw = response.choices[0].message.content
        return extract_code(raw)
    except Exception as e:
        return f"Error calling OpenAI API: {str(e)}"


# Example usage

if __name__ == '__main__':
    error_msg = '''/src/c-blosc2/blosc/blosc2.c:2838:66: error: too many arguments to function call, expected 4, have 5
 2838 |   int rc = handle_runlen(context, _src, nitems * typesize, dest, nitems * typesize);
      |            ~~~~~~~~~~~~~                                         ^~~~~~~~~~~~~~~~~/src/c-blosc2/blosc/blosc2.c:2838:66: error: too many arguments to function call, expected 4, have 5
 2838 |   int rc = handle_runlen(context, _src, nitems * typesize, dest, nitems * typesize);
      |            ~~~~~~~~~~~~~                                         ^~~~~~~~~~~~~~~~~/src/c-blosc2/blosc/blosc2.c:2838:66: error: too many arguments to function call, expected 4, have 5
 2838 |   int rc = handle_runlen(context, _src, nitems * typesize, dest, nitems * typesize);
      |            ~~~~~~~~~~~~~                                         ^~~~~~~~~~~~~~~~~'''

    caller_defA = '''int __revert_fdfeb7__blosc_getitem(blosc2_context* context, const void* src, int32_t srcsize,
                   int start, int nitems, void* dest) {
  uint8_t* _src = NULL;             /* current pos for source buffer */
  uint8_t flags;                    /* flags for header */
  int32_t ntbytes = 0;              /* the number of uncompressed bytes */
  int32_t nblocks;                   /* number of total blocks in buffer */
  int32_t leftover;                  /* extra bytes at end of buffer */
  int32_t* bstarts;                /* start pointers for each block */
  int32_t typesize, blocksize, nbytes;
  int32_t bsize, bsize2, ebsize, leftoverblock;
  int32_t cbytes;
  int32_t startb, stopb;
  int32_t stop = start + nitems;
  int j;

  if (nitems == 0) {
    // We have nothing to do
    return 0;
  }

  if (srcsize < BLOSC_MIN_HEADER_LENGTH) {
    /* Not enough input to parse Blosc1 header */
    return -1;
  }
  _src = (uint8_t*)(src);

  /* Read the header block */
  flags = _src[BLOSC2_CHUNK_FLAGS];                  /* flags */
  bool memcpyed = flags & (uint8_t)BLOSC_MEMCPYED;
  typesize = (int32_t)_src[BLOSC2_CHUNK_TYPESIZE];      /* typesize */
  nbytes = sw32_(_src + BLOSC2_CHUNK_NBYTES);         /* buffer size */
  blocksize = sw32_(_src + BLOSC2_CHUNK_BLOCKSIZE);      /* block size */
  cbytes = sw32_(_src + BLOSC2_CHUNK_CBYTES);    /* compressed buffer size */
  ebsize = blocksize + typesize * (int32_t)sizeof(int32_t);

  // Is that a chunk with a special value (runlen)?
  int rc = handle_runlen(context, _src, nitems * typesize, dest, nitems * typesize);
  if (rc < 0) {
    return -1;
  }
  if (rc > 0) {
    // This means that we have found a special value and we are done.
    return rc;
  }

  if (blocksize <= 0) {
    /* Invalid block size */
    return -1;
  }

  /* Total blocks */
  nblocks = nbytes / blocksize;
  leftover = nbytes % blocksize;
  nblocks = (leftover > 0) ? nblocks + 1 : nblocks;

  if (srcsize < context->header_overhead) {
    /* Not enough input to parse header */
    return -1;
  }

  if (context->header_overhead == BLOSC_EXTENDED_HEADER_LENGTH) {
    /* Extended header */
    uint8_t* filters = _src + BLOSC_MIN_HEADER_LENGTH;
    uint8_t* filters_meta = filters + 8;
    for (int i = 0; i < BLOSC2_MAX_FILTERS; i++) {
      context->filters[i] = filters[i];
      context->filters_meta[i] = filters_meta[i];
    }
    bstarts = (int32_t*)(_src + context->header_overhead);
    // The next is needed for lazy chunks
    context->nblocks = nblocks;
    context->blosc2_flags = _src[BLOSC2_CHUNK_BLOSC2_FLAGS];
  } else {
    /* Minimal header */
    flags_to_filters(flags, context->filters);
    bstarts = (int32_t*)(_src + context->header_overhead);
  }

  // Some checks for malformed buffers
  if (blocksize <= 0 || blocksize > nbytes || typesize <= 0 || typesize > BLOSC_MAX_TYPESIZE) {
    return -1;
  }

  /* Check region boundaries */
  if ((start < 0) || (start * typesize > nbytes)) {
    BLOSC_TRACE_ERROR("`start` out of bounds.");
    return -1;
  }

  if ((stop < 0) || (stop * typesize > nbytes)) {
    BLOSC_TRACE_ERROR("`start`+`nitems` out of bounds.");
    return -1;
  }

  if (_src + srcsize < (uint8_t *)(bstarts + nblocks)) {
    /* Not enough input to read all `bstarts` */
    return -1;
  }

  for (j = 0; j < nblocks; j++) {
    bsize = blocksize;
    leftoverblock = 0;
    if ((j == nblocks - 1) && (leftover > 0)) {
      bsize = leftover;
      leftoverblock = 1;
    }

    /* Compute start & stop for each block */
    startb = start * typesize - j * blocksize;
    stopb = stop * typesize - j * blocksize;
    if (stopb <= 0) {
      // We can exit as soon as this block is beyond stop
      break;
    }
    if (startb >= blocksize) {
      continue;
    }
    if (startb < 0) {
      startb = 0;
    }
    if (stopb > blocksize) {
      stopb = blocksize;
    }
    bsize2 = stopb - startb;

    /* Do the actual data copy */
    struct thread_context* scontext = context->serial_context;

    /* Resize the temporaries in serial context if needed */
    if (blocksize != scontext->tmp_blocksize) {
      my_free(scontext->tmp);
      scontext->tmp_nbytes = (size_t)3 * context->blocksize + ebsize;
      scontext->tmp = my_malloc(scontext->tmp_nbytes);
      scontext->tmp2 = scontext->tmp + blocksize;
      scontext->tmp3 = scontext->tmp + blocksize + ebsize;
      scontext->tmp4 = scontext->tmp + 2 * blocksize + ebsize;
      scontext->tmp_blocksize = (int32_t)blocksize;
    }

    // Regular decompression.  Put results in tmp2.
    // If the block is aligned and the worst case fits in destination, let's avoid a copy
    bool get_single_block = ((startb == 0) && (bsize == nitems * typesize));
    uint8_t* tmp2 = get_single_block ? dest : scontext->tmp2;
    // If memcpyed we don't have a bstarts section (because it is not needed)
    int32_t src_offset = memcpyed ? context->header_overhead + j * bsize : sw32_(bstarts + j);
    cbytes = __revert_fdfeb7_blosc_d(context->serial_context, bsize, leftoverblock,
                     src, srcsize, src_offset, j,
                     tmp2, 0, scontext->tmp, scontext->tmp3);
    if (cbytes < 0) {
      ntbytes = cbytes;
      break;
    }
    if (!get_single_block) {
      /* Copy to destination */
      memcpy((uint8_t *) dest + ntbytes, tmp2 + startb, (unsigned int) bsize2);
    }
    cbytes = (int)bsize2;
    ntbytes += cbytes;
  }

  return ntbytes;
}'''

    callee_defA = '''int handle_runlen(blosc2_context* context, uint8_t* src, uint32_t nbytes, uint8_t* dest, int32_t destsize) {
  bool doshuffle_flag = src[BLOSC2_CHUNK_FLAGS] & BLOSC_DOSHUFFLE;
  bool dobitshuffle_flag = src[BLOSC2_CHUNK_FLAGS] & BLOSC_DOBITSHUFFLE;
  if (!(doshuffle_flag & dobitshuffle_flag)) {
    // Not a Blosc2 chunk.  It cannot have a runlen.
    return 0;
  }
  context->header_overhead = BLOSC_EXTENDED_HEADER_LENGTH;  // a Blosc2 chunk
  int32_t cbytes_chunk = src[BLOSC2_CHUNK_CBYTES];
  int32_t typesize = src[BLOSC2_CHUNK_TYPESIZE];
  bool all_zeros = src[BLOSC2_CHUNK_BLOSC2_FLAGS] & (BLOSC2_ZERO_RUNLEN << 4);
  bool all_nans = src[BLOSC2_CHUNK_BLOSC2_FLAGS] & (BLOSC2_NAN_RUNLEN << 4);
  if ((cbytes_chunk != context->header_overhead + typesize) && (cbytes_chunk != context->header_overhead)) {
    return 0;
  }
  // all_values need to be checked first!
  if (all_zeros && all_nans) {
    // All repeated values
    int32_t nitems = nbytes / typesize;
    int rc = set_values(src, nitems, dest, destsize);
    return rc;
  }
  else if (all_nans) {
    int32_t nitems = nbytes / typesize;
    int rc = set_nans(src, nitems, dest, destsize);
    return rc;
  }
  else if (all_zeros) {
    memset(dest, 0, nbytes);
    return nbytes;
  }

  // 0 means no special value
  return 0;
}'''

    callee_defB = '''int handle_runlen(blosc_header *header, uint8_t* src, uint8_t* dest, int32_t destsize) {
  bool doshuffle_flag = header->flags & BLOSC_DOSHUFFLE;
  bool dobitshuffle_flag = header->flags & BLOSC_DOBITSHUFFLE;
  int rc = 0;

  if (doshuffle_flag & dobitshuffle_flag) {
    int32_t runlen_type = (header->blosc2_flags >> 4) & BLOSC2_RUNLEN_MASK;
    if (runlen_type == BLOSC2_VALUE_RUNLEN) {
      // All repeated values
      rc = set_values(header, src, dest, destsize);
    }
    else if (runlen_type == BLOSC2_NAN_RUNLEN) {
      rc = set_nans(header, src, dest, destsize);
    }
    else if (runlen_type == BLOSC2_ZERO_RUNLEN) {
      memset(dest, 0, destsize);
      rc = header->nbytes;
    }
  }

  return rc;
}'''
    # fixed_code = handle_func_sig_change(error_msg, caller_defA, callee_defA, callee_defB)
    # print("--- AI Generated Output ---")
    # print(fixed_code)
    
    
    error_msg = '''/src/c-blosc2/blosc/frame.c:2427:57: error: too many arguments to function call, expected 12, have 13
 2425 |   int rc = __revert_3055a0_get_header_info(frame, &header_len, &frame_len, &nbytes, &cbytes,
      |            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 2426 |                            &blocksize, &chunksize, &nchunks,
 2427 |                            &typesize, NULL, NULL, NULL, NULL);
      |                                                         ^~~~                                   ^~~~~~~~
    '''
    caller_def = '''int frame_get_lazychunk(blosc2_frame_s *frame, int nchunk, uint8_t **chunk, bool *needs_free) {
  int32_t header_len;
  int64_t frame_len;
  int64_t nbytes;
  int64_t cbytes;
  int32_t blocksize;
  int32_t chunksize;
  int32_t nchunks;
  int32_t typesize;
  int32_t lazychunk_cbytes;
  int64_t offset;
  FILE* fp = NULL;

  *chunk = NULL;
  *needs_free = false;
  int rc = __revert_3055a0_get_header_info(frame, &header_len, &frame_len, &nbytes, &cbytes,
                           &blocksize, &chunksize, &nchunks,
                           &typesize, NULL, NULL, NULL, NULL);
  if (rc < 0) {
    BLOSC_TRACE_ERROR("Unable to get meta info from frame.");
    return rc;
  }

  if (nchunk >= nchunks) {
    BLOSC_TRACE_ERROR("nchunk ('%d') exceeds the number of chunks "
                      "('%d') in frame.", nchunk, nchunks);
    return BLOSC2_ERROR_INVALID_PARAM;
  }

  // Get the offset to nchunk
  rc = get_coffset(frame, header_len, cbytes, nchunk, &offset);
  if (rc < 0) {
    BLOSC_TRACE_ERROR("Unable to get offset to chunk %d.", nchunk);
    return rc;
  }

  if (offset < 0) {
    // Special value
    lazychunk_cbytes = BLOSC_EXTENDED_HEADER_LENGTH;
    rc = frame_special_chunk(offset, chunksize, typesize, chunk,
                             (int32_t)lazychunk_cbytes, needs_free);
    goto end;
  }

  if (frame->cframe == NULL) {
    // TODO: make this portable across different endianness
    // Get info for building a lazy chunk
    int32_t chunk_nbytes;
    int32_t chunk_cbytes;
    int32_t chunk_blocksize;
    uint8_t header[BLOSC_MIN_HEADER_LENGTH];
    if (frame->sframe) {
      // The chunk is not in the frame
      fp = sframe_open_chunk(frame->urlpath, offset, "rb");
    }
    else {
      fp = fopen(frame->urlpath, "rb");
      fseek(fp, header_len + offset, SEEK_SET);
    }
    size_t rbytes = fread(header, 1, BLOSC_MIN_HEADER_LENGTH, fp);
    if (rbytes != BLOSC_MIN_HEADER_LENGTH) {
      BLOSC_TRACE_ERROR("Cannot read the header for chunk in the frame.");
      rc = BLOSC2_ERROR_FILE_READ;
      goto end;
    }
    rc = blosc2_cbuffer_sizes(header, &chunk_nbytes, &chunk_cbytes, &chunk_blocksize);
    if (rc < 0) {
      goto end;
    }
    size_t nblocks = chunk_nbytes / chunk_blocksize;
    size_t leftover_block = chunk_nbytes % chunk_blocksize;
    nblocks = leftover_block ? nblocks + 1 : nblocks;
    // Allocate space for the lazy chunk
    size_t trailer_len = sizeof(int32_t) + sizeof(int64_t) + nblocks * sizeof(int32_t);
    size_t trailer_offset = BLOSC_EXTENDED_HEADER_LENGTH + nblocks * sizeof(int32_t);
    lazychunk_cbytes = trailer_offset + trailer_len;
    *chunk = malloc(lazychunk_cbytes);
    *needs_free = true;

    // Read just the full header and bstarts section too (lazy partial length)
    if (frame->sframe) {
      fseek(fp, 0, SEEK_SET);
    }
    else {
      fseek(fp, header_len + offset, SEEK_SET);
    }

    rbytes = fread(*chunk, 1, trailer_offset, fp);
    if (rbytes != trailer_offset) {
      BLOSC_TRACE_ERROR("Cannot read the (lazy) chunk out of the frame.");
      rc = BLOSC2_ERROR_FILE_READ;
      goto end;
    }

    // Mark chunk as lazy
    uint8_t* blosc2_flags = *chunk + BLOSC2_CHUNK_BLOSC2_FLAGS;
    *blosc2_flags |= 0x08U;

    // Add the trailer (currently, nchunk + offset + block_csizes)
    if (frame->sframe) {
      *(int32_t*)(*chunk + trailer_offset) = offset;
      *(int64_t*)(*chunk + trailer_offset + sizeof(int32_t)) = offset;
    }
    else {
      *(int32_t*)(*chunk + trailer_offset) = nchunk;
      *(int64_t*)(*chunk + trailer_offset + sizeof(int32_t)) = header_len + offset;
    }

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
    *chunk = frame->cframe + header_len + offset;
    if ((int64_t)header_len + offset + BLOSC_MIN_HEADER_LENGTH > frame->len) {
      BLOSC_TRACE_ERROR("Cannot read the header for chunk in the (contiguous) frame.");
      rc = BLOSC2_ERROR_READ_BUFFER;
    } else {
      rc = blosc2_cbuffer_sizes(*chunk, NULL, &lazychunk_cbytes, NULL);
    }
  }

  end:
  if (fp != NULL) {
    fclose(fp);
  }
  if (rc < 0) {
    if (needs_free) {
      free(*chunk);
      *chunk = NULL;
    }
    return rc;
  }

  return (int)lazychunk_cbytes;
}
    '''
    callee_def = '''
    // Definition of __revert_3055a0_get_header_info:
int __revert_3055a0_get_header_info(blosc2_frame *frame, int32_t *header_len, int64_t *frame_len, int64_t *nbytes,
                    int64_t *cbytes, int32_t *chunksize, int32_t *nchunks, int32_t *typesize,
                    uint8_t *compcode, uint8_t *clevel, uint8_t *filters, uint8_t *filters_meta) {
  uint8_t* framep = frame->sdata;
  uint8_t header[FRAME_HEADER_MINLEN];

  if (frame->len <= 0) {
    return -1;
  }

  if (frame->sdata == NULL) {
    size_t rbytes = 0;
    FILE* fp = fopen(frame->fname, "rb");
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
  __revert_3055a0_swap_store(header_len, framep + FRAME_HEADER_LEN, sizeof(*header_len));
  __revert_3055a0_swap_store(frame_len, framep + FRAME_LEN, sizeof(*frame_len));
  __revert_3055a0_swap_store(nbytes, framep + FRAME_NBYTES, sizeof(*nbytes));
  __revert_3055a0_swap_store(cbytes, framep + FRAME_CBYTES, sizeof(*cbytes));
  __revert_3055a0_swap_store(chunksize, framep + FRAME_CHUNKSIZE, sizeof(*chunksize));
  if (typesize != NULL) {
    __revert_3055a0_swap_store(typesize, framep + FRAME_TYPESIZE, sizeof(*typesize));
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
        return -1;
      }
      *nchunks += 1;
    }
  } else {
    *nchunks = 0;
  }

  return 0;
}
    '''
    fixed_code = handle_renaming_patch_sig_change(error_msg, caller_def, callee_def)
    print("--- AI Generated Output ---")
    print(fixed_code)