import os
from openai import OpenAI
import re

# Initialize the client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def extract_code(text):
    blocks = re.findall(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL)
    return "\n\n".join(blocks).strip() if blocks else text.strip()


def handle_func_sig_change(error_message, caller_defA, callee_defA, callee_defB, model="gpt-4o"):
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
        temperature=0.1,  # Lower temperature for more precise following of instructions
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
    fixed_code = handle_func_sig_change(error_msg, caller_defA, callee_defA, callee_defB)
    print("--- AI Generated Output ---")
    print(fixed_code)