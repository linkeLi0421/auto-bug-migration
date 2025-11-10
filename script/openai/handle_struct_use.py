import os
from openai import OpenAI
import re

# Initialize the client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def extract_code(text):
    blocks = re.findall(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL)
    return "\n\n".join(blocks).strip() if blocks else text.strip()


def solve_code_migration(error_message, data_structureA, data_structureB, source_code, model="gpt-4o"):
    """
    Solve code migration problems using OpenAI API
    
    Args:
        error_message: The compilation error message
        data_structureA: The relevant data structure definition in version A
        data_structureB: The relevant data structure definition in version B
        source_code: The source code causing the error
        model: OpenAI model to use (default: gpt-4o)
    
    Returns:
        The AI's response with the solution
    """
    
    prompt = f"""I am transplanting a function from version A to version B. However, in version B I got a compilation error:

{error_message}

Related data structure in version A is:
{data_structureA}

Related data structure in version B is:
{data_structureB}

Related source code is:
{source_code}

Please fix only the function code to resolve the compilation error.
If a struct field from version A is deleted (not renamed) in version B, remove or refactor the code that used that field instead of inventing a replacement. If a field in version A appears to have been renamed or semantically replaced in version B, update the code to use the new field name instead of removing the logic. When you must set a missing pointer field, assign or compare it directly to NULL; never call NULL as if it were a function.
Note you should not change the number of function arguments and other codes' line number.
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
        max_completion_tokens=4096,
        )
        raw = response.choices[0].message.content
        return extract_code(raw)
    except Exception as e:
        return f"Error calling OpenAI API: {str(e)}"


# Example usage
if __name__ == "__main__":
    error_msg = """/src/c-blosc2/blosc/blosc2.c:4207:14: error: no member named 'udbtune' in 'struct blosc2_context_s'
 4207 |     context->udbtune->btune_free(context);
      |     ~~~~~~~  ^/src/c-blosc2/blosc/blosc2.c:4210:22: error: no member named 'preparams' in 'struct blosc2_context_s'; did you mean 'pparams'?
 4210 |     my_free(context->preparams);
      |                      ^~~~~~~~~/src/c-blosc2/blosc/blosc2.c:4212:16: error: no member named 'postfilter' in 'struct blosc2_context_s'; did you mean 'prefilter'?
 4212 |   if (context->postfilter != NULL) {
      |                ^~~~~~~~~~/src/c-blosc2/blosc/blosc2.c:4213:22: error: no member named 'postparams' in 'struct blosc2_context_s'; did you mean 'pparams'?
 4213 |     my_free(context->postparams);
      |                      ^~~~~~~~~~"""

    struct_defA = """struct blosc2_context_s {
  const uint8_t* src;
  /* The source buffer */
  uint8_t* dest;
  /* The destination buffer */
  uint8_t header_flags;
  /* Flags for header */
  uint8_t blosc2_flags;
  /* Flags specific for blosc2 */
  int32_t sourcesize;
  /* Number of bytes in source buffer */
  int32_t header_overhead;
  /* The number of bytes in chunk header */
  int32_t nblocks;
  /* Number of total blocks in buffer */
  int32_t leftover;
  /* Extra bytes at end of buffer */
  int32_t blocksize;
  /* Length of the block in bytes */
  int32_t output_bytes;
  /* Counter for the number of input bytes */
  int32_t srcsize;
  /* Counter for the number of output bytes */
  int32_t destsize;
  /* Maximum size for destination buffer */
  int32_t typesize;
  /* Type size */
  int32_t* bstarts;
  /* Starts for every block inside the compressed buffer */
  int32_t runlen_type;
  /* Run-length type for chunk.  0 if not run-length */
  int compcode;
  /* Compressor code to use */
  int clevel;
  /* Compression level (1-9) */
  int use_dict;
  /* Whether to use dicts or not */
  void* dict_buffer;
  /* The buffer to keep the trained dictionary */
  int32_t dict_size;
  /* The size of the trained dictionary */
  void* dict_cdict;
  /* The dictionary in digested form for compression */
  void* dict_ddict;
  /* The dictionary in digested form for decompression */
  uint8_t filter_flags;
  /* The filter flags in the filter pipeline */
  uint8_t filters[BLOSC2_MAX_FILTERS];
  /* the (sequence of) filters */
  uint8_t filters_meta[BLOSC2_MAX_FILTERS];
  /* the metainfo for filters */
  blosc2_prefilter_fn prefilter;
  /* prefilter function */
  blosc2_postfilter_fn postfilter;
  /* postfilter function */
  blosc2_prefilter_params *preparams;
  /* prefilter params */
  blosc2_postfilter_params *postparams;
  /* postfilter params */
  bool* block_maskout;
  /* The blocks that are not meant to be decompressed.
   * If NULL (default), all blocks in a chunk should be read. */
  int block_maskout_nitems;
  /* The number of items in block_maskout array (must match
   * the number of blocks in chunk) */
  blosc2_schunk* schunk;
  /* Associated super-chunk (if available) */
  struct thread_context* serial_context;
  /* Cache for temporaries for serial operation */
  int do_compress;
  /* 1 if we are compressing, 0 if decompressing */
  void *btune;
  /* Entry point for BTune persistence between runs */
  blosc2_btune *udbtune;
  /* User-defined BTune parameters */
  /* Threading */
  int nthreads;
  int new_nthreads;
  int threads_started;
  int end_threads;
  pthread_t *threads;
  struct thread_context *thread_contexts; /* only for user-managed threads */
  pthread_mutex_t count_mutex;
#ifdef BLOSC_POSIX_BARRIERS
  pthread_barrier_t barr_init;
  pthread_barrier_t barr_finish;
#else
  int count_threads;
  pthread_mutex_t count_threads_mutex;
  pthread_cond_t count_threads_cv;
#endif
#if !defined(_WIN32)
  pthread_attr_t ct_attr;      /* creation time attrs for threads */
#endif
  int thread_giveup_code;
  /* error code when give up */
  int thread_nblock;       /* block counter */
  int dref_not_init;       /* data ref in delta not initialized */
  pthread_mutex_t delta_mutex;
  pthread_cond_t delta_cv;
};"""

    struct_defB = """typedef struct blosc2_context_s blosc2_context;   /* opaque type */
struct blosc2_context_s {
  const uint8_t* src;
  /* The source buffer */
  uint8_t* dest;
  /* The destination buffer */
  uint8_t header_flags;
  /* Flags for header */
  uint8_t blosc2_flags;
  /* Flags specific for blosc2 */
  int32_t sourcesize;
  /* Number of bytes in source buffer */
  int32_t header_overhead;
  /* The number of bytes in chunk header */
  int32_t nblocks;
  /* Number of total blocks in buffer */
  int32_t leftover;
  /* Extra bytes at end of buffer */
  int32_t blocksize;
  /* Length of the block in bytes */
  int32_t output_bytes;
  /* Counter for the number of input bytes */
  int32_t srcsize;
  /* Counter for the number of output bytes */
  int32_t destsize;
  /* Maximum size for destination buffer */
  int32_t typesize;
  /* Type size */
  int32_t* bstarts;
  /* Starts for every block inside the compressed buffer */
  int compcode;
  /* Compressor code to use */
  int clevel;
  /* Compression level (1-9) */
  int use_dict;
  /* Whether to use dicts or not */
  void* dict_buffer;
  /* The buffer to keep the trained dictionary */
  int32_t dict_size;
  /* The size of the trained dictionary */
  void* dict_cdict;
  /* The dictionary in digested form for compression */
  void* dict_ddict;
  /* The dictionary in digested form for decompression */
  uint8_t filter_flags;
  /* The filter flags in the filter pipeline */
  uint8_t filters[BLOSC2_MAX_FILTERS];
  /* the (sequence of) filters */
  uint8_t filters_meta[BLOSC2_MAX_FILTERS];
  /* the metainfo for filters */
  blosc2_prefilter_fn prefilter;
  /* prefilter function */
  blosc2_prefilter_params *pparams;
  /* prefilter params */
  bool* block_maskout;
  /* The blocks that are not meant to be decompressed.
   * If NULL (default), all blocks in a chunk should be read. */
  int block_maskout_nitems;
  /* The number of items in block_maskout array (must match
   * the number of blocks in chunk) */
  blosc2_schunk* schunk;
  /* Associated super-chunk (if available) */
  struct thread_context* serial_context;
  /* Cache for temporaries for serial operation */
  int do_compress;
  /* 1 if we are compressing, 0 if decompressing */
  void *btune;
  /* Entry point for BTune persistence between runs */

  /* Threading */
  int nthreads;
  int new_nthreads;
  int threads_started;
  int end_threads;
  pthread_t *threads;
  struct thread_context *thread_contexts; /* only for user-managed threads */
  pthread_mutex_t count_mutex;
#ifdef BLOSC_POSIX_BARRIERS
  pthread_barrier_t barr_init;
  pthread_barrier_t barr_finish;
#else
  int count_threads;
  pthread_mutex_t count_threads_mutex;
  pthread_cond_t count_threads_cv;
#endif
#if !defined(_WIN32)
  pthread_attr_t ct_attr;      /* creation time attrs for threads */
#endif
  int thread_giveup_code;
  /* error code when give up */
  int thread_nblock;       /* block counter */
  int dref_not_init;       /* data ref in delta not initialized */
  pthread_mutex_t delta_mutex;
  pthread_cond_t delta_cv;
};"""

    code = """ivoid __revert_abfebc_blosc2_free_ctx(blosc2_context* context) {
  release_threadpool(context);
  if (context->serial_context != NULL) {
    free_thread_context(context->serial_context);
  }
  if (context->dict_cdict != NULL) {
#ifdef HAVE_ZSTD
    ZSTD_freeCDict(context->dict_cdict);
#endif
  }
  if (context->dict_ddict != NULL) {
#ifdef HAVE_ZSTD
    ZSTD_freeDDict(context->dict_ddict);
#endif
  }
  if (context->btune != NULL) {
    context->udbtune->btune_free(context);
  }
  if (context->prefilter != NULL) {
    my_free(context->preparams);
  }
  if (context->postfilter != NULL) {
    my_free(context->postparams);
  }

  if (context->block_maskout != NULL) {
    free(context->block_maskout);
  }
  my_free(context);
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
    solution = solve_code_migration(error_msg, struct_defA, struct_defB, code)
    print("\n" + "="*80)
    print("SOLUTION:")
    print("="*80)
    print(solution)
