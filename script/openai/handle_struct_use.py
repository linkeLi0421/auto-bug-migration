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
            temperature=0.1,
        )
        raw = response.choices[0].message.content
        return extract_code(raw)
    except Exception as e:
        return f"Error calling OpenAI API: {str(e)}"


# Example usage
if __name__ == "__main__":
    error_msg = """/src/c-blosc2/blosc/blosc2.c:1797:56: error: no member named 'special_type' in 'struct blosc2_context_s'
 1797 |           (context->blosc2_flags & 0x08u) && (context->special_type == __revert_cons_d1ea51_BLOSC2_NO_SPECIAL));
      |                                               ~~~~~~~  ^/src/c-blosc2/blosc/blosc2.c:1852:18: error: no member named 'special_type' in 'struct blosc2_context_s'
 1852 |     if (context->special_type == __revert_cons_d1ea51_BLOSC2_NO_SPECIAL) {
      |         ~~~~~~~  ^/src/c-blosc2/blosc/blosc2.c:1865:18: error: no member named 'postfilter' in 'struct blosc2_context_s'; did you mean 'prefilter'?
 1865 |     if (context->postfilter != NULL) {
      |                  ^~~~~~~~~~/src/c-blosc2/blosc/blosc2.c:1870:22: error: no member named 'special_type' in 'struct blosc2_context_s'
 1870 |     switch (context->special_type) {
      |             ~~~~~~~  ^/src/c-blosc2/blosc/blosc2.c:1895:18: error: no member named 'postfilter' in 'struct blosc2_context_s'; did you mean 'prefilter'?
 1895 |     if (context->postfilter != NULL) {
      |                  ^~~~~~~~~~/src/c-blosc2/blosc/blosc2.c:1898:36: error: no member named 'postparams' in 'struct blosc2_context_s'; did you mean 'pparams'?
 1898 |       memcpy(&postparams, context->postparams, sizeof(postparams));
      |                                    ^~~~~~~~~~/src/c-blosc2/blosc/blosc2.c:1910:20: error: no member named 'postfilter' in 'struct blosc2_context_s'; did you mean 'prefilter'?
 1910 |       if (context->postfilter(&postparams) != 0) {
      |                    ^~~~~~~~~~/src/c-blosc2/blosc/blosc2.c:1930:16: error: no member named 'postfilter' in 'struct blosc2_context_s'; did you mean 'prefilter'?
 1930 |       context->postfilter != NULL) {
      |                ^~~~~~~~~~/src/c-blosc2/blosc/blosc2.c:2058:42: error: no member named 'postfilter' in 'struct blosc2_context_s'; did you mean 'prefilter'?
 2058 |   if (last_filter_index >= 0 || context->postfilter != NULL) {
      |                                          ^~~~~~~~~~"""

    struct_defA = """typedef struct blosc2_context_s blosc2_context;   /* opaque type */
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
  int32_t special_type;
  /* Special type for chunk.  0 if not special. */
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

    code = """static int __revert_abb0fa_blosc_d(
    struct thread_context* thread_context, int32_t bsize,
    int32_t leftoverblock, bool memcpyed, const uint8_t* src, int32_t srcsize, int32_t src_offset,
    int32_t nblock, uint8_t* dest, int32_t dest_offset, uint8_t* tmp, uint8_t* tmp2) {
  blosc2_context* context = thread_context->parent_context;
  uint8_t* filters = context->filters;
  uint8_t *tmp3 = thread_context->tmp4;
  int32_t compformat = (context->header_flags & (uint8_t)0xe0) >> 5u;
  int dont_split = (context->header_flags & 0x10) >> 4;
  int32_t chunk_nbytes;
  int32_t chunk_cbytes;
  int nstreams;
  int32_t neblock;
  int32_t nbytes;                /* number of decompressed bytes in split */
  int32_t cbytes;                /* number of compressed bytes in split */
  int32_t ctbytes = 0;           /* number of compressed bytes in block */
  int32_t ntbytes = 0;           /* number of uncompressed bytes in block */
  uint8_t* _dest;
  int32_t typesize = context->typesize;
  bool instr_codec = context->blosc2_flags & __revert_cons_abb0fa_BLOSC2_INSTR_CODEC;
  const char* compname;
  int rc;

  rc = __revert_abb0fa_blosc2_cbuffer_sizes(src, &chunk_nbytes, &chunk_cbytes, NULL);
  if (rc < 0) {
    return rc;
  }

  if (context->block_maskout != NULL && context->block_maskout[nblock]) {
    // Do not decompress, but act as if we successfully decompressed everything
    return bsize;
  }

  // In some situations (lazychunks) the context can arrive uninitialized
  // (but BITSHUFFLE needs it for accessing the format of the chunk)
  if (context->src == NULL) {
    context->src = src;
  }

  // Chunks with special values cannot be lazy
  bool is_lazy = ((context->header_overhead == BLOSC_EXTENDED_HEADER_LENGTH) &&
          (context->blosc2_flags & 0x08u) && !context->special_type);
  if (is_lazy) {
    // The chunk is on disk, so just lazily load the block
    if (context->schunk == NULL) {
      BLOSC_TRACE_ERROR("Lazy chunk needs an associated super-chunk.");
      return BLOSC2_ERROR_INVALID_PARAM;
    }
    if (context->schunk->frame == NULL) {
      BLOSC_TRACE_ERROR("Lazy chunk needs an associated frame.");
      return BLOSC2_ERROR_INVALID_PARAM;
    }
    blosc2_frame_s* frame = (blosc2_frame_s*)context->schunk->frame;
    char* urlpath = frame->urlpath;
    int32_t trailer_len = sizeof(int32_t) + sizeof(int64_t) + context->nblocks * sizeof(int32_t);
    size_t trailer_offset = BLOSC_EXTENDED_HEADER_LENGTH + context->nblocks * sizeof(int32_t);
    int32_t nchunk;
    int64_t chunk_offset;
    // The nchunk and the offset of the current chunk are in the trailer
    nchunk = *(int32_t*)(src + trailer_offset);
    chunk_offset = *(int64_t*)(src + trailer_offset + sizeof(int32_t));
    // Get the csize of the nblock
    int32_t *block_csizes = (int32_t *)(src + trailer_offset + sizeof(int32_t) + sizeof(int64_t));
    int32_t block_csize = block_csizes[nblock];
    // Read the lazy block on disk
    void* fp = NULL;
    blosc2_io_cb *io_cb = __revert_abb0fa_blosc2_get_io_cb(context->schunk->storage->io->id);
    if (io_cb == NULL) {
      BLOSC_TRACE_ERROR("Error getting the input/output API");
      return __revert_cons_abb0fa_BLOSC2_ERROR_PLUGIN_IO;
    }

    if (frame->sframe) {
      // The chunk is not in the frame
      char* chunkpath = malloc(strlen(frame->urlpath) + 1 + 8 + strlen(".chunk") + 1);
      BLOSC_ERROR_NULL(chunkpath, BLOSC2_ERROR_MEMORY_ALLOC);
      sprintf(chunkpath, "%s/%08X.chunk", frame->urlpath, nchunk);
      fp = io_cb->open(chunkpath, "rb", context->schunk->storage->io->params);
      free(chunkpath);
      // The offset of the block is src_offset
      io_cb->seek(fp, src_offset, SEEK_SET);
    }
    else {
      fp = io_cb->open(urlpath, "rb", context->schunk->storage->io->params);
      // The offset of the block is src_offset
      io_cb->seek(fp, chunk_offset + src_offset, SEEK_SET);
    }
    // We can make use of tmp3 because it will be used after src is not needed anymore
    int64_t rbytes = io_cb->read(tmp3, 1, block_csize, fp);
    io_cb->close(fp);
    if ((int32_t)rbytes != block_csize) {
      BLOSC_TRACE_ERROR("Cannot read the (lazy) block out of the fileframe.");
      return BLOSC2_ERROR_READ_BUFFER;
    }
    src = tmp3;
    src_offset = 0;
    srcsize = block_csize;
  }

  // If the chunk is memcpyed, we just have to copy the block to dest and return
  if (memcpyed) {
    int bsize_ = leftoverblock ? chunk_nbytes % context->blocksize : bsize;
    if (!context->special_type) {
      if (chunk_nbytes + context->header_overhead != chunk_cbytes) {
        return BLOSC2_ERROR_WRITE_BUFFER;
      }
      if (chunk_cbytes < context->header_overhead + (nblock * context->blocksize) + bsize_) {
        /* Not enough input to copy block */
        return BLOSC2_ERROR_READ_BUFFER;
      }
    }
    if (!is_lazy) {
      src += context->header_overhead + nblock * context->blocksize;
    }
    _dest = dest + dest_offset;
    if (context->postfilter != NULL) {
      // We are making use of a postfilter, so use a temp for destination
      _dest = tmp;
    }
    rc = 0;
    switch (context->special_type) {
      case __revert_cons_abb0fa_BLOSC2_SPECIAL_VALUE:
        // All repeated values
        rc = __revert_abb0fa_set_values(context->typesize, context->src, _dest, bsize_);
        if (rc < 0) {
          BLOSC_TRACE_ERROR("__revert_abb0fa_set_values failed");
          return BLOSC2_ERROR_DATA;
        }
        break;
      case __revert_cons_abb0fa_BLOSC2_SPECIAL_NAN:
        rc = __revert_abb0fa_set_nans(context->typesize, _dest, bsize_);
        if (rc < 0) {
          BLOSC_TRACE_ERROR("__revert_abb0fa_set_nans failed");
          return BLOSC2_ERROR_DATA;
        }
        break;
      case __revert_cons_abb0fa_BLOSC2_SPECIAL_ZERO:
        memset(_dest, 0, bsize_);
        break;
      case __revert_cons_abb0fa_BLOSC2_SPECIAL_UNINIT:
        // We do nothing here
        break;
      default:
        memcpy(_dest, src, bsize_);
    }
    if (context->postfilter != NULL) {
      // Create new postfilter parameters for this block (must be private for each thread)
      blosc2_postfilter_params postparams;
      memcpy(&postparams, context->postparams, sizeof(postparams));
      postparams.in = tmp;
      postparams.out = dest + dest_offset;
      postparams.size = bsize;
      postparams.typesize = typesize;
      postparams.offset = nblock * context->blocksize;
      postparams.nchunk = context->schunk != NULL ? context->schunk->current_nchunk : -1;
      postparams.nblock = nblock;
      postparams.tid = thread_context->tid;
      postparams.ttmp = thread_context->tmp;
      postparams.ttmp_nbytes = thread_context->tmp_nbytes;
      postparams.ctx = context;

      // Execute the postfilter (the processed block will be copied to dest)
      if (context->postfilter(&postparams) != 0) {
        BLOSC_TRACE_ERROR("Execution of postfilter function failed");
        return __revert_cons_abb0fa_BLOSC2_ERROR_POSTFILTER;
      }
    }
    context->zfp_cell_nitems = 0;
    return bsize_;
  }

  if (!is_lazy && (src_offset <= 0 || src_offset >= srcsize)) {
    /* Invalid block src offset encountered */
    return BLOSC2_ERROR_DATA;
  }

  src += src_offset;
  srcsize -= src_offset;

  int last_filter_index = last_filter(filters, 'd');
  if (instr_codec) {
    // If instrumented, we don't want to run the filters
    _dest = dest + dest_offset;
  }
  else if (((last_filter_index >= 0) &&
       (next_filter(filters, BLOSC2_MAX_FILTERS, 'd') != BLOSC_DELTA)) ||
    context->postfilter != NULL) {
    // We are making use of some filter, so use a temp for destination
    _dest = tmp;
  }
  else {
    // If no filters, or only DELTA in pipeline
    _dest = dest + dest_offset;
  }

  /* The number of compressed data streams for this block */
  if (!dont_split && !leftoverblock && !context->use_dict) {
    // We don't want to split when in a training dict state
    nstreams = (int32_t)typesize;
  }
  else {
    nstreams = 1;
  }

  neblock = bsize / nstreams;
  if (neblock == 0) {
    /* Not enough space to output bytes */
    return -1;
  }
  for (int j = 0; j < nstreams; j++) {
    if (srcsize < (signed)sizeof(int32_t)) {
      /* Not enough input to read compressed size */
      return BLOSC2_ERROR_READ_BUFFER;
    }
    srcsize -= sizeof(int32_t);
    cbytes = sw32_(src);      /* amount of compressed bytes */
    if (cbytes > 0) {
      if (srcsize < cbytes) {
        /* Not enough input to read compressed bytes */
        return BLOSC2_ERROR_READ_BUFFER;
      }
      srcsize -= cbytes;
    }
    src += sizeof(int32_t);
    ctbytes += (signed)sizeof(int32_t);

    /* Uncompress */
    if (cbytes == 0) {
      // A run of 0's
      memset(_dest, 0, (unsigned int)neblock);
      nbytes = neblock;
    }
    else if (cbytes < 0) {
      // A negative number means some encoding depending on the token that comes next
      uint8_t token;

      if (srcsize < (signed)sizeof(uint8_t)) {
        // Not enough input to read token */
        return BLOSC2_ERROR_READ_BUFFER;
      }
      srcsize -= sizeof(uint8_t);

      token = src[0];
      src += 1;
      ctbytes += 1;

      if (token & 0x1) {
        // A run of bytes that are different than 0
        if (cbytes < -255) {
          // Runs can only encode a byte
          return BLOSC2_ERROR_RUN_LENGTH;
        }
        uint8_t value = -cbytes;
        memset(_dest, value, (unsigned int)neblock);
      } else {
        BLOSC_TRACE_ERROR("Invalid or unsupported compressed stream token value - %d", token);
        return BLOSC2_ERROR_RUN_LENGTH;
      }
      nbytes = neblock;
      cbytes = 0;  // everything is encoded in the cbytes token
    }
    else if (cbytes == neblock) {
      memcpy(_dest, src, (unsigned int)neblock);
      nbytes = (int32_t)neblock;
    }
    else {
      if (compformat == BLOSC_BLOSCLZ_FORMAT) {
        nbytes = blosclz_decompress(src, cbytes, _dest, (int)neblock);
      }
      else if (compformat == BLOSC_LZ4_FORMAT) {
        nbytes = lz4_wrap_decompress((char*)src, (size_t)cbytes,
                                     (char*)_dest, (size_t)neblock);
      }
  #if defined(HAVE_ZLIB)
      else if (compformat == BLOSC_ZLIB_FORMAT) {
        nbytes = zlib_wrap_decompress((char*)src, (size_t)cbytes,
                                      (char*)_dest, (size_t)neblock);
      }
  #endif /*  HAVE_ZLIB */
  #if defined(HAVE_ZSTD)
      else if (compformat == BLOSC_ZSTD_FORMAT) {
        nbytes = zstd_wrap_decompress(thread_context,
                                      (char*)src, (size_t)cbytes,
                                      (char*)_dest, (size_t)neblock);
      }
  #endif /*  HAVE_ZSTD */
      else if (compformat == __revert_cons_abb0fa_BLOSC_UDCODEC_FORMAT) {
        bool getcell = false;

#if defined(HAVE_PLUGINS)
        if ((context->compcode == BLOSC_CODEC_ZFP_FIXED_RATE) && (context->zfp_cell_nitems > 0)) {
          nbytes = zfp_getcell(context, src, cbytes, _dest, neblock);
          if (nbytes < 0) {
            return BLOSC2_ERROR_DATA;
          }
          if (nbytes == context->zfp_cell_nitems * typesize) {
            getcell = true;
          }
        }
#endif /* HAVE_PLUGINS */
        if (!getcell) {
          context->zfp_cell_nitems = 0;
          for (int i = 0; i < g_ncodecs; ++i) {
            if (g_codecs[i].compcode == context->compcode) {
              blosc2_dparams dparams;
              __revert_abb0fa_blosc2_ctx_get_dparams(context, &dparams);
              nbytes = g_codecs[i].decoder(src,
                                           cbytes,
                                           _dest,
                                           neblock,
                                           context->compcode_meta,
                                           &dparams,
                                           context->src);
              goto urcodecsuccess;
            }
          }
          BLOSC_TRACE_ERROR("User-defined compressor codec %d not found during decompression", context->compcode);
          return BLOSC2_ERROR_CODEC_SUPPORT;
        }
      urcodecsuccess:
        ;
      }
      else {
        compname = clibcode_to_clibname(compformat);
        BLOSC_TRACE_ERROR(
                "Blosc has not been compiled with decompression "
                "support for '%s' format.  "
                "Please recompile for adding this support.", compname);
        return BLOSC2_ERROR_CODEC_SUPPORT;
      }

      /* Check that decompressed bytes number is correct */
      if ((nbytes != neblock) && (context->zfp_cell_nitems == 0)) {
        return BLOSC2_ERROR_DATA;
      }

    }
    src += cbytes;
    ctbytes += cbytes;
    _dest += nbytes;
    ntbytes += nbytes;
  } /* Closes j < nstreams */

  if (!instr_codec) {
    if (last_filter_index >= 0 || context->postfilter != NULL) {
      /* Apply regular filter pipeline */
      int errcode = __revert_abb0fa_pipeline_backward(thread_context, bsize, dest, dest_offset, tmp, tmp2, tmp3,
                                      last_filter_index, nblock);
      if (errcode < 0)
        return errcode;
    }
  }

  /* Return the number of uncompressed bytes */
  return (int)ntbytes;
}"""

    print("Querying OpenAI API...")
    solution = solve_code_migration(error_msg, struct_defA, struct_defB, code)
    print("\n" + "="*80)
    print("SOLUTION:")
    print("="*80)
    print(solution)
