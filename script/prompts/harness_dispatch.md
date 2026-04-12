# Harness Dispatch Byte Modification

Modify the fuzz target to consume dispatch bytes from the input.

## Prompt

I need to modify the fuzz target for project {project} to support
an input-driven dispatch byte mechanism.

The file __bug_dispatch.h is already at {source_dir}/__bug_dispatch.h
and __bug_dispatch.c is at {source_dir}/__bug_dispatch.c.

Known harness source path(s) for this project/fuzzer:
{harness_source_hint}

Please make these changes:

1. Find the fuzz target source file that contains LLVMFuzzerTestOneInput
   (likely builds the fuzzer "{fuzzer}").

2. Add at the top of that file:
      #include "__bug_dispatch.h"
      #include <string.h>
      #include <stdlib.h>

3. At the VERY START of LLVMFuzzerTestOneInput (before any existing
   logic), add:
      if (size < __BUG_DISPATCH_BYTES) return 0;
      memcpy((void*)__bug_dispatch, data, __BUG_DISPATCH_BYTES);
      data += __BUG_DISPATCH_BYTES;
      size -= __BUG_DISPATCH_BYTES;

4. **Tight-copy the remaining data** into a fresh allocation so that
   ASAN can detect overflows at the exact boundary.  Without this,
   the dispatch prefix bytes inflate the libFuzzer allocation and
   small overflows (READ 1, READ 2) past the logical `size` can land
   inside the padding instead of hitting ASAN redzones.

   Right after the dispatch-stripping code from step 3, add:
      uint8_t *__fuzz_copy = (uint8_t *)malloc(size);
      if (!__fuzz_copy) return 0;
      memcpy(__fuzz_copy, data, size);

   Then replace every reference to `data` in the rest of the function
   with `__fuzz_copy` (or rename appropriately).

   Finally, add `free(__fuzz_copy);` just before `return 0;` at the
   end of the function (and before any other return after the copy).

   The complete dispatch preamble should look like:
      if (size < __BUG_DISPATCH_BYTES) return 0;
      memcpy((void*)__bug_dispatch, data, __BUG_DISPATCH_BYTES);
      data += __BUG_DISPATCH_BYTES;
      size -= __BUG_DISPATCH_BYTES;
      uint8_t *__fuzz_copy = (uint8_t *)malloc(size);
      if (!__fuzz_copy) return 0;
      memcpy(__fuzz_copy, data, size);

   Then use `__fuzz_copy` and `size` for the rest of the harness.

5. Make sure __bug_dispatch.c is compiled and linked into ALL fuzz
   targets.  Depending on the build system you may need to:
   - Add it to build.sh (e.g. add to a SOURCES list, or compile
     and link it explicitly)
   - Or add it to CMakeLists.txt / Makefile

After making changes, run: compile
If there are build errors, fix them.
