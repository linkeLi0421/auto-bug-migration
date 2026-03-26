# Harness Dispatch Byte Modification

Modify the fuzz target to consume dispatch bytes from the input.

## Prompt

I need to modify the fuzz target for project {project} to support
an input-driven dispatch byte mechanism.

The file __bug_dispatch.h is already at /src/{project}/__bug_dispatch.h
and __bug_dispatch.c is at /src/{project}/__bug_dispatch.c.

Please make these changes:

1. Find the fuzz target source file that contains LLVMFuzzerTestOneInput
   (likely builds the fuzzer "{fuzzer}").

2. Add at the top of that file:
      #include "__bug_dispatch.h"
      #include <string.h>

3. At the VERY START of LLVMFuzzerTestOneInput (before any existing
   logic), add:
      if (size < __BUG_DISPATCH_BYTES) return 0;
      memcpy((void*)__bug_dispatch, data, __BUG_DISPATCH_BYTES);
      data += __BUG_DISPATCH_BYTES;
      size -= __BUG_DISPATCH_BYTES;

4. Make sure __bug_dispatch.c is compiled and linked into ALL fuzz
   targets.  Depending on the build system you may need to:
   - Add it to build.sh (e.g. add to a SOURCES list, or compile
     and link it explicitly)
   - Or add it to CMakeLists.txt / Makefile

After making changes, run: sudo -E compile
If there are build errors, fix them.
