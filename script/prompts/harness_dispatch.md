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

5. **Make sure `__bug_dispatch.c` is compiled and linked into the
   fuzzer binary.**  Many projects' OBJECTS lists are produced by a
   `wildcard src/*.cpp` pattern or by autotools `*_SOURCES` blocks
   that will silently skip a stray `.c` file at the source root, so
   adding the header reference in the harness is NOT enough — you
   must wire the build system.

   First, identify the build system in use (run `ls`, `cat build.sh`,
   `find . -maxdepth 3 -name 'Makefile.am' -o -name 'CMakeLists.txt'
   -o -name 'BUILD.bazel'`). Then apply the matching recipe:

   - **Hand-written Makefile / build.sh `make` invocation:**
     edit `/src/build.sh` to compile the dispatch object and append
     it to the link rule's prereqs *after* `./configure` (so the
     generated Makefile exists), e.g.:
     ```
     clang $CFLAGS -c __bug_dispatch.c -o __bug_dispatch.o
     sed -i '/^<fuzzer-target>:/ s| *$| __bug_dispatch.o|' <path/to/Makefile>
     ```
     where `<fuzzer-target>` is the rule name from the generated
     Makefile (e.g. `fuzz/fuzz_<name>`). Do this *before* the line
     that runs `make`.

   - **Autotools (`Makefile.am`):** add `$(top_srcdir)/__bug_dispatch.c`
     to the relevant `*_SOURCES` block (or `noinst_LTLIBRARIES` /
     `lib_LTLIBRARIES` source list) so it gets compiled into the same
     `.la` the fuzzer links against. Re-run `./autogen.sh` /
     `./configure` if needed.

   - **CMake:** in the `CMakeLists.txt` that defines the fuzzer
     target, either append `__bug_dispatch.c` to that target's source
     list, or `add_library(bug_dispatch STATIC __bug_dispatch.c)` +
     `target_link_libraries(<fuzzer-target> PRIVATE bug_dispatch)`.

   - **Bazel:** add `__bug_dispatch.c` to the fuzzer rule's `srcs`.

6. After making the source/build changes, run: `compile`

   Then VERIFY the symbol actually got linked. Run:
   ```
   nm -D /out/{fuzzer} 2>/dev/null | grep ' __bug_dispatch$' || \
     nm /out/{fuzzer} 2>/dev/null | grep ' __bug_dispatch$'
   ```
   The expected output contains a line ending in ` D __bug_dispatch`
   (defined data symbol). If it shows ` U __bug_dispatch` (undefined)
   or nothing, the link is broken — the build system change in step 5
   did not take effect. Fix and rebuild before declaring done.

   Likewise, the build is NOT successful if the link step printed
   `undefined reference to '__bug_dispatch'` even when an old binary
   from a previous build is still on disk.
