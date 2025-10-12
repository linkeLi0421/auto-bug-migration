#ifdef __APPLE__
  #define _DARWIN_C_SOURCE
#endif
#define _GNU_SOURCE 
#include <stdio.h>
#include <dlfcn.h>
#include <stdint.h>

static FILE *trace_fp = NULL;

void __cyg_profile_func_enter(void *func, void *caller) {
    if (!trace_fp) {
        trace_fp = fopen("/tmp/trace.txt", "w");
        if (!trace_fp) trace_fp = stderr;
    }
    
    Dl_info info;
    if (dladdr(func, &info)) {
      uintptr_t offset = (uintptr_t)func - (uintptr_t)info.dli_fbase;
      uintptr_t caller_offset = (uintptr_t)caller - (uintptr_t)info.dli_fbase;
      fprintf(trace_fp, "offset: %ld called by: %ld\n", offset, caller_offset);
      fflush(trace_fp);
    }
}