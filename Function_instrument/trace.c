#ifdef __APPLE__
  #define _DARWIN_C_SOURCE
#endif
#define _GNU_SOURCE 
#include <stdio.h>
#include <dlfcn.h>
#include <stdint.h>

void __cyg_profile_func_enter(void *func, void *caller) {
    Dl_info info;
    if (dladdr(func, &info)) {
      uintptr_t offset = (uintptr_t)func - (uintptr_t)info.dli_fbase;
      uintptr_t caller_offset = (uintptr_t)caller - (uintptr_t)info.dli_fbase;
      printf("offset: %ld called by: %ld\n", offset, caller_offset);
    }
    fflush(stdout);
}