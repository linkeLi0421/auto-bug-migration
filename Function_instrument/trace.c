#ifdef __APPLE__
  #define _DARWIN_C_SOURCE
#endif
#define _GNU_SOURCE
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dlfcn.h>

/*
 * Two compile-time paths:
 *   Clang >  15 (PIE default): use dladdr() per-call to subtract dli_fbase
 *   Clang <= 15 (non-PIE):     use /proc/self/maps + ELF PT_LOAD at init time
 */

#if !defined(__clang__) || __clang_major__ <= 15
#include <elf.h>
#endif

static int trace_fd = -1;
static volatile int in_trace = 0;

/* Write a uintptr_t as lowercase hex to buf; return number of chars written. */
__attribute__((no_instrument_function))
static int uptr_to_hex(uintptr_t val, char *buf) {
    static const char hex[] = "0123456789abcdef";
    char tmp[20];
    int len = 0;
    if (val == 0) { buf[0] = '0'; return 1; }
    while (val > 0) {
        tmp[len++] = hex[val & 0xf];
        val >>= 4;
    }
    for (int i = 0; i < len; i++)
        buf[i] = tmp[len - 1 - i];
    return len;
}

/* ================================================================
 * Clang <= 15 path: /proc/self/maps + ELF PT_LOAD (non-PIE default)
 * ================================================================ */
#if !defined(__clang__) || __clang_major__ <= 15

static volatile int ready = 0;
static uintptr_t runtime_base = 0;
static uintptr_t elf_load_vaddr = 0;

__attribute__((no_instrument_function))
static uintptr_t parse_hex(const char *s, int len) {
    uintptr_t val = 0;
    for (int i = 0; i < len; i++) {
        char c = s[i];
        if (c >= '0' && c <= '9')      val = val * 16 + (c - '0');
        else if (c >= 'a' && c <= 'f')  val = val * 16 + (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')  val = val * 16 + (c - 'A' + 10);
        else break;
    }
    return val;
}

__attribute__((no_instrument_function))
static uintptr_t read_elf_load_vaddr(void) {
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) return 0;

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        close(fd);
        return 0;
    }
    if (lseek(fd, ehdr.e_phoff, SEEK_SET) < 0) {
        close(fd);
        return 0;
    }
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) break;
        if (phdr.p_type == PT_LOAD) {
            close(fd);
            return (uintptr_t)phdr.p_vaddr;
        }
    }
    close(fd);
    return 0;
}

__attribute__((constructor, no_instrument_function))
static void trace_init(void) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd >= 0) {
        char buf[128];
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            int end = 0;
            while (end < n && buf[end] != '-') end++;
            runtime_base = parse_hex(buf, end);
        }
    }
    elf_load_vaddr = read_elf_load_vaddr();
    ready = 1;
}

__attribute__((no_instrument_function))
void __cyg_profile_func_enter(void *func, void *caller) {
    if (!ready) return;
    if (in_trace) return;
    in_trace = 1;

    if (trace_fd < 0) {
        trace_fd = open("/tmp/trace.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (trace_fd < 0) trace_fd = STDERR_FILENO;
    }

    uintptr_t offset = (uintptr_t)func - runtime_base + elf_load_vaddr;
    uintptr_t caller_off = (uintptr_t)caller - runtime_base + elf_load_vaddr;

    char line[128];
    int pos = 0;
    memcpy(line + pos, "offset: ", 8); pos += 8;
    pos += uptr_to_hex(offset, line + pos);
    memcpy(line + pos, " called by: ", 12); pos += 12;
    pos += uptr_to_hex(caller_off, line + pos);
    line[pos++] = '\n';
    write(trace_fd, line, pos);

    in_trace = 0;
}

/* ================================================================
 * Clang > 15 path: dladdr() per-call (PIE default)
 * ================================================================ */
#else

__attribute__((no_instrument_function))
void __cyg_profile_func_enter(void *func, void *caller) {
    if (in_trace) return;
    in_trace = 1;

    if (trace_fd < 0) {
        trace_fd = open("/tmp/trace.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (trace_fd < 0) trace_fd = STDERR_FILENO;
    }

    Dl_info info;
    uintptr_t offset = (uintptr_t)func;
    uintptr_t caller_off = (uintptr_t)caller;

    if (dladdr(func, &info) && info.dli_fbase) {
        uintptr_t base = (uintptr_t)info.dli_fbase;
        offset = (uintptr_t)func - base;
        caller_off = (uintptr_t)caller - base;
    }

    char line[128];
    int pos = 0;
    memcpy(line + pos, "offset: ", 8); pos += 8;
    pos += uptr_to_hex(offset, line + pos);
    memcpy(line + pos, " called by: ", 12); pos += 12;
    pos += uptr_to_hex(caller_off, line + pos);
    line[pos++] = '\n';
    write(trace_fd, line, pos);

    in_trace = 0;
}

#endif

__attribute__((no_instrument_function))
void __cyg_profile_func_exit(void *func, void *caller) {
    (void)func;
    (void)caller;
}
