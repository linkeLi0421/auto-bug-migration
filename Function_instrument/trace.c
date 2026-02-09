#ifdef __APPLE__
  #define _DARWIN_C_SOURCE
#endif
#define _GNU_SOURCE
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

static int trace_fd = -1;
static volatile int in_trace = 0;
static volatile int ready = 0;
static uintptr_t base_addr = 0;

/* Parse hex string into uintptr_t. */
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

/* Write an unsigned long in decimal to buf; return number of chars written. */
__attribute__((no_instrument_function))
static int ulong_to_str(unsigned long val, char *buf) {
    char tmp[24];
    int len = 0;
    if (val == 0) { buf[0] = '0'; return 1; }
    while (val > 0) {
        tmp[len++] = '0' + (val % 10);
        val /= 10;
    }
    for (int i = 0; i < len; i++)
        buf[i] = tmp[len - 1 - i];
    return len;
}

/*
 * Read the main executable's base address from /proc/self/maps.
 * The first line's start address is the load base of the main binary.
 * All instrumented functions live in the main binary (shared libs like
 * libc aren't compiled with -finstrument-functions).
 */
__attribute__((constructor, no_instrument_function))
static void trace_init(void) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd >= 0) {
        char buf[128];
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            /* First line: "55a3c000-55a4d000 r--p ..." — parse up to '-' */
            int end = 0;
            while (end < n && buf[end] != '-') end++;
            base_addr = parse_hex(buf, end);
        }
    }
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

    char line[128];
    int pos = 0;

    unsigned long offset = (unsigned long)((uintptr_t)func - base_addr);
    unsigned long caller_offset = (unsigned long)((uintptr_t)caller - base_addr);

    memcpy(line + pos, "offset: ", 8); pos += 8;
    pos += ulong_to_str(offset, line + pos);
    memcpy(line + pos, " called by: ", 12); pos += 12;
    pos += ulong_to_str(caller_offset, line + pos);
    line[pos++] = '\n';

    write(trace_fd, line, pos);

    in_trace = 0;
}

__attribute__((no_instrument_function))
void __cyg_profile_func_exit(void *func, void *caller) {
    (void)func;
    (void)caller;
}
