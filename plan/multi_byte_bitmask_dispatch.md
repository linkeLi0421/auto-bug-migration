# Multi-byte bitmask dispatch

## Core idea

Change `__bug_dispatch` from a single `uint8_t` to a `uint8_t[]` array.
Start with 1 byte (bits 0-7). When bit 8 is needed, re-inject the header
with size 2, recompile — the harness auto-adapts via a macro.

## 1. Header/source templates (parameterized)

```c
// __bug_dispatch.h
#ifndef __BUG_DISPATCH_H
#define __BUG_DISPATCH_H
#include <stdint.h>
#define __BUG_DISPATCH_BYTES {dispatch_bytes}
extern volatile uint8_t __bug_dispatch[__BUG_DISPATCH_BYTES];
#endif

// __bug_dispatch.c
#include "__bug_dispatch.h"
volatile uint8_t __bug_dispatch[__BUG_DISPATCH_BYTES] = {0};
```

`_inject_dispatch_files()` takes `dispatch_bytes` param and re-injects
whenever the size grows. Since the harness uses the `__BUG_DISPATCH_BYTES`
macro, recompiling is enough — no agent re-invocation needed.

## 2. Harness prompt (`harness_dispatch.md`)

Change the harness code the agent inserts from reading 1 byte to using
the macro:

```c
#include <string.h>
if (size < __BUG_DISPATCH_BYTES) return 0;
memcpy((void*)__bug_dispatch, data, __BUG_DISPATCH_BYTES);
data += __BUG_DISPATCH_BYTES;
size -= __BUG_DISPATCH_BYTES;
```

## 3. Prompt substitution in all dispatch prompts

Currently: `__bug_dispatch & (1 << {dispatch_bit})` where `dispatch_bit` = 0-7

Change to: `__bug_dispatch[{dispatch_byte}] & (1 << {dispatch_bit})` where:
- `dispatch_byte = next_bit // 8`
- `dispatch_bit = next_bit % 8`

Affects: `conflict_resolve_dispatch.md`, `self_trigger_dispatch.md`,
`regression_dispatch.md`

Both `dispatch_byte` and `dispatch_bit` must be threaded through all
three agent-call sites (`resolve_conflict_with_agent`,
`resolve_self_trigger_with_dispatch`, `resolve_with_dispatch`) and
passed to `_load_prompt()`.

## 4. Python dispatch_state changes

```python
dispatch_state = {
    "next_bit": 0,
    "dispatch_bytes": 1,     # NEW — current array size
    "bits": {},
    "poc_bytes": {},          # int values can now exceed 255
    "harness_modified": False,
    "dispatch_file_injected": False,
}
```

`dispatch_bytes` is persisted in `_save_step_state()` and restored in
the `--start-step` resume path. This is required so that resume
re-injects dispatch files with the correct array size and serializes
PoCs with the right byte count.

## 5. Auto-grow logic

Extract a helper `_ensure_dispatch_capacity(dispatch_state, container, project)`
called before each bit allocation. When `next_bit >= dispatch_bytes * 8`:

1. `dispatch_state["dispatch_bytes"] += 1`
2. Re-inject `__bug_dispatch.h/.c` with new size
3. Rebuild ASAN+UBSAN (harness adapts via macro)
4. Rewrite all PoCs in `/work/` via `_apply_all_dispatch_bytes()`
   so existing testcases get the wider prefix immediately

## 6. PoC serialization (`_apply_all_dispatch_bytes`)

Currently: `bytes([dval])` (1 byte)

Change to: `dval.to_bytes(dispatch_bytes, 'little')` (N bytes,
little-endian so Python bit N maps to `__bug_dispatch[N//8] & (1 << N%8)`)

## 7. Resume path (`--start-step`)

Currently at line 1702: `_inject_dispatch_files(container, project)`
with no size parameter.

Change to: read `dispatch_bytes` from saved state and pass it:
```python
dispatch_bytes = dispatch_state.get("dispatch_bytes", 1)
_inject_dispatch_files(container, project, dispatch_bytes)
```

## 8. Output formatting

Update the summary/output code that prints `poc_bytes` values
(currently assumes single-byte hex `0x{dval:02x}`). For multi-byte
values, format as e.g. `0x0130` or show per-byte breakdown.

## Files changed

- `script/bug_transplant_merge.py`:
  - `_DISPATCH_HEADER` / `_DISPATCH_SOURCE` — parameterized with `{dispatch_bytes}`
  - `_inject_dispatch_files()` — takes `dispatch_bytes` param
  - `_apply_all_dispatch_bytes()` — multi-byte serialization
  - `_ensure_dispatch_capacity()` — NEW grow helper
  - `dispatch_state` init — add `dispatch_bytes: 1`
  - `_save_step_state()` / resume path — persist and restore `dispatch_bytes`
  - All three agent-call sites — pass both `dispatch_byte` and `dispatch_bit`
  - Summary/output formatting — handle multi-byte poc values
- `script/prompts/harness_dispatch.md` — macro-based multi-byte read
- `script/prompts/conflict_resolve_dispatch.md` — `{dispatch_byte}` + `{dispatch_bit}`
- `script/prompts/self_trigger_dispatch.md` — same
- `script/prompts/regression_dispatch.md` — same

## What stays the same

- `poc_bytes[bug_id] |= (1 << bit_index)` — Python ints handle arbitrary bit widths
- `next_bit` increments the same way
- All prompt text/guidance unchanged, only the C expression changes
- Bitmask semantics fully preserved (independent bits, OR-able)
