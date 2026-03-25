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

## 5. Auto-grow logic

When allocating a new bit and `next_bit >= dispatch_bytes * 8`:

1. `dispatch_bytes += 1`
2. Re-inject `__bug_dispatch.h/.c` with new size
3. Rebuild (harness adapts via macro)
4. Pad all existing PoCs to new width

## 6. PoC serialization (`_apply_all_dispatch_bytes`)

Currently: `bytes([dval])` (1 byte)

Change to: `dval.to_bytes(dispatch_bytes, 'little')` (N bytes, little-endian
to match `memcpy` on x86)

## Files changed

- `script/bug_transplant_merge.py` — templates, inject function,
  dispatch_state init, prompt args, poc serialization, grow logic
- `script/prompts/harness_dispatch.md` — macro-based multi-byte read
- `script/prompts/conflict_resolve_dispatch.md` — `{dispatch_byte}` + `{dispatch_bit}`
- `script/prompts/self_trigger_dispatch.md` — same
- `script/prompts/regression_dispatch.md` — same

## What stays the same

- `poc_bytes[bug_id] |= (1 << bit_index)` — Python ints handle arbitrary bit widths
- `next_bit` increments the same way
- All prompt text/guidance unchanged, only the C expression changes
- Bitmask semantics fully preserved (independent bits, OR-able)
