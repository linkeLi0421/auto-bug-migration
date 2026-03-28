# Offline Dispatch Wrapping

Wrap a standalone bug transplant patch with bitmask-based dispatch so it
can coexist with other bugs in the same binary, and prepend the dispatch
byte to its testcase.

## Prompt

I am preparing bug transplant patches for project {project} to be merged
into a single binary. Each bug gets a bit in a dispatch bitmask so the
fuzzer can select which bug's code path is active at runtime.

Bug {bug_id} is assigned **bit {dispatch_bit}** in `__bug_dispatch[{dispatch_byte}]`.

The standalone patch (works in isolation, no dispatch):
  {patch_path}

The testcase file:
  {testcase_path}

Your job:
1. Rewrite the patch to add dispatch wrapping around EVERY change.
2. Prepend the dispatch byte to the testcase.

---

## Dispatch wrapping rules

### Runtime code changes (if/else blocks, function calls, assignments)

For EVERY runtime code change `- OLD` / `+ NEW`, keep BOTH versions
and gate on the dispatch bit:

```c
#include "__bug_dispatch.h"

if (__bug_dispatch[{dispatch_byte}] & (1 << {dispatch_bit})) {{
    // {bug_id}'s version (NEW — from the patch)
}} else {{
    // Original version (OLD — before the patch)
}}
```

For code **deletions** (lines removed, nothing added), wrap the original
code so it is skipped when the bit is set:

```c
if (!(__bug_dispatch[{dispatch_byte}] & (1 << {dispatch_bit}))) {{
    // Original code (skipped when {bug_id} is active)
}}
```

### Macro / #define changes

Use a ternary conditioned on the dispatch bit:

```c
// BEFORE:
#define LIMIT 4080
// AFTER (bit {dispatch_bit} for {bug_id}):
#include "__bug_dispatch.h"
#define LIMIT ((__bug_dispatch[{dispatch_byte}] & (1 << {dispatch_bit})) ? 4096 : 4080)
```

If a macro ALREADY has a dispatch ternary from a previous bug,
OR your condition into the existing one — do NOT replace it:

```c
// BEFORE (bit 0 dispatching for a previous bug):
#define LIMIT ((__bug_dispatch[0] & (1 << 0)) ? 4096 : 4080)
// AFTER (add bit {dispatch_bit} for {bug_id}):
#define LIMIT ((__bug_dispatch[0] & (1 << 0)) || (__bug_dispatch[{dispatch_byte}] & (1 << {dispatch_bit})) \
    ? 4096 : 4080)
```

### Struct / type changes

Struct field type changes (e.g. `UWORD8` → `UWORD32`) cannot be
dispatched at runtime. Apply them directly — the larger type is
backward compatible.

### Header includes

Add `#include "__bug_dispatch.h"` (with the correct relative path)
to any file that uses `__bug_dispatch`. Add it once per file, near
the top with other includes. If the include already exists, do not
duplicate it.

---

## Testcase update

The fuzzer harness reads `__bug_dispatch` from the first byte(s) of
the test input. Prepend the correct bitmask byte to the testcase:

- Bit {dispatch_bit} → byte value `{dispatch_value}` (decimal)
- Original testcase at `{testcase_path}` → output to `{output_testcase_path}`

```bash
python3 -c "
d = open('{testcase_path}', 'rb').read()
open('{output_testcase_path}', 'wb').write(bytes([{dispatch_value}]) + d)
"
```

Local bugs (no dispatch bit) get byte value `0x00` prepended.

---

## Checklist

- [ ] Every hunk in the patch is wrapped (missing one = lost bug)
- [ ] Both OLD and NEW code are preserved in if/else
- [ ] Macros use ternary, not if/else
- [ ] Existing macro ternaries are OR'd into, not replaced
- [ ] Struct type changes applied directly (no dispatch)
- [ ] `#include "__bug_dispatch.h"` added where needed
- [ ] Testcase has dispatch byte prepended
- [ ] `sudo -E compile` succeeds after all changes
