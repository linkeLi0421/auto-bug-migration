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

Struct layout is fixed at compile time — you cannot conditionally
add or change fields with a runtime `if`. Apply these directly
(no dispatch gating):

- **Field type widening** (e.g. `UWORD8` → `UWORD32`): apply
  directly — the larger type is backward compatible.
- **New field additions**: add the field unconditionally — an extra
  zero-initialized field is harmless. Then dispatch-wrap only the
  **code that reads/writes** the new field (in `.c` files) using
  the normal if/else pattern.

### Header includes

Add `#include "__bug_dispatch.h"` (with the correct relative path)
to any file that uses `__bug_dispatch`. Add it once per file, near
the top with other includes. If the include already exists, do not
duplicate it.

### Non-C files (scripts, resource files, data)

Dispatch gating is a **protocol**, not a C idiom: at runtime, the
active branch must be chosen by reading bit `{dispatch_bit}` of
`__bug_dispatch[{dispatch_byte}]` from the process's memory. If the
patch modifies a file in another language, translate the same
protocol using whatever mechanism that language offers — don't give
up and don't silently drop the change.

Pick the cheapest accessor for the file's language and build it once;
subsequent bugs in the same language can reuse it.

| File class | Accessor strategy |
| --- | --- |
| Interpreted language embedded in the binary (PostScript, Lua, Tcl, …) | Register a one-shot native operator that returns the bit as a bool, then branch inline with the language's `if`/`ifelse`. Example for PostScript: a new `.bug_dispatch_bit` op reading `__bug_dispatch[]`, used as `<byte> <mask> .bug_dispatch_bit {{ NEW }} {{ OLD }} ifelse`. |
| Scripting language running in a separate process (shell, Python standalone script) | Have the harness write `/tmp/__bug_dispatch` (raw bytes) or export an env var after setting `__bug_dispatch[]`; the script reads it and branches on the bit. |
| FFI-capable runtime (Python, Ruby, Node) running in-process | Look up the `__bug_dispatch` symbol via `ctypes`/FFI and branch natively. |
| Pure data resource with no logic (JSON, YAML, images, binary tables) | Don't try to gate inline. Keep both files (e.g. `foo.json` and `foo.bug_{bug_id}.json`) and gate the **loader code** (a C-level `if` that picks which path to open) on the dispatch bit. |
| Build-time-only file (configure script, CMakeLists, Makefile) | Cannot be runtime-dispatched. Flag this back — the bug will have to be applied unconditionally or skipped, not wrapped. |

Requirements for any accessor you add:
- Keep it minimal (ideally one short function) and put it next to
  existing dispatch code so it's easy to find.
- Surface the accessor source/registration in the resulting diff —
  don't assume it already exists.
- The accessor reads the same `__bug_dispatch[]` global the C side
  uses; do not duplicate the dispatch state.
- Both OLD and NEW code must still be preserved (the PS `ifelse`,
  the Python `if/else`, the loader's `if`-picked path, etc.).

**Accessor without call site = no wrap.** Adding the accessor in C
(or registering it, or exporting it) is only half the job. You MUST
also modify the original file the bug touched so that the accessor
is actually called at runtime and selects between OLD/NEW. If the
input patch modifies `foo.ps`, your wrapped output must *also*
modify `foo.ps` — the agent that only adds a PostScript operator
without calling it from the `.ps` file has produced a silently
broken wrap. Concretely: for every file `F` in the input patch,
your wrapped patch must touch either `F` itself (wrapping inline) or
replace it through a loader gate (with the old/new variants both
present and a C-level `if` selecting between them). It is NOT
acceptable for the set of files touched by the wrapped patch to be
a strict subset of the set of files touched by the input patch —
except for struct/header/macro changes that the earlier sections
say to apply unconditionally.

Verification protocol before you finish:
1. List every file in the input patch.
2. For each file, confirm your wrapped patch either modifies it
   with the same OLD/NEW content gated on the dispatch bit, OR
   replaces it through an explicit two-variant + gated loader, OR
   applies it unconditionally per the struct/macro/header rules.
3. If a file is uncovered, go back and add the call site — do not
   ship a wrapped patch that is silently missing branches.

If you cannot find a language-appropriate way to read `__bug_dispatch[]`
without unreasonable infrastructure, report that explicitly in your
summary — do not pretend the patch was wrapped.

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
- [ ] Struct changes (type widening, new fields) applied directly (no dispatch)
- [ ] Non-C file changes gated via a language-appropriate accessor (new op, FFI lookup, harness-exported param, or two-file + gated loader)
- [ ] Every file in the input patch is ALSO in the wrapped patch (accessor without call site = broken wrap); exceptions only for struct/macro/header rules above
- [ ] `#include "__bug_dispatch.h"` added where needed
- [ ] Testcase has dispatch byte prepended
- [ ] `compile` succeeds after all changes
