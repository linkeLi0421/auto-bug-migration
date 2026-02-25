# Plan: Resolve `__revert_*` Missing Definitions In Using Files

## Goal
When build/link fails because a `__revert_*` function is declared/called but not defined in the same translation unit, automatically add the missing function definition to the file that uses it (via `_extra_<file>` patch), instead of only adding a prototype.

## Evidence From Current Failure (OSV-2023-1370)
- `final_ossfuzz_build_output.log` shows:
  - `undefined reference to '__revert_..._ks_resize'` from `header.c` and `cram_encode.c`
  - `undefined reference to '__revert_..._nibble2base'` from `cram_encode.c`
  - repeated `-Wundefined-internal` warnings in `htslib/kstring.h` and `cram/cram_encode.c`
- `htslib-2023-1370.log` shows relocation moved header definitions into one `.c` file, which is insufficient for internal-linkage helpers used across multiple translation units.

## Root Cause To Address
- `static` / `static inline` `__revert_*` helpers need definition visibility per translation unit.
- Current flow handles missing declarations well, but for this case it often adds only prototypes; linker still fails because function bodies are missing where used.

## Implementation Plan
- [x] Add explicit parser outputs for this failure mode in `script/react_agent/build_log.py`:
  - detect and emit structured records for:
    - linker: `undefined reference to '__revert_*'` with `file`, `function`, `symbol`
    - compile warning: `function '__revert_*' has internal linkage but is not defined` with `file`, `symbol`
  - include enough context to identify the using file deterministically.

- [x] Add a reusable symbol-definition source resolver:
  - location: `script/react_agent/tools/extra_patch_tools.py` (or small shared helper module if cleaner).
  - behavior:
    - given `__revert_<sha>_<name>`, extract full function body from patch bundle `-` lines first.
    - fallback to V1 KB/source lookup and rename underlying function to exact `__revert_*` symbol.
    - return full definition text (not prototype).

- [x] Extend extra patch override logic to support definition insertion mode:
  - update `make_extra_patch_override(...)` in `script/react_agent/tools/extra_patch_tools.py`.
  - new decision path:
    - if symbol is `__revert_*` and unresolved-definition pattern is active, insert function definition block into target `_extra_<file>` hunk.
    - keep existing declaration-only behavior for ordinary undeclared-symbol cases.

- [x] Add policy in agent decision flow:
  - location: `script/react_agent/agent_langgraph.py`.
  - if active diagnostic is unresolved `__revert_*` definition (linker undefined reference or undefined-internal warning), force `make_extra_patch_override` for the using file with definition mode.
  - avoid `make_link_error_patch_override` body rewrites unless the active function itself must change.

- [x] Add using-file targeting rules:
  - linker case: use linker error file path (e.g., `header.c`, `cram_encode.c`) as insertion target.
  - undefined-internal warning case: use warning file path as insertion target.
  - for multiple using files, generate one insertion per file.

- [x] Add duplicate/ODR safety checks:
  - before inserting, detect if target `_extra_` already defines the exact symbol; skip duplicate insert.
  - preserve exact function signature and `static`/`inline` qualifiers from source definition.
  - never transform `__revert_*` name back to underlying symbol.

- [ ] Refine relocation behavior to avoid regressions:
  - location: `script/revert_patch_test.py` (`relocate_header_revert_defs_before_add_context`).
  - keep current relocation for normal cases.
  - add guard: for helper definitions that are internal-linkage and used in multiple TUs, do not rely solely on one relocation target; allow later per-file redefinition insertion path to repair deterministically.

- [x] Add regression tests:
  - `script/react_agent/test_langgraph_agent.sh`:
    - fixture with linker undefined `__revert_*` from file A, definition found elsewhere; expect definition inserted into `_extra_A`.
    - fixture with `-Wundefined-internal` for `__revert_*`; expect same-file definition insertion.
    - fixture to ensure no duplicate insertion when symbol already defined in `_extra_`.

- [ ] Add end-to-end validation for htslib OSV-2023-1370:
  - run the same pipeline that produced `multi_20260225_014529_2471929_61a16a10`.
  - confirm no remaining:
    - `undefined reference to '__revert_*'`
    - `has internal linkage but is not defined` for active `__revert_*` symbols.

## Acceptance Criteria
- [x] Agent automatically patches using files with missing `__revert_*` definitions (function bodies, not just prototypes).
- [ ] Build proceeds past link stage for the current failure class without manual edits.
- [x] Existing undeclared-symbol and non-`__revert_*` workflows remain unchanged.
- [x] No duplicate-definition regressions introduced in existing linker-error fixtures.

## Notes
- This plan keeps current architecture (patch bundle + `_extra_` overrides + tool-driven edits) and adds a targeted branch for unresolved `__revert_*` definition semantics.
