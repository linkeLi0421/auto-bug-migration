---
name: PoC replay must match merge-time ASAN retry protocol
description: When reproducing transplanted bugs, use both UAR-off and UAR-on ASAN variants with 10 attempts × 10 runs each — a single UAR-on replay silently misses bugs
type: feedback
---

When replaying PoCs to collect crash output (e.g. to populate `fuzzbench/benchmarks/<bench>/crashes/`), follow the same protocol that `bug_verify.py:verify_bug_triggers` uses during merge-time verification:

- Try **both** ASAN variants, in order:
  - UAR-off: `ASAN_OPTIONS=detect_leaks=0`
  - UAR-on:  `ASAN_OPTIONS=detect_leaks=0:detect_stack_use_after_return=1:max_uar_stack_size_log=16`
- Per variant: up to 10 attempts × `-runs=10` each
- Return on the first attempt that produces an `AddressSanitizer:` / `SUMMARY:` line (or matches the reference stack when one exists)

**Why:** UAR-on masks some heap bugs. Concrete case: libredwg OSV-2022-654, OSV-2023-1099, OSV-2023-316 were marked `triggered:true` at merge time but never crashed on single-shot `-runs=5` UAR-on replay — and all three crashed on the first UAR-off attempt. A one-variant replay looks like the bug "doesn't reproduce" when really the ASAN config suppressed it.

**How to apply:** For any bulk crash-collection loop against the benchmark image (or any compiled transplant binary), iterate `(variants × attempts)` before declaring a PoC non-reproducing. Also expect libfuzzer `-runs=N` to take much longer than 30 s on large DWG/DXF/binary inputs — bound timeouts at ≥60 s and continue past TimeoutExpired rather than aborting the whole loop.
