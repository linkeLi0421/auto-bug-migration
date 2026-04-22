---
name: Benchmark-image crash collection requires the merge image and uses dispatch-prefixed PoCs
description: How fuzzbench_generate.py populates crashes/ and bug_metadata.json, and which pitfalls block it
type: project
---

`fuzzbench_generate.py:collect_crash_lines_from_image` is the function that populates `<benchmark>/crashes/<bug>.txt` and the crash_file/crash_line fields in `bug_metadata.json`. The function:

1. Builds the benchmark Docker image (`FROM <project>-merge:<commit-prefix>` — must exist). `ensure_merge_container` + `commit_merge_container` will rebuild it from scratch via `start_merge_container` → `_rebuild_project_image` → `fuzz_helper.py build_version`, which is slow (~20–30 min).
2. Runs `/usr/local/bin/compile` inside, commits as `crash-line-collector:<project>-compiled`. This post-build binary is the one that actually contains the `__bug_dispatch` symbol — the `bug-merge-<project>` container's `/out/<fuzzer>` is the **pre-merge** binary and will not reproduce any dispatch-gated bug (verify with `nm /out/<fuzzer> | grep __bug_dispatch`).
3. For each bug, runs the PoC inside `crash-line-collector:<project>-compiled`. The benchmark harness consumes the first `__BUG_DISPATCH_BYTES` bytes as dispatch bits and passes the rest to `LLVMFuzzerTestOneInput`. The merge-offline testcases under `testcases/testcase-<bug>-patched` already have the dispatch prefix baked in (little-endian u32/u8…).

**Why:** Most dispatch-gated bugs don't fire without the right `__bug_dispatch[]` byte pattern, and the library-level gates are conditionals like `__bug_dispatch[1] & (1 << 6)`. Running raw PoCs against the pre-merge `bug-merge-<project>` binary skips the gate entirely.

**How to apply:** When someone asks to re-populate `crashes/` or refresh `bug_metadata.json`:
- Always replay against `crash-line-collector:<project>-compiled` (or the already-committed `<project>-merge:<commit>` + recompile).
- Reuse merge-offline `testcases/testcase-<bug>-patched` files as-is — they include the dispatch prefix.
- Apply the UAR-off + UAR-on × 10 × 10 retry protocol (see `feedback_poc_replay_asan_protocol.md`); the single-shot path in `collect_crash_lines_from_image` (30 s, `-runs=10`, UAR-on only) misses UAR-sensitive bugs and aborts on the first timing-out non-triggerer.
- If `<project>-merge:<commit>` is missing, a small driver that calls `ensure_merge_container` + `commit_merge_container` + a resilient replay loop (continue-on-timeout) is cleaner than re-running the full `fuzzbench_generate.py`.
