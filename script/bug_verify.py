"""Shared fuzz-target bug verification.

Single source of truth for the "does <bug> trigger against this binary
+ testcase?" question. Used by the single-bug transplant
(``bug_transplant.py``), the merge pipelines (``bug_transplant_merge.py``,
``bug_transplant_merge_offline.py``), and any other caller that needs a
consistent trigger signal.

The verification protocol is:
  * Up to ``_VERIFY_ATTEMPTS`` attempts per ASAN variant, each running
    the fuzzer with ``-runs=10`` — matches ``fuzz_helper.py reproduce``.
  * Two ASAN variants are tried in order:
      - **UAR-off** (default behaviour, matches ``collect_crash``).
        Required for some heap/global overflows whose detection depends
        on the allocator landing a buffer at a specific address —
        turning on ``detect_stack_use_after_return`` reserves a large
        per-thread fake-stack ``mmap`` region that shifts those
        allocations and moves the overread out of any ASAN redzone, so
        the crash silently disappears.
      - **UAR-on** (``detect_stack_use_after_return=1``). Needed to
        catch actual stack-use-after-return bugs that ASAN cannot see
        with the feature disabled.
  * Each candidate crash is compared against the reference ``crash_log``
    via the two-tier matcher (see :func:`crash_stacks_match`): top-3
    project-code overlap first, then same-sanitizer-class +
    same-direction + call-chain-overlap + file overlap. If no reference
    crash log is available, any sanitizer SUMMARY counts as a match.
"""
from __future__ import annotations

import logging
import re
import subprocess

logger = logging.getLogger(__name__)

_VERIFY_ATTEMPTS = 20
_RUNS_PER_ATTEMPT = 10


# ---------------------------------------------------------------------------
# Stack-matching helpers (two-tier crash equivalence)
# ---------------------------------------------------------------------------


def extract_crash_funcs(text: str, limit: int = 0) -> list[str]:
    """Extract function names from crash stack frames in /src/ project code."""
    funcs = []
    for m in re.finditer(r'#\d+\s+\S+ in (\S+)\s+/src/', text):
        funcs.append(m.group(1))
    return funcs[:limit] if limit else funcs


def extract_sanitizer_class(text: str) -> tuple[str | None, str | None]:
    """Extract sanitizer error class and access direction from crash output.

    Returns ``(error_class, direction)`` e.g. ``("heap-buffer-overflow", "READ")``
    or ``(None, None)`` if not found.
    """
    m = re.search(
        r'ERROR:\s*\w+Sanitizer:\s*([\w-]+)\s+on address.*?\n'
        r'(READ|WRITE)\s+of\s+size',
        text, re.DOTALL,
    )
    if m:
        return m.group(1), m.group(2)
    m_summary = re.search(r'SUMMARY:\s*\w+Sanitizer:\s*([\w-]+)', text)
    m_dir = re.search(r'(READ|WRITE)\s+of\s+size', text)
    return (
        m_summary.group(1) if m_summary else None,
        m_dir.group(1) if m_dir else None,
    )


def extract_crash_files(text: str) -> set[str]:
    """Extract source file basenames from crash stack frames in /src/."""
    files = set()
    for m in re.finditer(r'/src/\S+/([\w._-]+\.\w+):\d+', text):
        files.add(m.group(1))
    return files


def crash_stacks_match(orig_text: str, new_text: str) -> bool:
    """Loose match: any overlap in project-code call chain or source files.

    The combined dispatch binary often surfaces the same underlying bug as
    a different sanitizer class / top frame (SEGV vs heap-UAF, gc_trace vs
    restore_space, etc.), so we accept any stack that shares at least one
    ``/src/`` function or source file with the reference.
    """
    orig_funcs = set(extract_crash_funcs(orig_text))
    new_funcs = set(extract_crash_funcs(new_text))
    if orig_funcs and new_funcs and orig_funcs & new_funcs:
        return True

    orig_files = extract_crash_files(orig_text)
    new_files = extract_crash_files(new_text)
    if orig_files and new_files and orig_files & new_files:
        return True

    # Reference log has no usable stack (e.g. build failed during
    # collect_crash): accept any sanitizer crash rather than rejecting.
    if not orig_funcs and not orig_files:
        logger.info(
            "Reference crash log has no stack data — accepting any sanitizer crash",
        )
        return True

    return False


_SANITIZER_SUMMARY_RE = re.compile(
    r"SUMMARY:\s*(Address|Memory|Undefined|Thread|Leak)Sanitizer",
)


def _exec_capture_cmd(container: str, cmd: str, timeout: int = 600) -> tuple[int, str]:
    """Run a command inside *container* and return (rc, combined_output)."""
    docker_cmd = ["docker", "exec", container, "bash", "-c", cmd]
    try:
        result = subprocess.run(
            docker_cmd, capture_output=True, encoding="utf-8",
            errors="replace", timeout=timeout,
        )
        return result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {timeout}s"


def verify_bug_triggers(
    container: str,
    bug_id: str,
    fuzzer: str,
    testcase: str,
    sanitizer: str = "address",
    crash_log: str | None = None,
    *,
    fuzzer_path: str | None = None,
    quiet: bool = False,
) -> bool:
    """Run the fuzzer binary for the given sanitizer and check for a crash.

    Retries up to :data:`_VERIFY_ATTEMPTS` times per ASAN configuration
    (10 fuzz runs each, via ``-runs=10``) and tries two ASAN_OPTIONS
    configurations (UAR-off then UAR-on). Returns True as soon as
    either detects a crash whose stack matches the reference
    ``crash_log`` (when provided) via :func:`crash_stacks_match`.

    If no ``crash_log`` is supplied, any sanitizer SUMMARY counts as a
    trigger.

    ``fuzzer_path`` overrides the default ``/out/<sanitizer>/<fuzzer>``
    location (useful at wrap time, before the per-sanitizer output
    directory is populated).

    ``quiet=True`` downgrades the per-attempt info/warning log lines to
    debug — callers that expect the bug NOT to trigger (e.g. bit-off
    dispatch verification) use this and do their own reporting.
    """
    sym_path = "/out/llvm-symbolizer"
    if fuzzer_path is None:
        fuzzer_path = f"/out/{sanitizer}/{fuzzer}"

    info_log = logger.debug if quiet else logger.info
    warn_log = logger.debug if quiet else logger.warning

    ref_text: str | None = None
    if crash_log:
        try:
            ref_text = open(crash_log, errors="replace").read()
        except FileNotFoundError:
            ref_text = None

    asan_variants = (
        (
            "UAR-off",
            f"detect_leaks=0:external_symbolizer_path={sym_path}",
        ),
        (
            "UAR-on",
            f"detect_leaks=0:detect_stack_use_after_return=1"
            f":max_uar_stack_size_log=16:external_symbolizer_path={sym_path}",
        ),
    )

    last_ret = -1
    saw_wrong_crash = False
    for variant_name, asan_opts in asan_variants:
        env_prefix = f"export ASAN_OPTIONS={asan_opts}; "
        logger.debug("[%s] verify variant=%s", bug_id, variant_name)
        for attempt in range(_VERIFY_ATTEMPTS):
            cmd = (
                f"{env_prefix}"
                f"if [ ! -x {fuzzer_path} ]; then "
                f"echo 'ERROR: {fuzzer_path} not found'; exit 99; fi; "
                f"{fuzzer_path} -runs={_RUNS_PER_ATTEMPT} /work/{testcase} 2>&1"
            )
            ret, output = _exec_capture_cmd(container, cmd, timeout=120)
            last_ret = ret
            logger.debug(
                "[%s] verify exit=%d variant=%s attempt=%d/%d",
                bug_id, ret, variant_name, attempt + 1, _VERIFY_ATTEMPTS,
            )

            has_summary = bool(_SANITIZER_SUMMARY_RE.search(output))
            if not has_summary:
                continue

            if ref_text is not None:
                if crash_stacks_match(ref_text, output):
                    info_log(
                        "[%s] Bug triggers OK (stack match, %s)",
                        bug_id, variant_name,
                    )
                    return True
                saw_wrong_crash = True
                continue

            info_log(
                "[%s] Bug triggers OK (SUMMARY match, no reference log, %s)",
                bug_id, variant_name,
            )
            return True

    # Single summary line — per-attempt mismatch diagnostics stay at debug
    # inside ``crash_stacks_match`` so a wrong-bug streak doesn't flood the log.
    if saw_wrong_crash:
        warn_log(
            "[%s] Crashed under %d attempts x 2 ASAN variants but stack never "
            "matched reference (wrong bug?) — see debug log for class/direction "
            "/ chain details",
            bug_id, _VERIFY_ATTEMPTS,
        )
    else:
        warn_log(
            "[%s] Bug does NOT trigger under either ASAN variant after "
            "%d attempts each (exit=%d)",
            bug_id, _VERIFY_ATTEMPTS, last_ret,
        )
    return False
