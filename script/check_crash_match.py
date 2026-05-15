#!/usr/bin/env python3
"""Check whether two crash logs represent the same bug.

Thin CLI wrapper over `bug_verify.crash_stacks_match` — the same loose-match
oracle the transplant verification flow uses. Designed to be called from
inside the OSS-Fuzz container during patch minimization so the minimizer can
verify "the candidate after this revert still triggers the SAME bug as the
reference," not just "any sanitizer crash still appears."

Exit codes:
  0  PASS  — candidate has a sanitizer SUMMARY AND its project-code stack
            overlaps the reference's stack (shared function or source file).
  1  FAIL  — candidate either has no sanitizer SUMMARY at all, or its stack
            does not overlap the reference (different bug).
  2  USAGE — bad arguments or missing files.

Output is a one-line PASS / FAIL header followed by short signature
diagnostics so a calling agent can reason about what changed.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from bug_verify import (  # noqa: E402
    crash_stacks_match,
    extract_crash_files,
    extract_crash_funcs,
    extract_sanitizer_class,
)


def _summary(label: str, text: str) -> str:
    cls, direction = extract_sanitizer_class(text)
    funcs = extract_crash_funcs(text)
    files = extract_crash_files(text)
    return (
        f"{label}: class={cls!r} dir={direction!r} "
        f"top_funcs={funcs[:3]} files={sorted(files)[:5]}"
    )


def main() -> int:
    p = argparse.ArgumentParser(
        description="Decide whether two crash logs trigger the same bug.",
    )
    p.add_argument(
        "reference",
        help="Reference crash log. The bug we want to keep triggering.",
    )
    p.add_argument(
        "candidate",
        help="New crash log produced after a minimization step.",
    )
    args = p.parse_args()

    ref_path = Path(args.reference)
    new_path = Path(args.candidate)
    if not ref_path.is_file():
        print(f"USAGE: reference {ref_path} not found")
        return 2
    if not new_path.is_file():
        print(f"FAIL: candidate {new_path} not found (build or run failed?)")
        return 1

    ref_text = ref_path.read_text(errors="replace")
    new_text = new_path.read_text(errors="replace")

    print(_summary("reference", ref_text))
    print(_summary("candidate", new_text))

    new_class, _ = extract_sanitizer_class(new_text)
    if not new_class:
        print("FAIL: candidate has no sanitizer SUMMARY — no crash detected")
        return 1

    if not crash_stacks_match(ref_text, new_text):
        ref_funcs = set(extract_crash_funcs(ref_text))
        new_funcs = set(extract_crash_funcs(new_text))
        ref_files = extract_crash_files(ref_text)
        new_files = extract_crash_files(new_text)
        print(
            "FAIL: candidate stack does not overlap reference — likely a "
            "different bug. Re-apply the change you just reverted."
        )
        print(f"  shared project funcs: {sorted(ref_funcs & new_funcs)}")
        print(f"  shared project files: {sorted(ref_files & new_files)}")
        return 1

    ref_class, _ = extract_sanitizer_class(ref_text)
    if ref_class and new_class and ref_class != new_class:
        print(
            f"PASS (with class drift): {ref_class} -> {new_class}. "
            "Stacks overlap so the same code site is firing under "
            "different sanitizer instrumentation."
        )
    else:
        print("PASS: candidate matches reference.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
