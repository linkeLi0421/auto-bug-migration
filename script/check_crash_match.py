#!/usr/bin/env python3
"""Check whether two crash logs represent the same bug.

CLI wrapper that classifies a (reference, candidate) crash-log pair as
``exact``, ``partial``, ``rejected``, or ``no_data`` using the same logic
``script/rq3_validity.py`` uses for benchmark-level RQ3 reporting.

Designed to be called from inside the OSS-Fuzz container during patch
minimization (and during post-agent transplant verification) so each step
verifies "the candidate after this revert still triggers the SAME bug as
the reference," not just "any sanitizer crash still appears."

Cleaning steps applied to both sides before comparison:
* Drop sanitizer / libFuzzer / libc / compiler-rt infrastructure frames
  (so a library-internal `__asan_memcpy` or `fuzzer::Fuzzer::ExecuteCallback`
  frame doesn't count as a "shared project frame").
* Strip dispatch-wrap function-name suffixes (`_osv_<year>_<id>` and
  `_original`) the merge step appends to gated functions.

Verdict:
* **exact**    — same sanitizer class + same first cleaned project frame
                 + same top-3 (function, file) fingerprint (line drift OK).
* **partial**  — same first cleaned project frame regardless of sanitizer
                 class (SEGV ↔ undefined-behavior at the same site is the
                 same root cause caught by different instrumentation),
                 OR same sanitizer class with non-empty cleaned-frame
                 stack overlap.
* **rejected** — neither holds. The candidate is a different bug.
* **no_data**  — at least one log has no sanitizer SUMMARY.

Exit codes:
  0  PASS  — verdict is ``exact`` or ``partial``.
  1  FAIL  — verdict is ``rejected`` or ``no_data``.
  2  USAGE — bad arguments or missing reference file.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from rq3_validity import classify  # noqa: E402


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
        help="New crash log produced after a build / minimization step.",
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

    verdict, details = classify(ref_text, new_text)

    print(f"reference: class={details['orig_class']!r}  top={details['orig_top']!r}")
    print(f"           top3={details['orig_top3']!r}")
    print(f"candidate: class={details['post_class']!r}  top={details['post_top']!r}")
    print(f"           top3={details['post_top3']!r}")
    print(f"shared funcs: {details['shared_funcs']}  shared files: {details['shared_files']}")

    if verdict == "exact":
        print("PASS (exact): same class + same top project frame + same top-3 fingerprint.")
        return 0
    if verdict == "partial":
        print("PASS (partial): same first project frame — same code site, possibly "
              "different sanitizer instrumentation. Treating as same bug.")
        return 0
    if verdict == "no_data":
        print("FAIL (no_data): candidate has no usable sanitizer SUMMARY — no crash detected.")
        return 1
    # rejected
    print("FAIL (rejected): candidate's first project frame differs from reference "
          "and stacks do not align. Different bug. If you just reverted a change, "
          "re-apply it: `git checkout HEAD -- <file>` (or undo the hunk). The "
          "binary 'still crashes,' but with a bug you introduced — not the one "
          "you were trying to preserve.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
