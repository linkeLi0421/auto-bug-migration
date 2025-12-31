from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional, Tuple


_COMPILER_ERROR_RE = re.compile(
    r"^(?P<file>[^:\n]+):(?P<line>\d+):(?P<col>\d+):\s*(?:fatal\s+)?error:\s*(?P<msg>.*)$"
)


def load_build_log(path_or_stdin: Optional[str]) -> str:
    """Load a build log from a file path, or stdin when path_or_stdin is '-' / None."""
    if not path_or_stdin or path_or_stdin == "-":
        return sys.stdin.read()
    return Path(path_or_stdin).read_text(encoding="utf-8", errors="replace")


def find_first_fatal(build_log: str) -> Tuple[str, str]:
    """Return the first compiler error line and a small surrounding snippet."""
    lines = build_log.splitlines()
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if _COMPILER_ERROR_RE.match(stripped):
            start = max(idx - 5, 0)
            end = min(idx + 6, len(lines))
            return stripped, "\n".join(lines[start:end])

    # Best-effort fallback if the log doesn't match file:line:col format.
    for idx, line in enumerate(lines):
        if "error:" in line:
            stripped = line.strip()
            start = max(idx - 5, 0)
            end = min(idx + 6, len(lines))
            return stripped, "\n".join(lines[start:end])

    return "", ""

