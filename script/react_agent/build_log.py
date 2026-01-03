from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


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


def iter_compiler_errors(build_log: str, *, limit: int = 50, snippet_lines: int = 2) -> List[Dict[str, Any]]:
    """Return compiler errors parsed from the log in order.

    Output items:
      - file, line, col, msg, raw
      - snippet: small surrounding context block
    """
    lines = build_log.splitlines()
    errors: List[Dict[str, Any]] = []
    seen: set[Tuple[str, int, int, str]] = set()
    max_n = max(0, min(int(limit or 0), 200))
    ctx = max(0, min(int(snippet_lines or 0), 10))

    for idx, line in enumerate(lines):
        stripped = line.strip()
        m = _COMPILER_ERROR_RE.match(stripped)
        if not m:
            continue
        file_path = str(m.group("file"))
        line_no = int(m.group("line"))
        col_no = int(m.group("col"))
        msg = str(m.group("msg"))

        key = (file_path, line_no, col_no, msg)
        if key in seen:
            continue
        seen.add(key)

        start = max(idx - ctx, 0)
        end = min(idx + ctx + 1, len(lines))
        errors.append(
            {
                "file": file_path,
                "line": line_no,
                "col": col_no,
                "msg": msg,
                "raw": stripped,
                "snippet": "\n".join(lines[start:end]),
            }
        )
        if len(errors) >= max_n:
            break

    return errors
