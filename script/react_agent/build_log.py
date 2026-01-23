from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


_COMPILER_ERROR_RE = re.compile(
    r"^(?P<file>[^:\n]+):(?P<line>\d+):(?P<col>\d+):\s*(?:fatal\s+)?error:\s*(?P<msg>.*)$"
)
_COMPILER_WARNING_RE = re.compile(r"^(?P<file>[^:\n]+):(?P<line>\d+):(?P<col>\d+):\s*warning:\s*(?P<msg>.*)$")

def load_build_log(path_or_stdin: Optional[str]) -> str:
    """Load a build log from a file path, or stdin when path_or_stdin is '-' / None."""
    if not path_or_stdin or path_or_stdin == "-":
        return sys.stdin.read()
    return Path(path_or_stdin).read_text(encoding="utf-8", errors="replace")


def find_first_fatal(build_log: str) -> Tuple[str, str]:
    """Return the first compiler error line and its full diagnostic block.

    A diagnostic block starts at the first `file:line:col: error:` (or warning) line
    and includes all subsequent lines until the next `error:`/`warning:` diagnostic.
    """
    lines = build_log.splitlines()
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if _COMPILER_ERROR_RE.match(stripped):
            end = len(lines)
            for j in range(idx + 1, len(lines)):
                nxt = lines[j].strip()
                if _COMPILER_ERROR_RE.match(nxt) or _COMPILER_WARNING_RE.match(nxt):
                    end = j
                    break
            return stripped, "\n".join(lines[idx:end]).strip()

    # Best-effort fallback if the log doesn't match file:line:col format.
    for idx, line in enumerate(lines):
        if "error:" in line:
            stripped = line.strip()
            end = len(lines)
            for j in range(idx + 1, len(lines)):
                nxt = lines[j]
                if "error:" in nxt or "warning:" in nxt:
                    end = j
                    break
            return stripped, "\n".join(lines[idx:end]).strip()

    return "", ""


def iter_compiler_errors(build_log: str, *, snippet_lines: int = 2) -> List[Dict[str, Any]]:
    """Return compiler errors parsed from the log in order.

    Output items:
      - file, line, col, msg, raw
      - snippet: full diagnostic block (from this error/warning line until the next one)
    """
    lines = build_log.splitlines()
    errors: List[Dict[str, Any]] = []
    seen: set[Tuple[str, int, int, str]] = set()

    # Identify all compiler diagnostic start lines first so we can compute exact blocks.
    starts: List[Tuple[int, str, re.Match[str]]] = []
    for idx, line in enumerate(lines):
        stripped = line.strip()
        level = "error"
        m_err = _COMPILER_ERROR_RE.match(stripped)
        if m_err:
            starts.append((idx, level, m_err))
            continue
        m_warn = _COMPILER_WARNING_RE.match(stripped)
        if m_warn:
            starts.append((idx, "warning", m_warn))
            continue

    for i, (idx, level, m) in enumerate(starts):
        file_path = str(m.group("file"))
        line_no = int(m.group("line"))
        col_no = int(m.group("col"))
        msg = str(m.group("msg"))

        if level == "warning":
            # Include only a small subset of warnings that frequently represent hard build
            # failures in OSS-Fuzz (e.g. -Werror=implicit-function-declaration).
            if (
                "undeclared function" not in msg
                and "implicit declaration of function" not in msg
                and "no previous prototype for function" not in msg
            ):
                continue

        key = (file_path, line_no, col_no, msg)
        if key in seen:
            continue
        seen.add(key)

        end = starts[i + 1][0] if i + 1 < len(starts) else len(lines)
        block = "\n".join(lines[idx:end]).strip()
        errors.append(
            {
                "file": file_path,
                "line": line_no,
                "col": col_no,
                "msg": msg,
                "raw": lines[idx].strip(),
                "level": level,
                "snippet": block,
            }
        )
    return errors
