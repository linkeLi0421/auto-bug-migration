from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


_COMPILER_ERROR_RE = re.compile(
    r"^(?P<file>[^:\n]+):(?P<line>\d+):(?P<col>\d+):\s*(?:fatal\s+)?error:\s*(?P<msg>.*)$"
)
_COMPILER_WARNING_RE = re.compile(r"^(?P<file>[^:\n]+):(?P<line>\d+):(?P<col>\d+):\s*warning:\s*(?P<msg>.*)$")

# Warnings about undeclared functions (treated as errors for our purposes)
_UNDECLARED_FUNC_WARNING_PATTERNS = [
    "call to undeclared function",
    "implicit declaration of function",
    "no previous prototype for function",
]

_LD_IN_FUNCTION_RE = re.compile(r"in function\s*[`'](?P<func>[^`']+)[`']")
_LD_UNDEF_REF_SECTION_RE = re.compile(
    r"(?P<file>[^:\s][^:\n]*):\((?P<section>[^)]*)\):\s*undefined reference to\s*[`'](?P<symbol>[^`']+)[`']"
)
_LD_UNDEF_REF_LINE_RE = re.compile(
    r"(?P<file>[^:\s][^:\n]*):(?P<line>\d+):\s*undefined reference to\s*[`'](?P<symbol>[^`']+)[`']"
)


def _extract_func_from_ld_section(section: str) -> str:
    """Best-effort parse a function name from ld section strings like `.text.foo[foo]+0x1a`."""
    raw = str(section or "").strip()
    if not raw:
        return ""
    m = re.search(r"\.text\.(?P<func>[A-Za-z_][A-Za-z0-9_]*)\b", raw)
    if m:
        return str(m.group("func") or "").strip()
    return ""


def iter_linker_errors(build_log: str, *, snippet_lines: int = 2) -> List[Dict[str, Any]]:
    """Return linker undefined-reference errors parsed from the log in order.

    Output items:
      - kind='linker', file, line (0 if unknown), function (when available), symbol, msg, raw
      - snippet: small context window around the error (includes `in function ...` when present)
    """
    lines = build_log.splitlines()
    errors: List[Dict[str, Any]] = []
    seen: set[tuple[str, int, str, str]] = set()

    current_func = ""
    current_func_idx = -1

    ctx_n = max(0, min(int(snippet_lines or 0), 50))

    def make_snippet(idx: int) -> str:
        start = idx
        if current_func_idx >= 0 and 0 <= idx - current_func_idx <= 3:
            start = current_func_idx
        elif idx > 0 and _LD_IN_FUNCTION_RE.search(lines[idx - 1]):
            start = idx - 1
        # Calculate initial end based on ctx_n lines after the error
        max_end = min(idx + 1 + ctx_n, len(lines))
        end = idx + 1  # Start with just the error line
        # Extend end up to max_end, but stop if we hit another linker error or "in function" for a different func
        for j in range(idx + 1, max_end):
            line_j = lines[j].strip()
            # Stop if we hit another "in function" line (indicates a new error block)
            m_func_j = _LD_IN_FUNCTION_RE.search(line_j)
            if m_func_j:
                func_j = str(m_func_j.group("func") or "").strip()
                # Allow if it's the same function as current error, otherwise stop
                if func_j and func_j != current_func:
                    break
            # Stop if we hit another "undefined reference" line
            if _LD_UNDEF_REF_SECTION_RE.search(line_j) or _LD_UNDEF_REF_LINE_RE.search(line_j):
                break
            # Include clang/collect2 failure lines
            if line_j.startswith("clang: error:") or line_j.startswith("collect2:") or "linker command failed" in line_j:
                end = j + 1
                break
            end = j + 1
        return "\n".join(lines[start:end]).strip()

    for idx, line in enumerate(lines):
        stripped = line.strip()
        m_func = _LD_IN_FUNCTION_RE.search(stripped)
        if m_func:
            cur = str(m_func.group("func") or "").strip()
            if cur:
                current_func = cur
                current_func_idx = idx

        m = _LD_UNDEF_REF_SECTION_RE.search(stripped) or _LD_UNDEF_REF_SECTION_RE.search(line)
        file_path = ""
        line_no = 0
        section = ""
        symbol = ""
        if m:
            file_path = str(m.group("file") or "").strip()
            section = str(m.group("section") or "").strip()
            symbol = str(m.group("symbol") or "").strip()
        else:
            m2 = _LD_UNDEF_REF_LINE_RE.search(stripped) or _LD_UNDEF_REF_LINE_RE.search(line)
            if not m2:
                continue
            file_path = str(m2.group("file") or "").strip()
            try:
                line_no = int(m2.group("line") or 0)
            except (TypeError, ValueError):
                line_no = 0
            symbol = str(m2.group("symbol") or "").strip()

        if not file_path or not symbol:
            continue

        func = _extract_func_from_ld_section(section) or current_func
        msg = f"undefined reference to `{symbol}`"
        key = (file_path, int(line_no or 0), func, symbol)
        if key in seen:
            continue
        seen.add(key)

        errors.append(
            {
                "kind": "linker",
                "file": file_path,
                "line": int(line_no or 0),
                "col": 0,
                "function": func,
                "symbol": symbol,
                "msg": msg,
                "raw": stripped,
                "level": "error",
                "snippet": make_snippet(idx),
            }
        )
    return errors


def load_build_log(path_or_stdin: Optional[str]) -> str:
    """Load a build log from a file path, or stdin when path_or_stdin is '-' / None."""
    if not path_or_stdin or path_or_stdin == "-":
        return sys.stdin.read()
    return Path(path_or_stdin).read_text(encoding="utf-8", errors="replace")


def _is_undeclared_func_warning(line: str) -> bool:
    """Check if a warning line is about an undeclared function."""
    lower = line.lower()
    return any(pattern in lower for pattern in _UNDECLARED_FUNC_WARNING_PATTERNS)


def find_first_fatal(build_log: str) -> Tuple[str, str]:
    """Return the first compiler error line and its full diagnostic block.

    A diagnostic block starts at the first `file:line:col: error:` (or undeclared function warning) line
    and includes all subsequent lines until the next `error:`/`warning:` diagnostic.
    """
    lines = build_log.splitlines()
    for idx, line in enumerate(lines):
        stripped = line.strip()
        # Check for errors
        if _COMPILER_ERROR_RE.match(stripped):
            end = len(lines)
            for j in range(idx + 1, len(lines)):
                nxt = lines[j].strip()
                if _COMPILER_ERROR_RE.match(nxt) or _COMPILER_WARNING_RE.match(nxt):
                    end = j
                    break
            return stripped, "\n".join(lines[idx:end]).strip()
        # Check for undeclared function warnings (treated as errors)
        m_warn = _COMPILER_WARNING_RE.match(stripped)
        if m_warn and _is_undeclared_func_warning(stripped):
            end = len(lines)
            for j in range(idx + 1, len(lines)):
                nxt = lines[j].strip()
                if _COMPILER_ERROR_RE.match(nxt) or _COMPILER_WARNING_RE.match(nxt):
                    end = j
                    break
            return stripped, "\n".join(lines[idx:end]).strip()

    linker_errors = iter_linker_errors(build_log, snippet_lines=6)
    if linker_errors:
        first = linker_errors[0]
        return str(first.get("raw", "") or "").strip(), str(first.get("snippet", "") or "").strip()

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

    # Check if there are any undeclared function warnings in the build log.
    # If so, we filter out "static declaration follows non-static declaration" errors
    # because they're a symptom of the undeclared function, not a root cause.
    has_undeclared_func_warning = any(
        _is_undeclared_func_warning(m.group(0)) for _, level, m in starts if level == "warning"
    )

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

        # Skip "static declaration follows non-static declaration" errors when there are
        # undeclared function warnings. The undeclared function causes an implicit non-static
        # declaration; fixing it (by adding proper declaration) resolves this error.
        if has_undeclared_func_warning and "static declaration" in msg and "follows non-static" in msg:
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
