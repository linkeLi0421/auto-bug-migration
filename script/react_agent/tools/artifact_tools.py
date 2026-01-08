from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional


def _repo_root() -> Path:
    # script/react_agent/tools/artifact_tools.py -> script/react_agent/tools -> script/react_agent -> script -> repo
    return Path(__file__).resolve().parents[3]


def _artifact_allow_root() -> Path:
    explicit = str(os.environ.get("REACT_AGENT_ARTIFACT_DIR", "") or "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    root = str(os.environ.get("REACT_AGENT_ARTIFACT_ROOT", "") or "").strip()
    if root:
        return Path(root).expanduser().resolve()
    return (_repo_root() / "data" / "react_agent_artifacts").resolve()


def _clamp_int(value: Any, default: int, *, min_value: int, max_value: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default
    return max(min_value, min(n, max_value))


def _parse_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def read_artifact(
    *,
    artifact_path: str,
    start_line: int = 1,
    max_lines: int = 200,
    query: str = "",
    context_lines: int = 8,
    max_chars: int = 20000,
) -> Dict[str, Any]:
    """Read a slice from an artifact file created during this agent run.

    Notes:
    - max_lines=0 means "read all remaining lines".
    - max_chars=0 means "no character truncation".
    """
    allow_root = _artifact_allow_root()
    if not allow_root.exists():
        raise FileNotFoundError(f"Artifact root does not exist: {allow_root}")

    ap = str(artifact_path or "").strip()
    if not ap:
        raise ValueError("artifact_path must be non-empty")

    path = Path(ap).expanduser().resolve()
    try:
        path.relative_to(allow_root)
    except ValueError as exc:
        raise ValueError(f"artifact_path must be under artifact root: {allow_root}") from exc

    if not path.is_file():
        raise FileNotFoundError(f"Artifact not found: {path}")

    start_n = _clamp_int(start_line, 1, min_value=1, max_value=10_000_000)
    ctx = _clamp_int(context_lines, 8, min_value=0, max_value=200)

    max_lines_raw = _parse_int(max_lines, 200)
    max_lines_n: Optional[int]
    if max_lines_raw == 0:
        max_lines_n = None
    else:
        max_lines_n = _clamp_int(max_lines_raw, 200, min_value=1, max_value=10_000_000)

    max_chars_raw = _parse_int(max_chars, 20000)
    max_chars_n: Optional[int]
    if max_chars_raw == 0:
        max_chars_n = None
    else:
        max_chars_n = _clamp_int(max_chars_raw, 20000, min_value=1, max_value=50_000_000)

    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    total_lines = len(lines)

    match_line: Optional[int] = None
    q = str(query or "")
    if q.strip():
        needle = q
        for idx, line in enumerate(lines, start=1):
            if needle in line:
                match_line = idx
                break
        if match_line is not None:
            start_n = max(match_line - ctx, 1)

    if max_lines_n is None:
        slice_lines = lines[start_n - 1 :]
    else:
        slice_lines = lines[start_n - 1 : start_n - 1 + max_lines_n]
    end_n = start_n + len(slice_lines) - 1 if slice_lines else start_n
    out_text = "\n".join(slice_lines).rstrip("\n") + ("\n" if slice_lines else "")
    truncated = end_n < total_lines
    if max_chars_n is not None and len(out_text) > max_chars_n:
        out_text = out_text[:max_chars_n].rstrip("\n") + "\n...[truncated]"
        truncated = True

    return {
        "artifact_path": str(path),
        "total_lines": total_lines,
        "returned_line_range": [start_n, min(end_n, total_lines) if total_lines else 0],
        "truncated": truncated,
        "query": q.strip() or None,
        "match_line": match_line,
        "text": out_text,
    }
