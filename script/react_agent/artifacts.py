from __future__ import annotations

import hashlib
import os
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_PATCH_TOOL_FIELDS: dict[str, dict[str, str]] = {
    "get_error_patch_context": {"excerpt": ".diff"},
    "get_error_v1_code_slice": {"func_code": ".c"},
    "get_patch": {"patch_text": ".diff"},
    "make_error_patch_override": {"old_func_code": ".c", "patch_text": ".diff"},
    "ossfuzz_apply_patch_and_test": {
        "build_output": ".log",
        "check_build_output": ".log",
        "run_fuzzer_output": ".log",
    },
}


def _repo_root() -> Path:
    # script/react_agent/artifacts.py -> script/react_agent -> script -> repo
    return Path(__file__).resolve().parents[2]


def _safe_filename(name: str, *, max_len: int = 120) -> str:
    raw = str(name or "").strip()
    raw = raw.replace(os.sep, "_")
    # Keep leading/trailing "_" intact (patch_key can legitimately start/end with "_");
    # strip only "."/"-" to avoid hidden/awkward names.
    cleaned = _SAFE_NAME_RE.sub("_", raw).strip(".-")
    if not cleaned:
        cleaned = "artifact"
    return cleaned[:max_len]


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    for i in range(1, 10_000):
        candidate = parent / f"{stem}.{i}{suffix}"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not allocate unique artifact path for: {path}")


def _line_count(text: str) -> int:
    # splitlines() ignores the trailing newline; that’s fine for counting logical lines.
    return len((text or "").splitlines())


@dataclass(frozen=True)
class ArtifactRef:
    artifact_path: str
    sha256: str
    bytes: int
    lines: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_path": self.artifact_path,
            "sha256": self.sha256,
            "bytes": self.bytes,
            "lines": self.lines,
        }


class ArtifactStore:
    """Write-only helper used by the agent runtime to persist large tool outputs."""

    def __init__(self, root_dir: str | Path, *, overwrite: bool = False) -> None:
        self.root = Path(root_dir).expanduser().resolve()
        self._overwrite = bool(overwrite)

    def write_text(self, *, name: str, text: str, ext: str = ".txt") -> ArtifactRef:
        self.root.mkdir(parents=True, exist_ok=True)
        safe = _safe_filename(name)
        ext_norm = str(ext or "")
        if ext_norm and not ext_norm.startswith("."):
            ext_norm = "." + ext_norm
        if not ext_norm:
            ext_norm = ".txt"
        path = self.root / f"{safe}{ext_norm}"
        if self._overwrite:
            try:
                if path.exists():
                    path.unlink()
            except IsADirectoryError as exc:
                raise RuntimeError(f"Artifact path is a directory: {path}") from exc
        else:
            path = _unique_path(path)

        data = (text or "").encode("utf-8", errors="replace")
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        return ArtifactRef(
            artifact_path=str(path),
            sha256=digest,
            bytes=len(data),
            lines=_line_count(text),
        )


def _focus_snippet(text: str, terms: list[str], *, context_lines: int = 10, max_lines: int = 120, max_chars: int = 6000) -> str:
    raw = str(text or "")
    if not raw.strip() or not terms:
        return ""
    lines = raw.splitlines()
    match_idx: Optional[int] = None
    for term in terms:
        t = str(term or "").strip()
        if not t:
            continue
        for i, line in enumerate(lines):
            if t in line:
                match_idx = i
                break
        if match_idx is not None:
            break
    if match_idx is None:
        return ""
    ctx = max(0, min(int(context_lines or 0), 200))
    start = max(match_idx - ctx, 0)
    end = min(match_idx + ctx + 1, len(lines))
    snippet_lines = lines[start:end]
    if max_lines and len(snippet_lines) > int(max_lines):
        snippet_lines = snippet_lines[: int(max_lines)]
    out = "\n".join(snippet_lines).rstrip("\n")
    if max_chars and len(out) > int(max_chars):
        out = out[: int(max_chars)].rstrip("\n") + "\n...[truncated]"
    return out


def _artifact_name(*, tool: str, field: str, args: Dict[str, Any]) -> str:
    parts = [str(tool or "").strip() or "tool", str(field or "").strip() or "output"]
    for key in ("symbol_name", "patch_key", "old_signature", "file_path"):
        v = str(args.get(key, "") or "").strip()
        if not v:
            continue
        if key == "file_path":
            v = Path(v).name
        parts.append(v)
        break
    return "_".join(parts)


def offload_patch_output(
    *, store: ArtifactStore, tool: str, args: Dict[str, Any], output: Any, focus_terms: Optional[list[str]] = None
) -> Any:
    """Persist patch-related outputs to artifacts and replace them with ArtifactRef dictionaries."""
    if not isinstance(output, dict):
        return output

    spec = _PATCH_TOOL_FIELDS.get(str(tool or "").strip())
    if not spec:
        return output

    updated: Dict[str, Any] = dict(output)
    changed = False
    terms = [t for t in (focus_terms or []) if str(t or "").strip()]
    for key, ext in spec.items():
        val = updated.get(key)
        if not isinstance(val, str):
            continue
        if not val.strip():
            continue
        if terms and tool == "get_error_patch_context" and key == "excerpt":
            snippet = _focus_snippet(val, terms)
            if snippet:
                updated.setdefault("focus_excerpt", snippet)
        if terms and tool == "get_error_v1_code_slice" and key == "func_code":
            snippet = _focus_snippet(val, terms)
            if snippet:
                updated.setdefault("focus_func_snippet", snippet)
        ref = store.write_text(name=_artifact_name(tool=tool, field=key, args=args), text=val, ext=ext)
        updated[key] = ref.to_dict()
        changed = True
    return updated if changed else output


def default_run_id() -> str:
    ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    return f"{ts}_{os.getpid()}_{uuid.uuid4().hex[:8]}"


def resolve_artifact_dir(
    *,
    cli_dir: str,
    disabled: bool,
    patch_key: str = "",
    patch_key_overwrite: bool = True,
) -> Tuple[Optional[ArtifactStore], str]:
    """Return (store, artifact_dir) or (None, '') when disabled.

    When selecting the default per-patch_key directory under `REACT_AGENT_ARTIFACT_ROOT`,
    `patch_key_overwrite` controls whether repeated artifact writes reuse the same filenames
    (overwrite=True) or allocate unique filenames (overwrite=False).
    """
    if disabled:
        return None, ""

    explicit = str(cli_dir or "").strip()
    if not explicit:
        explicit = str(os.environ.get("REACT_AGENT_ARTIFACT_DIR", "") or "").strip()

    if explicit:
        store = ArtifactStore(explicit)
        return store, str(store.root)

    root_raw = str(os.environ.get("REACT_AGENT_ARTIFACT_ROOT", "") or "").strip()
    if root_raw:
        root = Path(root_raw).expanduser().resolve()
    else:
        root = _repo_root() / "data" / "react_agent_artifacts"

    patch_key_clean = str(patch_key or "").strip()
    if patch_key_clean:
        safe_key = _safe_filename(patch_key_clean, max_len=160)
        store = ArtifactStore(root / safe_key, overwrite=bool(patch_key_overwrite))
        return store, str(store.root)

    run_id = default_run_id()
    store = ArtifactStore(root / run_id)
    return store, str(store.root)
