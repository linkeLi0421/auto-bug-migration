from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple


class SourceManager:
    """Map JSON paths to local filesystem paths and read code segments."""

    def __init__(self, local_v1_path: str, local_v2_path: str) -> None:
        """Set local repo roots and initialize include resolution caches."""
        self.local_v1_path = Path(local_v1_path).resolve()
        self.local_v2_path = Path(local_v2_path).resolve()
        self._include_cache: Dict[Tuple[str, str], Optional[Path]] = {}
        self._include_dirs = {
            "v1": self._default_include_dirs(self.local_v1_path),
            "v2": self._default_include_dirs(self.local_v2_path),
        }

    def _default_include_dirs(self, root: Path) -> List[Path]:
        include_dir = root / "include"
        return [include_dir] if include_dir.is_dir() else [root]

    def _resolve_include(self, header: str, version: str) -> Optional[Path]:
        cache_key = (version, header)
        if cache_key in self._include_cache:
            return self._include_cache[cache_key]
        for inc_dir in self._include_dirs.get(version, []):
            candidate = inc_dir / header
            if candidate.exists():
                self._include_cache[cache_key] = candidate.resolve()
                return self._include_cache[cache_key]
        for path in self._repo_root(version).rglob(header):
            if path.is_file():
                self._include_cache[cache_key] = path.resolve()
                return self._include_cache[cache_key]
        self._include_cache[cache_key] = None
        return None

    def _repo_root(self, version: str) -> Path:
        return self.local_v1_path if version == "v1" else self.local_v2_path

    def _resolve_path(self, json_path: str, version: str) -> Optional[Path]:
        """Resolve a JSON path to a local file path."""
        if json_path.startswith("/src"):
            rel = json_path[len("/src") :].lstrip("/")
            repo_root = self._repo_root(version)
            repo_name = repo_root.name
            if repo_name:
                rel_norm = rel.replace("\\", "/")
                prefix = f"{repo_name}/"
                if rel_norm == repo_name:
                    rel = ""
                elif rel_norm.startswith(prefix):
                    rel = rel_norm[len(prefix) :]
            return repo_root if not rel else (repo_root / rel)
        if json_path.lstrip().startswith("#include") or "#include" in json_path:
            after = json_path.split("#include", 1)[-1].strip()
            header = (
                after.split("<")[-1].split(">")[0].strip()
                if "<" in after and ">" in after
                else after.strip().strip('"')
            )
            return self._resolve_include(header, version)
        path = Path(json_path)
        if path.is_absolute():
            return path
        return self._repo_root(version) / json_path

    def get_code_segment(self, file_path: str, start_line: int, end_line: int, version: str) -> str:
        """Read a code segment between start_line and end_line (inclusive)."""
        resolved = self._resolve_path(file_path, version)
        if not resolved or not resolved.exists():
            return ""
        text = resolved.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        start = max(start_line - 1, 0)
        end = min(end_line, len(lines))
        return "\n".join(lines[start:end])

    def get_function_code(self, kb_node: dict, version: str) -> str:
        """Return the source code for a node's extent."""
        extent = kb_node.get("extent", {})
        start = extent.get("start", {})
        end = extent.get("end", {})
        file_path = start.get("file") or kb_node.get("location", {}).get("file")
        if not file_path:
            return ""
        start_line = int(start.get("line", 1))
        end_line = int(end.get("line", start_line))
        return self.get_code_segment(file_path, start_line, end_line, version)

