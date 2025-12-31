from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


_DEFINITION_KINDS = {
    "FUNCTION_DEFI",
    "CXX_METHOD",
    "FUNCTION_TEMPLATE",
    "STRUCT_DECL",
    "UNION_DECL",
    "ENUM_DECL",
}


def _is_definition(node: dict) -> bool:
    kind = str(node.get("kind", ""))
    if node.get("is_definition") is True:
        return True
    if kind in _DEFINITION_KINDS:
        return True
    return kind.endswith(("DEFI", "DEF", "DEFINITION"))


def _select_best(nodes: List[dict]) -> Optional[dict]:
    if not nodes:
        return None
    def kind_score(kind: str) -> int:
        order = {
            "FUNCTION_DEFI": 50,
            "CXX_METHOD": 45,
            "FUNCTION_TEMPLATE": 40,
            "FUNCTION_DECL": 10,
        }
        return order.get(kind, 0)

    def file_score(file_path: str) -> int:
        fp = file_path.strip()
        if "#include" in fp:
            return 0
        lowered = fp.replace("\\", "/").lower()
        penalty = 0
        for bad in ("/fuzz/", "fuzz/", "/test/", "test/", "/tests/", "tests/", "/example/", "examples/"):
            if bad in lowered:
                penalty -= 10
                break
        suffix = Path(fp).suffix.lower()
        if suffix in {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}:
            return 30 + penalty
        if suffix in {".h", ".hh", ".hpp", ".hxx"}:
            return 20 + penalty
        if suffix:
            return 10 + penalty
        return 5 + penalty

    def extent_score(node: dict) -> int:
        extent = node.get("extent", {})
        start = extent.get("start", {})
        end = extent.get("end", {})
        start_line = int(start.get("line", 0) or 0)
        end_line = int(end.get("line", 0) or 0)
        if start_line and end_line:
            length = max(end_line - start_line, 0)
            return 5 + min(length, 200)
        return 0

    def rank(node: dict) -> Tuple[int, int, int, int, int, int]:
        kind = str(node.get("kind", ""))
        file_path = str(node.get("location", {}).get("file", ""))
        loc = node.get("location", {}) or {}
        line = int(loc.get("line", 10**9) or 10**9)
        col = int(loc.get("column", 10**9) or 10**9)
        return (
            1 if _is_definition(node) else 0,
            file_score(file_path),
            kind_score(kind),
            extent_score(node),
            -line,
            -col,
        )

    return max(nodes, key=rank)


class KbIndex:
    """Aggregate scattered JSON files into an in-memory index."""

    def __init__(self, v1_root_dir: str, v2_root_dir: str) -> None:
        """Load JSON analysis data and build USR and name-based indices."""
        self.index: Dict[str, Dict[str, List[dict]]] = {}
        self.name_index: Dict[str, Dict[str, List[dict]]] = {}
        self.signature_index: Dict[str, Dict[str, List[dict]]] = {}
        self.file_index: Dict[str, Dict[str, List[dict]]] = {"v1": {}, "v2": {}}
        self._load_dir(Path(v1_root_dir), "v1")
        self._load_dir(Path(v2_root_dir), "v2")

    def _load_dir(self, root: Path, version: str) -> None:
        for json_path in sorted(root.rglob("*_analysis.json")):
            try:
                with json_path.open(encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, list):
                continue
            for node in data:
                if not isinstance(node, dict):
                    continue
                usr = node.get("usr")
                spelling = node.get("spelling")
                signature = node.get("signature")
                file_path = node.get("location", {}).get("file")
                if usr:
                    self.index.setdefault(usr, {"v1": [], "v2": []})[version].append(node)
                if spelling:
                    self.name_index.setdefault(spelling, {"v1": [], "v2": []})[version].append(
                        node
                    )
                if signature:
                    self.signature_index.setdefault(signature, {"v1": [], "v2": []})[version].append(
                        node
                    )
                if file_path:
                    self.file_index[version].setdefault(file_path, []).append(node)

    def query_symbol(self, name_or_usr: str) -> Dict[str, Optional[dict]]:
        """Return the best V1/V2 node for a symbol name or USR."""
        if name_or_usr in self.index:
            entry = self.index[name_or_usr]
        elif name_or_usr in self.signature_index:
            entry = self.signature_index[name_or_usr]
        else:
            entry = self.name_index.get(name_or_usr, {"v1": [], "v2": []})
        v1_nodes = entry.get("v1", [])
        v2_nodes = entry.get("v2", [])
        if name_or_usr not in self.index and name_or_usr not in self.signature_index:
            v1_files = {n.get("location", {}).get("file") for n in v1_nodes if isinstance(n, dict)}
            v2_files = {n.get("location", {}).get("file") for n in v2_nodes if isinstance(n, dict)}
            common = {f for f in (v1_files & v2_files) if f}
            if common:
                v1_nodes = [n for n in v1_nodes if n.get("location", {}).get("file") in common]
                v2_nodes = [n for n in v2_nodes if n.get("location", {}).get("file") in common]
        return {"v1": _select_best(v1_nodes), "v2": _select_best(v2_nodes)}

    def query_all(self, name_or_usr: str) -> Dict[str, List[dict]]:
        """Return all V1/V2 nodes for a symbol name, signature, or USR."""
        if name_or_usr in self.index:
            entry = self.index[name_or_usr]
        elif name_or_usr in self.signature_index:
            entry = self.signature_index[name_or_usr]
        else:
            entry = self.name_index.get(name_or_usr, {"v1": [], "v2": []})
        return {"v1": list(entry.get("v1", [])), "v2": list(entry.get("v2", []))}

    def get_callers_callees(self, name: str, version: str = "v1") -> List[str]:
        """Return a list of dependencies found in a function's file scope nodes."""
        node = self.query_symbol(name).get(version)
        if not node:
            return []
        extent = node.get("extent", {})
        start = extent.get("start", {})
        end = extent.get("end", {})
        file_path = start.get("file") or node.get("location", {}).get("file")
        if not file_path:
            return []
        start_line = int(start.get("line", 0))
        end_line = int(end.get("line", 0))
        has_extent = start_line > 0 and end_line > 0
        deps: List[str] = []
        call_kinds = {"CALL_EXPR", "CXX_METHOD_CALL_EXPR"}
        for ast_node in self.file_index.get(version, {}).get(file_path, []):
            if not isinstance(ast_node, dict):
                continue
            kind = ast_node.get("kind")
            if kind not in call_kinds:
                if kind == "DECL_REF_EXPR" and "callee" in ast_node:
                    pass
                else:
                    continue
            loc = ast_node.get("location", {})
            if loc.get("file") != file_path:
                continue
            if has_extent:
                line = int(loc.get("line", 0))
                if not (start_line <= line <= end_line):
                    continue
            callee = ast_node.get("callee", {})
            dep = (
                ast_node.get("spelling")
                or callee.get("usr")
                or callee.get("signature")
                or ast_node.get("usr")
            )
            if dep:
                deps.append(dep)
        # Preserve order but avoid duplicates.
        uniq: List[str] = []
        seen: set[str] = set()
        for d in deps:
            if d not in seen:
                seen.add(d)
                uniq.append(d)
        return uniq


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

    def get_code_segment(
        self, file_path: str, start_line: int, end_line: int, version: str
    ) -> str:
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


class AgentTools:
    """High-level tools for the ReAct agent."""

    def __init__(self, kb_index: KbIndex, source_manager: SourceManager) -> None:
        """Bind the KB index and source manager."""
        self.kb_index = kb_index
        self.source_manager = source_manager

    def inspect_symbol(self, symbol_name: str) -> str:
        """Return formatted V1/V2 code for a symbol."""
        nodes = self.kb_index.query_symbol(symbol_name)
        v1_node = nodes.get("v1")
        v2_node = nodes.get("v2")
        v1_code = self.source_manager.get_function_code(v1_node, "v1") if v1_node else ""
        v2_code = self.source_manager.get_function_code(v2_node, "v2") if v2_node else ""
        status = "Missing"
        if v2_node:
            status = "Same" if (v1_code and v2_code and v1_code == v2_code) else "Changed"

        v1_file = v1_node.get("location", {}).get("file") if v1_node else "Unknown"
        v2_file = v2_node.get("location", {}).get("file") if v2_node else "Unknown"
        return (
            "=== Version 1 ===\n"
            f"File: {v1_file}\n"
            "Code:\n"
            f"{v1_code}\n\n"
            "=== Version 2 ===\n"
            f"Status: {status}\n"
            f"File: {v2_file}\n"
            "Code:\n"
            f"{v2_code}"
        )

    def read_file_context(
        self, file_path: str, line_number: int, context: int = 5, version: str = "v2"
    ) -> str:
        """Return source context around a line number."""
        if not file_path or line_number <= 0:
            return ""
        start_line = max(line_number - max(context, 0), 1)
        end_line = max(line_number + max(context, 0), start_line)
        resolved = self.source_manager._resolve_path(file_path, version)
        if not resolved or not resolved.exists():
            return ""
        text = resolved.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        if not lines:
            return ""
        end_line = min(end_line, len(lines))

        numbered: List[str] = []
        for ln in range(start_line, end_line + 1):
            prefix = ">>" if ln == line_number else "  "
            numbered.append(f"{prefix}{ln:6d}: {lines[ln - 1]}")

        return (
            f"File: {file_path}\n"
            f"Resolved: {resolved}\n"
            f"Context: line {line_number} (±{context})\n"
            + "\n".join(numbered)
        )

    def search_definition_in_v1(self, symbol_name: str) -> str:
        """Return V1 code for the best matching symbol definition."""
        node = self.kb_index.query_symbol(symbol_name).get("v1")
        if not node:
            return ""
        file_path = node.get("location", {}).get("file") or "Unknown"
        code = self.source_manager.get_function_code(node, "v1")
        return (
            "=== Version 1 ===\n"
            f"File: {file_path}\n"
            "Code:\n"
            f"{code}"
        )
