from __future__ import annotations

import json
import re
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


def _extract_type_names(type_text: str) -> List[str]:
    """Extract best-effort candidate symbol names from a typedef/type string."""
    text = str(type_text or "").strip()
    if not text:
        return []

    cleaned = re.sub(r"[^A-Za-z0-9_]+", " ", text)
    tokens = [t for t in cleaned.split() if t]
    if not tokens:
        return []

    qualifiers = {
        "const",
        "volatile",
        "restrict",
        "__restrict",
        "__restrict__",
        "signed",
        "unsigned",
        "short",
        "long",
        "static",
        "extern",
        "register",
    }

    names: List[str] = []
    for i, tok in enumerate(tokens):
        if tok in {"struct", "enum", "union"} and i + 1 < len(tokens):
            names.append(tokens[i + 1])

    for tok in reversed(tokens):
        if tok in qualifiers or tok in {"struct", "enum", "union"}:
            continue
        names.append(tok)
        break

    uniq: List[str] = []
    seen: set[str] = set()
    for name in names:
        if name and name not in seen:
            seen.add(name)
            uniq.append(name)
    return uniq


def _pseudo_node_for_extent(*, kind: str, extent: dict, reason: str, spelling: str = "", usr: str = "") -> dict:
    start = extent.get("start", {}) if isinstance(extent, dict) else {}
    file_path = str(start.get("file", "") or "")
    line = int(start.get("line", 0) or 0)
    col = int(start.get("column", 0) or 0)
    node: dict = {
        "kind": kind,
        "spelling": spelling,
        "location": {"file": file_path, "line": line, "column": col},
        "extent": extent,
        "__reason": reason,
    }
    if usr:
        node["usr"] = usr
    return node


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

    @staticmethod
    def _resolve_dir(root: Path) -> Path:
        """Resolve a KB directory, falling back to glob-based prefix matching.

        The caller may pass a full commit hash (e.g. ``project-9e1ffd856614fcfc...``)
        while the actual directory uses a truncated hash (``project-9e1ffd85``).
        """
        if root.is_dir():
            return root
        # Try prefix glob in the parent directory.
        parent = root.parent
        name = root.name
        if parent.is_dir() and name:
            # Try progressively shorter prefixes (min 8 chars) to find a matching dir.
            for length in (len(name), max(len(name) // 2, 8), 8):
                prefix = name[:length]
                candidates = sorted(parent.glob(f"{prefix}*"))
                dirs = [c for c in candidates if c.is_dir()]
                if len(dirs) == 1:
                    return dirs[0]
        return root

    def _load_dir(self, root: Path, version: str) -> None:
        root = self._resolve_dir(root)
        if not root.is_dir():
            return
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
                    self.name_index.setdefault(spelling, {"v1": [], "v2": []})[version].append(node)
                if signature:
                    self.signature_index.setdefault(signature, {"v1": [], "v2": []})[version].append(node)
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

    def related_definition_candidates(self, node: dict, version: str, *, max_depth: int = 4) -> List[dict]:
        """Derive related definition candidates from one KB node.

        This is a best-effort helper intended for cases where the primary symbol
        match is a typedef/forward decl but the KB contains a TYPE_REF pointing
        at the underlying definition extent.
        """
        ver = str(version).strip().lower()
        if ver not in {"v1", "v2"}:
            return []
        if not isinstance(node, dict):
            return []

        results: List[dict] = []
        seen: set[str] = set()

        def node_key(n: dict) -> str:
            usr = str(n.get("usr", "") or "").strip()
            extent = n.get("extent", {}) if isinstance(n.get("extent"), dict) else {}
            start = extent.get("start", {}) if isinstance(extent.get("start"), dict) else {}
            end = extent.get("end", {}) if isinstance(extent.get("end"), dict) else {}
            fp = str(start.get("file", "") or "")
            sl = int(start.get("line", 0) or 0)
            el = int(end.get("line", 0) or 0)
            kind = str(n.get("kind", "") or "")
            spelling = str(n.get("spelling", "") or "")
            reason = str(n.get("__reason", "") or "").strip()
            # For pseudo nodes derived from nested extents, include the extent in the key even if
            # they carry the same USR as other candidates; otherwise we may dedup away the real body.
            if reason:
                return f"pseudo:{usr}:{kind}:{spelling}:{fp}:{sl}:{el}:{reason}"
            if usr:
                return f"usr:{usr}"
            return f"ext:{kind}:{spelling}:{fp}:{sl}:{el}"

        def add(n: dict) -> None:
            k = node_key(n)
            if k in seen:
                return
            seen.add(k)
            results.append(n)

        def best_for(query: str) -> Optional[dict]:
            if not query:
                return None
            found = self.query_symbol(query).get(ver)
            return found if isinstance(found, dict) else None

        def visit(n: dict, depth: int) -> None:
            if depth <= 0 or not isinstance(n, dict):
                return

            kind = str(n.get("kind", "") or "")

            if kind == "TYPEDEF_DECL":
                typedef = str(n.get("typedef", "") or "")
                for name in _extract_type_names(typedef):
                    target = best_for(name)
                    if target:
                        add(target)
                        visit(target, depth - 1)

            if kind == "TYPE_REF" or isinstance(n.get("type_ref"), dict):
                type_ref = n.get("type_ref", {}) if isinstance(n.get("type_ref"), dict) else {}
                usr = str(type_ref.get("usr", "") or "").strip()
                if usr:
                    target = best_for(usr)
                    if target:
                        add(target)
                        visit(target, depth - 1)

                typedef_extent = type_ref.get("typedef_extent")
                if isinstance(typedef_extent, dict):
                    start = typedef_extent.get("start", {}) if isinstance(typedef_extent.get("start"), dict) else {}
                    end = typedef_extent.get("end", {}) if isinstance(typedef_extent.get("end"), dict) else {}
                    if str(start.get("file", "") or "").strip() and int(start.get("line", 0) or 0) > 0 and int(end.get("line", 0) or 0) > 0:
                        add(
                            _pseudo_node_for_extent(
                                kind=str(type_ref.get("target_kind", "") or "TYPEDEF_EXTENT"),
                                extent=typedef_extent,
                                reason="type_ref.typedef_extent",
                                spelling=str(type_ref.get("target_name", "") or ""),
                                usr=usr,
                            )
                        )

                underlying = type_ref.get("underlying")
                if isinstance(underlying, dict):
                    extent = underlying.get("extent")
                    if isinstance(extent, dict):
                        start = extent.get("start", {}) if isinstance(extent.get("start"), dict) else {}
                        end = extent.get("end", {}) if isinstance(extent.get("end"), dict) else {}
                        if str(start.get("file", "") or "").strip() and int(start.get("line", 0) or 0) > 0 and int(end.get("line", 0) or 0) > 0:
                            add(
                                _pseudo_node_for_extent(
                                    kind=str(underlying.get("kind", "") or "UNDERLYING_EXTENT"),
                                    extent=extent,
                                    reason="type_ref.underlying.extent",
                                    spelling=str(underlying.get("name", "") or ""),
                                    usr=usr,
                                )
                            )
                    name = str(underlying.get("name", "") or "").strip()
                    if name:
                        target = best_for(name)
                        if target:
                            add(target)
                            visit(target, depth - 1)

        visit(node, max_depth)
        return results

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
            dep = ast_node.get("spelling") or callee.get("usr") or callee.get("signature") or ast_node.get("usr")
            if dep:
                deps.append(dep)
        uniq: List[str] = []
        seen: set[str] = set()
        for d in deps:
            if d not in seen:
                seen.add(d)
                uniq.append(d)
        return uniq
