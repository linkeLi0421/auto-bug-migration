from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.kb_index import KbIndex
from core.source_manager import SourceManager


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

    def read_file_context(self, file_path: str, line_number: int, context: int = 5, version: str = "v2") -> str:
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

    def search_definition(self, symbol_name: str, version: str = "v1") -> str:
        """Return a bounded bundle of symbol definition snippets for the requested version."""
        ver = str(version).strip().lower()
        if ver not in {"v1", "v2"}:
            return ""

        name = str(symbol_name or "").strip()
        if not name:
            return ""

        primary = self.kb_index.query_symbol(name).get(ver)
        if not primary:
            return ""

        max_snippets = 3

        def extent_range(n: dict) -> Tuple[str, int, int]:
            extent = n.get("extent", {}) if isinstance(n.get("extent"), dict) else {}
            start = extent.get("start", {}) if isinstance(extent.get("start"), dict) else {}
            end = extent.get("end", {}) if isinstance(extent.get("end"), dict) else {}
            loc = n.get("location", {}) if isinstance(n.get("location"), dict) else {}
            file_path = str(start.get("file") or loc.get("file") or "Unknown")
            start_line = int(start.get("line") or loc.get("line") or 0)
            end_line = int(end.get("line") or start_line or 0)
            return file_path, start_line, end_line

        def node_key(n: dict) -> str:
            usr = str(n.get("usr", "") or "").strip()
            fp, sl, el = extent_range(n)
            kind = str(n.get("kind", "") or "")
            spelling = str(n.get("spelling", "") or "")
            reason = str(n.get("__reason", "") or "").strip()
            # For pseudo candidates derived from nested extents (e.g. type_ref.typedef_extent),
            # include the extent in the key even when a USR is present; otherwise we may drop
            # the real definition if multiple extents share the same USR.
            if reason:
                return f"pseudo:{usr}:{kind}:{spelling}:{fp}:{sl}:{el}:{reason}"
            if usr:
                return f"usr:{usr}"
            return f"ext:{kind}:{spelling}:{fp}:{sl}:{el}"

        def snippet_lines(n: dict) -> int:
            _, sl, el = extent_range(n)
            if sl > 0 and el > 0 and el >= sl:
                return el - sl + 1
            return 0

        def looks_forward_decl(n: dict) -> bool:
            kind = str(n.get("kind", "") or "")
            line_count = snippet_lines(n)
            if kind in {"TYPEDEF_DECL", "STRUCT_DECL", "UNION_DECL", "ENUM_DECL", "TYPE_REF"} and line_count <= 2:
                return True
            return False

        def render_snippet(n: dict, *, title: str) -> str:
            kind = str(n.get("kind", "") or "Unknown")
            fp, sl, el = extent_range(n)
            reason = str(n.get("__reason", "") or "").strip()
            reason_suffix = f" ({reason})" if reason else ""
            where = fp
            if sl > 0 and el > 0:
                where = f"{fp}:{sl}-{el}"
            elif sl > 0:
                where = f"{fp}:{sl}"
            code = self.source_manager.get_function_code(n, ver).rstrip("\n")
            return (
                f"{title}:\n"
                f"- kind: {kind}{reason_suffix}\n"
                f"- file: {where}\n"
                "Code:\n"
                f"{code}"
            ).rstrip("\n")

        primary_text = render_snippet(primary, title="Primary match")

        # Gather related candidates from all nodes for the symbol (TYPE_REF often carries the real extent).
        all_nodes = self.kb_index.query_all(name).get(ver, [])
        related: List[dict] = []
        seen: set[str] = {node_key(primary)}
        for n in all_nodes:
            for cand in self.kb_index.related_definition_candidates(n, ver):
                k = node_key(cand)
                if k in seen:
                    continue
                seen.add(k)
                related.append(cand)

        def related_rank(n: dict) -> Tuple[int, int, int]:
            kind = str(n.get("kind", "") or "")
            is_def = 1 if (n.get("is_definition") is True or kind in {"STRUCT_DECL", "UNION_DECL", "ENUM_DECL"}) else 0
            return (is_def, snippet_lines(n), 0 if looks_forward_decl(n) else 1)

        related.sort(key=related_rank, reverse=True)

        real_definition: Optional[dict] = None
        if looks_forward_decl(primary):
            for cand in related:
                if snippet_lines(cand) > max(3, snippet_lines(primary)):
                    real_definition = cand
                    break

        pieces: List[str] = []
        header = "=== Version 1 ===" if ver == "v1" else "=== Version 2 ==="
        pieces.append(header)
        pieces.append(f"Symbol: {name}")
        pieces.append("")
        pieces.append(primary_text)

        remaining = related
        if real_definition is not None:
            pieces.append("")
            pieces.append(render_snippet(real_definition, title="Real definition"))
            remaining = [c for c in related if node_key(c) != node_key(real_definition)]

        if remaining:
            pieces.append("")
            pieces.append("Related definitions:")
            for idx, cand in enumerate(remaining[: max(0, max_snippets - (1 if real_definition else 0))], start=1):
                kind = str(cand.get("kind", "") or "Unknown")
                fp, sl, el = extent_range(cand)
                reason = str(cand.get("__reason", "") or "").strip()
                reason_suffix = f" ({reason})" if reason else ""
                where = fp
                if sl > 0 and el > 0:
                    where = f"{fp}:{sl}-{el}"
                elif sl > 0:
                    where = f"{fp}:{sl}"
                code = self.source_manager.get_function_code(cand, ver).rstrip("\n")
                pieces.append(f"{idx}. kind: {kind}{reason_suffix} file: {where}")
                pieces.append("   Code:")
                pieces.append("\n".join(f"   {line}" for line in code.splitlines()) if code else "   (no code)")

        return "\n".join(pieces).rstrip("\n")

    def search_text(self, query: str, *, version: str = "v2", limit: int = 20, file_glob: str = "") -> Dict[str, Any]:
        """Search for a literal string in the source tree (macro/typedef fallback)."""
        q = str(query or "")
        ver = str(version).strip().lower()
        limit_n = max(0, min(int(limit or 0), 200))
        if ver not in {"v1", "v2"}:
            return {"query": q, "version": ver, "matches": [], "truncated": False, "error": "invalid version"}
        if not q or limit_n <= 0:
            return {"query": q, "version": ver, "matches": [], "truncated": False, "error": ""}

        root = self.source_manager._repo_root(ver)
        patterns = [str(file_glob)] if str(file_glob or "").strip() else [
            "*.h",
            "*.hpp",
            "*.hh",
            "*.hxx",
            "*.c",
            "*.cc",
            "*.cpp",
            "*.cxx",
            "*.inc",
        ]

        matches: List[Dict[str, Any]] = []
        scanned_files = 0
        truncated = False
        for pattern in patterns:
            for path in root.rglob(pattern):
                if not path.is_file():
                    continue
                try:
                    if path.stat().st_size > 2_000_000:
                        continue
                except OSError:
                    continue
                scanned_files += 1
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for line_no, line in enumerate(text.splitlines(), start=1):
                    if q not in line:
                        continue
                    try:
                        file_rel = str(path.relative_to(root))
                    except ValueError:
                        file_rel = str(path)
                    matches.append({"file": file_rel, "line": line_no, "text": line.rstrip("\n")})
                    if len(matches) >= limit_n:
                        truncated = True
                        break
                if truncated:
                    break
            if truncated:
                break

        return {
            "query": q,
            "version": ver,
            "repo_root": str(root),
            "file_glob": str(file_glob or ""),
            "matches": matches,
            "truncated": truncated,
            "scanned_files": scanned_files,
        }
