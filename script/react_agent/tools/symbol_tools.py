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

    def kb_search_symbols(
        self,
        symbols: List[str],
        *,
        version: str = "v2",
        kinds: Optional[List[str]] = None,
        limit_per_symbol: int = 5,
    ) -> Dict[str, Any]:
        """Query the KB index for existence/locations/snippets of symbols (batch-friendly).

        This is intended to replace repo-wide grep for most agent workflows, including macro
        definition lookups (MACRO_DEFINITION).
        """
        ver = str(version).strip().lower()
        if ver not in {"v1", "v2"}:
            return {"version": ver, "results": [], "error": "invalid version"}

        limit_n = max(0, min(int(limit_per_symbol or 0), 50))
        kind_set = {str(k).strip() for k in (kinds or []) if str(k).strip()} or None

        def is_definition(node: dict) -> bool:
            kind = str(node.get("kind", "") or "")
            return node.get("is_definition") is True or kind.endswith(("DEFI", "DEF", "DEFINITION")) or kind in {
                "STRUCT_DECL",
                "UNION_DECL",
                "ENUM_DECL",
                "MACRO_DEFINITION",
            }

        def extent_lines(node: dict) -> int:
            extent = node.get("extent", {}) if isinstance(node.get("extent"), dict) else {}
            start = extent.get("start", {}) if isinstance(extent.get("start"), dict) else {}
            end = extent.get("end", {}) if isinstance(extent.get("end"), dict) else {}
            sl = int(start.get("line", 0) or 0)
            el = int(end.get("line", 0) or 0)
            if sl > 0 and el >= sl:
                return el - sl + 1
            return 0

        def loc_tuple(node: dict) -> Tuple[str, int, int]:
            loc = node.get("location", {}) if isinstance(node.get("location"), dict) else {}
            fp = str(loc.get("file", "") or "")
            ln = int(loc.get("line", 0) or 0)
            col = int(loc.get("column", 0) or 0)
            return fp, ln, col

        results: List[Dict[str, Any]] = []
        for raw in symbols or []:
            sym = str(raw or "").strip()
            if not sym:
                continue

            nodes = self.kb_index.query_all(sym).get(ver, [])
            if kind_set is not None:
                nodes = [n for n in nodes if isinstance(n, dict) and str(n.get("kind", "") or "").strip() in kind_set]

            def rank(n: dict) -> Tuple[int, int, int, int]:
                fp, ln, col = loc_tuple(n)
                # Higher is better for the first two. Then stable-ish ordering by location.
                return (1 if is_definition(n) else 0, extent_lines(n), -ln, -col)

            nodes_sorted = sorted([n for n in nodes if isinstance(n, dict)], key=rank, reverse=True)
            truncated = False
            chosen = nodes_sorted
            if limit_n and len(nodes_sorted) > limit_n:
                chosen = nodes_sorted[:limit_n]
                truncated = True

            matches: List[Dict[str, Any]] = []
            for n in chosen:
                fp, ln, col = loc_tuple(n)
                code = self.source_manager.get_function_code(n, ver).rstrip("\n")
                matches.append(
                    {
                        "kind": str(n.get("kind", "") or "").strip(),
                        "file": fp,
                        "line": ln,
                        "column": col,
                        "code": code,
                    }
                )

            results.append(
                {
                    "symbol": sym,
                    "exists": bool(matches),
                    "matches": matches,
                    "truncated": truncated,
                }
            )

        return {"version": ver, "kinds": sorted(kind_set) if kind_set else None, "limit_per_symbol": limit_n, "results": results}
