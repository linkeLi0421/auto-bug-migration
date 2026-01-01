from __future__ import annotations

from typing import List

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

    def search_definition_in_v1(self, symbol_name: str) -> str:
        """Deprecated: use `search_definition(..., version=\"v1\")`."""
        return self.search_definition(symbol_name, version="v1")

    def search_definition(self, symbol_name: str, version: str = "v1") -> str:
        """Return code for the best matching symbol definition in the requested version."""
        ver = str(version).strip().lower()
        if ver not in {"v1", "v2"}:
            return ""
        node = self.kb_index.query_symbol(symbol_name).get(ver)
        if not node:
            return ""
        file_path = node.get("location", {}).get("file") or "Unknown"
        code = self.source_manager.get_function_code(node, ver)
        header = "=== Version 1 ===" if ver == "v1" else "=== Version 2 ==="
        return f"{header}\n" f"File: {file_path}\n" "Code:\n" f"{code}"

