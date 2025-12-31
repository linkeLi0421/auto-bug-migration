from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional

from agent_tools import AgentTools


ToolName = Literal["inspect_symbol", "read_file_context", "search_definition_in_v1"]


TOOL_SPECS: list[Dict[str, Any]] = [
    {
        "name": "inspect_symbol",
        "args": {"symbol_name": "string"},
        "description": "Return formatted V1/V2 code for a symbol.",
    },
    {
        "name": "read_file_context",
        "args": {"file_path": "string", "line_number": "int", "context": "int", "version": "v1|v2"},
        "description": "Read source context around a line number.",
    },
    {
        "name": "search_definition_in_v1",
        "args": {"symbol_name": "string"},
        "description": "Return V1 code for the best matching symbol definition.",
    },
]

ALLOWED_TOOLS: set[str] = {spec["name"] for spec in TOOL_SPECS}


@dataclass(frozen=True)
class ToolObservation:
    """Result of executing a tool call."""

    ok: bool
    tool: str
    args: Dict[str, Any]
    output: str
    error: Optional[str] = None


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class ToolRunner:
    """Dispatch tool calls to AgentTools with best-effort validation."""

    def __init__(self, agent_tools: Optional[AgentTools], mode: Literal["real", "fake"] = "real") -> None:
        self._agent_tools = agent_tools
        self._mode = mode

    def call(self, tool: str, args: Dict[str, Any]) -> ToolObservation:
        """Execute a tool call and return a JSON-serializable observation."""
        if tool not in ALLOWED_TOOLS:
            return ToolObservation(False, tool, args, output="", error=f"Unknown tool: {tool}")
        if not isinstance(args, dict):
            return ToolObservation(False, tool, {}, output="", error="Tool args must be an object")

        if self._mode == "fake":
            return ToolObservation(True, tool, args, output=f"[FAKE TOOL OUTPUT] {tool}({args})")
        if not self._agent_tools:
            return ToolObservation(False, tool, args, output="", error="Tool runner not configured")

        try:
            if tool == "inspect_symbol":
                symbol_name = str(args.get("symbol_name", "")).strip()
                if not symbol_name:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: symbol_name")
                out = self._agent_tools.inspect_symbol(symbol_name)
                return ToolObservation(True, tool, {"symbol_name": symbol_name}, output=out)

            if tool == "search_definition_in_v1":
                symbol_name = str(args.get("symbol_name", "")).strip()
                if not symbol_name:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: symbol_name")
                out = self._agent_tools.search_definition_in_v1(symbol_name)
                return ToolObservation(True, tool, {"symbol_name": symbol_name}, output=out)

            if tool == "read_file_context":
                file_path = str(args.get("file_path", "")).strip()
                line_number = _as_int(args.get("line_number"), 0)
                context = _as_int(args.get("context"), 5)
                version = str(args.get("version", "v2")).strip() or "v2"
                if not file_path:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: file_path")
                if line_number <= 0:
                    return ToolObservation(False, tool, args, output="", error="Invalid arg: line_number")
                out = self._agent_tools.read_file_context(
                    file_path=file_path,
                    line_number=line_number,
                    context=context,
                    version=version,
                )
                return ToolObservation(
                    True,
                    tool,
                    {"file_path": file_path, "line_number": line_number, "context": context, "version": version},
                    output=out,
                )

            return ToolObservation(False, tool, args, output="", error=f"Unhandled tool: {tool}")
        except Exception as exc:  # noqa: BLE001
            return ToolObservation(False, tool, args, output="", error=f"{type(exc).__name__}: {exc}")
