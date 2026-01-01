from __future__ import annotations

"""Compatibility shim.

New code should import from `script/react_agent/tools/` instead of this module.
"""

from tools.registry import ALLOWED_TOOLS, TOOL_SPECS, ToolName
from tools.runner import ToolObservation, ToolRunner

__all__ = [
    "ALLOWED_TOOLS",
    "TOOL_SPECS",
    "ToolName",
    "ToolObservation",
    "ToolRunner",
]
