from __future__ import annotations

"""Compatibility shim.

New code should prefer:
- `core.kb_index.KbIndex`
- `core.source_manager.SourceManager`
- `tools.symbol_tools.AgentTools`
"""

from core.kb_index import KbIndex
from core.source_manager import SourceManager
from tools.symbol_tools import AgentTools

__all__ = [
    "AgentTools",
    "KbIndex",
    "SourceManager",
]

