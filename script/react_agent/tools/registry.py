from __future__ import annotations

from typing import Any, Dict, Literal

ToolName = Literal[
    "inspect_symbol",
    "read_file_context",
    "search_definition",
    "search_definition_in_v1",
    "list_patch_bundle",
    "get_patch",
    "search_patches",
    "get_error_patch",
    "parse_build_errors",
]


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
        "name": "search_definition",
        "args": {"symbol_name": "string", "version": "v1|v2"},
        "description": "Return code for the best matching symbol definition in the requested version.",
    },
    {
        "name": "search_definition_in_v1",
        "args": {"symbol_name": "string"},
        "description": "Return V1 code for the best matching symbol definition (deprecated: use search_definition).",
    },
    {
        "name": "list_patch_bundle",
        "args": {"patch_path": "string", "filter_file": "string?", "filter_patch_type": "string?", "limit": "int?"},
        "description": "List patches from a tmp_patch bundle (read-only).",
    },
    {
        "name": "get_patch",
        "args": {"patch_path": "string", "patch_key": "string", "include_text": "bool?", "max_lines": "int?"},
        "description": "Fetch one patch (metadata + optional truncated diff text).",
    },
    {
        "name": "search_patches",
        "args": {"patch_path": "string", "query": "string", "limit": "int?"},
        "description": "Search patches by key/file/signature/type.",
    },
    {
        "name": "get_error_patch",
        "args": {"patch_path": "string", "file_path": "string", "line_number": "int"},
        "description": "Map a build error location to the best patch key/signature.",
    },
    {
        "name": "parse_build_errors",
        "args": {"build_log_path": "string?", "build_log_text": "string?"},
        "description": "Parse compiler errors into structured fields (read-only).",
    },
]

ALLOWED_TOOLS: set[str] = {str(spec.get("name", "")) for spec in TOOL_SPECS}

