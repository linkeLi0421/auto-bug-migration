from __future__ import annotations

from typing import Any, Dict, Literal

ToolName = Literal[
    "read_artifact",
    "read_file_context",
    "search_definition",
    "search_definition_in_v1",
    "search_text",
    "ossfuzz_apply_patch_and_test",
    "list_patch_bundle",
    "get_patch",
    "search_patches",
    "get_error_patch",
    "get_error_patch_context",
    "get_error_v1_function_code",
    "make_error_function_patch",
    "parse_build_errors",
]


TOOL_SPECS: list[Dict[str, Any]] = [
    {
        "name": "read_artifact",
        "args": {
            "artifact_path": "string",
            "start_line": "int?",
            "max_lines": "int?",
            "query": "string?",
            "context_lines": "int?",
            "max_chars": "int?",
        },
        "description": "Read a bounded slice from an artifact file produced by this agent run.",
    },
    {
        "name": "read_file_context",
        "args": {"file_path": "string", "line_number": "int", "context": "int", "version": "v1|v2"},
        "description": "Read source context around a source-checkout line number (use KB extents or pre_patch_* mapping in patch-aware runs).",
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
        "name": "search_text",
        "args": {"query": "string", "version": "v1|v2", "limit": "int?", "file_glob": "string?"},
        "description": "Search source files for a literal string (macro/typedef fallback).",
    },
    {
        "name": "ossfuzz_apply_patch_and_test",
        "args": {
            "project": "string",
            "commit": "string",
            "patch_path": "string",
            "patch_override_paths": "list[string]?",
            "build_csv": "string?",
            "sanitizer": "string?",
            "architecture": "string?",
            "engine": "string?",
            "fuzz_target": "string?",
            "run_fuzzer_seconds": "int?",
            "timeout_seconds": "int?",
            "use_sudo": "bool?",
        },
    "description": "Merge a tmp_patch bundle with override patch diff files, then run OSS-Fuzz Docker build/check_build.",
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
        "name": "get_error_patch_context",
        "args": {
            "patch_path": "string",
            "file_path": "string",
            "line_number": "int",
            "error_text": "string?",
            "context_lines": "int?",
            "max_total_lines": "int?",
        },
        "description": "Map a build error location to a patch and return a bounded diff excerpt + pre_patch_* line mapping when available.",
    },
    {
        "name": "get_error_v1_function_code",
        "args": {
            "patch_path": "string",
            "file_path": "string",
            "line_number": "int",
            "max_lines": "int?",
            "max_chars": "int?",
        },
        "description": "Extract the V1-origin function body from the patch bundle for a build error location (from '-' lines in the mapped function slice).",
    },
    {
        "name": "make_error_function_patch",
        "args": {
            "patch_path": "string",
            "file_path": "string",
            "line_number": "int",
            "new_func_code": "string",
            "context_lines": "int?",
            "max_lines": "int?",
            "max_chars": "int?",
        },
        "description": "Rewrite the mapped recreated-function slice in the patch bundle by replacing its '-' lines with the provided code (each line stored as '-...') and recomputing hunk lengths.",
    },
    {
        "name": "parse_build_errors",
        "args": {"build_log_path": "string?", "build_log_text": "string?"},
        "description": "Parse compiler errors into structured fields (read-only).",
    },
]

ALLOWED_TOOLS: set[str] = {str(spec.get("name", "")) for spec in TOOL_SPECS}
