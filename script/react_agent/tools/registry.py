from __future__ import annotations

from typing import Any, Dict, Literal

ToolName = Literal[
    "read_artifact",
    "read_file_context",
    "search_definition",
    "kb_search_symbols",
    "ossfuzz_apply_patch_and_test",
    "list_patch_bundle",
    "get_patch",
    "search_patches",
    "get_error_patch_context",
    "get_error_v1_code_slice",
    "make_error_patch_override",
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
        "name": "kb_search_symbols",
        "args": {"symbols": "list[string]", "version": "v1|v2", "kinds": "list[string]?", "limit_per_symbol": "int?"},
        "description": "Query the clang-JSON KB for symbol existence/locations/snippets (batch-friendly; includes MACRO_DEFINITION).",
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
        "name": "get_error_v1_code_slice",
        "args": {
            "excerpt": "object?",
            "patch_path": "string?",
            "file_path": "string?",
            "line_number": "int?",
            "max_lines": "int?",
            "max_chars": "int?",
        },
        "description": "Extract the V1-origin code slice (from '-' lines) for a build error. Preferred: pass excerpt={artifact_path: ...} from get_error_patch_context.excerpt. Fallback: pass patch_path+file_path+line_number. Also returns macro-token hints (defined_macros / macro_tokens_not_defined_in_slice).",
    },
    {
        "name": "make_error_patch_override",
        "args": {
            "patch_path": "string",
            "file_path": "string",
            "line_number": "int",
            "new_func_code": "string",
            "context_lines": "int?",
            "max_lines": "int?",
            "max_chars": "int?",
        },
        "description": "Rewrite the mapped patch slice in the patch bundle by replacing its '-' lines with the provided code (each line stored as '-...') and recomputing hunk lengths.",
    },
    {
        "name": "parse_build_errors",
        "args": {"build_log_path": "string?", "build_log_text": "string?"},
        "description": "Parse compiler errors into structured fields (read-only).",
    },
]

ALLOWED_TOOLS: set[str] = {str(spec.get("name", "")) for spec in TOOL_SPECS}
