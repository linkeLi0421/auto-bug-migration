from __future__ import annotations

from typing import Any, Dict, Literal

ToolName = Literal[
    "read_artifact",
    "read_file_context",
    "search_definition",
    "ossfuzz_apply_patch_and_test",
    "list_patch_bundle",
    "get_patch",
    "search_patches",
    "get_error_patch_context",
    "get_link_error_patch_context",
    "make_extra_patch_override",
    "make_error_patch_override",
    "revise_patch_hunk",
    "make_link_error_patch_override",
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
        "description": (
            "Return code for the best matching top-level symbol definition in the requested version "
            "(function/typedef/struct/enum/union/macro-like decls). Not intended for struct *fields*; to locate "
            "members, inspect the parent struct body."
        ),
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
            "timeout_seconds": "int?",
            "use_sudo": "bool?",
        },
    "description": "Merge a tmp_patch bundle with override patch diff files, then run OSS-Fuzz Docker build.",
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
        "description": (
            "Map a compiler/build error location (file_path + line_number) to a patch and return the full unified-diff "
            "hunk excerpt (applyable) plus merged/tail helpers: patch_minus_code (all '-' lines) and error_func_code "
            "(the mapped '-' slice that contains the error location). Also returns pre_patch_* line mapping when available. "
            "Use this for ALL compiler errors (file:line:col: error/warning). "
            "For linker 'undefined reference to' errors use get_link_error_patch_context instead."
        ),
    },
    {
        "name": "get_link_error_patch_context",
        "args": {
            "patch_path": "string",
            "file_path": "string",
            "function_name": "string",
            "error_text": "string?",
            "context_lines": "int?",
            "max_total_lines": "int?",
        },
        "description": (
            "ONLY for linker 'undefined reference to' errors. "
            "Map a linker undefined-reference error to a patch slice using file_path + function_name and return "
            "the full unified-diff hunk excerpt (applyable) plus patch_minus_code (all '-' lines) and "
            "error_func_code (the mapped '-' slice for that function). "
            "Do NOT use this for compiler errors (file:line:col: error/warning) — use get_error_patch_context instead. "
            "IMPORTANT: file_path must be the actual source file name (e.g., 'card-itacns.c' or 'src/libopensc/card-itacns.c'), "
            "NOT a patch_key. Extract the file name from the linker error message (e.g., 'card-itacns.c:(.text...)' → 'card-itacns.c'). "
            "Use error_file_path from context if available."
        ),
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
        "description": (
            "Rewrite the mapped patch slice in the patch bundle by replacing its '-' lines with the provided code (each line stored as '-...') "
            "and recomputing hunk lengths. IMPORTANT: file_path/line_number must be the build-log /src/... error location (not pre_patch_*). "
            "In merged/tail hunks (function-by-function mode), new_func_code MUST rewrite only the mapped slice for the active function (do not include other functions; "
            "do not paste unified-diff headers). patch_text is always returned in full (max_lines/max_chars do not truncate the diff) "
            "to avoid corrupt override patches."
        ),
    },
    {
        "name": "revise_patch_hunk",
        "args": {
            "patch_path": "string",
            "file_path": "string",
            "line_number": "int",
            "revised_hunk": "string",
        },
        "description": (
            "Rewrite a mixed -/+ patch slice using a sign-flipped edited hunk. "
            "Use this for non-__revert_* hunks with both '-' and '+' lines (e.g. LLVMFuzzerTestOneInput call-site edits). "
            "The revised_hunk must use the sign-flipped convention from get_error_patch_context's editable_hunk field: "
            "'-' lines = V2 code being REMOVED (must stay unchanged), '+' lines = V1 code being ADDED (may be edited). "
            "IMPORTANT: file_path/line_number must be the build-log /src/... error location."
        ),
    },
    {
        "name": "make_link_error_patch_override",
        "args": {
            "patch_path": "string",
            "file_path": "string",
            "function_name": "string",
            "new_func_code": "string",
            "error_text": "string?",
            "context_lines": "int?",
            "max_lines": "int?",
            "max_chars": "int?",
        },
        "description": (
            "ONLY for linker 'undefined reference to' errors. "
            "Rewrite a linker-error mapped patch slice by replacing its '-' lines with the provided code (each line stored as '-...') "
            "and recomputing hunk lengths. Use after get_link_error_patch_context when the build fails at link time "
            "with 'undefined reference to ...' inside a __revert_* function. "
            "Do NOT use this for compiler errors — use make_error_patch_override instead."
        ),
    },
    {
        "name": "make_extra_patch_override",
        "args": {"patch_path": "string", "file_path": "string", "symbol_name": "string"},
        "description": (
            "Deterministically extend a file's `_extra_*` hunk to provide a missing declaration/define/typedef. "
            "Use for undeclared function/type/macro issues (including warning-level diagnostics like 'call to undeclared function ...'). "
            "The tool infers the `_extra_<file>` patch_key from file_path and returns a full override diff (never truncated)."
        ),
    },
    {
        "name": "parse_build_errors",
        "args": {"build_log_path": "string?", "build_log_text": "string?"},
        "description": "Parse compiler errors into structured fields (read-only).",
    },
]

ALLOWED_TOOLS: set[str] = {str(spec.get("name", "")) for spec in TOOL_SPECS}
