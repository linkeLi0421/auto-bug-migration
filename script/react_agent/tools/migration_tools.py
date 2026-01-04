from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict


_SCRIPT_DIR = Path(__file__).resolve().parents[2]
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from migration_tools.tools import (  # noqa: E402
    get_error_patch as _get_error_patch,
    get_error_patch_context as _get_error_patch_context,
    get_error_v1_function_code as _get_error_v1_function_code,
    get_patch as _get_patch,
    list_patch_bundle as _list_patch_bundle,
    make_error_function_patch as _make_error_function_patch,
    parse_build_errors_tool as _parse_build_errors_tool,
    search_patches as _search_patches,
)


def _allowed_roots_from_env() -> list[str] | None:
    raw = os.environ.get("REACT_AGENT_PATCH_ALLOWED_ROOTS", "").strip()
    if not raw:
        return None
    roots = [r.strip() for r in raw.split(os.pathsep) if r.strip()]
    return roots or None


def list_patch_bundle(*, patch_path: str, filter_file: str = "", filter_patch_type: str = "", limit: int = 50) -> Dict[str, Any]:
    return _list_patch_bundle(
        patch_path=patch_path,
        filter_file=filter_file,
        filter_patch_type=filter_patch_type,
        limit=limit,
        allowed_roots=_allowed_roots_from_env(),
    )


def get_patch(*, patch_path: str, patch_key: str, include_text: bool = False, max_lines: int = 200) -> Dict[str, Any]:
    return _get_patch(
        patch_path=patch_path,
        patch_key=patch_key,
        include_text=include_text,
        max_lines=max_lines,
        allowed_roots=_allowed_roots_from_env(),
    )


def search_patches(*, patch_path: str, query: str, limit: int = 50) -> Dict[str, Any]:
    return _search_patches(
        patch_path=patch_path,
        query=query,
        limit=limit,
        allowed_roots=_allowed_roots_from_env(),
    )


def get_error_patch(*, patch_path: str, file_path: str, line_number: int) -> Dict[str, Any]:
    return _get_error_patch(
        patch_path=patch_path,
        file_path=file_path,
        line_number=line_number,
        allowed_roots=_allowed_roots_from_env(),
    )


def get_error_patch_context(
    *,
    patch_path: str,
    file_path: str,
    line_number: int,
    error_text: str = "",
    context_lines: int = 30,
    max_total_lines: int = 200,
) -> Dict[str, Any]:
    return _get_error_patch_context(
        patch_path=patch_path,
        file_path=file_path,
        line_number=line_number,
        error_text=error_text,
        context_lines=context_lines,
        max_total_lines=max_total_lines,
        allowed_roots=_allowed_roots_from_env(),
    )


def get_error_v1_function_code(
    *,
    patch_path: str,
    file_path: str,
    line_number: int,
    max_lines: int = 200,
    max_chars: int = 12000,
) -> Dict[str, Any]:
    return _get_error_v1_function_code(
        patch_path=patch_path,
        file_path=file_path,
        line_number=line_number,
        max_lines=max_lines,
        max_chars=max_chars,
        allowed_roots=_allowed_roots_from_env(),
    )


def make_error_function_patch(
    *,
    patch_path: str,
    file_path: str,
    line_number: int,
    new_func_code: str,
    context_lines: int = 0,
    max_lines: int = 2000,
    max_chars: int = 200000,
) -> Dict[str, Any]:
    return _make_error_function_patch(
        patch_path=patch_path,
        file_path=file_path,
        line_number=line_number,
        new_func_code=new_func_code,
        context_lines=context_lines,
        max_lines=max_lines,
        max_chars=max_chars,
        allowed_roots=_allowed_roots_from_env(),
    )


def parse_build_errors(*, build_log_text: str = "", build_log_path: str = "") -> Dict[str, Any]:
    return _parse_build_errors_tool(
        build_log_text=build_log_text,
        build_log_path=build_log_path,
    )
