from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict


_SCRIPT_DIR = Path(__file__).resolve().parents[2]
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from migration_tools.tools import (  # noqa: E402
    get_error_patch as _get_error_patch,
    get_patch as _get_patch,
    list_patch_bundle as _list_patch_bundle,
    parse_build_errors_tool as _parse_build_errors_tool,
    search_patches as _search_patches,
)


def list_patch_bundle(*, patch_path: str, filter_file: str = "", filter_patch_type: str = "", limit: int = 50) -> Dict[str, Any]:
    return _list_patch_bundle(
        patch_path=patch_path,
        filter_file=filter_file,
        filter_patch_type=filter_patch_type,
        limit=limit,
    )


def get_patch(*, patch_path: str, patch_key: str, include_text: bool = False, max_lines: int = 200) -> Dict[str, Any]:
    return _get_patch(
        patch_path=patch_path,
        patch_key=patch_key,
        include_text=include_text,
        max_lines=max_lines,
    )


def search_patches(*, patch_path: str, query: str, limit: int = 50) -> Dict[str, Any]:
    return _search_patches(
        patch_path=patch_path,
        query=query,
        limit=limit,
    )


def get_error_patch(*, patch_path: str, file_path: str, line_number: int) -> Dict[str, Any]:
    return _get_error_patch(
        patch_path=patch_path,
        file_path=file_path,
        line_number=line_number,
    )


def parse_build_errors(*, build_log_text: str = "", build_log_path: str = "") -> Dict[str, Any]:
    return _parse_build_errors_tool(
        build_log_text=build_log_text,
        build_log_path=build_log_path,
    )

