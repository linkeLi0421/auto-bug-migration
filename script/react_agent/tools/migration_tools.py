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
    get_link_error_patch as _get_link_error_patch,
    get_link_error_patch_context as _get_link_error_patch_context,
    get_patch as _get_patch,
    list_patch_bundle as _list_patch_bundle,
    make_error_patch_override as _make_error_patch_override,
    make_link_error_patch_override as _make_link_error_patch_override,
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


def get_link_error_patch(*, patch_path: str, file_path: str, function_name: str) -> Dict[str, Any]:
    return _get_link_error_patch(
        patch_path=patch_path,
        file_path=file_path,
        function_name=function_name,
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


def get_link_error_patch_context(
    *,
    patch_path: str,
    file_path: str,
    function_name: str,
    error_text: str = "",
    context_lines: int = 30,
    max_total_lines: int = 200,
) -> Dict[str, Any]:
    return _get_link_error_patch_context(
        patch_path=patch_path,
        file_path=file_path,
        function_name=function_name,
        error_text=error_text,
        context_lines=context_lines,
        max_total_lines=max_total_lines,
        allowed_roots=_allowed_roots_from_env(),
    )


def make_error_patch_override(
    *,
    patch_path: str,
    file_path: str,
    line_number: int,
    new_func_code: str,
    context_lines: int = 0,
    max_lines: int = 2000,
    max_chars: int = 200000,
) -> Dict[str, Any]:
    return _make_error_patch_override(
        patch_path=patch_path,
        file_path=file_path,
        line_number=line_number,
        new_func_code=new_func_code,
        context_lines=context_lines,
        max_lines=max_lines,
        max_chars=max_chars,
        allowed_roots=_allowed_roots_from_env(),
    )


def make_link_error_patch_override(
    *,
    patch_path: str,
    file_path: str,
    function_name: str,
    new_func_code: str,
    context_lines: int = 0,
    max_lines: int = 2000,
    max_chars: int = 200000,
) -> Dict[str, Any]:
    return _make_link_error_patch_override(
        patch_path=patch_path,
        file_path=file_path,
        function_name=function_name,
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


def make_func_call_fix(
    *,
    patch_path: str,
    file_path: str,
    line_number: int,
    old_call: str,
    new_call: str,
) -> Dict[str, Any]:
    """Apply a targeted line-level fix for function call argument errors.

    Instead of rewriting the entire function body, this replaces just the specific
    call site line(s). Much more efficient for large functions.
    """
    from migration_tools.tools import (
        load_patch_bundle,
        _get_error_patch_from_bundle,
        _norm_path,
    )

    old_call_stripped = old_call.strip()
    new_call_stripped = new_call.strip()

    if not old_call_stripped or not new_call_stripped:
        raise ValueError("old_call and new_call must be non-empty")

    bundle = load_patch_bundle(patch_path, allowed_roots=_allowed_roots_from_env())
    mapping = _get_error_patch_from_bundle(bundle, patch_path=patch_path, file_path=file_path, line_number=line_number)
    patch_key = mapping.get("patch_key")

    if not patch_key or str(patch_key) not in bundle.patches:
        return {
            **mapping,
            "fixed": False,
            "note": "No matching patch_key; cannot apply line fix.",
        }

    func_start = mapping.get("func_start_index")
    func_end = mapping.get("func_end_index")
    if not isinstance(func_start, int) or not isinstance(func_end, int) or func_start < 0 or func_end < 0:
        return {
            **mapping,
            "fixed": False,
            "note": "Patch mapping lacks a rewriteable '-' slice; cannot apply line fix.",
        }

    patch = bundle.patches[str(patch_key)]
    patch_lines = (patch.patch_text or "").splitlines()
    if len(patch_lines) < 4:
        return {
            **mapping,
            "fixed": False,
            "note": "Patch text is too short.",
        }

    first_hunk_idx = next((i for i, l in enumerate(patch_lines) if l.startswith("@@")), -1)
    body_start = first_hunk_idx + 1 if first_hunk_idx >= 0 else 4
    body_len = len(patch_lines) - body_start
    func_start_n = max(0, min(int(func_start), body_len))
    func_end_n = max(0, min(int(func_end), body_len))

    if func_end_n <= func_start_n:
        return {
            **mapping,
            "fixed": False,
            "note": "Invalid patch slice indices.",
        }

    slice_start = body_start + func_start_n
    slice_end = body_start + func_end_n

    # Find and replace the old_call in the '-' lines within the slice
    fixed_count = 0
    for i in range(slice_start, slice_end):
        line = patch_lines[i]
        if not line.startswith("-"):
            continue
        line_content = line[1:]  # Remove the '-' prefix
        if old_call_stripped in line_content:
            # Replace the call in this line
            new_line_content = line_content.replace(old_call_stripped, new_call_stripped)
            patch_lines[i] = "-" + new_line_content
            fixed_count += 1

    if fixed_count == 0:
        return {
            **mapping,
            "fixed": False,
            "note": f"Could not find '{old_call_stripped}' in the mapped patch slice.",
            "old_call": old_call_stripped,
        }

    # Recompute hunk header (line counts may change if new_call spans multiple lines)
    # For simple replacements, counts stay the same
    new_patch_text = "\n".join(patch_lines)

    # Update the patch in the bundle
    patch.patch_text = new_patch_text

    # Save the updated bundle
    import pickle
    with open(patch_path, "wb") as f:
        pickle.dump(bundle, f)

    return {
        **mapping,
        "fixed": True,
        "fixed_count": fixed_count,
        "old_call": old_call_stripped,
        "new_call": new_call_stripped,
        "note": f"Replaced {fixed_count} occurrence(s) of the call site.",
    }
