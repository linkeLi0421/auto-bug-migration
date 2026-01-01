from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .build_errors import parse_build_errors
from .patch_bundle import PatchBundle, load_patch_bundle
from .types import PatchInfo


_HUNK_RE = re.compile(r"^@@ -(?P<old_start>\d+)(?:,(?P<old_len>\d+))? \\+(?P<new_start>\d+)(?:,(?P<new_len>\d+))? @@")


def _parse_first_hunk(patch_text: str) -> Optional[Tuple[int, int, int, int]]:
    for line in (patch_text or "").splitlines():
        if not line.startswith("@@"):
            continue
        m = _HUNK_RE.match(line.strip())
        if not m:
            continue
        old_start = int(m.group("old_start"))
        old_len = int(m.group("old_len") or 1)
        new_start = int(m.group("new_start"))
        new_len = int(m.group("new_len") or 1)
        return old_start, old_len, new_start, new_len
    return None


def _norm_path(path: str) -> str:
    return str(path or "").replace("\\", "/")


def _file_candidates(file_path: str) -> List[str]:
    fp = _norm_path(file_path).strip()
    candidates: List[str] = []
    if not fp:
        return candidates
    candidates.append(fp.lstrip("./"))
    if "/src/" in fp:
        after = fp.split("/src/", 1)[1]
        candidates.append(after)
        parts = after.split("/")
        if len(parts) > 1:
            candidates.append("/".join(parts[1:]))
    candidates.append(fp.lstrip("/"))
    # Dedup preserve order
    seen: set[str] = set()
    out: List[str] = []
    for c in candidates:
        c2 = c.strip("/")
        if not c2 or c2 in seen:
            continue
        seen.add(c2)
        out.append(c2)
    return out


def _file_matches(patch_file: str, file_path: str) -> bool:
    pf = _norm_path(patch_file).strip().lstrip("./").strip("/")
    if not pf:
        return False
    for c in _file_candidates(file_path):
        if pf == c:
            return True
        if c.endswith("/" + pf):
            return True
        if pf.endswith("/" + c):
            return True
    return False


def _patch_summary(key: str, patch: PatchInfo) -> Dict[str, Any]:
    return {
        "key": key,
        "file_path_old": patch.file_path_old,
        "file_path_new": patch.file_path_new,
        "file_type": patch.file_type,
        "old_start_line": patch.old_start_line,
        "old_end_line": patch.old_end_line,
        "new_start_line": patch.new_start_line,
        "new_end_line": patch.new_end_line,
        "patch_type": sorted(list(patch.patch_type or set())),
        "old_signature": patch.old_signature,
        "new_signature": patch.new_signature,
    }


def list_patch_bundle(
    *,
    patch_path: str,
    filter_file: str = "",
    filter_patch_type: str = "",
    limit: int = 50,
    allowed_roots: Optional[List[str]] = None,
) -> Dict[str, Any]:
    bundle = load_patch_bundle(patch_path, allowed_roots=allowed_roots)
    limit_n = max(0, min(int(limit or 0), 200))
    file_filter = str(filter_file or "").strip()
    pt_filter = str(filter_patch_type or "").strip()

    matches: List[Dict[str, Any]] = []
    for key in bundle.keys_sorted:
        patch = bundle.patches[key]
        if file_filter and not _file_matches(patch.file_path_new, file_filter):
            continue
        if pt_filter and pt_filter not in (patch.patch_type or set()):
            continue
        matches.append(_patch_summary(key, patch))
        if len(matches) >= limit_n:
            break

    return {
        "patch_path": str(Path(patch_path)),
        "total": len(bundle.patches),
        "matched": len(matches),
        "limit": limit_n,
        "patches": matches,
    }


def get_patch(
    *,
    patch_path: str,
    patch_key: str,
    include_text: bool = False,
    max_lines: int = 200,
    allowed_roots: Optional[List[str]] = None,
) -> Dict[str, Any]:
    bundle = load_patch_bundle(patch_path, allowed_roots=allowed_roots)
    key = str(patch_key)
    if key not in bundle.patches:
        raise KeyError(f"Unknown patch_key: {key}")
    patch = bundle.patches[key]
    out = _patch_summary(key, patch)
    if include_text:
        max_n = max(0, min(int(max_lines or 0), 1000))
        lines = (patch.patch_text or "").splitlines()
        truncated = len(lines) > max_n
        text = "\n".join(lines[:max_n])
        out["patch_text"] = text
        out["patch_text_truncated"] = truncated
        out["patch_text_lines_total"] = len(lines)
        out["patch_text_lines_returned"] = len(text.splitlines()) if text else 0
    return out


def search_patches(*, patch_path: str, query: str, limit: int = 50, allowed_roots: Optional[List[str]] = None) -> Dict[str, Any]:
    bundle = load_patch_bundle(patch_path, allowed_roots=allowed_roots)
    q = str(query or "").strip().lower()
    limit_n = max(0, min(int(limit or 0), 200))
    if not q:
        return {"patch_path": str(Path(patch_path)), "query": "", "matched": 0, "patches": []}

    matches: List[Dict[str, Any]] = []
    for key in bundle.keys_sorted:
        patch = bundle.patches[key]
        hay = " ".join(
            [
                key,
                str(patch.file_path_old or ""),
                str(patch.file_path_new or ""),
                str(patch.old_signature or ""),
                str(patch.new_signature or ""),
                " ".join(sorted(list(patch.patch_type or set()))),
            ]
        ).lower()
        if q not in hay:
            continue
        matches.append(_patch_summary(key, patch))
        if len(matches) >= limit_n:
            break

    return {"patch_path": str(Path(patch_path)), "query": q, "matched": len(matches), "limit": limit_n, "patches": matches}


def get_error_patch(
    *, patch_path: str, file_path: str, line_number: int, allowed_roots: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Best-effort mapping from a build error location to a patch key in the bundle."""
    bundle = load_patch_bundle(patch_path, allowed_roots=allowed_roots)
    ln = int(line_number or 0)
    if ln <= 0:
        raise ValueError("line_number must be > 0")

    add_num = 0
    key_of_line_num: Optional[str] = None
    selected_hunk: Optional[Tuple[int, int, int, int]] = None

    # Replicate revert_patch_test.get_error_patch ordering: patch_key_list sorted by new_start_line desc,
    # then scanned in reverse while adjusting offsets.
    for key in reversed(bundle.keys_sorted):
        patch = bundle.patches[key]
        if not _file_matches(patch.file_path_new, file_path):
            continue
        hunk = _parse_first_hunk(patch.patch_text) or (
            int(patch.old_start_line or 0),
            max(int((patch.old_end_line or 0) - (patch.old_start_line or 0)), 0),
            int(patch.new_start_line or 0),
            max(int((patch.new_end_line or 0) - (patch.new_start_line or 0)), 0),
        )
        old_start, old_len, new_start, new_len = hunk
        if old_len <= 0:
            add_num += new_len - old_len
            continue
        if new_start <= ln + add_num <= new_start + old_len - 1:
            key_of_line_num = key
            selected_hunk = hunk
            break
        add_num += new_len - old_len

    if not key_of_line_num:
        return {
            "patch_path": str(Path(patch_path)),
            "file_path": file_path,
            "line_number": ln,
            "patch_key": None,
            "old_signature": None,
            "func_start_index": None,
            "func_end_index": None,
        }

    patch = bundle.patches[key_of_line_num]
    old_function_signature = patch.old_signature

    if "Recreated function" not in (patch.patch_type or set()):
        return {
            "patch_path": str(Path(patch_path)),
            "file_path": file_path,
            "line_number": ln,
            "patch_key": key_of_line_num,
            "old_signature": old_function_signature,
            "func_start_index": None,
            "func_end_index": None,
        }

    # Best-effort port of the original logic for recreated-function patches.
    patch_lines = (patch.patch_text or "").split("\n")
    front_context_num = next((i for i, x in enumerate(patch_lines[4:]) if x and x[0] == "-"), -1)

    old_start = selected_hunk[0] if selected_hunk else int(patch.old_start_line or 0)
    index_old_infun = 0
    patch_flag = False
    for line in patch_lines[front_context_num + 4 :]:
        if line.startswith("-"):
            index_old_infun += 1
            if not patch_flag:
                patch_flag = True
        elif line.startswith("+"):
            if not patch_flag:
                patch_flag = True
        else:
            index_old_infun += 1
        if ln + add_num == old_start + index_old_infun:
            break

    hiden_func_items = sorted((patch.hiden_func_dict or {}).items(), key=lambda x: x[1])
    func_start_index = front_context_num
    func_end_index = len(patch_lines) - next((i for i, x in enumerate(reversed(patch_lines)) if x and x[0] == "-"), -1) - 4

    if {"Merged functions", "Tail function"} & (patch.patch_type or set()):
        last_offset = front_context_num
        last_func_sig = hiden_func_items[0][0] if hiden_func_items else old_function_signature
        chosen = False
        for func_sig, offset in hiden_func_items:
            if offset > index_old_infun:
                func_start_index = last_offset
                func_end_index = offset
                old_function_signature = last_func_sig
                chosen = True
                break
            last_offset = offset
            last_func_sig = func_sig
        if not chosen:
            func_start_index = last_offset
            old_function_signature = last_func_sig
            func_end_index = len(patch_lines) - next((i for i, x in enumerate(reversed(patch_lines)) if x and x[0] == "-"), -1) - 4

    return {
        "patch_path": str(Path(patch_path)),
        "file_path": file_path,
        "line_number": ln,
        "patch_key": key_of_line_num,
        "old_signature": old_function_signature,
        "func_start_index": func_start_index,
        "func_end_index": func_end_index,
    }


def parse_build_errors_tool(*, build_log_text: str = "", build_log_path: str = "") -> Dict[str, Any]:
    if build_log_text and build_log_path:
        raise ValueError("Provide only one of build_log_text or build_log_path")
    if build_log_path:
        text = Path(build_log_path).read_text(encoding="utf-8", errors="replace")
    else:
        text = build_log_text
    return parse_build_errors(text)
