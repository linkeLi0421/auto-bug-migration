from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .build_errors import parse_build_errors
from .patch_bundle import PatchBundle, load_patch_bundle
from .types import PatchInfo


_HUNK_RE = re.compile(r"^@@ -(?P<old_start>\d+)(?:,(?P<old_len>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_len>\d+))? @@")


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


def _iter_hunks(patch_text: str) -> List[Dict[str, Any]]:
    """Parse unified-diff hunks with their body lines."""
    hunks: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for line in (patch_text or "").splitlines():
        if line.startswith("@@"):
            if current:
                hunks.append(current)
            m = _HUNK_RE.match(line.strip())
            if not m:
                current = None
                continue
            current = {
                "old_start": int(m.group("old_start")),
                "old_len": int(m.group("old_len") or 1),
                "new_start": int(m.group("new_start")),
                "new_len": int(m.group("new_len") or 1),
                "lines": [],
            }
            continue
        if current is not None:
            current["lines"].append(line)
    if current:
        hunks.append(current)
    return hunks


def _infer_migrated_side(patch_text: str) -> str:
    """Best-effort heuristic: which side likely contains migration artifacts."""
    markers = ("__revert_", "__rervert_")
    removed = 0
    added = 0
    for line in (patch_text or "").splitlines():
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("-") and any(m in line for m in markers):
            removed += 1
        elif line.startswith("+") and any(m in line for m in markers):
            added += 1
    if removed > added:
        return "old"
    if added > removed:
        return "new"
    return ""


def _map_new_to_old_in_hunk(hunk: Dict[str, Any], target_new: int) -> Optional[int]:
    old_ln = int(hunk["old_start"])
    new_ln = int(hunk["new_start"])
    for line in hunk.get("lines", []):
        if not line:
            continue
        prefix = line[0]
        if prefix == " ":
            if new_ln == target_new:
                return old_ln
            old_ln += 1
            new_ln += 1
        elif prefix == "+":
            if new_ln == target_new:
                return None
            new_ln += 1
        elif prefix == "-":
            old_ln += 1
        else:
            continue
    return None


def _map_old_to_new_in_hunk(hunk: Dict[str, Any], target_old: int) -> Optional[int]:
    old_ln = int(hunk["old_start"])
    new_ln = int(hunk["new_start"])
    for line in hunk.get("lines", []):
        if not line:
            continue
        prefix = line[0]
        if prefix == " ":
            if old_ln == target_old:
                return new_ln
            old_ln += 1
            new_ln += 1
        elif prefix == "-":
            if old_ln == target_old:
                return None
            old_ln += 1
        elif prefix == "+":
            new_ln += 1
        else:
            continue
    return None


def _map_new_to_old_line(hunks: List[Dict[str, Any]], target_new: int) -> Tuple[Optional[int], str]:
    if target_new <= 0:
        return None, "invalid target line"
    delta = 0  # old - new for hunks strictly before the target
    for hunk in hunks:
        new_start = int(hunk["new_start"])
        new_len = int(hunk["new_len"])
        if target_new < new_start:
            return target_new + delta, "outside hunks"
        if new_start <= target_new < new_start + max(new_len, 0):
            mapped = _map_new_to_old_in_hunk(hunk, target_new)
            if mapped is None:
                return None, "line is added-only in patch"
            return mapped, "mapped inside hunk"
        delta += int(hunk["old_len"]) - int(hunk["new_len"])
    return target_new + delta, "outside hunks"


def _map_old_to_new_line(hunks: List[Dict[str, Any]], target_old: int) -> Tuple[Optional[int], str]:
    if target_old <= 0:
        return None, "invalid target line"
    delta = 0  # new - old for hunks strictly before the target
    for hunk in hunks:
        old_start = int(hunk["old_start"])
        old_len = int(hunk["old_len"])
        if target_old < old_start:
            return target_old + delta, "outside hunks"
        if old_start <= target_old < old_start + max(old_len, 0):
            mapped = _map_old_to_new_in_hunk(hunk, target_old)
            if mapped is None:
                return None, "line is deleted-only in patch"
            return mapped, "mapped inside hunk"
        delta += int(hunk["new_len"]) - int(hunk["old_len"])
    return target_old + delta, "outside hunks"


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


def _get_error_patch_from_bundle(bundle: PatchBundle, *, patch_path: str, file_path: str, line_number: int) -> Dict[str, Any]:
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

    patch_lines = (patch.patch_text or "").splitlines()
    first_hunk_idx = next((i for i, l in enumerate(patch_lines) if l.startswith("@@")), -1)
    body_start = first_hunk_idx + 1 if first_hunk_idx >= 0 else 4
    body = patch_lines[body_start:] if body_start < len(patch_lines) else []
    front_context_num = next((i for i, x in enumerate(body) if x and x[0] == "-"), -1)

    def last_minus_end_index() -> int:
        for i in range(len(body) - 1, -1, -1):
            if body[i].startswith("-"):
                return i + 1
        return 0

    if "Recreated function" not in (patch.patch_type or set()):
        # Generic (non-recreated-function) slice: choose a rewriteable '-' run inside the hunk that matches the error line.
        target_ln = ln + add_num

        def iter_hunks() -> List[Dict[str, Any]]:
            hunks: List[Dict[str, Any]] = []
            if first_hunk_idx < 0 or body_start >= len(patch_lines):
                return hunks
            i = first_hunk_idx
            while i < len(patch_lines):
                line = patch_lines[i]
                if not line.startswith("@@"):
                    i += 1
                    continue
                m = _HUNK_RE.match(line.strip())
                if not m:
                    i += 1
                    continue
                old_start = int(m.group("old_start"))
                old_len = int(m.group("old_len") or 1)
                new_start = int(m.group("new_start"))
                new_len = int(m.group("new_len") or 1)
                h_body_start = i + 1
                j = h_body_start
                while j < len(patch_lines) and not patch_lines[j].startswith("@@") and not patch_lines[j].startswith("diff --git "):
                    j += 1
                hunks.append(
                    {
                        "old_start": old_start,
                        "old_len": old_len,
                        "new_start": new_start,
                        "new_len": new_len,
                        "body_start": max(h_body_start - body_start, 0),
                        "body_end": max(j - body_start, 0),
                    }
                )
                i = j
            return hunks

        def locate_old_line(h: Dict[str, Any], target: int) -> Optional[int]:
            old_ln = int(h["old_start"])
            new_ln = int(h["new_start"])
            start = int(h["body_start"])
            end = int(h["body_end"])
            for idx in range(start, max(start, end)):
                line = body[idx] if 0 <= idx < len(body) else ""
                if not line:
                    continue
                prefix = line[0]
                if prefix == " ":
                    if old_ln == target:
                        return idx
                    old_ln += 1
                    new_ln += 1
                elif prefix == "-":
                    if old_ln == target:
                        return idx
                    old_ln += 1
                elif prefix == "+":
                    new_ln += 1
                elif prefix == "\\":
                    pass
                else:
                    if old_ln == target:
                        return idx
                    old_ln += 1
                    new_ln += 1
            return None

        def locate_new_line(h: Dict[str, Any], target: int) -> Optional[int]:
            old_ln = int(h["old_start"])
            new_ln = int(h["new_start"])
            start = int(h["body_start"])
            end = int(h["body_end"])
            for idx in range(start, max(start, end)):
                line = body[idx] if 0 <= idx < len(body) else ""
                if not line:
                    continue
                prefix = line[0]
                if prefix == " ":
                    if new_ln == target:
                        return idx
                    old_ln += 1
                    new_ln += 1
                elif prefix == "+":
                    if new_ln == target:
                        return idx
                    new_ln += 1
                elif prefix == "-":
                    old_ln += 1
                elif prefix == "\\":
                    pass
                else:
                    if new_ln == target:
                        return idx
                    old_ln += 1
                    new_ln += 1
            return None

        def nearest_minus_run(start: int, end: int, around: int) -> Optional[Tuple[int, int]]:
            runs: List[Tuple[int, int]] = []
            i = max(0, start)
            end_n = max(0, min(end, len(body)))
            while i < end_n:
                if body[i].startswith("-"):
                    s = i
                    i += 1
                    while i < end_n and body[i].startswith("-"):
                        i += 1
                    runs.append((s, i))
                else:
                    i += 1
            if not runs:
                return None

            def dist(run: Tuple[int, int]) -> int:
                s, e = run
                if s <= around < e:
                    return 0
                if around < s:
                    return s - around
                return around - (e - 1)

            return min(runs, key=dist)

        hunks = iter_hunks()
        chosen_hunk: Optional[Dict[str, Any]] = None
        chosen_idx: Optional[int] = None

        for h in hunks:
            idx = locate_old_line(h, target_ln)
            if idx is not None:
                chosen_hunk = h
                chosen_idx = idx
                break
        if chosen_hunk is None:
            for h in hunks:
                idx = locate_new_line(h, target_ln)
                if idx is not None:
                    chosen_hunk = h
                    chosen_idx = idx
                    break

        if chosen_hunk is None and hunks:
            chosen_hunk = hunks[0]
            chosen_idx = int(chosen_hunk["body_start"])
        if chosen_hunk is None or chosen_idx is None:
            return {
                "patch_path": str(Path(patch_path)),
                "file_path": file_path,
                "line_number": ln,
                "patch_key": key_of_line_num,
                "old_signature": old_function_signature,
                "func_start_index": None,
                "func_end_index": None,
            }

        h_start = int(chosen_hunk["body_start"])
        h_end = int(chosen_hunk["body_end"])
        run = nearest_minus_run(h_start, h_end, int(chosen_idx))
        if run is None:
            return {
                "patch_path": str(Path(patch_path)),
                "file_path": file_path,
                "line_number": ln,
                "patch_key": key_of_line_num,
                "old_signature": old_function_signature,
                "func_start_index": None,
                "func_end_index": None,
            }

        func_start_index, func_end_index = run
        return {
            "patch_path": str(Path(patch_path)),
            "file_path": file_path,
            "line_number": ln,
            "patch_key": key_of_line_num,
            "old_signature": old_function_signature,
            "func_start_index": func_start_index,
            "func_end_index": func_end_index,
        }

    # Best-effort port of the original logic for recreated-function patches.

    old_start = selected_hunk[0] if selected_hunk else int(patch.old_start_line or 0)
    index_old_infun = 0
    patch_flag = False
    for line in patch_lines[body_start + front_context_num :]:
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
    func_end_index = last_minus_end_index()

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
            func_end_index = (
                last_minus_end_index()
            )

    return {
        "patch_path": str(Path(patch_path)),
        "file_path": file_path,
        "line_number": ln,
        "patch_key": key_of_line_num,
        "old_signature": old_function_signature,
        "func_start_index": func_start_index,
        "func_end_index": func_end_index,
    }


def get_error_patch(
    *, patch_path: str, file_path: str, line_number: int, allowed_roots: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Best-effort mapping from a build error location to a patch key in the bundle."""
    bundle = load_patch_bundle(patch_path, allowed_roots=allowed_roots)
    return _get_error_patch_from_bundle(bundle, patch_path=patch_path, file_path=file_path, line_number=line_number)


def get_error_patch_context(
    *,
    patch_path: str,
    file_path: str,
    line_number: int,
    error_text: str = "",
    context_lines: int = 30,
    max_total_lines: int = 200,
    allowed_roots: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Return a small patch excerpt for a build error location."""
    bundle = load_patch_bundle(patch_path, allowed_roots=allowed_roots)
    mapping = _get_error_patch_from_bundle(bundle, patch_path=patch_path, file_path=file_path, line_number=line_number)
    patch_key = mapping.get("patch_key")
    if not patch_key or str(patch_key) not in bundle.patches:
        return {
            **mapping,
            "patch_text_lines_total": 0,
            "excerpt_line_range": [0, 0],
            "excerpt_truncated": False,
            "excerpt": "",
            "pre_patch_file_path": None,
            "pre_patch_line_number": None,
            "mapping_note": "No matching patch_key; cannot derive pre-patch mapping.",
        }

    patch = bundle.patches[str(patch_key)]
    patch_lines = (patch.patch_text or "").splitlines()
    total = len(patch_lines)

    # Return the entire unified-diff hunk containing the mapped slice.
    first_hunk_idx = next((i for i, l in enumerate(patch_lines) if l.startswith("@@")), -1)
    body_start = first_hunk_idx + 1 if first_hunk_idx >= 0 else 4

    anchor = first_hunk_idx if first_hunk_idx >= 0 else 0
    func_start = mapping.get("func_start_index")
    if isinstance(func_start, int) and func_start >= 0:
        anchor = max(0, min(body_start + func_start, total - 1))

    hunk_start = first_hunk_idx
    if anchor >= 0:
        for i in range(anchor, -1, -1):
            if patch_lines[i].startswith("@@"):
                hunk_start = i
                break

    file_header_end = first_hunk_idx if first_hunk_idx >= 0 else 0
    file_header_lines = patch_lines[:file_header_end] if file_header_end > 0 else []

    if hunk_start is None or hunk_start < 0:
        # No hunks found; return the whole patch text.
        excerpt_lines = patch_lines
        hunk_start = 0
        hunk_end = total
    else:
        hunk_end = total
        for j in range(hunk_start + 1, total):
            line = patch_lines[j]
            if line.startswith("@@") or line.startswith("diff --git "):
                hunk_end = j
                break
        excerpt_lines = file_header_lines + patch_lines[hunk_start:hunk_end]

    excerpt_truncated = False

    hunks = _iter_hunks(patch.patch_text or "")
    migrated_side = _infer_migrated_side(patch.patch_text or "")
    pre_patch_file_path: Optional[str] = None
    pre_patch_line_number: Optional[int] = None
    mapping_note = ""
    if hunks:
        if migrated_side == "new":
            pre_patch_file_path = str(patch.file_path_old or "")
            mapped, reason = _map_new_to_old_line(hunks, int(line_number))
            pre_patch_line_number = int(mapped) if isinstance(mapped, int) and mapped > 0 else None
            mapping_note = f"Mapped migrated(new)->original(old): {reason}."
        elif migrated_side == "old":
            pre_patch_file_path = str(patch.file_path_new or "")
            mapped, reason = _map_old_to_new_line(hunks, int(line_number))
            pre_patch_line_number = int(mapped) if isinstance(mapped, int) and mapped > 0 else None
            mapping_note = f"Mapped migrated(old)->original(new): {reason}."
        else:
            new_to_old, r1 = _map_new_to_old_line(hunks, int(line_number))
            old_to_new, r2 = _map_old_to_new_line(hunks, int(line_number))
            if new_to_old is None and isinstance(old_to_new, int) and old_to_new > 0:
                pre_patch_file_path = str(patch.file_path_new or "")
                pre_patch_line_number = old_to_new
            else:
                pre_patch_file_path = str(patch.file_path_old or "")
                pre_patch_line_number = new_to_old if isinstance(new_to_old, int) and new_to_old > 0 else None
            mapping_note = (
                "Ambiguous patch direction for pre-patch mapping. "
                f"Assuming error line is in new side: {new_to_old} ({r1}). "
                f"Assuming error line is in old side: {old_to_new} ({r2})."
            )
    else:
        mapping_note = "No hunks found; cannot derive pre-patch mapping."

    symbols: List[str] = []
    if error_text:
        text = str(error_text)
        patterns = [
            r"unknown type name '([^']+)'",
            r"use of undeclared identifier '([^']+)'",
            r"implicit declaration of function\s+'([^']+)'",
            r"undeclared function '([^']+)'",
            r"conflicting types for '([^']+)'",
        ]
        for pat in patterns:
            symbols.extend(re.findall(pat, text))
        for member, struct_name in re.findall(r"no member named '([^']+)' in '([^']+)'", text):
            symbols.append(member)
            symbols.append(struct_name)
        # Dedup preserve order
        seen: set[str] = set()
        symbols = [s for s in symbols if s and not (s in seen or seen.add(s))]

    return {
        **mapping,
        "patch_text_lines_total": total,
        "hunk_line_range": [hunk_start, hunk_end],
        "hunk_lines_total": max(hunk_end - hunk_start, 0),
        "excerpt_line_range": [hunk_start, hunk_end],
        "excerpt_truncated": excerpt_truncated,
        "excerpt": ("\n".join(excerpt_lines).rstrip("\n") + "\n") if excerpt_lines else "",
        "excerpt_note": (
            "Returned the full unified-diff hunk containing the mapped slice (from @@ header to next @@/diff/EOF). "
            "The excerpt includes the file-level diff header (diff --git/---/+++) to make it applyable."
        ),
        "symbols": symbols,
        "pre_patch_file_path": pre_patch_file_path or None,
        "pre_patch_line_number": pre_patch_line_number,
        "mapping_note": mapping_note,
    }


def _repo_root() -> Path:
    # script/migration_tools/tools.py -> script/migration_tools -> script -> repo
    return Path(__file__).resolve().parents[2]


def _is_allowed_artifact_path(path: Path) -> bool:
    p = path.expanduser().resolve()
    if not p.is_file():
        return False
    env_root = str(os.environ.get("REACT_AGENT_ARTIFACT_ROOT", "") or "").strip()
    allowed: List[Path] = []
    if env_root:
        allowed.append(Path(env_root).expanduser().resolve())
    allowed.append((_repo_root() / "data" / "react_agent_artifacts").resolve())
    return any(a == p or a in p.parents for a in allowed)


def _load_excerpt_text(excerpt: Any) -> str:
    if isinstance(excerpt, str):
        return excerpt
    if isinstance(excerpt, dict):
        artifact_path = str(excerpt.get("artifact_path", "") or "").strip()
        if not artifact_path:
            raise ValueError("excerpt.artifact_path is required when excerpt is an object")
        p = Path(artifact_path)
        if not _is_allowed_artifact_path(p):
            raise ValueError(f"excerpt.artifact_path is not under allowed artifact roots: {p}")
        return p.read_text(encoding="utf-8", errors="replace")
    raise ValueError("excerpt must be a string diff excerpt or an object with artifact_path")


def _extract_minus_lines_from_unified_diff(diff_text: str) -> List[str]:
    lines = str(diff_text or "").splitlines()
    in_hunk = False
    out: List[str] = []
    for line in lines:
        if line.startswith("@@"):
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if not line:
            continue
        if line.startswith("\\"):
            continue
        if line.startswith("+") or line.startswith(" "):
            continue
        if not line.startswith("-"):
            continue
        # Skip unified-diff file headers if they appear (usually outside hunks).
        if line.startswith("---"):
            continue
        out.append(line[1:])
    return out


def get_error_v1_code_slice(
    *,
    excerpt: Any,
    allowed_roots: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Extract V1-origin code from '-' lines in a unified-diff excerpt.

    The excerpt is typically provided by `get_error_patch_context.excerpt` as either:
    - a string containing a unified diff, or
    - an object like {"artifact_path": "..."} pointing at a saved excerpt file.
    """
    _ = allowed_roots  # kept for backward compatibility with other tool signatures

    func_lines = _extract_minus_lines_from_unified_diff(_load_excerpt_text(excerpt))
    total_lines = len(func_lines)

    defined_macros: set[str] = set()
    for line in func_lines:
        m = re.match(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b", line)
        if m:
            defined_macros.add(str(m.group(1)))

    referenced_macro_tokens: set[str] = set()
    for line in func_lines:
        stripped = re.sub(r'"([^"\\]|\\.)*"', '""', line)
        stripped = re.sub(r"//.*$", "", stripped)
        stripped = re.sub(r"/\*.*?\*/", "", stripped)
        for tok in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", stripped):
            if tok.isupper() and any(c.isalpha() for c in tok):
                referenced_macro_tokens.add(tok)

    missing_macro_tokens = referenced_macro_tokens - defined_macros
    defined_macros_list = sorted(defined_macros)[:200]
    referenced_macro_tokens_list = sorted(referenced_macro_tokens)[:400]
    missing_macro_tokens_list = sorted(missing_macro_tokens)[:200]

    code = "\n".join(func_lines)

    return {
        "patch_path": "",
        "file_path": "",
        "line_number": 0,
        "patch_key": "",
        "old_signature": "",
        "func_start_index": None,
        "func_end_index": None,
        "func_code": code,
        "func_code_lines_total": total_lines,
        "func_code_lines_returned": total_lines,
        "func_code_truncated": False,
        "defined_macros": defined_macros_list,
        "referenced_macro_tokens": referenced_macro_tokens_list,
        "macro_tokens_not_defined_in_slice": missing_macro_tokens_list,
        "note": "Extracted from '-' lines in a unified-diff excerpt (typically get_error_patch_context.excerpt).",
    }


def _extract_first_code_fence(text: str) -> str:
    raw = str(text or "").strip()
    if "```" not in raw:
        return raw
    m = re.search(r"```(?:[a-zA-Z0-9_+-]+)?\n(.*?)```", raw, flags=re.DOTALL)
    if m:
        return (m.group(1) or "").strip()
    return raw.replace("```", "").strip()


def _truncate_text(*, text: str, max_lines: int, max_chars: int) -> Tuple[str, bool, int, int]:
    lines = (text or "").splitlines()
    total_lines = len(lines)
    max_n = max(0, min(int(max_lines or 0), 50000))
    returned = lines[:max_n]
    out = "\n".join(returned)
    truncated = total_lines > len(returned)

    max_c = max(0, min(int(max_chars or 0), 2_000_000))
    if max_c and len(out) > max_c:
        out = out[:max_c].rstrip("\n") + "\n...[truncated]"
        truncated = True

    return out, truncated, total_lines, len(returned)


def make_error_patch_override(
    *,
    patch_path: str,
    file_path: str,
    line_number: int,
    new_func_code: str,
    context_lines: int = 0,
    max_lines: int = 2000,
    max_chars: int = 200000,
    allowed_roots: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Rewrite a mapped patch slice by replacing its `-` lines.

    This tool uses the `(patch_key, old_signature, func_start_index, func_end_index)` mapping
    to locate the rewriteable `-` slice and rewrites the underlying patch text by replacing
    those `-` lines with `new_func_code` (each line prefixed with `-`).

    The tool is read-only: it returns the updated patch text but does not apply it.
    """
    new_code = _extract_first_code_fence(new_func_code)
    if not new_code.strip():
        raise ValueError("new_func_code must be non-empty")

    bundle = load_patch_bundle(patch_path, allowed_roots=allowed_roots)
    mapping = _get_error_patch_from_bundle(bundle, patch_path=patch_path, file_path=file_path, line_number=line_number)
    patch_key = mapping.get("patch_key")

    if not patch_key or str(patch_key) not in bundle.patches:
        return {
            **mapping,
            "old_func_code": "",
            "old_func_code_truncated": False,
            "patch_text": "",
            "patch_text_truncated": False,
            "note": "No matching patch_key; cannot generate a patch-slice replacement diff.",
        }

    func_start = mapping.get("func_start_index")
    func_end = mapping.get("func_end_index")
    if not isinstance(func_start, int) or not isinstance(func_end, int) or func_start < 0 or func_end < 0:
        return {
            **mapping,
            "old_func_code": "",
            "old_func_code_truncated": False,
            "patch_text": "",
            "patch_text_truncated": False,
            "note": "Patch mapping lacks a rewriteable '-' slice; cannot rewrite patch.",
        }

    patch = bundle.patches[str(patch_key)]
    rel_file = str(patch.file_path_new or patch.file_path_old or file_path or "").strip()
    rel_file = _norm_path(rel_file).lstrip("./").lstrip("/")
    if not rel_file:
        rel_file = _norm_path(file_path).lstrip("./").lstrip("/")

    patch_lines = (patch.patch_text or "").splitlines()
    if len(patch_lines) < 4:
        return {
            **mapping,
            "old_func_code": "",
            "old_func_code_truncated": False,
            "patch_text": "",
            "patch_text_truncated": False,
            "note": "Patch text is too short to contain a unified-diff header.",
        }

    first_hunk_idx = next((i for i, l in enumerate(patch_lines) if l.startswith("@@")), -1)
    body_start = first_hunk_idx + 1 if first_hunk_idx >= 0 else 4
    body_len = len(patch_lines) - body_start
    func_start_n = max(0, min(int(func_start), body_len))
    func_end_n = max(0, min(int(func_end), body_len))
    if func_end_n <= func_start_n:
        return {
            **mapping,
            "old_func_code": "",
            "old_func_code_truncated": False,
            "patch_text": "",
            "patch_text_truncated": False,
            "note": "Invalid patch slice indices (empty slice).",
        }

    slice_start = body_start + func_start_n
    slice_end = body_start + func_end_n
    slice_lines = patch_lines[slice_start:slice_end]
    old_func_lines = [line[1:] for line in slice_lines if line.startswith("-")]
    old_func_code_full = "\n".join(old_func_lines).rstrip("\n")

    def _norm_for_compare(text: str) -> str:
        return "\n".join(line.rstrip() for line in str(text or "").splitlines()).strip()

    new_code_norm = str(new_code).replace("\r\n", "\n").replace("\r", "\n")

    if _norm_for_compare(old_func_code_full) == _norm_for_compare(new_code_norm):
        raise ValueError("new_func_code is identical to the existing mapped '-' slice (no-op rewrite)")
    new_func_lines = new_code_norm.splitlines()
    if not any(line.strip() for line in new_func_lines):
        raise ValueError("new_func_code must contain at least one non-empty line")
    new_minus_lines = [f"-{line}" for line in new_func_lines]
    new_len = len(new_func_lines)

    rewritten_slice: List[str] = []
    inserted = False
    for line in slice_lines:
        if line.startswith("-"):
            if not inserted:
                rewritten_slice.extend(new_minus_lines)
                inserted = True
            continue
        rewritten_slice.append(line)
    if not inserted:
        return {
            **mapping,
            "old_func_code": "",
            "old_func_code_truncated": False,
            "patch_text": "",
            "patch_text_truncated": False,
            "note": "No '-' lines found in the mapped patch slice; cannot rewrite patch.",
        }

    delta = len(rewritten_slice) - len(slice_lines)
    patch_lines[slice_start:slice_end] = rewritten_slice

    # If the patch contains merged/tail functions, adjust offsets after the rewritten slice.
    hiden_func_dict_updated: Optional[Dict[str, int]] = None
    if delta and getattr(patch, "hiden_func_dict", None):
        try:
            new_hiden: Dict[str, int] = {}
            for sig, off in (patch.hiden_func_dict or {}).items():
                off_i = int(off)
                new_hiden[str(sig)] = off_i + delta if off_i >= func_end_n else off_i
            hiden_func_dict_updated = new_hiden
            patch_hiden_note = f" Updated hiden_func_dict offsets by {delta} lines."
        except Exception:
            patch_hiden_note = ""
    else:
        patch_hiden_note = ""

    # Recompute hunk header lengths and recompute +new_start offsets.
    #
    # We keep -old_start stable and recompute +new_start by accumulating the
    # per-hunk delta (new_len - old_len) from the rewritten hunk bodies.
    new_shift = 0
    i = 0
    while i < len(patch_lines):
        line = patch_lines[i]
        if line.startswith("diff --git "):
            new_shift = 0
            i += 1
            continue
        if not line.startswith("@@"):
            i += 1
            continue
        m = _HUNK_RE.match(line.strip())
        if not m:
            i += 1
            continue
        old_start = int(m.group("old_start"))
        old_len_hdr = int(m.group("old_len") or 1)
        new_start_hdr = int(m.group("new_start"))
        new_len_hdr = int(m.group("new_len") or 1)

        old_len = 0
        new_len_hunk = 0
        j = i + 1
        while j < len(patch_lines):
            body_line = patch_lines[j]
            if body_line.startswith("@@") or body_line.startswith("diff --git "):
                break
            if not body_line:
                j += 1
                continue
            prefix = body_line[0]
            if prefix == " ":
                old_len += 1
                new_len_hunk += 1
            elif prefix == "-":
                old_len += 1
            elif prefix == "+":
                new_len_hunk += 1
            elif prefix == "\\":
                # "\ No newline at end of file" marker
                pass
            j += 1

        is_file_add = old_start == 0 and old_len_hdr == 0
        is_file_del = new_start_hdr == 0 and new_len_hdr == 0
        new_start = new_start_hdr if (is_file_add or is_file_del) else (old_start + new_shift)
        patch_lines[i] = f"@@ -{old_start},{old_len} +{new_start},{new_len_hunk} @@"

        new_shift += new_len_hunk - old_len
        i = j

    patch_text_full = "\n".join(patch_lines)

    old_func_code, old_truncated, _, _ = _truncate_text(text=old_func_code_full, max_lines=200, max_chars=12000)
    patch_text, patch_truncated, patch_total_lines, patch_returned_lines = _truncate_text(
        text=patch_text_full, max_lines=max_lines, max_chars=max_chars
    )

    out: Dict[str, Any] = {
        **mapping,
        "file_path_patch": rel_file,
        "old_func_code": old_func_code,
        "old_func_code_truncated": old_truncated,
        "new_func_code_lines": new_len,
        "patch_text": patch_text,
        "patch_text_truncated": patch_truncated,
        "patch_text_lines_total": patch_total_lines,
        "patch_text_lines_returned": patch_returned_lines,
        "note": (
            "Rewrote the patch bundle's mapped patch slice by replacing '-' lines with the provided code. "
            "Use the returned patch_text to update the patch bundle entry."
            + patch_hiden_note
        ),
    }
    if hiden_func_dict_updated is not None:
        out["hiden_func_dict_updated"] = hiden_func_dict_updated
    return out


def parse_build_errors_tool(*, build_log_text: str = "", build_log_path: str = "") -> Dict[str, Any]:
    if build_log_text and build_log_path:
        raise ValueError("Provide only one of build_log_text or build_log_path")
    if build_log_path:
        text = Path(build_log_path).read_text(encoding="utf-8", errors="replace")
    else:
        text = build_log_text
    return parse_build_errors(text)
