from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from artifacts import ArtifactRef, ArtifactStore


_FUNC_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_HUNK_RE = re.compile(
    r"^@@\s+-(?P<old_start>\d+)(?:,(?P<old_len>\d+))?\s+\+(?P<new_start>\d+)(?:,(?P<new_len>\d+))?\s+@@"
)
_CONTROL_STMT_RE = re.compile(r"^(?:if|for|while|switch|return|goto|break|continue|else|do)\b")


def _repo_root() -> Path:
    # script/react_agent/tools/extra_patch_tools.py -> script/react_agent/tools -> script/react_agent -> script -> repo
    return Path(__file__).resolve().parents[3]


def _artifact_root() -> Path:
    root = str(os.environ.get("REACT_AGENT_ARTIFACT_ROOT", "") or "").strip()
    if root:
        return Path(root).expanduser().resolve()
    return (_repo_root() / "data" / "react_agent_artifacts").resolve()


def _allowed_patch_roots_from_env() -> list[str] | None:
    raw = os.environ.get("REACT_AGENT_PATCH_ALLOWED_ROOTS", "").strip()
    if not raw:
        return None
    roots = [r.strip() for r in raw.split(os.pathsep) if r.strip()]
    return roots or None


def _normalize_file_basename(file_path: str) -> str:
    raw = str(file_path or "").strip()
    if not raw:
        return ""
    return Path(raw).name


def _infer_extra_patch_key(*, bundle: Any, file_path: str) -> str:
    base = _normalize_file_basename(file_path)
    if not base:
        return ""
    candidate = f"_extra_{base}"
    if isinstance(getattr(bundle, "patches", None), dict) and candidate in bundle.patches:
        return candidate
    # Fallback: scan for a matching _extra_* entry that targets this file.
    patches = getattr(bundle, "patches", None)
    if isinstance(patches, dict):
        for key, patch in patches.items():
            if not isinstance(key, str) or not key.startswith("_extra_"):
                continue
            fp_new = str(getattr(patch, "file_path_new", "") or "")
            fp_old = str(getattr(patch, "file_path_old", "") or "")
            if Path(fp_new).name == base or Path(fp_old).name == base:
                return key
    return ""


def _strip_diff_prefix(line: str) -> str:
    if not line:
        return ""
    if line[0] in {"-", "+", " "}:
        return line[1:]
    return line


def _extract_c_declaration_from_function_code(code: str) -> List[str]:
    """Best-effort extraction of a function declaration/prototype from a C function body."""
    text = str(code or "").replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        return []
    lines = text.splitlines()
    out: List[str] = []
    for raw in lines:
        out.append(raw.rstrip())
        if "{" in raw:
            break
    # Convert the first '{' into a ';' and drop anything after.
    joined = "\n".join(out)
    if "{" not in joined:
        # Maybe this is already a prototype.
        return [l for l in out if l.strip()]
    head = joined.split("{", 1)[0].rstrip()
    if not head.endswith(")"):
        head = head.rstrip()
    head_lines = head.splitlines()
    if not head_lines:
        return []
    head_lines[-1] = head_lines[-1].rstrip() + ";"
    return [l.rstrip() for l in head_lines if l.strip()]


def _rewrite_first_function_name(lines: List[str], *, old: str, new: str) -> List[str]:
    """Replace the first occurrence of `old(` as a function name with `new(`."""
    if not lines or not old or not new or old == new:
        return lines
    pat = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(old)}\s*\(")
    out: List[str] = []
    replaced = False
    for line in lines:
        if not replaced:
            m = pat.search(line)
            if m:
                line = pat.sub(f"{new}(", line, count=1)
                replaced = True
        out.append(line)
    return out


def _rewrite_first_identifier(lines: List[str], *, old: str, new: str) -> List[str]:
    """Replace the first whole-identifier occurrence of `old` with `new`."""
    if not lines or not old or not new or old == new:
        return lines
    pat = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(old)}(?![A-Za-z0-9_])")
    out: List[str] = []
    replaced = False
    for line in lines:
        if not replaced:
            m = pat.search(line)
            if m:
                line = pat.sub(new, line, count=1)
                replaced = True
        out.append(line)
    return out


def _looks_like_statement(code_line: str) -> bool:
    stripped = str(code_line or "").lstrip()
    if not stripped:
        return False
    if stripped.startswith("#"):
        return True
    if _CONTROL_STMT_RE.match(stripped):
        return True
    return False


def _is_valid_function_prototype(lines: List[str], *, symbol_name: str) -> bool:
    if not lines:
        return False
    want = str(symbol_name or "").strip()
    if not want:
        return False
    last = next((l for l in reversed(lines) if str(l).strip()), "")
    if not str(last).strip().endswith(";"):
        return False

    joined = "\n".join(str(l) for l in lines)
    if "{" in joined or "}" in joined:
        return False
    if want not in joined:
        return False
    if "=" in joined:
        return False

    needle = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(want)}\s*\(")
    for line in lines:
        text = str(line or "")
        if not needle.search(text):
            continue
        if _looks_like_statement(text):
            return False
        return True

    return False


def _extract_function_prototype_from_bundle(bundle: Any, *, symbol_name: str) -> List[str]:
    """Try to find a function definition for `symbol_name` inside the patch bundle and derive a prototype."""
    want = str(symbol_name or "").strip()
    if not want:
        return []
    patches = getattr(bundle, "patches", None)
    if not isinstance(patches, dict):
        return []

    # Scan all patch_texts for a line that looks like a file-scope prototype/definition for "<symbol_name>(".
    # Do not match call sites inside other functions (those often lead to nonsense like `if (...) ;` at file scope).
    needle = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(want)}\s*\(")
    for patch in patches.values():
        patch_text = str(getattr(patch, "patch_text", "") or "")
        if not patch_text:
            continue
        lines = patch_text.splitlines()
        for idx, line in enumerate(lines):
            if not line.startswith("-") or line.startswith("---"):
                continue
            code = _strip_diff_prefix(line).rstrip()
            if not needle.search(code):
                continue
            if code[:1] in {" ", "\t"}:
                continue
            if _looks_like_statement(code):
                continue
            # Walk backward to include leading decl/attribute lines (but stop at '}' / blank / headers).
            start = idx
            for j in range(idx - 1, max(-1, idx - 12), -1):
                prev = lines[j]
                if not prev.startswith("-") or prev.startswith("---"):
                    break
                prev_code = _strip_diff_prefix(prev).rstrip()
                if not prev_code.strip():
                    break
                if "{" in prev_code:
                    break
                if prev_code.strip() in {"}", "};"} or prev_code.strip().endswith("}"):
                    break
                start = j

            # Walk forward until we reach the opening '{' for the definition.
            end = idx
            for j in range(idx, min(len(lines), idx + 24)):
                cur = lines[j]
                if not cur.startswith("-") or cur.startswith("---"):
                    break
                end = j
                if "{" in _strip_diff_prefix(cur):
                    break

            block = [_strip_diff_prefix(l).rstrip() for l in lines[start : end + 1]]
            proto = _extract_c_declaration_from_function_code("\n".join(block) + "\n")
            if proto and _is_valid_function_prototype(proto, symbol_name=want):
                return proto
    return []


def _recompute_hunk_headers(lines: List[str]) -> List[str]:
    """Recompute @@ hunk header lengths after edits (best-effort)."""
    out = list(lines)
    new_shift = 0
    i = 0
    while i < len(out):
        line = out[i]
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
        while j < len(out):
            body_line = out[j]
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
                pass
            j += 1

        is_file_add = old_start == 0 and old_len_hdr == 0
        is_file_del = new_start_hdr == 0 and new_len_hdr == 0
        new_start = new_start_hdr if (is_file_add or is_file_del) else (old_start + new_shift)
        out[i] = f"@@ -{old_start},{old_len} +{new_start},{new_len_hunk} @@"

        new_shift += new_len_hunk - old_len
        i = j
    return out


def _insert_minus_block_into_patch_text(patch_text: str, *, insert_lines: List[str]) -> str:
    """Insert `insert_lines` (raw code, no diff prefix) as '-' lines into a unified diff hunk."""
    raw = str(patch_text or "")
    if not raw.strip():
        return ""
    lines = raw.splitlines()
    first_hunk = next((i for i, l in enumerate(lines) if l.startswith("@@")), -1)
    if first_hunk < 0:
        return raw.rstrip("\n") + "\n"

    # Insert after the last '-' line in the first hunk body (before trailing context).
    insert_at = None
    for i in range(first_hunk + 1, len(lines)):
        if lines[i].startswith("@@") or lines[i].startswith("diff --git "):
            break
        if lines[i].startswith("-") and not lines[i].startswith("---"):
            insert_at = i + 1

    if insert_at is None:
        insert_at = first_hunk + 1

    # Convert raw code lines to diff '-' lines.
    block: List[str] = []
    for l in insert_lines:
        if l == "":
            block.append("-")
        else:
            block.append("-" + l)

    updated = list(lines)
    updated[insert_at:insert_at] = block
    updated = _recompute_hunk_headers(updated)
    return "\n".join(updated).rstrip("\n") + "\n"


def _symbol_underlying_name(symbol: str) -> Tuple[str, str]:
    """Return (kind, underlying_name) for common generated-name patterns."""
    s = str(symbol or "").strip()
    if not s:
        return "", ""
    m = re.match(r"^__revert_[0-9a-fA-F]+_(?P<name>[A-Za-z_][A-Za-z0-9_]*)$", s)
    if m:
        return "revert_function", str(m.group("name") or "")
    m = re.match(r"^__revert_var_[0-9a-fA-F]+_(?P<name>[A-Za-z_][A-Za-z0-9_]*)$", s)
    if m:
        return "revert_var", str(m.group("name") or "")
    m = re.match(r"^__rervert_var_[0-9a-fA-F]+_(?P<name>[A-Za-z_][A-Za-z0-9_]*)$", s)
    if m:
        return "revert_var", str(m.group("name") or "")
    m = re.match(r"^__revert_cons_[0-9a-fA-F]+_(?P<name>[A-Za-z_][A-Za-z0-9_]*)$", s)
    if m:
        return "revert_const", str(m.group("name") or "")
    return "", ""


_KB_INSERTABLE_KINDS = {
    "ENUM_DECL",
    "FUNCTION_DECL",
    "FUNCTION_DEFI",
    "MACRO_DEFINITION",
    "STRUCT_DECL",
    "TYPEDEF_DECL",
    "UNION_DECL",
    "VAR_DECL",
}


def _kb_node_extent_lines(node: dict) -> int:
    extent = node.get("extent", {}) if isinstance(node.get("extent"), dict) else {}
    start = extent.get("start", {}) if isinstance(extent.get("start"), dict) else {}
    end = extent.get("end", {}) if isinstance(extent.get("end"), dict) else {}
    sl = int(start.get("line", 0) or 0)
    el = int(end.get("line", 0) or 0)
    if sl > 0 and el >= sl:
        return el - sl + 1
    return 0


def _kb_node_location_tuple(node: dict) -> Tuple[str, int, int]:
    loc = node.get("location", {}) if isinstance(node.get("location"), dict) else {}
    fp = str(loc.get("file", "") or "")
    ln = int(loc.get("line", 0) or 0)
    col = int(loc.get("column", 0) or 0)
    return fp, ln, col


def _kb_node_key(node: dict) -> str:
    usr = str(node.get("usr", "") or "").strip()
    reason = str(node.get("__reason", "") or "").strip()
    kind = str(node.get("kind", "") or "").strip()
    spelling = str(node.get("spelling", "") or "").strip()

    extent = node.get("extent", {}) if isinstance(node.get("extent"), dict) else {}
    start = extent.get("start", {}) if isinstance(extent.get("start"), dict) else {}
    end = extent.get("end", {}) if isinstance(extent.get("end"), dict) else {}
    fp = str(start.get("file", "") or "")
    sl = int(start.get("line", 0) or 0)
    el = int(end.get("line", 0) or 0)

    if reason:
        return f"pseudo:{usr}:{kind}:{spelling}:{fp}:{sl}:{el}:{reason}"
    if usr:
        return f"usr:{usr}:{kind}:{spelling}:{fp}:{sl}:{el}"
    return f"ext:{kind}:{spelling}:{fp}:{sl}:{el}"


def _kb_pick_insertable_node(agent_tools: Any, *, symbol: str, version: str, max_nodes: int = 200) -> Optional[dict]:
    """Pick a KB node that can be safely inserted at file scope.

    The KB often only contains `DECL_REF_EXPR` for file-scope objects, but those nodes typically
    include `type_ref.typedef_extent` pointing at the declaration/definition. Use
    `KbIndex.related_definition_candidates` to derive pseudo nodes for those extents.
    """
    ver = str(version or "").strip().lower()
    if ver not in {"v1", "v2"}:
        return None
    name = str(symbol or "").strip()
    if not name:
        return None

    kb_index = getattr(agent_tools, "kb_index", None)
    if kb_index is None:
        return None

    nodes = []
    try:
        nodes = (kb_index.query_all(name) or {}).get(ver, [])
    except Exception:
        nodes = []
    nodes = [n for n in nodes if isinstance(n, dict)]

    candidates: List[dict] = []
    seen: set[str] = set()

    for n in nodes[: max(0, int(max_nodes or 0))]:
        for cand in [n] + list(kb_index.related_definition_candidates(n, ver, max_depth=2) or []):
            if not isinstance(cand, dict):
                continue
            k = _kb_node_key(cand)
            if k in seen:
                continue
            seen.add(k)
            candidates.append(cand)

    insertable = [c for c in candidates if str(c.get("kind", "") or "").strip() in _KB_INSERTABLE_KINDS]
    if not insertable:
        return None

    kind_score = {
        "MACRO_DEFINITION": 80,
        "TYPEDEF_DECL": 70,
        "ENUM_DECL": 60,
        "STRUCT_DECL": 55,
        "UNION_DECL": 55,
        "VAR_DECL": 50,
        "FUNCTION_DEFI": 40,
        "FUNCTION_DECL": 35,
    }

    def rank(node: dict) -> Tuple[int, int, int, int, int, int]:
        kind = str(node.get("kind", "") or "").strip()
        spelling = str(node.get("spelling", "") or "").strip()
        reason = str(node.get("__reason", "") or "").strip()
        fp, ln, col = _kb_node_location_tuple(node)
        return (
            1 if spelling == name else 0,
            kind_score.get(kind, 0),
            _kb_node_extent_lines(node),
            1 if reason else 0,
            -ln,
            -col,
        )

    return max(insertable, key=rank)


def make_extra_patch_override(
    agent_tools: Any,
    *,
    patch_path: str,
    file_path: str,
    symbol_name: str,
    version: str = "v1",
) -> Dict[str, Any]:
    """Deterministically extend an `_extra_*` hunk to provide a missing decl/define/typedef.

    Primary goal: when the build log reports an undeclared symbol (often a generated `__revert_*` function),
    add a forward declaration (or macro/type) into the file's `_extra_<file>` hunk so the agent doesn't
    inline declarations into the active function body.
    """
    from migration_tools.patch_bundle import load_patch_bundle  # type: ignore

    patch_path_s = str(patch_path or "").strip()
    if not patch_path_s:
        raise ValueError("patch_path must be non-empty")
    file_path_s = str(file_path or "").strip()
    if not file_path_s:
        raise ValueError("file_path must be non-empty")
    symbol = str(symbol_name or "").strip()
    if not symbol:
        raise ValueError("symbol_name must be non-empty")

    bundle = load_patch_bundle(patch_path_s, allowed_roots=_allowed_patch_roots_from_env())
    extra_key = _infer_extra_patch_key(bundle=bundle, file_path=file_path_s)
    if not extra_key:
        return {
            "patch_path": str(Path(patch_path_s).expanduser().resolve()),
            "file_path": file_path_s,
            "symbol_name": symbol,
            "patch_key": "",
            "patch_text": "",
            "note": "No matching _extra_* patch_key found for this file.",
        }

    patch = bundle.patches.get(extra_key) if isinstance(getattr(bundle, "patches", None), dict) else None
    if patch is None:
        return {
            "patch_path": str(Path(patch_path_s).expanduser().resolve()),
            "file_path": file_path_s,
            "symbol_name": symbol,
            "patch_key": extra_key,
            "patch_text": "",
            "note": "Extra patch_key is missing from the bundle.",
        }

    existing = str(getattr(patch, "patch_text", "") or "")
    if symbol in existing:
        return {
            "patch_path": str(Path(patch_path_s).expanduser().resolve()),
            "file_path": file_path_s,
            "symbol_name": symbol,
            "patch_key": extra_key,
            "patch_text": existing,
            "note": "Symbol already present in extra hunk; no change.",
        }

    inserted_lines: List[str] = []
    insert_kind = ""
    kind, underlying = _symbol_underlying_name(symbol)

    # 1) Best-effort: for generated __revert_* functions, extract the prototype from the bundle itself.
    if kind == "revert_function":
        proto = _extract_function_prototype_from_bundle(bundle, symbol_name=symbol)
        if proto:
            inserted_lines = proto
            insert_kind = "function_prototype_from_bundle"

    # 2) Fallback to KB/JSON: locate underlying symbol code and synthesize a declaration.
    if not inserted_lines and agent_tools is not None:
        requested = str(version or "v1").strip().lower()
        if requested not in {"v1", "v2"}:
            requested = "v1"
        versions_to_try = [requested, ("v2" if requested == "v1" else "v1")]
        query = underlying or symbol
        for ver in versions_to_try:
            chosen = _kb_pick_insertable_node(agent_tools, symbol=query, version=ver)
            if chosen is None:
                continue
            chosen_kind = str(chosen.get("kind", "") or "").strip()
            reason = str(chosen.get("__reason", "") or "").strip()
            reason_suffix = f":{reason}" if reason else ""
            source_manager = getattr(agent_tools, "source_manager", None)
            code = ""
            if source_manager is not None:
                code = str(source_manager.get_function_code(chosen, ver) or "")
            if not code.strip():
                continue

            if "FUNCTION" in chosen_kind:
                decl_lines = _extract_c_declaration_from_function_code(code)
            else:
                decl_lines = [l.rstrip("\n") for l in code.replace("\r\n", "\n").replace("\r", "\n").splitlines()]
            decl_lines = [l.rstrip() for l in decl_lines if l is not None and str(l).strip()]
            if not decl_lines:
                continue

            if underlying:
                if kind == "revert_function":
                    decl_lines = _rewrite_first_function_name(decl_lines, old=underlying, new=symbol)
                elif kind in {"revert_var", "revert_const"}:
                    decl_lines = _rewrite_first_identifier(decl_lines, old=underlying, new=symbol)
            inserted_lines = decl_lines
            insert_kind = f"declaration_from_kb:{ver}:{chosen_kind}{reason_suffix}"
            break

    if not inserted_lines:
        return {
            "patch_path": str(Path(patch_path_s).expanduser().resolve()),
            "file_path": file_path_s,
            "symbol_name": symbol,
            "patch_key": extra_key,
            "patch_text": "",
            "note": "Failed to locate a definition/decl for the symbol (bundle+KB).",
        }

    # Ensure a blank line separator before the inserted block for readability.
    block_lines = [""] + [l.rstrip() for l in inserted_lines if l is not None]

    updated_text = _insert_minus_block_into_patch_text(existing, insert_lines=block_lines)

    # Persist the override diff under the *extra patch_key* directory so patch_key inference works later.
    store = ArtifactStore(_artifact_root() / extra_key, overwrite=False)
    ref = store.write_text(
        name=f"make_extra_patch_override_patch_text_{_normalize_file_basename(file_path_s)}_{symbol}",
        text=updated_text,
        ext=".diff",
    )

    return {
        "patch_path": str(Path(patch_path_s).expanduser().resolve()),
        "file_path": file_path_s,
        "symbol_name": symbol,
        "symbol_kind_hint": kind,
        "underlying_symbol": underlying,
        "patch_key": extra_key,
        "insert_kind": insert_kind,
        "inserted_code": "\n".join(inserted_lines).rstrip("\n") + "\n",
        "patch_text": ref.to_dict(),
        "patch_text_truncated": False,
        "patch_text_lines_total": len(updated_text.splitlines()),
        "note": "Inserted missing declaration into the file's _extra_* hunk and returned an override diff artifact.",
    }
