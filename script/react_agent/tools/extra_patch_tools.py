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
    # If no extra hunk exists in the bundle, default to a synthesized patch_key.
    return candidate


def _normalize_repo_rel_path(agent_tools: Any, *, file_path: str, version: str = "v2") -> str:
    """Best-effort derive the repo-relative path used by patch_text diff headers."""
    sm = getattr(agent_tools, "source_manager", None)
    raw = str(file_path or "").strip()
    if not raw:
        return ""
    if sm is not None:
        try:
            resolved = sm._resolve_path(raw, version)  # type: ignore[attr-defined]
        except Exception:
            resolved = None
        if resolved is not None:
            try:
                root = sm._repo_root(version)  # type: ignore[attr-defined]
                rel = resolved.resolve().relative_to(root.resolve())
                return rel.as_posix()
            except Exception:
                pass

    # Fallback: strip the /src/<repo>/ prefix when present.
    if raw.startswith("/src"):
        rel = raw[len("/src") :].lstrip("/")
        if sm is not None:
            try:
                repo = sm._repo_root(version)  # type: ignore[attr-defined]
                repo_name = str(getattr(repo, "name", "") or "").strip()
                if repo_name and rel.replace("\\", "/").startswith(repo_name + "/"):
                    rel = rel.replace("\\", "/")[len(repo_name) + 1 :]
            except Exception:
                pass
        return rel.replace("\\", "/")
    return raw.replace("\\", "/")


_PP_IF_RE = re.compile(r"^#\s*(?:if|ifdef|ifndef)\b")
_PP_ENDIF_RE = re.compile(r"^#\s*endif\b")

_FUNC_DEF_KINDS = {"FUNCTION_DEFI", "CXX_METHOD", "FUNCTION_TEMPLATE"}


def _normalize_signature(sig: str) -> Tuple[str, str, Tuple[str, ...]]:
    """Normalize a C-like function signature into (return_type, name, arg_types).

    Best-effort port of `compare_function_signatures` logic from `script/revert_patch_test.py`,
    avoiding the heavyweight import.
    """
    text = str(sig or "").strip()
    if not text:
        return "", "", tuple()

    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\b(?:__attribute__|__declspec)\b\s*\([^)]*\)", "", text).strip()

    open_paren = text.find("(")
    close_paren = text.rfind(")")
    if open_paren < 0 or close_paren < open_paren:
        return "", "", tuple()

    head = text[:open_paren].strip()
    args = text[open_paren + 1 : close_paren].strip()

    parts = head.split()
    if not parts:
        return "", "", tuple()

    func_name = parts[-1]
    ret_type = " ".join(parts[:-1]).strip()

    arg_types: List[str] = []
    if args and args != "void":
        for arg in args.split(","):
            a = arg.strip()
            if not a:
                continue
            # Remove default values and extract type; keep all but last token (parameter name).
            a = a.split("=", 1)[0].strip()
            tokens = a.split()
            if not tokens:
                continue
            arg_type = " ".join(tokens[:-1]) if len(tokens) > 1 else tokens[0]
            arg_types.append(arg_type.strip())

    return ret_type, func_name, tuple(arg_types)


def _compare_function_signatures(sig1: str, sig2: str, *, ignore_arg_types: bool = False) -> bool:
    """Return True if two function signatures match (ignoring parameter names)."""
    s1 = _normalize_signature(sig1)
    s2 = _normalize_signature(sig2)
    if ignore_arg_types:
        ret_type1, func_name1, args_types1 = s1
        ret_type2, func_name2, args_types2 = s2
        return ret_type1 == ret_type2 and func_name1 == func_name2 and len(args_types1) == len(args_types2)
    return s1 == s2


def _extra_skeleton_anchor_func_sig() -> str:
    return str(os.environ.get("REACT_AGENT_EXTRA_SKELETON_ANCHOR_FUNC_SIG", "") or "").strip()


def _ast_insert_line_number_for_extra_skeleton(agent_tools: Any, *, file_path: str, version: str = "v2") -> int:
    """Return a 1-based insertion line based on AST analysis (best-effort).

    Strategy: insert before a selected function definition start line (start.line).
    - If `REACT_AGENT_EXTRA_SKELETON_ANCHOR_FUNC_SIG` is set, try to match that signature (ignore arg types).
    - Otherwise, insert before the first function definition in the file (smallest start line).
    """
    def no_anchor() -> int:
        return -1

    kb = getattr(agent_tools, "kb_index", None)
    if kb is None:
        return no_anchor()

    ver = str(version or "v2").strip().lower()
    if ver not in {"v1", "v2"}:
        ver = "v2"

    base = Path(str(file_path or "").strip()).name
    if not base:
        return no_anchor()

    file_index = getattr(kb, "file_index", None)
    if not isinstance(file_index, dict) or ver not in file_index:
        return -1

    nodes = file_index[ver].get(base) if isinstance(file_index[ver], dict) else None
    if not isinstance(nodes, list) or not nodes:
        return no_anchor()

    def in_file(node: dict) -> bool:
        extent = node.get("extent", {}) if isinstance(node.get("extent"), dict) else {}
        start = extent.get("start", {}) if isinstance(extent.get("start"), dict) else {}
        loc = node.get("location", {}) if isinstance(node.get("location"), dict) else {}
        start_file = str(start.get("file") or loc.get("file") or "")
        if not start_file:
            return False
        if "#include" in start_file:
            return False
        return Path(start_file).name == base

    def start_line(node: dict) -> int:
        extent = node.get("extent", {}) if isinstance(node.get("extent"), dict) else {}
        start = extent.get("start", {}) if isinstance(extent.get("start"), dict) else {}
        return int(start.get("line", 0) or 0)

    def end_line(node: dict) -> int:
        extent = node.get("extent", {}) if isinstance(node.get("extent"), dict) else {}
        end = extent.get("end", {}) if isinstance(extent.get("end"), dict) else {}
        return int(end.get("line", 0) or 0)

    candidates: List[dict] = []
    for n in nodes:
        if not isinstance(n, dict):
            continue
        if str(n.get("kind", "") or "").strip() not in _FUNC_DEF_KINDS:
            continue
        if not in_file(n):
            continue
        sl = start_line(n)
        el = end_line(n)
        if sl <= 0 or el <= 0:
            continue
        candidates.append(n)

    if not candidates:
        return no_anchor()

    want_sig = _extra_skeleton_anchor_func_sig()
    if want_sig:
        for n in candidates:
            sig = str(n.get("signature", "") or "")
            if sig and _compare_function_signatures(sig, want_sig, ignore_arg_types=True):
                sl = start_line(n)
                return sl if sl > 0 else -1

    first = min(candidates, key=lambda n: (start_line(n), end_line(n)))
    sl = start_line(first)
    return sl if sl > 0 else -1


def _find_file_scope_insertion_index(lines: List[str]) -> int:
    """Return a 0-based index where file-scope decls can be inserted safely.

    Heuristic: place insertions after leading comment + preprocessor/header region, but never inside an
    unterminated preprocessor conditional block.

    Special case: if the entire file is wrapped in #ifdef (common for feature-guarded code),
    fall back to inserting after the last #include statement in the initial header section.
    """
    in_block_comment = False
    pp_nesting = 0
    last_include_idx = -1
    header_section_ended = False  # Track if we've left the initial header/preprocessor section

    for idx, raw in enumerate(lines):
        stripped = str(raw or "").lstrip()
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("/*"):
            if "*/" not in stripped:
                in_block_comment = True
            continue
        if stripped.startswith("//"):
            continue
        if not stripped:
            continue
        if stripped.startswith("#"):
            if stripped.startswith("#include"):
                # Only track includes in the initial header section
                # Stop tracking once we've seen function definitions or global declarations
                if not header_section_ended:
                    last_include_idx = idx
            if _PP_IF_RE.match(stripped):
                pp_nesting += 1
            elif _PP_ENDIF_RE.match(stripped):
                pp_nesting = max(pp_nesting - 1, 0)
            continue
        if pp_nesting > 0:
            continue
        # We've found a non-preprocessor, non-comment line at file scope
        # This marks the end of the header section (includes are typically before declarations/definitions)
        # However, we only mark the section as ended if this looks like a function or variable declaration
        # (to allow for interleaved defines/typedefs after includes)
        if "(" in stripped or stripped.rstrip().endswith(";") or stripped.rstrip().endswith("{"):
            header_section_ended = True
        return idx

    # If we couldn't find a safe spot (e.g., entire file wrapped in #ifdef),
    # insert after the last #include in the initial header section.
    if last_include_idx >= 0:
        return last_include_idx + 1
    return 0


def _new_extra_patch_skeleton(agent_tools: Any, *, file_path: str, context_lines: int = 3) -> str:
    """Create a minimal unified diff skeleton for a brand-new `_extra_*` patch key."""
    sm = getattr(agent_tools, "source_manager", None)
    if sm is None:
        return ""

    resolved = None
    try:
        resolved = sm._resolve_path(str(file_path or "").strip(), "v2")  # type: ignore[attr-defined]
    except Exception:
        resolved = None
    if resolved is None or not resolved.exists():
        return ""
    text = resolved.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    if not lines:
        return ""

    insert_at = -1
    insert_line = _ast_insert_line_number_for_extra_skeleton(agent_tools, file_path=str(file_path or "").strip(), version="v2")
    if insert_line > 0:
        # We insert before the context line at insert_line; index is 0-based.
        idx = insert_line - 1
        if 0 <= idx < len(lines):
            insert_at = idx

    if insert_at < 0:
        insert_at = _find_file_scope_insertion_index(lines)

    # Find the last #include line in the initial header section to ensure we don't insert before type definitions
    # Stop tracking includes once we've seen actual code (to avoid late includes in the file)
    last_include_idx = -1
    seen_code = False
    for i, raw in enumerate(lines):
        stripped = str(raw or "").lstrip()
        # Track includes only in the header section
        if stripped.startswith("#include"):
            if not seen_code:
                last_include_idx = i
        # Mark that we've seen code if this is a non-preprocessor, non-comment, non-blank line
        elif stripped and not stripped.startswith("#") and not stripped.startswith("//") and not stripped.startswith("/*"):
            seen_code = True

    # Ensure insert_at is after all #include statements in the header section
    if last_include_idx >= 0 and insert_at <= last_include_idx:
        insert_at = last_include_idx + 1
    start_line = insert_at + 1
    ctx = lines[insert_at : insert_at + max(1, int(context_lines or 0))]
    if not ctx:
        ctx = [lines[0]]
        start_line = 1

    rel = _normalize_repo_rel_path(agent_tools, file_path=str(file_path or "").strip(), version="v2")
    if not rel:
        rel = _normalize_file_basename(file_path)
    if not rel:
        return ""

    hdr = f"@@ -{start_line},{len(ctx)} +{start_line},{len(ctx)} @@"
    body = "\n".join(" " + l for l in ctx)
    return (
        f"diff --git a/{rel} b/{rel}\n"
        f"--- a/{rel}\n"
        f"+++ b/{rel}\n"
        f"{hdr}\n"
        f"{body}\n"
    )


def _strip_diff_prefix(line: str) -> str:
    if not line:
        return ""
    if line[0] in {"-", "+", " "}:
        return line[1:]
    return line


def _symbol_defined_in_extra_hunk(patch_text: str, *, symbol_name: str) -> bool:
    """Return True if the `_extra_*` hunk already provides a definition/decl for symbol_name.

    This must be conservative: a symbol can appear in macro bodies or call sites without being defined.
    """
    want = str(symbol_name or "").strip()
    if not want:
        return False

    want_re = re.escape(want)
    fn_pat = re.compile(rf"(?<![A-Za-z0-9_]){want_re}\s*\(")
    declared_name_pat = re.compile(
        rf"(?<![A-Za-z0-9_]){want_re}(?![A-Za-z0-9_])\s*(?:\[\s*|=|,|;|:|__attribute__\b|__declspec\b)"
    )
    typedef_fn_ptr_pat = re.compile(rf"^typedef\b.*\(\s*\*\s*{want_re}\s*\)")
    tag_head_pat = re.compile(rf"^(?:typedef\s+)?(?:struct|union|enum)\s+{want_re}\b")

    in_block_comment = False
    raw_lines = str(patch_text or "").splitlines()
    for idx, raw in enumerate(raw_lines):
        if not raw.startswith("-") or raw.startswith("---"):
            continue
        code = _strip_diff_prefix(raw).rstrip()
        stripped = code.lstrip()
        if not stripped:
            continue
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("/*"):
            if "*/" not in stripped:
                in_block_comment = True
            continue
        if stripped.startswith("//"):
            continue

        # Macros: only treat as defined if we see a matching '#define NAME ...' line.
        m = re.match(r"^#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b", stripped)
        if m:
            if m.group(1) == want:
                return True
            # Other macros can reference `want` in their bodies; do not treat as a definition.
            continue

        # Do not treat macro continuation/body lines as definitions (they typically end with '\').
        if stripped.rstrip().endswith("\\"):
            continue

        # Tag bodies: treat `struct|union|enum NAME {` (or `{` on the next inserted line) as a definition.
        # Avoid treating `struct NAME;` or `struct NAME *p;` as "already defined".
        if tag_head_pat.match(stripped):
            if "{" in stripped:
                return True
            # Some style puts `{` on the next line: `typedef struct TAG` then `{`.
            for j in range(idx + 1, min(len(raw_lines), idx + 8)):
                nxt = raw_lines[j]
                if not nxt.startswith("-") or nxt.startswith("---"):
                    break
                nxt_code = _strip_diff_prefix(nxt).strip()
                if not nxt_code or nxt_code.startswith(("/*", "//")):
                    continue
                if nxt_code.startswith("{"):
                    return True
                break

        # Function prototypes/defs at file scope.
        if not stripped.startswith("#"):
            if fn_pat.search(stripped) and not _looks_like_statement(stripped):
                if stripped.rstrip().endswith(";") or "{" in stripped:
                    return True

        # Typedefs for function pointers (common C style): `typedef <ret> (*NAME)(...);`
        if stripped.startswith("typedef") and stripped.rstrip().endswith(";"):
            if typedef_fn_ptr_pat.match(stripped):
                return True

        # Other file-scope declarations: treat as defined only if NAME appears in a declarator position,
        # not merely as a referenced type inside a prototype/param list.
        if not stripped.startswith("#") and stripped.rstrip().endswith(";"):
            # Avoid treating forward tag decls (`struct NAME;`) as a definition; tag bodies require `{`.
            if re.match(rf"^(?:struct|union|enum)\s+{want_re}\b", stripped):
                continue
            m_decl = declared_name_pat.search(stripped)
            if m_decl:
                # If the only match is inside a function prototype parameter list (unnamed-parameter style),
                # it will appear after the first '(' on the line; ignore those.
                first_paren = stripped.find("(")
                if first_paren >= 0 and m_decl.start() > first_paren:
                    continue
                return True

    return False


_FORWARD_TYPEDEF_RE = re.compile(
    r"^typedef\s+(?P<tag_kind>struct|union|enum)\s+"
    r"(?P<tag>[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*;"
)


def _find_forward_typedef_tag(patch_text: str, *, alias: str) -> Tuple[str, str]:
    """Return (tag_kind, tag_name) if patch_text contains `typedef <tag_kind> <tag> <alias>;`."""
    want = str(alias or "").strip()
    if not want:
        return "", ""
    for raw in str(patch_text or "").splitlines():
        if not raw.startswith("-") or raw.startswith("---"):
            continue
        code = _strip_diff_prefix(raw).strip()
        if not code or code.startswith(("/*", "//")):
            continue
        m = _FORWARD_TYPEDEF_RE.match(code)
        if not m:
            continue
        if str(m.group("alias") or "") == want:
            return str(m.group("tag_kind") or ""), str(m.group("tag") or "")
    return "", ""


def _tag_definition_present_in_extra_hunk(patch_text: str, *, tag_kind: str, tag_name: str) -> bool:
    """Return True if patch_text already includes a tag definition like `struct TAG {`."""
    kind = str(tag_kind or "").strip()
    tag = str(tag_name or "").strip()
    if not kind or not tag:
        return False
    pat = re.compile(rf"^(?:{re.escape(kind)})\s+{re.escape(tag)}\s*\{{")
    for raw in str(patch_text or "").splitlines():
        if not raw.startswith("-") or raw.startswith("---"):
            continue
        code = _strip_diff_prefix(raw).strip()
        if not code:
            continue
        if pat.match(code):
            return True
    return False


def _is_header_path(file_path: str) -> bool:
    suffix = Path(str(file_path or "")).suffix.lower()
    return suffix in {".h", ".hh", ".hpp", ".hxx"}


def _kb_all_candidates(agent_tools: Any, *, symbol: str, version: str, max_nodes: int = 200) -> List[dict]:
    ver = str(version or "").strip().lower()
    if ver not in {"v1", "v2"}:
        return []
    name = str(symbol or "").strip()
    if not name:
        return []
    kb_index = getattr(agent_tools, "kb_index", None)
    if kb_index is None:
        return []

    try:
        nodes = (kb_index.query_all(name) or {}).get(ver, [])
    except Exception:
        nodes = []
    nodes = [n for n in nodes if isinstance(n, dict)]

    candidates: List[dict] = []
    seen: set[str] = set()
    for n in nodes[: max(0, int(max_nodes or 0))]:
        for cand in [n] + list(kb_index.related_definition_candidates(n, ver, max_depth=3) or []):
            if not isinstance(cand, dict):
                continue
            k = _kb_node_key(cand)
            if k in seen:
                continue
            seen.add(k)
            candidates.append(cand)
    return candidates


def _kb_pick_kind_node(agent_tools: Any, *, symbol: str, version: str, kind: str) -> Optional[dict]:
    want_kind = str(kind or "").strip()
    if not want_kind:
        return None
    candidates = _kb_all_candidates(agent_tools, symbol=symbol, version=version)
    filtered = [c for c in candidates if str(c.get("kind", "") or "").strip() == want_kind]
    if not filtered:
        return None

    def rank(node: dict) -> Tuple[int, int, int, int, int]:
        fp, ln, col = _kb_node_location_tuple(node)
        return (
            1 if _is_header_path(fp) else 0,
            _kb_node_extent_lines(node),
            1 if str(node.get("spelling", "") or "").strip() == str(symbol or "").strip() else 0,
            -ln,
            -col,
        )

    return max(filtered, key=rank)


_TYPEDEF_STRUCT_ALIAS_RE = re.compile(
    r"^\s*typedef\s+struct\s+(?P<tag>[A-Za-z_][A-Za-z0-9_]*)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;\s*$"
)


def _opaque_ptr_type_for_typedef(agent_tools: Any, *, typedef_name: str, version: str = "v2") -> str:
    """Return a pointer type name if typedef_name is opaque in the requested version.

    Heuristic: if `typedef struct TAG T;` exists but `struct TAG` is not defined in a header file in this version,
    treat T as opaque and prefer using a pointer (`TPtr` when available, else `T *`).
    """
    ver = str(version or "").strip().lower()
    if ver not in {"v1", "v2"}:
        ver = "v2"
    name = str(typedef_name or "").strip()
    if not name:
        return ""

    # Locate the typedef declaration for T.
    td = _kb_pick_kind_node(agent_tools, symbol=name, version=ver, kind="TYPEDEF_DECL")
    if td is None:
        return ""
    source_manager = getattr(agent_tools, "source_manager", None)
    if source_manager is None:
        return ""
    td_code = str(source_manager.get_function_code(td, ver) or "").replace("\r\n", "\n").replace("\r", "\n")
    td_line = next((l for l in td_code.splitlines() if str(l).strip()), "")
    if not td_line:
        return ""

    # If the typedef itself defines the struct body, it is not opaque.
    if "{" in td_code and "}" in td_code:
        return ""

    m = _TYPEDEF_STRUCT_ALIAS_RE.match(td_line)
    if not m or str(m.group("name") or "") != name:
        return ""
    tag = str(m.group("tag") or "").strip()
    if not tag:
        return ""

    # If the struct definition is available in a header, treat it as non-opaque.
    struct_header_defs = False
    for q in (f"struct {tag}", tag):
        for cand in _kb_all_candidates(agent_tools, symbol=q, version=ver):
            if str(cand.get("kind", "") or "").strip() != "STRUCT_DECL":
                continue
            fp, _, _ = _kb_node_location_tuple(cand)
            if not _is_header_path(fp):
                continue
            code = str(source_manager.get_function_code(cand, ver) or "")
            if "{" in code and "}" in code:
                struct_header_defs = True
                break
        if struct_header_defs:
            break
    if struct_header_defs:
        return ""

    # Prefer a conventional pointer typedef (e.g. xmlMutexPtr) if it exists.
    ptr_name = f"{name}Ptr"
    ptr_td = _kb_pick_kind_node(agent_tools, symbol=ptr_name, version=ver, kind="TYPEDEF_DECL")
    if ptr_td is not None:
        return ptr_name
    return f"{name} *"


def _parse_simple_var_decl(line: str) -> Optional[Tuple[str, str]]:
    """Parse a simple file-scope var declaration line into (type_name, var_name)."""
    text = str(line or "").strip()
    if not text or not text.endswith(";"):
        return None
    if text.startswith("#"):
        return None
    if "(" in text or ")" in text:
        return None
    if "{" in text or "}" in text:
        return None
    if "=" in text:
        return None
    if "[" in text or "]" in text:
        return None

    body = text[:-1].strip()
    # Normalize '*' tokens to make pointer detection easy.
    tokens = body.replace("*", " * ").split()
    if len(tokens) < 2:
        return None
    var_name = tokens[-1]
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", var_name):
        return None

    # If the variable is already a pointer, do not rewrite.
    if len(tokens) >= 2 and tokens[-2] == "*":
        return None

    type_name = tokens[-2]
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", type_name):
        return None
    return type_name, var_name


def _rewrite_opaque_var_decl_line(agent_tools: Any, *, code_line: str, version_for_type: str = "v2") -> str:
    parsed = _parse_simple_var_decl(code_line)
    if not parsed:
        return code_line
    type_name, var_name = parsed
    ptr_type = _opaque_ptr_type_for_typedef(agent_tools, typedef_name=type_name, version=version_for_type)
    if not ptr_type:
        return code_line

    # Preserve leading indentation (rare in file-scope decls, but avoid changing formatting).
    prefix = code_line[: len(code_line) - len(code_line.lstrip())]
    # Preserve any leading qualifiers before the type token.
    body = code_line.strip()[:-1].strip()
    tokens = body.replace("*", " * ").split()
    # Replace only the final type token (the one immediately before var_name).
    if len(tokens) < 2 or tokens[-1] != var_name:
        return code_line
    tokens[-2] = ptr_type
    rewritten = " ".join(tokens) + ";"
    return prefix + rewritten


def _rewrite_existing_opaque_var_decl_in_extra_hunk(agent_tools: Any, *, patch_text: str, symbol_name: str) -> str:
    """If the extra hunk already defines symbol_name with an unsafe by-value opaque type, rewrite it."""
    want = str(symbol_name or "").strip()
    if not want or not patch_text.strip():
        return ""

    lines = str(patch_text or "").splitlines()
    updated = list(lines)
    changed = False
    ident_pat = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(want)}(?![A-Za-z0-9_])")
    for i, raw in enumerate(lines):
        if not raw.startswith("-") or raw.startswith("---"):
            continue
        code = _strip_diff_prefix(raw).rstrip()
        stripped = code.strip()
        if not stripped or not stripped.endswith(";"):
            continue
        if not ident_pat.search(stripped):
            continue
        rewritten = _rewrite_opaque_var_decl_line(agent_tools, code_line=stripped, version_for_type="v2")
        if rewritten != stripped:
            updated[i] = "-" + rewritten
            changed = True
            break

    if not changed:
        return ""
    updated = _recompute_hunk_headers(updated)
    return "\n".join(updated).rstrip("\n") + "\n"


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


def _insert_minus_block_into_patch_text(patch_text: str, *, insert_lines: List[str], prefer_prepend: bool = False) -> str:
    """Insert `insert_lines` (raw code, no diff prefix) as '-' lines into a unified diff hunk.

    By default, this appends after any existing '-' lines in the first hunk body. When prefer_prepend is True,
    insert at the top of the hunk body so type declarations (typedef/tag bodies) can appear before previously
    inserted prototypes/macros.
    """
    raw = str(patch_text or "")
    if not raw.strip():
        return ""
    lines = raw.splitlines()
    first_hunk = next((i for i, l in enumerate(lines) if l.startswith("@@")), -1)
    if first_hunk < 0:
        return raw.rstrip("\n") + "\n"

    insert_at = first_hunk + 1
    if not prefer_prepend:
        # Insert after the last '-' line in the first hunk body (before trailing context).
        for i in range(first_hunk + 1, len(lines)):
            if lines[i].startswith("@@") or lines[i].startswith("diff --git "):
                break
            if lines[i].startswith("-") and not lines[i].startswith("---"):
                insert_at = i + 1

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


def _should_prepend_extra_hunk_insertion(*, insert_kind: str, inserted_lines: List[str]) -> bool:
    """Return True when inserted_lines should be prepended in the `_extra_*` hunk.

    C requires types to be declared before use in prototypes; if a type insertion happens after prototypes
    were already inserted, we must prepend the type block so those prototypes remain valid.
    """
    kind = str(insert_kind or "")
    if any(k in kind for k in ("TYPEDEF_DECL", "STRUCT_DECL", "UNION_DECL", "ENUM_DECL", "tag_definition_from_kb")):
        return True

    first = next((str(l) for l in (inserted_lines or []) if str(l).strip()), "")
    if not first:
        return False
    head = first.lstrip()
    if head.startswith("typedef"):
        return True
    if re.match(r"^(?:struct|union|enum)\b", head):
        if "{" in head:
            return True
        # Brace-on-next-line style: `struct TAG` then `{`.
        for l in (inserted_lines or [])[1:]:
            s = str(l).strip()
            if not s:
                continue
            if s.startswith("{"):
                return True
            break
        # Forward tag declaration (`struct TAG;`) still needs to precede prototypes using TAG.
        if re.match(r"^(?:struct|union|enum)\s+[A-Za-z_][A-Za-z0-9_]*\s*;\s*$", head):
            return True
    return False


_EXTRA_MERGE_DEFINE_RE = re.compile(r"^#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b")
_EXTRA_MERGE_TAG_RE = re.compile(r"^(?:typedef\s+)?(?P<kind>struct|union|enum)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b")
_EXTRA_MERGE_CONTROL_WORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "goto",
    "break",
    "continue",
    "else",
    "do",
    "sizeof",
}


def _merge_extra_hunk_blocks(*args: Any, **kwargs: Any) -> List[List[str]]:
    """Merge `_extra_*` inserted blocks by semantic key (best-effort, deterministic).

    Accepts either:
      - `_merge_extra_hunk_blocks(blocks)` where `blocks` is `List[List[str]]`, or
      - `_merge_extra_hunk_blocks(base_blocks, other_blocks, ...)` with multiple block lists, or
      - `_merge_extra_hunk_blocks(block_lists=[...])`.
    Returns a merged `List[List[str]]` preserving first-seen order; for duplicate prototypes, prefers `static`.
    """

    def normalize_block_list(value: Any) -> List[List[str]]:
        if not isinstance(value, list):
            return []
        out: List[List[str]] = []
        for item in value:
            if not isinstance(item, list):
                continue
            out.append([str(x) for x in item if x is not None])
        return out

    block_lists: List[List[List[str]]] = []
    if "block_lists" in kwargs:
        for item in (kwargs.get("block_lists") or []):
            block_lists.append(normalize_block_list(item))
    elif len(args) == 1 and isinstance(args[0], list):
        block_lists.append(normalize_block_list(args[0]))
    else:
        for item in args:
            block_lists.append(normalize_block_list(item))

    blocks_in: List[List[str]] = []
    for bl in block_lists:
        blocks_in.extend(bl)

    def typedef_declared_name(lines: List[str]) -> str:
        joined = " ".join(str(l).strip() for l in (lines or []) if str(l).strip())
        if not joined:
            return ""
        m = re.search(r"\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", joined)
        if m:
            return str(m.group(1) or "")
        m = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\]\s*)?;\s*$", joined)
        if m:
            return str(m.group(1) or "")
        return ""

    def semantic_id(block: List[str]) -> Tuple[str, str]:
        head = next((str(l).strip() for l in (block or []) if str(l).strip()), "")
        if not head:
            return ("text", "")

        m = _EXTRA_MERGE_DEFINE_RE.match(head)
        if m:
            return ("define", str(m.group(1) or ""))

        if head.startswith("typedef"):
            name = typedef_declared_name(block)
            return ("typedef", name or "\n".join(block).strip())

        m = _EXTRA_MERGE_TAG_RE.match(head)
        if m:
            return ("tag", f"{m.group('kind')} {m.group('name')}".strip())

        func_name = ""
        for raw in block:
            for m2 in _FUNC_NAME_RE.finditer(str(raw or "")):
                cand = str(m2.group(1) or "")
                if cand and cand not in _EXTRA_MERGE_CONTROL_WORDS:
                    func_name = cand
                    break
            if func_name:
                break
        if func_name:
            return ("prototype", func_name)

        return ("text", "\n".join(block).strip())

    def is_static_prototype(block: List[str]) -> bool:
        joined = " ".join(str(l).strip() for l in (block or []) if str(l).strip())
        return bool(re.search(r"(?<![A-Za-z0-9_])static(?![A-Za-z0-9_])", joined))

    def choose_better(kind: str, *, current: List[str], candidate: List[str]) -> List[str]:
        if kind == "prototype":
            cur_static = is_static_prototype(current)
            cand_static = is_static_prototype(candidate)
            if cur_static != cand_static:
                return candidate if cand_static else current

            cur_tail = next((str(l).strip() for l in reversed(current) if str(l).strip()), "")
            cand_tail = next((str(l).strip() for l in reversed(candidate) if str(l).strip()), "")
            cur_semicolon = cur_tail.endswith(";")
            cand_semicolon = cand_tail.endswith(";")
            if cur_semicolon != cand_semicolon:
                return candidate if cand_semicolon else current

        return candidate if len("\n".join(candidate)) > len("\n".join(current)) else current

    merged: Dict[str, Dict[str, Any]] = {}
    order = 0
    for block in blocks_in:
        kind, name = semantic_id(block)
        key = f"{kind}:{name}"
        existing = merged.get(key)
        if existing is None:
            merged[key] = {"kind": kind, "name": name, "lines": list(block), "order": order}
            order += 1
            continue
        cur_lines = list(existing.get("lines") or [])
        if cur_lines == block:
            continue
        existing["lines"] = choose_better(kind, current=cur_lines, candidate=block)

    merged_items = sorted((v for v in merged.values() if isinstance(v, dict)), key=lambda it: int(it.get("order") or 0))
    return [list(it.get("lines") or []) for it in merged_items if it.get("lines")]


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


def _kb_pick_insertable_node_filtered(
    agent_tools: Any,
    *,
    symbol: str,
    version: str,
    allowed_kinds: set[str],
    max_nodes: int = 200,
) -> Optional[dict]:
    """Like _kb_pick_insertable_node, but restrict candidates to allowed_kinds."""
    ver = str(version or "").strip().lower()
    if ver not in {"v1", "v2"}:
        return None
    name = str(symbol or "").strip()
    if not name:
        return None
    kinds = {str(k or "").strip() for k in (allowed_kinds or set()) if str(k or "").strip()}
    if not kinds:
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

    insertable = [c for c in candidates if str(c.get("kind", "") or "").strip() in kinds]
    if not insertable:
        return None

    def rank(node: dict) -> Tuple[int, int, int, int, int]:
        kind = str(node.get("kind", "") or "").strip()
        reason = str(node.get("__reason", "") or "").strip()
        fp, ln, col = _kb_node_location_tuple(node)
        return (
            _kb_node_extent_lines(node),
            1 if reason else 0,
            1 if fp else 0,
            -ln,
            -col,
        )

    return max(insertable, key=rank)


def _upgrade_existing_forward_typedef_in_extra_hunk(
    agent_tools: Any,
    *,
    patch_text: str,
    symbol_name: str,
    requested_version: str,
) -> Tuple[str, str, str]:
    """If patch_text already contains a forward typedef, insert the tag body (struct/union/enum) from KB.

    Returns (updated_patch_text, inserted_code, insert_kind). Empty updated_patch_text means no change.
    """
    if agent_tools is None:
        return "", "", ""
    sym = str(symbol_name or "").strip()
    if not sym:
        return "", "", ""

    tag_kind, tag = _find_forward_typedef_tag(patch_text, alias=sym)
    if not tag_kind or not tag:
        return "", "", ""
    if _tag_definition_present_in_extra_hunk(patch_text, tag_kind=tag_kind, tag_name=tag):
        return "", "", ""

    kind_map = {"struct": "STRUCT_DECL", "union": "UNION_DECL", "enum": "ENUM_DECL"}
    want_kind = kind_map.get(tag_kind)
    if not want_kind:
        return "", "", ""

    requested = str(requested_version or "v1").strip().lower()
    if requested not in {"v1", "v2"}:
        requested = "v1"
    versions_to_try = [requested, ("v2" if requested == "v1" else "v1")]

    source_manager = getattr(agent_tools, "source_manager", None)
    if source_manager is None:
        return "", "", ""

    struct_code = ""
    used_ver = ""
    chosen_kind = ""
    for ver in versions_to_try:
        chosen = _kb_pick_insertable_node_filtered(agent_tools, symbol=tag, version=ver, allowed_kinds={want_kind})
        if chosen is None:
            continue
        code = str(source_manager.get_function_code(chosen, ver) or "")
        if not code.strip():
            continue
        # Ensure this is a real tag body definition.
        if "{" not in code:
            continue
        if f"{tag_kind} {tag}" not in code:
            # Be tolerant of formatting, but require the tag identifier to show up.
            if tag not in code:
                continue
        struct_code = code
        used_ver = ver
        chosen_kind = str(chosen.get("kind", "") or "").strip()
        break

    if not struct_code.strip():
        return "", "", ""

    inserted_lines = [l.rstrip("\n") for l in struct_code.replace("\r\n", "\n").replace("\r", "\n").splitlines()]
    inserted_lines = [l.rstrip() for l in inserted_lines if l is not None]
    if not inserted_lines:
        return "", "", ""

    updated = _insert_minus_block_into_patch_text(patch_text, insert_lines=[""] + inserted_lines, prefer_prepend=True)
    insert_kind = f"tag_definition_from_kb:{used_ver}:{chosen_kind or want_kind}"
    return updated, "\n".join(inserted_lines).rstrip("\n") + "\n", insert_kind


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

    patches = bundle.patches if isinstance(getattr(bundle, "patches", None), dict) else {}
    patch = patches.get(extra_key)
    if patch is None:
        existing = _new_extra_patch_skeleton(agent_tools, file_path=file_path_s)
        if not existing.strip():
            return {
                "patch_path": str(Path(patch_path_s).expanduser().resolve()),
                "file_path": file_path_s,
                "symbol_name": symbol,
                "patch_key": extra_key,
                "patch_text": "",
                "note": "Failed to create a new _extra_* patch hunk skeleton (could not read V2 source for file).",
            }
    else:
        existing = str(getattr(patch, "patch_text", "") or "")

    if _symbol_defined_in_extra_hunk(existing, symbol_name=symbol):
        # If the symbol exists but is unsafe (common: opaque typedef used by-value), rewrite it.
        updated_existing = ""
        if agent_tools is not None:
            updated_existing = _rewrite_existing_opaque_var_decl_in_extra_hunk(agent_tools, patch_text=existing, symbol_name=symbol)
        if updated_existing:
            store = ArtifactStore(_artifact_root() / extra_key, overwrite=False)
            ref = store.write_text(
                name=f"make_extra_patch_override_patch_text_{_normalize_file_basename(file_path_s)}_{symbol}",
                text=updated_existing,
                ext=".diff",
            )
            return {
                "patch_path": str(Path(patch_path_s).expanduser().resolve()),
                "file_path": file_path_s,
                "symbol_name": symbol,
                "patch_key": extra_key,
                "insert_kind": "rewrite_existing_opaque_var_decl",
                "inserted_code": "",
                "patch_text": ref.to_dict(),
                "patch_text_truncated": False,
                "patch_text_lines_total": len(updated_existing.splitlines()),
                "note": "Symbol already present, but rewrote an unsafe by-value opaque type declaration in the extra hunk.",
            }

        # If the symbol exists only as a forward typedef (e.g. `typedef struct TAG Name;`),
        # inserting the tag body can be required for field access (`ptr->field` needs a complete type).
        updated_existing, inserted_code, insert_kind = _upgrade_existing_forward_typedef_in_extra_hunk(
            agent_tools,
            patch_text=existing,
            symbol_name=symbol,
            requested_version=str(version or "v1"),
        )
        if updated_existing:
            store = ArtifactStore(_artifact_root() / extra_key, overwrite=False)
            ref = store.write_text(
                name=f"make_extra_patch_override_patch_text_{_normalize_file_basename(file_path_s)}_{symbol}",
                text=updated_existing,
                ext=".diff",
            )
            return {
                "patch_path": str(Path(patch_path_s).expanduser().resolve()),
                "file_path": file_path_s,
                "symbol_name": symbol,
                "patch_key": extra_key,
                "insert_kind": insert_kind or "upgrade_forward_typedef_with_tag_body",
                "inserted_code": inserted_code or "",
                "patch_text": ref.to_dict(),
                "patch_text_truncated": False,
                "patch_text_lines_total": len(updated_existing.splitlines()),
                "note": "Symbol already present as a forward typedef; inserted the tag body definition into the extra hunk.",
            }

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
        note = "Failed to locate a definition/decl for the symbol (bundle+KB)."
        if agent_tools is not None:
            kb_index = getattr(agent_tools, "kb_index", None)
            query = underlying or symbol
            if kb_index is not None:
                try:
                    v1_nodes = list((kb_index.query_all(query) or {}).get("v1", []))
                    v2_nodes = list((kb_index.query_all(query) or {}).get("v2", []))
                    if v1_nodes or v2_nodes:
                        note = (
                            f"KB has nodes for {query!r} (v1={len(v1_nodes)}, v2={len(v2_nodes)}), "
                            "but none produced readable source code. "
                            "This often means the configured --v1-src/--v2-src working trees don't match the KB JSON "
                            "file layout/revision. Fix the src paths or set REACT_AGENT_V1_SRC_COMMIT/"
                            "REACT_AGENT_V2_SRC_COMMIT so SourceManager can fall back to `git show <commit>:<path>`."
                        )
                except Exception:
                    pass
        return {
            "patch_path": str(Path(patch_path_s).expanduser().resolve()),
            "file_path": file_path_s,
            "symbol_name": symbol,
            "patch_key": extra_key,
            "patch_text": "",
            "note": note,
        }

    # If we are inserting a by-value global of an opaque type (common with typedef'd structs),
    # rewrite it to a pointer form to avoid incomplete-type build errors.
    if agent_tools is not None and len(inserted_lines) == 1:
        rewritten = _rewrite_opaque_var_decl_line(agent_tools, code_line=str(inserted_lines[0] or "").rstrip(), version_for_type="v2")
        if rewritten != str(inserted_lines[0] or "").rstrip():
            inserted_lines = [rewritten]
            insert_kind = (insert_kind + ":opaque_by_value_rewritten_to_ptr").strip(":")

    # Ensure a blank line separator before the inserted block for readability.
    block_lines = [""] + [l.rstrip() for l in inserted_lines if l is not None]

    updated_text = _insert_minus_block_into_patch_text(
        existing,
        insert_lines=block_lines,
        prefer_prepend=_should_prepend_extra_hunk_insertion(insert_kind=insert_kind, inserted_lines=inserted_lines),
    )

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
