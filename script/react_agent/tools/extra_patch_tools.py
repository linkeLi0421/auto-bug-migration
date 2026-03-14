from __future__ import annotations

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
    patches = getattr(bundle, "patches", None)
    if isinstance(patches, dict) and candidate in patches:
        return candidate
    # Check for split variants: _extra_<filename>__h<old_start>
    if isinstance(patches, dict):
        split_prefix = f"{candidate}__h"
        split_matches = [k for k in patches if k.startswith(split_prefix)]
        if split_matches:

            def _hunk_start(key: str) -> int:
                suffix = key[len(split_prefix):]
                try:
                    return int(suffix)
                except ValueError:
                    return 10**9

            split_matches.sort(key=_hunk_start)
            return split_matches[0]
    # Fallback: scan for a matching _extra_* entry that targets this file.
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

    def _strip_src_repo_prefix(path_s: str, *, repo_name: str = "") -> str:
        """Normalize /src/<repo>/... and src/<repo>/... to repo-relative path."""
        s = str(path_s or "").replace("\\", "/").strip()
        if not s:
            return ""
        if s.startswith("/src/"):
            s = s[len("/src/") :]
        elif s == "/src":
            s = ""
        elif s.startswith("src/"):
            s = s[len("src/") :]
        elif s == "src":
            s = ""
        if repo_name:
            if s == repo_name:
                s = ""
            elif s.startswith(repo_name + "/"):
                s = s[len(repo_name) + 1 :]
            elif s == f"{repo_name}-src":
                s = ""
            elif s.startswith(f"{repo_name}-src/"):
                s = s[len(f"{repo_name}-src/") :]
        return s

    path_norm = raw.replace("\\", "/")

    if sm is not None:
        root = None
        try:
            root = sm._repo_root(version)  # type: ignore[attr-defined]
        except Exception:
            root = None

        if root is not None:
            try:
                p = Path(path_norm)
                if p.is_absolute() and p.exists():
                    rel = p.resolve().relative_to(root.resolve()).as_posix()
                    repo_name = str(getattr(root, "name", "") or "").strip()
                    rel_norm = _strip_src_repo_prefix(rel, repo_name=repo_name)
                    return rel_norm if rel_norm else rel
            except Exception:
                pass

        try:
            resolved = sm._resolve_path(raw, version)  # type: ignore[attr-defined]
        except Exception:
            resolved = None
        if resolved is not None and resolved.exists():
            try:
                if root is None:
                    root = sm._repo_root(version)  # type: ignore[attr-defined]
                rel = resolved.resolve().relative_to(root.resolve()).as_posix()
                repo_name = str(getattr(root, "name", "") or "").strip()
                rel_norm = _strip_src_repo_prefix(rel, repo_name=repo_name)
                return rel_norm if rel_norm else rel
            except Exception:
                pass

    # Fallback: strip /src and repo-name aliases when present.
    rel = path_norm.lstrip("/")
    if path_norm.startswith("/src") or path_norm.startswith("src/"):
        rel = _strip_src_repo_prefix(path_norm)
    if sm is not None:
        try:
            repo = sm._repo_root(version)  # type: ignore[attr-defined]
            repo_name = str(getattr(repo, "name", "") or "").strip()
            rel = _strip_src_repo_prefix(rel, repo_name=repo_name)
        except Exception:
            pass
    return rel.replace("\\", "/")


_TEST_LIKE_DIR_NAMES = {
    "test",
    "tests",
    "testing",
    "fuzz",
    "fuzzer",
    "examples",
    "example",
    "docs",
    "doc",
    "bench",
    "benches",
    "benchmark",
    "benchmarks",
}


def _looks_test_like_relpath(rel_path: str) -> bool:
    parts = [str(p).lower() for p in Path(str(rel_path or "")).parts[:-1]]
    for seg in parts:
        if seg in _TEST_LIKE_DIR_NAMES or seg.startswith("test"):
            return True
    return False


def _normalize_requested_relpath(requested_path: str, *, repo_name: str = "") -> str:
    s = str(requested_path or "").replace("\\", "/").strip()
    if not s:
        return ""
    if s.startswith("/src/"):
        s = s[len("/src/") :]
    elif s == "/src":
        s = ""
    elif s.startswith("src/"):
        s = s[len("src/") :]
    elif s == "src":
        s = ""
    s = s.lstrip("/")
    if repo_name:
        if s == repo_name:
            s = ""
        elif s.startswith(repo_name + "/"):
            s = s[len(repo_name) + 1 :]
        elif s == f"{repo_name}-src":
            s = ""
        elif s.startswith(f"{repo_name}-src/"):
            s = s[len(f"{repo_name}-src/") :]
    return s


def _best_basename_candidate(candidates: List[Path], *, repo_root: Path, requested_path: str) -> Optional[Path]:
    """Pick a deterministic best file when basename lookup yields multiple matches."""
    if not candidates:
        return None

    repo_name = str(getattr(repo_root, "name", "") or "").strip()
    req_rel = _normalize_requested_relpath(requested_path, repo_name=repo_name)
    req_parts = [str(p) for p in Path(req_rel).parts if str(p) not in {"", "."}]
    req_dir_parts = [p.lower() for p in req_parts[:-1]]

    def _dir_suffix_match_len(rel_parts: List[str]) -> int:
        if not req_dir_parts:
            return 0
        rel_dir = [p.lower() for p in rel_parts[:-1]]
        n = 0
        while n < len(req_dir_parts) and n < len(rel_dir):
            if req_dir_parts[-1 - n] != rel_dir[-1 - n]:
                break
            n += 1
        return n

    def _score(path: Path) -> tuple:
        try:
            rel = path.resolve().relative_to(repo_root.resolve()).as_posix()
        except Exception:
            rel = path.name
        rel_parts = [str(p) for p in Path(rel).parts if str(p) not in {"", "."}]
        exact_hint = 1 if req_rel and rel == req_rel else 0
        suffix_hint = 1 if req_rel and rel.endswith("/" + req_rel) else 0
        dir_hint = _dir_suffix_match_len(rel_parts)
        is_test_like = 1 if _looks_test_like_relpath(rel) else 0
        is_top_level = 1 if len(rel_parts) <= 1 else 0
        return (
            -exact_hint,
            -suffix_hint,
            -dir_hint,
            is_test_like,
            -is_top_level,
            len(rel_parts),
            len(rel),
            rel,
        )

    return min(candidates, key=_score)


def _resolve_extra_skeleton_file(agent_tools: Any, *, file_path: str) -> Tuple[Optional[Path], str]:
    """Resolve a file path for `_extra_*` skeleton creation, with deterministic fallbacks."""
    sm = getattr(agent_tools, "source_manager", None)
    if sm is None:
        return None, "v2"

    # Try V2 first, then V1.
    for ver in ("v2", "v1"):
        try:
            resolved = sm._resolve_path(str(file_path or "").strip(), ver)  # type: ignore[attr-defined]
        except Exception:
            resolved = None
        if resolved is not None and resolved.exists():
            return resolved, ver

    basename = Path(str(file_path or "")).name
    if not basename:
        return None, "v2"

    for ver in ("v2", "v1"):
        try:
            repo_root = sm._repo_root(ver)  # type: ignore[attr-defined]
        except Exception:
            continue
        candidates = [p for p in repo_root.rglob(basename) if p.is_file()]
        chosen = _best_basename_candidate(candidates, repo_root=repo_root, requested_path=str(file_path or ""))
        if chosen is not None:
            return chosen, ver
    return None, "v2"


_PP_IF_RE = re.compile(r"^#\s*(?:if|ifdef|ifndef)\b")
_PP_ENDIF_RE = re.compile(r"^#\s*endif\b")

_FUNC_DEF_KINDS = {"FUNCTION_DEFI", "CXX_METHOD", "FUNCTION_TEMPLATE"}


def _find_include_guard_endif(lines: List[str]) -> int:
    """Return the 0-based index of the closing ``#endif`` of an include guard, or -1.

    An include guard is detected when the file starts with ``#ifndef`` / ``#define``
    (possibly preceded by comments/blank lines) and ends with a matching ``#endif``
    that brings the preprocessor nesting back to zero.  We return the index of that
    final ``#endif`` so callers can clamp insertions to stay inside the guard.
    """
    if not lines:
        return -1

    # 1. Check if the file opens with an include guard pattern.
    #    Skip leading blank lines, single-line comments, and multi-line /* ... */ blocks.
    guard_open_idx = -1
    in_block_comment = False
    for i, raw in enumerate(lines):
        stripped = str(raw or "").lstrip().lstrip("\ufeff")
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue
        if not stripped:
            continue
        if stripped.startswith("//"):
            continue
        if stripped.startswith("/*"):
            if "*/" not in stripped:
                in_block_comment = True
            continue
        if re.match(r"^#\s*ifndef\b", stripped):
            guard_open_idx = i
        break  # first meaningful line must be #ifndef

    if guard_open_idx < 0:
        # Also accept #pragma once -- but there is no closing #endif to clamp to.
        return -1

    # 2. Walk the file tracking preprocessor nesting; record the last #endif that
    #    brings nesting back to zero.
    pp_nesting = 0
    last_zero_endif = -1
    for i, raw in enumerate(lines):
        stripped = str(raw or "").lstrip()
        if _PP_IF_RE.match(stripped):
            pp_nesting += 1
        elif _PP_ENDIF_RE.match(stripped):
            pp_nesting -= 1
            if pp_nesting == 0:
                last_zero_endif = i

    # 3. Only treat it as a guard #endif if nothing meaningful follows it.
    if last_zero_endif < 0:
        return -1
    for i in range(last_zero_endif + 1, len(lines)):
        stripped = str(lines[i] or "").strip()
        if stripped and not stripped.startswith("//") and not stripped.startswith("/*"):
            return -1  # there is real code after; not a simple include guard
    return last_zero_endif


def _is_preprocessor_if_zero_line(stripped_line: str) -> bool:
    s = str(stripped_line or "").strip()
    m = re.match(r"^#\s*if\b(?P<expr>.*)$", s)
    if not m:
        return False
    expr = str(m.group("expr") or "")
    expr = re.sub(r"/\*.*?\*/", " ", expr)
    expr = re.sub(r"//.*$", "", expr)
    expr = expr.strip()
    if not expr:
        return False
    return bool(re.match(r"^0(?:\b|[()!<>=&|+\-*/%])", expr))


def _collect_if0_blocks(lines: List[str]) -> List[Tuple[int, int]]:
    """Return (start_idx, end_idx) pairs for #if 0 ... #endif blocks."""
    blocks: List[Tuple[int, int]] = []
    stack: List[Tuple[int, bool]] = []
    for i, raw in enumerate(lines):
        stripped = str(raw or "").lstrip()
        if _PP_IF_RE.match(stripped):
            stack.append((i, _is_preprocessor_if_zero_line(stripped)))
            continue
        if _PP_ENDIF_RE.match(stripped):
            if not stack:
                continue
            start_i, is_if0 = stack.pop()
            if is_if0:
                blocks.append((start_i, i))
    return blocks


def _skip_out_of_if0_block(lines: List[str], idx: int) -> int:
    """Move insertion index out of #if 0 blocks so inserted code is compiled."""
    if not lines:
        return 0
    idx = max(0, min(int(idx), len(lines)))
    blocks = _collect_if0_blocks(lines)
    if not blocks:
        return idx

    changed = True
    while changed:
        changed = False
        for start_i, end_i in blocks:
            # idx is an insertion point *before* line idx.
            # start_i < idx <= end_i means we are inside the disabled block.
            if start_i < idx <= end_i:
                idx = min(end_i + 1, len(lines))
                changed = True
                break
    return idx


def _preprocessor_nesting_before_index(lines: List[str], idx: int) -> int:
    """Return active #if nesting immediately before insertion index `idx`."""
    if not lines:
        return 0
    idx = max(0, min(int(idx), len(lines)))
    nesting = 0
    for i in range(0, idx):
        stripped = str(lines[i] or "").lstrip()
        if _PP_IF_RE.match(stripped):
            nesting += 1
        elif _PP_ENDIF_RE.match(stripped):
            nesting = max(nesting - 1, 0)
    return nesting


def _skip_out_of_preprocessor_block(lines: List[str], idx: int) -> int:
    """Move insertion index out of active #if/#ifdef/#ifndef blocks.

    This is for non-header files where declarations inside conditional regions
    may not be visible for all build configurations.

    Exception: file-level feature guards (``#ifndef MRB_NO_FLOAT`` wrapping
    the entire file) are NOT skipped — they are intentional wrappers, not
    conditional sections that should be avoided.  A guard is detected when the
    enclosing ``#if*`` starts near the top of the file (within the first 10
    non-blank, non-comment, non-include lines) and its matching ``#endif`` is
    within the last 5 lines of the file.
    """
    if not lines:
        return 0
    idx = max(0, min(int(idx), len(lines)))
    nesting = _preprocessor_nesting_before_index(lines, idx)
    if nesting <= 0:
        return idx

    # Find the matching #endif for the enclosing block.
    scan_nesting = nesting
    endif_idx = -1
    for i in range(idx, len(lines)):
        stripped = str(lines[i] or "").lstrip()
        if _PP_IF_RE.match(stripped):
            scan_nesting += 1
            continue
        if _PP_ENDIF_RE.match(stripped):
            scan_nesting -= 1
            if scan_nesting <= 0:
                endif_idx = i
                break

    if endif_idx < 0:
        # Unterminated conditional block: keep original insertion point.
        return idx

    # Detect file-level feature guard: the outermost #if* that encloses idx
    # starts near the top and the #endif is near the bottom.
    # Walk backward from idx to find the opening #if* at nesting level 1.
    open_idx = -1
    back_nesting = nesting
    for i in range(idx - 1, -1, -1):
        stripped = str(lines[i] or "").lstrip()
        if _PP_ENDIF_RE.match(stripped):
            back_nesting += 1
        elif _PP_IF_RE.match(stripped):
            back_nesting -= 1
            if back_nesting <= 0:
                open_idx = i
                break

    if open_idx >= 0:
        # Count non-trivial lines before the opening #if* (comments, blanks,
        # includes, and preprocessor lines don't count).
        substantive_before = 0
        for i in range(open_idx):
            s = str(lines[i] or "").lstrip()
            if not s or s.startswith("//") or s.startswith("/*") or s.startswith("*") or s.startswith("#"):
                continue
            substantive_before += 1
        lines_after_endif = len(lines) - 1 - endif_idx
        if substantive_before <= 2 and lines_after_endif <= 5:
            # This is a file-level guard — stay inside it.
            return idx

    # Not a file-level guard — skip past the #endif.
    return min(endif_idx + 1, len(lines))


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


def _bundle_earliest_reference_line(bundle: Any, *, file_path: str, symbol_name: str) -> int:
    """Scan regular hunks in *bundle* for the earliest *call/use* of *symbol_name*.

    Returns the ``new_start_line`` (V2 line number) of the earliest hunk whose
    ``-`` lines contain a call/use (not a forward-declaration/definition) of
    *symbol_name*, or -1 if not found.  Only non-``_extra_*`` hunks for the
    same file (by basename) are considered.

    We return the V2 (new-side) line rather than V1 (old-side) because the
    skeleton generator reads V2 source to build the ``_extra_*`` hunk context.
    """
    if bundle is None or not symbol_name:
        return -1
    patches = getattr(bundle, "patches", None)
    if not isinstance(patches, dict):
        return -1
    target_basename = Path(str(file_path or "")).name
    if not target_basename:
        return -1

    _C_STMT_KW = {"return", "if", "else", "while", "for",
                   "switch", "case", "do", "goto", "break",
                   "continue", "sizeof", "typeof"}

    earliest = -1
    for key, patch_info in patches.items():
        key_s = str(key or "")
        if key_s.startswith("_extra_"):
            continue
        pt = str(getattr(patch_info, "patch_text", "") or "")
        if not pt.strip():
            continue
        if target_basename not in pt:
            continue
        nsl = int(getattr(patch_info, "new_start_line", 0) or 0)
        if nsl <= 0:
            continue

        # Check if any '-' line has a call/use (not decl/def) of the symbol.
        has_use = False
        for line in pt.splitlines():
            if not line.startswith("-") or line.startswith("---"):
                continue
            if symbol_name not in line:
                continue
            content = line[1:].strip()
            # Skip forward declarations / definitions of the symbol itself.
            _stripped = content
            for _q in ("static", "inline", "extern", "const",
                       "unsigned", "signed", "struct", "enum",
                       "volatile"):
                _stripped = re.sub(r"^" + _q + r"\s+", "", _stripped)
            _dm = re.match(
                r"(\w+)[\s*]+" + re.escape(symbol_name) + r"\s*\(",
                _stripped,
            )
            if _dm and _dm.group(1) not in _C_STMT_KW:
                continue  # declaration/definition — skip
            has_use = True
            break

        if not has_use:
            continue

        if earliest < 0 or nsl < earliest:
            earliest = nsl
    return earliest


def _ast_insert_line_number_for_extra_skeleton(
    agent_tools: Any,
    *,
    file_path: str,
    version: str = "v2",
    symbol_name: str = "",
    bundle: Any = None,
    force_tier1: bool = False,
) -> int:
    """Return a 1-based insertion line based on AST analysis (best-effort).

    Strategy: insert before a selected function definition start line (start.line).
    - Tier 1 (default): insert before the first function definition in the file.
    - Tier 2 (`__revert_*` only): anchor before the function preceding the underlying V2 target.
    - `force_tier1=True` bypasses Tier 2 and always uses "before first function".
    - If `REACT_AGENT_EXTRA_SKELETON_ANCHOR_FUNC_SIG` is set, try to match that signature (ignore arg types).
    """
    def no_anchor() -> int:
        return -1

    kb = getattr(agent_tools, "kb_index", None)
    if kb is None:
        return no_anchor()

    ver = str(version or "v2").strip().lower()
    if ver not in {"v1", "v2"}:
        ver = "v2"
    _kind, _underlying = _symbol_underlying_name(str(symbol_name or ""))

    base = Path(str(file_path or "").strip()).name
    if not base:
        return no_anchor()

    file_index = getattr(kb, "file_index", None)
    if not isinstance(file_index, dict) or ver not in file_index:
        return -1

    # Try basename first, then scan for a key ending with the basename (the
    # KB file_index may be keyed by a relative path like "htslib/vcf.h").
    ver_index = file_index[ver] if isinstance(file_index[ver], dict) else {}
    nodes = ver_index.get(base)
    if not isinstance(nodes, list) or not nodes:
        for key in ver_index:
            if Path(key).name == base:
                nodes = ver_index[key]
                break
    if not isinstance(nodes, list) or not nodes:
        # No KB data; give up.
        return no_anchor()

    # NOTE: For __revert_* functions (kind == "revert_function"), we intentionally
    # fall through to the default "before first function definition" logic below.
    # Forward declarations must appear before call sites; anchoring after the V2
    # function body (extent.end.line + 1) placed them too late, causing
    # "conflicting types" errors when the call site preceded the V2 function end.

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

    if force_tier1:
        first = min(candidates, key=lambda n: (start_line(n), end_line(n)))
        sl = start_line(first)
        return sl if sl > 0 else -1

    want_sig = _extra_skeleton_anchor_func_sig()
    if want_sig:
        for n in candidates:
            sig = str(n.get("signature", "") or "")
            if sig and _compare_function_signatures(sig, want_sig, ignore_arg_types=True):
                sl = start_line(n)
                return sl if sl > 0 else -1

    # For __revert_* symbols, use smarter insertion logic instead of blindly
    # anchoring at the first function.  The first-function anchor may precede
    # required type definitions (e.g. bcf_hdr_t), causing "unknown type name"
    # and "conflicting types" errors.
    if not force_tier1 and _kind == "revert_function" and _underlying:
        tier2_anchor = -1
        # Tier 2: KB heuristic — find the underlying V2 function in the
        # candidates and anchor before the immediately preceding function.
        # In typical header layouts (e.g. vcf.h) the caller is defined just
        # before the callee, so this places the forward declaration after all
        # type definitions and before the call site.
        target_node = None
        for n in candidates:
            sp = str(n.get("spelling", "") or "").strip()
            if sp == _underlying:
                target_node = n
                break
        if target_node is not None:
            target_sl = start_line(target_node)
            if target_sl > 0:
                preceding = [n for n in candidates if 0 < start_line(n) < target_sl]
                if preceding:
                    prev = max(preceding, key=lambda n: start_line(n))
                    prev_sl = start_line(prev)
                    if prev_sl > 0:
                        tier2_anchor = prev_sl
                # No preceding function — anchor at the underlying function
                # itself; types it uses must already be defined by then.
                if tier2_anchor <= 0:
                    tier2_anchor = target_sl

        # Guardrail: if we can see an earlier reference from existing non-extra
        # hunks, never place the declaration after that first use.
        ref_line = _bundle_earliest_reference_line(
            bundle,
            file_path=str(file_path or "").strip(),
            symbol_name=str(symbol_name or "").strip(),
        )
        ref_anchor = -1
        if ref_line > 0:
            containing = [
                n for n in candidates
                if start_line(n) > 0 and end_line(n) > 0 and start_line(n) <= ref_line <= end_line(n)
            ]
            if containing:
                ref_anchor = max(containing, key=lambda n: start_line(n))
                ref_anchor = start_line(ref_anchor)
            else:
                preceding = [n for n in candidates if 0 < start_line(n) < ref_line]
                if preceding:
                    ref_anchor = start_line(max(preceding, key=lambda n: start_line(n)))
                else:
                    first_ref = min(candidates, key=lambda n: (start_line(n), end_line(n)))
                    ref_anchor = start_line(first_ref)

        if ref_anchor > 0 and (tier2_anchor <= 0 or tier2_anchor > ref_line):
            return ref_anchor
        if tier2_anchor > 0:
            return tier2_anchor
        if ref_anchor > 0:
            return ref_anchor

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
    in_macro_continuation = False
    pp_nesting = 0
    last_include_idx = -1
    header_section_ended = False  # Track if we've left the initial header/preprocessor section

    for idx, raw in enumerate(lines):
        # Strip BOM (U+FEFF) so that BOM-prefixed comment/preprocessor lines
        # (e.g. '\ufeff/** @file ...') are recognised correctly.
        stripped = str(raw or "").lstrip().lstrip("\ufeff")
        # Track multi-line #define macros (lines ending with backslash).
        if in_macro_continuation:
            if not str(raw or "").rstrip().endswith("\\"):
                in_macro_continuation = False
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
            # Check if this preprocessor line continues (multi-line macro).
            if str(raw or "").rstrip().endswith("\\"):
                in_macro_continuation = True
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


def _skip_past_macro_continuation(lines: List[str], idx: int) -> int:
    """If `idx` falls inside a multi-line #define (backslash-continued), advance past it."""
    if idx <= 0 or idx >= len(lines):
        return idx
    # Check if the immediately preceding line ends with backslash (we are inside a macro body).
    if not str(lines[idx - 1] or "").rstrip().endswith("\\"):
        return idx
    # Advance past all remaining backslash-continued lines.
    while idx < len(lines) and str(lines[idx] or "").rstrip().endswith("\\"):
        idx += 1
    # Skip one more (the final line of the macro which doesn't end with \).
    if idx < len(lines):
        idx += 1
    return min(idx, len(lines))


def _earliest_bundle_hunk_start(*, bundle: Any, file_path: str) -> Optional[int]:
    """Return the 0-based earliest old_start_line of non-_extra_* hunks for *file_path*.

    Returns ``None`` when no non-_extra_* hunks target this file.
    """
    if bundle is None:
        return None
    patches = getattr(bundle, "patches", None)
    if not isinstance(patches, dict):
        return None
    base = Path(str(file_path or "").strip()).name
    if not base:
        return None

    earliest: Optional[int] = None
    for key, patch in patches.items():
        if str(key or "").startswith("_extra_"):
            continue
        fp_new = str(getattr(patch, "file_path_new", "") or "").strip()
        fp_old = str(getattr(patch, "file_path_old", "") or "").strip()
        if Path(fp_new).name != base and Path(fp_old).name != base:
            continue
        pt = str(getattr(patch, "patch_text", "") or "")
        for line in pt.splitlines():
            m = _HUNK_RE.match(line)
            if m:
                old_start = int(m.group("old_start") or 0)
                if old_start > 0:
                    idx = old_start - 1  # 0-based
                    if earliest is None or idx < earliest:
                        earliest = idx
                break
    return earliest


def _new_extra_patch_skeleton(
    agent_tools: Any,
    *,
    file_path: str,
    context_lines: int = 3,
    symbol_name: str = "",
    bundle: Any = None,
    force_tier1: bool = False,
) -> str:
    """Create a minimal unified diff skeleton for a brand-new `_extra_*` patch key."""
    sm = getattr(agent_tools, "source_manager", None)
    if sm is None:
        return ""

    resolved, version_used = _resolve_extra_skeleton_file(agent_tools, file_path=str(file_path or "").strip())
    if resolved is None or not resolved.exists():
        return ""
    text = resolved.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    if not lines:
        return ""

    insert_at = -1
    insert_line = _ast_insert_line_number_for_extra_skeleton(
        agent_tools, file_path=str(file_path or "").strip(), version=version_used, symbol_name=str(symbol_name or "").strip(),
        bundle=bundle, force_tier1=bool(force_tier1),
    )
    # Compute the earliest non-_extra_* hunk start for this file as a ceiling.
    # The _extra_ anchor must be before all function-body hunks.
    _hunk_ceiling = _earliest_bundle_hunk_start(bundle=bundle, file_path=str(file_path or "").strip())

    if insert_line > 0:
        # We insert before the context line at insert_line; index is 0-based.
        idx = insert_line - 1
        # Clamp to before the earliest non-_extra_* hunk for this file.
        # If the AST anchor falls inside/after a hunk range, the backward walk
        # below will find a safe file-scope boundary from the clamped position.
        _was_clamped = False
        if _hunk_ceiling is not None and idx >= _hunk_ceiling:
            idx = max(_hunk_ceiling - 1, 0)
            _was_clamped = True
        if 0 <= idx < len(lines):
            # Walk backwards in V2 source to find a safe insertion boundary.
            # Two-pass approach:
            # Pass 1: look for '}' at column 0 (strongest file-scope signal).
            # Pass 2 (header fallback): if no col-0 '}' found, look for
            #         indented '}', semicolon-terminated decl, or blank line.
            raw_at = lines[idx].rstrip()
            if raw_at and raw_at.lstrip() not in ("}", ""):
                found_boundary = False
                # Pass 1: column-0 '}'
                for back_i in range(idx - 1, -1, -1):
                    if lines[back_i].rstrip() == "}":
                        idx = back_i + 1
                        found_boundary = True
                        break
                # When clamped by a hunk ceiling and Pass 1 found no column-0 '}',
                # the region before the hunk is inside a function body.  Fall through
                # to _find_file_scope_insertion_index instead of Pass 2 (which would
                # pick a blank line or ';' still inside the function body).
                if _was_clamped and not found_boundary:
                    idx = -1  # signal: use _find_file_scope_insertion_index
                # Pass 2: header-file fallback (no col-0 braces) — only when NOT clamped
                elif not found_boundary:
                    for back_i in range(idx - 1, -1, -1):
                        bl = lines[back_i].rstrip()
                        bls = bl.lstrip()
                        # Indented closing brace
                        if bls == "}":
                            idx = back_i + 1
                            found_boundary = True
                            break
                        # Semicolon-terminated non-comment line
                        if bls.endswith(";") and "/*" not in bls and not bls.startswith("*") and not bls.startswith("//"):
                            idx = back_i + 1
                            found_boundary = True
                            break
                        # Blank line
                        if not bls:
                            idx = back_i + 1
                            found_boundary = True
                            break

            # If idx landed inside or at the start of a block comment,
            # advance past the closing */.
            if idx < len(lines):
                in_comment = False
                # Check if we're inside a /* ... */ block by scanning from
                # a few lines above through the current line.
                scan_start = max(0, idx - 30)
                for ci in range(scan_start, idx + 1):
                    cl = lines[ci]
                    if "/*" in cl:
                        in_comment = True
                    if "*/" in cl:
                        in_comment = False
                if in_comment:
                    # Advance past the closing */
                    for ci in range(idx + 1, len(lines)):
                        if "*/" in lines[ci]:
                            idx = ci + 1
                            break

            insert_at = idx

    if insert_at < 0:
        insert_at = _find_file_scope_insertion_index(lines)

    # Do not place inserted declarations inside dead-code regions.
    # Backward boundary selection can otherwise jump to a `}` under `#if 0`.
    insert_at = _skip_out_of_if0_block(lines, insert_at)
    if not _is_header_path(str(file_path or "")):
        insert_at = _skip_out_of_preprocessor_block(lines, insert_at)

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

    # Safety: if insert_at lands inside a multi-line #define macro (backslash-continued lines),
    # advance past the macro to avoid splitting it.
    insert_at = _skip_past_macro_continuation(lines, insert_at)
    insert_at = _skip_out_of_if0_block(lines, insert_at)
    if not _is_header_path(str(file_path or "")):
        insert_at = _skip_out_of_preprocessor_block(lines, insert_at)

    # For header files with include guards, clamp insert_at to stay inside the guard
    # AND inside any trailing `extern "C" { ... }` block.
    if _is_header_path(str(file_path or "")):
        guard_endif_idx = _find_include_guard_endif(lines)
        if guard_endif_idx >= 0:
            # Walk backward from the guard #endif to skip trailing
            # preprocessor / extern "C" closing blocks and blank lines.
            ceiling = guard_endif_idx  # 0-based
            for i in range(guard_endif_idx - 1, -1, -1):
                stripped = lines[i].strip()
                if not stripped:
                    ceiling = i
                    continue
                # #ifdef / #ifndef mark the START of a preprocessor conditional
                # block.  Include this line in the ceiling but stop walking —
                # everything above is real code that must not be swallowed
                # (e.g. a function closing '}' separated from the guard block
                # by blank lines).
                if re.match(r'^#\s*(?:ifdef|ifndef)\b', stripped):
                    ceiling = i
                    break
                if stripped in ("}", "#endif") or re.match(r'^#\s*(?:else|endif)\b', stripped):
                    ceiling = i
                    continue
                if stripped.startswith("extern") and "{" in stripped:
                    ceiling = i
                    continue
                break
            if insert_at >= ceiling:
                insert_at = ceiling

    insert_at = _skip_out_of_if0_block(lines, insert_at)

    # Final safety: if insert_at still overlaps a non-_extra_* hunk after all
    # the above adjustments, clamp again (the header-guard or skip logic may
    # have pushed it forward).
    if _hunk_ceiling is not None and insert_at >= _hunk_ceiling:
        insert_at = max(_hunk_ceiling - 1, 0)

    start_line = insert_at + 1
    ctx = lines[insert_at : insert_at + max(1, int(context_lines or 0))]
    if not ctx:
        ctx = [lines[0]]
        start_line = 1

    rel = ""
    if resolved is not None and resolved.exists():
        try:
            repo_root = sm._repo_root(version_used)  # type: ignore[attr-defined]
            rel = resolved.resolve().relative_to(repo_root.resolve()).as_posix()
        except Exception:
            rel = ""
    if not rel:
        rel = _normalize_repo_rel_path(agent_tools, file_path=str(file_path or "").strip(), version=version_used)
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

    tag_match = re.match(r"^(struct|union|enum)\s+([A-Za-z_][A-Za-z0-9_]*)$", want)
    want_is_tag_ref = bool(tag_match)
    want_tag_kind = str(tag_match.group(1) if tag_match else "").strip()
    want_id = str(tag_match.group(2) if tag_match else want).strip()
    if not want_id:
        return False

    want_re = re.escape(want_id)
    if want_is_tag_ref:
        tag_kind_re = re.escape(want_tag_kind)
        tag_head_pat = re.compile(rf"^(?:typedef\s+)?{tag_kind_re}\s+{want_re}\b")
        fn_pat = re.compile(r"$^")  # unused for tag symbols
        declared_name_pat = re.compile(r"$^")  # unused for tag symbols
        typedef_fn_ptr_pat = re.compile(r"$^")  # unused for tag symbols
    else:
        tag_head_pat = re.compile(rf"^(?:typedef\s+)?(?:struct|union|enum)\s+{want_re}\b")
        fn_pat = re.compile(rf"(?<![A-Za-z0-9_]){want_re}\s*\(")
        declared_name_pat = re.compile(
            rf"(?<![A-Za-z0-9_]){want_re}(?![A-Za-z0-9_])\s*(?:\[\s*|=|,|;|:|__attribute__\b|__declspec\b)"
        )
        typedef_fn_ptr_pat = re.compile(rf"^typedef\b.*\(\s*\*\s*{want_re}\s*\)")

    in_block_comment = False
    # Track syntactic scope depth from minus-lines only. We only consider a
    # symbol "already defined" when matched at file scope (depth == 0).
    brace_depth = 0
    brace_comment_state = False
    raw_lines = str(patch_text or "").splitlines()
    for idx, raw in enumerate(raw_lines):
        if not raw.startswith("-") or raw.startswith("---"):
            continue
        code = _strip_diff_prefix(raw).rstrip()
        stripped = code.lstrip()
        at_file_scope = brace_depth == 0
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
        if at_file_scope and tag_head_pat.match(stripped):
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
        if at_file_scope and not want_is_tag_ref and not stripped.startswith("#"):
            if fn_pat.search(stripped) and not _looks_like_statement(stripped):
                if stripped.rstrip().endswith(";") or "{" in stripped:
                    return True

        # Typedefs for function pointers (common C style): `typedef <ret> (*NAME)(...);`
        if at_file_scope and not want_is_tag_ref and stripped.startswith("typedef") and stripped.rstrip().endswith(";"):
            if typedef_fn_ptr_pat.match(stripped):
                return True

        # Other file-scope declarations: treat as defined only if NAME appears in a declarator position,
        # not merely as a referenced type inside a prototype/param list.
        if at_file_scope and not want_is_tag_ref and not stripped.startswith("#") and stripped.rstrip().endswith(";"):
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

        # Keep scope tracking after all checks so `at_file_scope` reflects
        # this line's entry scope. Ignore preprocessor lines for depth.
        if not stripped.startswith("#"):
            delta, brace_comment_state = _brace_delta_ignoring_comments(code, brace_comment_state)
            brace_depth += delta
            if brace_depth < 0:
                brace_depth = 0

    return False


def _symbol_function_definition_in_extra_hunk(patch_text: str, *, symbol_name: str) -> bool:
    """Return True when `_extra_*` minus lines contain a real function definition for symbol_name."""
    want = str(symbol_name or "").strip()
    if not want:
        return False
    fn_pat = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(want)}\s*\(")
    lines = str(patch_text or "").splitlines()
    for idx, raw in enumerate(lines):
        if not raw.startswith("-") or raw.startswith("---"):
            continue
        code = _strip_diff_prefix(raw).rstrip()
        stripped = code.lstrip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        if not fn_pat.search(stripped):
            continue
        if _looks_like_statement(stripped):
            continue
        # Scan contiguous minus-lines and require '{' before ';' to distinguish
        # definitions from prototypes.
        chunk: List[str] = []
        for j in range(idx, min(len(lines), idx + 512)):
            nxt = lines[j]
            if not nxt.startswith("-") or nxt.startswith("---"):
                break
            chunk.append(_strip_diff_prefix(nxt).rstrip())
        if not chunk:
            continue
        joined = "\n".join(chunk)
        brace_pos = joined.find("{")
        semi_pos = joined.find(";")
        if brace_pos >= 0 and (semi_pos < 0 or brace_pos < semi_pos):
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


_ALL_CAPS_ATTR_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\s*(?:\([^)]*\))?")


def _strip_attribute_macros_from_prototype(lines: List[str], *, func_name: str) -> List[str]:
    """Strip unknown ALL_CAPS attribute macros from the return-type portion of a C prototype.

    Tokens like ``HTS_OPT3``, ``ATTRIBUTE_HIDDEN``, ``NOINLINE`` are V1-only
    attribute macros that cause parse errors when inserted into V2 code.
    We only strip tokens that appear *before* the function name so that
    ALL_CAPS types in parameter lists (``BOOL``, ``DWORD``, ``FILE``) are kept.
    """
    if not lines or not func_name:
        return lines
    joined = "\n".join(lines)
    # Find the function name in the joined text.
    fn_pat = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(func_name)}\s*\(")
    m = fn_pat.search(joined)
    if m is None:
        return lines
    prefix = joined[: m.start()]
    suffix = joined[m.start() :]
    # Strip ALL_CAPS tokens from the prefix (return-type / attribute area).
    cleaned = _ALL_CAPS_ATTR_RE.sub("", prefix)
    # Collapse whitespace.
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    cleaned = re.sub(r"\n ", "\n", cleaned)
    result = (cleaned + suffix).strip()
    return [l.rstrip() for l in result.splitlines() if l.strip()]


def _strip_c_comments_from_line(line: str) -> str:
    """Remove C-style /* */ and // comments from a single line.
    
    This is a best-effort sanitization for prototype extraction;
    it handles simple cases but not nested comments or preprocessor directives.
    """
    text = str(line or "")
    # Remove // comments first (everything after // to end of line)
    if "//" in text:
        text = text.split("//", 1)[0]
    # Remove /* */ comments
    while "/*" in text and "*/" in text:
        start = text.find("/*")
        end = text.find("*/", start + 2)
        if end == -1:
            break
        text = text[:start] + text[end + 2:]
    # If there's an unclosed /*, remove everything from /* onwards
    if "/*" in text:
        text = text[:text.find("/*")]
    return text


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
    
    # Strip C comments from the extracted prototype to avoid malformed
    # declarations like "void foo() /*;" which would comment out subsequent code.
    head = _strip_c_comments_from_line(head)
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
    # wasm3-style TRY macro: `_   (Call(...));` often appears at column 1 inside a function body.
    # Treat it as a statement so we don't mis-detect call sites as file-scope prototypes.
    if re.match(r"^_\s*\(", stripped):
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
    # A C prototype should contain exactly one ';' terminator. Multiple semicolons usually means we
    # accidentally captured statements (e.g. macro calls + other lines) rather than a declaration.
    if joined.count(";") != 1:
        return False
    if "{" in joined or "}" in joined:
        return False
    if want not in joined:
        return False
    if "=" in joined:
        return False

    # A C function prototype must have a return type (and possibly qualifiers/attributes)
    # before the function name.  A bare `funcname(args);` is a call site, not a prototype.
    first_pos = joined.find(want)
    if first_pos >= 0 and not joined[:first_pos].strip():
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
            # Walk backward to include leading decl/attribute lines (but stop at '}' / blank / headers / comments).
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
                # Stop at comment lines — avoid capturing file-header or
                # doc-comment blocks as part of the prototype.
                stripped_prev = prev_code.strip()
                if (stripped_prev.endswith("*/") or stripped_prev.startswith("/*")
                        or stripped_prev.startswith("*") or stripped_prev.startswith("//")):
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


def _extract_function_definition_from_bundle(bundle: Any, *, symbol_name: str) -> List[str]:
    """Try to find a file-scope function definition for symbol_name in patch `-` lines."""
    want = str(symbol_name or "").strip()
    if not want:
        return []
    patches = getattr(bundle, "patches", None)
    if not isinstance(patches, dict):
        return []

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

            # Include leading qualifiers/attributes above the symbol line.
            start = idx
            for j in range(idx - 1, max(-1, idx - 16), -1):
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
                stripped_prev = prev_code.strip()
                if (
                    stripped_prev.endswith("*/")
                    or stripped_prev.startswith("/*")
                    or stripped_prev.startswith("*")
                    or stripped_prev.startswith("//")
                ):
                    break
                start = j

            saw_open = False
            brace_depth = 0
            in_block_comment = False
            end = -1
            for j in range(start, min(len(lines), start + 2000)):
                cur = lines[j]
                if not cur.startswith("-") or cur.startswith("---"):
                    if saw_open:
                        break
                    continue
                cur_code = _strip_diff_prefix(cur).rstrip()
                if "{" in cur_code:
                    saw_open = True
                if saw_open:
                    delta, in_block_comment = _brace_delta_ignoring_comments(cur_code, in_block_comment)
                    brace_depth += delta
                    if brace_depth <= 0:
                        end = j
                        break

            if not saw_open or end < idx:
                continue

            block_lines = []
            for raw in lines[start : end + 1]:
                if raw.startswith("-") and not raw.startswith("---"):
                    block_lines.append(_strip_diff_prefix(raw).rstrip())
            joined = "\n".join(block_lines)
            if "{" not in joined:
                continue
            if not needle.search(joined):
                continue
            return [str(l) for l in block_lines if l is not None]

    return []


def _recompute_hunk_headers(lines: List[str]) -> List[str]:
    """Recompute @@ hunk header lengths after edits (best-effort)."""
    out = list(lines)
    i = 0
    while i < len(out):
        line = out[i]
        if line.startswith("diff --git "):
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

        # Keep new-side start anchors stable. Recomputing later hunks from a cumulative
        # shift can move +start backward (e.g. +691 -> +540) after first-hunk edits,
        # which causes strict reverse-apply checks to report offsets.
        new_start = new_start_hdr
        out[i] = f"@@ -{old_start},{old_len} +{new_start},{new_len_hunk} @@"

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
        # Insert after the last '-' line that is at brace depth 0 (file scope)
        # in the first hunk body.  This prevents inserting inside enum, struct,
        # or function body definitions that were previously prepended.
        brace_depth = 0
        for i in range(first_hunk + 1, len(lines)):
            if lines[i].startswith("@@") or lines[i].startswith("diff --git "):
                break
            if lines[i].startswith("-") and not lines[i].startswith("---"):
                code = lines[i][1:]  # strip the '-' prefix
                # Strip single-line comments and inline block comments before
                # counting braces so that `// }` or `/* { */` don't skew depth.
                code_for_braces = re.sub(r'//.*$', '', code)
                code_for_braces = re.sub(r'/\*.*?\*/', '', code_for_braces)
                brace_depth += code_for_braces.count("{") - code_for_braces.count("}")
                if brace_depth < 0:
                    brace_depth = 0  # closing brace of outer scope; reset
                if brace_depth == 0:
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


def _strip_comment_minus_lines(patch_text: str) -> str:
    """Remove leading comment-only '-' lines from an _extra_* hunk.

    These appear when a skeleton is incorrectly created at the beginning of a
    BOM-prefixed file, causing file-header comment lines (/** @file ... */) to
    be captured as '-' content.  They duplicate the context lines and produce
    broken diffs when applied.
    """
    raw = str(patch_text or "")
    if not raw.strip():
        return raw
    lines = raw.splitlines()
    first_hunk = next((i for i, l in enumerate(lines) if l.startswith("@@")), -1)
    if first_hunk < 0:
        return raw

    # Identify the contiguous block of leading '-' lines in the first hunk body.
    # If ALL of them are comment lines (or blank), strip them entirely.
    start = first_hunk + 1
    end = start
    has_non_comment = False
    for i in range(start, len(lines)):
        if lines[i].startswith("@@") or lines[i].startswith("diff --git "):
            break
        if not (lines[i].startswith("-") and not lines[i].startswith("---")):
            break
        code = lines[i][1:].strip()  # strip the '-' prefix
        if not code:
            end = i + 1
            continue
        if code.startswith("#"):
            # Preprocessor lines (for example `#if 0 /* ... */`) are code, not comments.
            has_non_comment = True
            break
        if (code.startswith("/*") or code.startswith("*") or code.startswith("//")
                or code.endswith("*/")):
            end = i + 1
            continue
        # Found a non-comment '-' line → stop; only strip the leading comment block.
        has_non_comment = True
        break

    if end > start and not has_non_comment:
        # All '-' lines are comments — strip them all.
        updated = lines[:start] + lines[end:]
        updated = _recompute_hunk_headers(updated)
        return "\n".join(updated).rstrip("\n") + "\n"

    if end > start and has_non_comment:
        # Leading comment block followed by real declarations — strip just the comments.
        updated = lines[:start] + lines[end:]
        updated = _recompute_hunk_headers(updated)
        return "\n".join(updated).rstrip("\n") + "\n"

    return raw


_EXTRA_ENUM_HEAD_RE = re.compile(r"^\s*(?:typedef\s+)?enum\b.*\{")
_EXTRA_REVERT_WRAPPER_RE = re.compile(r"__revert_[0-9a-f]{8,}_[A-Za-z_][A-Za-z0-9_]*")
_EXTRA_ENUM_DISABLE_IF0_RE = re.compile(r"^\s*#\s*if\s+0\b.*enum duplicated", re.IGNORECASE)
_EXTRA_ENUM_FWD_DECL_RE = re.compile(r"^enum\s+[A-Za-z_][A-Za-z0-9_]*\s*;\s*$")


def _brace_delta_ignoring_comments(code: str, in_block_comment: bool) -> Tuple[int, bool]:
    """Return (brace_delta, in_block_comment_after) for a single C code line."""
    delta = 0
    i = 0
    n = len(code)
    while i < n:
        if in_block_comment:
            end = code.find("*/", i)
            if end < 0:
                return delta, True
            i = end + 2
            in_block_comment = False
            continue

        if code.startswith("//", i):
            break
        if code.startswith("/*", i):
            in_block_comment = True
            i += 2
            continue

        ch = code[i]
        if ch == "{":
            delta += 1
        elif ch == "}":
            delta -= 1
        i += 1

    return delta, in_block_comment


def _repair_revert_decls_inserted_inside_enum(patch_text: str) -> str:
    """Move misplaced `__revert_<sha>_*` declarations out of enum bodies.

    Older runs could produce `_extra_*` hunks where multi-line enum blocks were
    split by blank lines and then category-sorted, interleaving function
    declarations into enum members. This repair pass is conservative: it only
    moves declarations that contain `__revert_<hex>_...` and are currently
    inside an enum block in the first hunk.
    """
    raw = str(patch_text or "")
    if not raw.strip():
        return raw

    lines = raw.splitlines()
    first_hunk = next((i for i, l in enumerate(lines) if l.startswith("@@")), -1)
    if first_hunk < 0:
        return raw

    end = len(lines)
    for i in range(first_hunk + 1, len(lines)):
        if lines[i].startswith("@@") or lines[i].startswith("diff --git "):
            end = i
            break

    body = lines[first_hunk + 1 : end]
    out_body: List[str] = []
    changed = False

    # Stack entries: {"depth": int, "moved": List[List[str]]}
    enum_stack: List[Dict[str, Any]] = []
    brace_depth = 0
    in_block_comment = False

    i = 0
    while i < len(body):
        raw_line = body[i]
        is_minus = raw_line.startswith("-") and not raw_line.startswith("---")

        # Only move `__revert_<sha>_*` declarations when currently inside enum.
        if is_minus and enum_stack:
            code = raw_line[1:]
            if _EXTRA_REVERT_WRAPPER_RE.search(code):
                block: List[str] = []
                while i < len(body):
                    l = body[i]
                    if not (l.startswith("-") and not l.startswith("---")):
                        break
                    c = l[1:]
                    block.append(l)
                    i += 1
                    if c.strip().endswith(";"):
                        while i < len(body) and body[i] == "-":
                            block.append(body[i])
                            i += 1
                        break
                enum_stack[-1]["moved"].append(block)
                changed = True
                continue

        out_body.append(raw_line)

        if is_minus:
            code = raw_line[1:]
            starts_enum = bool(_EXTRA_ENUM_HEAD_RE.match(code.strip()))

            delta, in_block_comment = _brace_delta_ignoring_comments(code, in_block_comment)
            brace_depth += delta
            if brace_depth < 0:
                brace_depth = 0

            # Record enum depth *after* processing the opening '{' line.
            if starts_enum and "{" in code:
                enum_stack.append({"depth": brace_depth, "moved": []})

            # If we closed the current enum, emit any moved declarations now.
            while enum_stack and brace_depth < int(enum_stack[-1]["depth"]):
                info = enum_stack.pop()
                moved_blocks = info.get("moved") or []
                if moved_blocks:
                    if out_body and out_body[-1] != "-":
                        out_body.append("-")
                    for blk in moved_blocks:
                        out_body.extend([str(x) for x in blk])

        i += 1

    if not changed:
        return raw

    updated = lines[: first_hunk + 1] + out_body + lines[end:]
    # Moving declaration blocks can change old/new body line counts (e.g. when
    # adding a separator '-' blank line), so refresh @@ header lengths.
    updated = _recompute_hunk_headers(updated)
    return "\n".join(updated).rstrip("\n") + "\n"


def _repair_disabled_enum_if0_wrapper(patch_text: str) -> str:
    """Remove `#if 0 /* enum duplicated ... */` wrappers around enum blocks.

    Some model-generated overrides disable transplanted enums with a `#if 0`
    wrapper and then leave only `enum NAME;` in scope, which causes incomplete
    enum type errors.  This repair unwraps that disabled enum block and removes
    the nearby forward declaration line.
    """
    raw = str(patch_text or "")
    if not raw.strip():
        return raw

    lines = raw.splitlines()
    first_hunk = next((i for i, l in enumerate(lines) if l.startswith("@@")), -1)
    if first_hunk < 0:
        return raw

    end = len(lines)
    for i in range(first_hunk + 1, len(lines)):
        if lines[i].startswith("@@") or lines[i].startswith("diff --git "):
            end = i
            break

    body = lines[first_hunk + 1 : end]
    out_body: List[str] = []
    changed = False
    inside_disabled_enum = False
    skip_following_enum_fwd_decl = False

    for raw_line in body:
        is_minus = raw_line.startswith("-") and not raw_line.startswith("---")
        code = raw_line[1:].strip() if is_minus else ""

        if is_minus and _EXTRA_ENUM_DISABLE_IF0_RE.match(code):
            inside_disabled_enum = True
            skip_following_enum_fwd_decl = True
            changed = True
            continue

        if inside_disabled_enum and is_minus and re.match(r"^#\s*endif\b", code):
            inside_disabled_enum = False
            changed = True
            continue

        if skip_following_enum_fwd_decl and is_minus and not inside_disabled_enum:
            if code and "forward-declare the enum" in code.lower():
                changed = True
                continue
            if _EXTRA_ENUM_FWD_DECL_RE.match(code):
                skip_following_enum_fwd_decl = False
                changed = True
                continue
            if code and not code.startswith("//"):
                skip_following_enum_fwd_decl = False

        out_body.append(raw_line)

    if not changed:
        return raw

    updated = lines[: first_hunk + 1] + out_body + lines[end:]
    updated = _recompute_hunk_headers(updated)
    return "\n".join(updated).rstrip("\n") + "\n"


def _first_hunk_minus_code_lines(patch_text: str) -> List[str]:
    """Return code lines from '-' entries in the first hunk body."""
    raw = str(patch_text or "")
    if not raw.strip():
        return []
    lines = raw.splitlines()
    first_hunk = next((i for i, l in enumerate(lines) if l.startswith("@@")), -1)
    if first_hunk < 0:
        return []

    out: List[str] = []
    for i in range(first_hunk + 1, len(lines)):
        line = lines[i]
        if line.startswith("@@") or line.startswith("diff --git "):
            break
        if line.startswith("-") and not line.startswith("---"):
            out.append(_strip_diff_prefix(line).rstrip())
    return out


def _split_code_lines_into_blocks(code_lines: List[str]) -> List[List[str]]:
    """Split code lines into declaration blocks separated by blank lines."""
    blocks: List[List[str]] = []
    cur: List[str] = []
    for raw in (code_lines or []):
        line = str(raw or "").rstrip()
        if not line.strip():
            if cur:
                blocks.append(cur)
                cur = []
            continue
        cur.append(line)
    if cur:
        blocks.append(cur)
    return blocks


def _flatten_blocks_with_blank_lines(blocks: List[List[str]]) -> List[str]:
    """Flatten declaration blocks into code lines, keeping one blank line between blocks."""
    out: List[str] = []
    for block in (blocks or []):
        clean = [str(l).rstrip() for l in (block or []) if str(l or "").strip()]
        if not clean:
            continue
        if out:
            out.append("")
        out.extend(clean)
    return out


def _extra_hunk_contains_enum_tag(patch_text: str, *, tag_name: str) -> bool:
    """Return True if first hunk minus-lines contain `enum <tag_name>`."""
    tag = str(tag_name or "").strip()
    if not tag:
        return False
    head_re = re.compile(rf"^(?:typedef\s+)?enum\s+{re.escape(tag)}\b")
    for code in _first_hunk_minus_code_lines(patch_text):
        if head_re.match(str(code or "").strip()):
            return True
    return False


def _is_enum_insertion_block(*, insert_kind: str, inserted_lines: List[str]) -> bool:
    """Return True when the insertion payload is an enum declaration/definition block."""
    kind = str(insert_kind or "")
    if "ENUM_DECL" in kind:
        return True
    first = next((str(l).strip() for l in (inserted_lines or []) if str(l).strip()), "")
    if not first:
        return False
    return bool(re.match(r"^(?:typedef\s+)?enum\b", first))


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


_ENUM_CONST_USR_RE = re.compile(r"@E@(?P<enum_name>[^@]+)@[^@]+$")


def _enum_name_from_enum_constant_usr(usr: str) -> str:
    """Extract enum type name from an enum-constant USR (e.g. ``c:@E@Type@VALUE``)."""
    text = str(usr or "").strip()
    if not text:
        return ""
    m = _ENUM_CONST_USR_RE.search(text)
    if not m:
        return ""
    return str(m.group("enum_name") or "").strip()


def _kb_enum_decl_candidates_from_enum_constant_refs(
    agent_tools: Any,
    *,
    nodes: List[dict],
    version: str,
    max_nodes: int = 200,
) -> List[dict]:
    """Derive ENUM_DECL candidates from enum-constant references.

    Some KBs only surface ``DECL_REF_EXPR``/``ENUM_CONSTANT_DECL`` for a queried
    token (for example, ``RANSPR``). In that shape we still want an insertable
    node, so we recover the parent enum name from type-ref USR and query the
    corresponding ``ENUM_DECL``.
    """
    ver = str(version or "").strip().lower()
    if ver not in {"v1", "v2"}:
        return []
    kb_index = getattr(agent_tools, "kb_index", None)
    if kb_index is None:
        return []

    enum_names: set[str] = set()
    for n in list(nodes or [])[: max(0, int(max_nodes or 0))]:
        if not isinstance(n, dict):
            continue
        kind = str(n.get("kind", "") or "").strip()
        if kind == "ENUM_CONSTANT_DECL":
            enum_name = _enum_name_from_enum_constant_usr(str(n.get("usr", "") or ""))
            if enum_name:
                enum_names.add(enum_name)
        type_ref = n.get("type_ref", {}) if isinstance(n.get("type_ref"), dict) else {}
        if str(type_ref.get("target_kind", "") or "").strip() == "ENUM_CONSTANT_DECL":
            enum_name = _enum_name_from_enum_constant_usr(str(type_ref.get("usr", "") or ""))
            if enum_name:
                enum_names.add(enum_name)

    derived: List[dict] = []
    seen: set[str] = set()
    for enum_name in sorted(enum_names):
        for query in (enum_name, f"enum {enum_name}"):
            try:
                found = (kb_index.query_all(query) or {}).get(ver, [])
            except Exception:
                found = []
            for n in found:
                if not isinstance(n, dict):
                    continue
                if str(n.get("kind", "") or "").strip() != "ENUM_DECL":
                    continue
                k = _kb_node_key(n)
                if k in seen:
                    continue
                seen.add(k)
                derived.append(n)
    return derived


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

    # Enum constants often arrive as DECL_REF_EXPR/ENUM_CONSTANT_DECL and are not
    # directly insertable at file scope. Recover the parent ENUM_DECL when possible.
    for cand in _kb_enum_decl_candidates_from_enum_constant_refs(
        agent_tools, nodes=candidates, version=ver, max_nodes=max_nodes
    ):
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

    for cand in _kb_enum_decl_candidates_from_enum_constant_refs(
        agent_tools, nodes=candidates, version=ver, max_nodes=max_nodes
    ):
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


# ---------------------------------------------------------------------------
# Enum conflict detection and renaming helpers
# ---------------------------------------------------------------------------

_ENUM_RENAME_PREFIX = "_revert_"


def _extract_enum_constant_names(code: str) -> List[str]:
    """Extract enumerator names from C enum source code.

    Handles patterns like ``NAME = VALUE,``, ``NAME,``, ``NAME = OTHER,``,
    and multiple enumerators per line.

    Important: inline comments are stripped before tokenization so plain words
    in comments (for example "Specialisation of EXTERNAL") are not mistaken for
    enum constants.
    """
    names: List[str] = []
    in_body = False
    in_block_comment = False
    for line in str(code or "").splitlines():
        # Strip // and /* ... */ comments while preserving code text.
        clean_chars: List[str] = []
        i = 0
        while i < len(line):
            ch = line[i]
            nxt = line[i + 1] if i + 1 < len(line) else ""
            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue
            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            if ch == "/" and nxt == "/":
                break
            clean_chars.append(ch)
            i += 1

        stripped = "".join(clean_chars).strip()
        # Skip preprocessor lines
        if not stripped or stripped.startswith("#"):
            continue
        if "{" in stripped:
            in_body = True
            stripped = stripped[stripped.index("{") + 1:]
        if not in_body:
            continue
        tail = stripped
        if "}" in tail:
            tail = tail[:tail.index("}")]
        # Extract NAME tokens before '=', ',', '}', or at end of line
        for m in re.finditer(r"([A-Za-z_]\w*)\s*(?:=|,|}|$)", tail):
            name = m.group(1)
            if name not in ("enum", "typedef", "struct", "union"):
                if name not in names:
                    names.append(name)
        if "}" in stripped:
            break
    return names


def _check_v2_enum_conflict(kb_index: Any, enum_names: List[str]) -> set:
    """Return enum constant names that also exist in V2 as ENUM_CONSTANT_DECL."""
    conflicts: set = set()
    if kb_index is None:
        return conflicts
    for name in enum_names:
        try:
            v2_nodes = (kb_index.query_all(name) or {}).get("v2", [])
        except Exception:
            v2_nodes = []
        for n in v2_nodes:
            if isinstance(n, dict) and n.get("kind") == "ENUM_CONSTANT_DECL":
                conflicts.add(name)
                break
    return conflicts


def _check_v2_enum_tag_conflict(kb_index: Any, tag_name: str) -> bool:
    """Return True if *tag_name* exists in V2 as ``ENUM_DECL``."""
    if not kb_index or not tag_name:
        return False
    try:
        v2_nodes = (kb_index.query_all(tag_name) or {}).get("v2", [])
    except Exception:
        return False
    return any(
        isinstance(n, dict) and n.get("kind") == "ENUM_DECL"
        for n in v2_nodes
    )


def _extract_enum_tag_from_code(code: str) -> str:
    """Extract the enum tag name from C enum source, or ``''`` if anonymous."""
    m = re.search(r"(?:typedef\s+)?enum\s+([A-Za-z_]\w*)", str(code or ""))
    return m.group(1) if m else ""


def _prefix_enum_source(code: str, enum_names: List[str], prefix: str, tag_rename_map: Optional[Dict[str, str]] = None) -> Tuple[str, Dict[str, str]]:
    """Rename enumerator names and optionally the enum tag in source code.

    *tag_rename_map* is an optional ``{old_tag: new_tag}`` dict.  When
    provided the enum tag name is also renamed and included in the returned
    *rename_map*.

    Returns (modified_code, rename_map) where rename_map maps old→new.
    Processes longest names first to avoid partial replacements.
    """
    rename_map: Dict[str, str] = {}
    result = str(code or "")
    # Sort by length descending to avoid partial replacements (e.g. RANS before RANS0)
    sorted_names = sorted(enum_names, key=len, reverse=True)
    for name in sorted_names:
        new_name = f"{prefix}{name}"
        rename_map[name] = new_name
    # Apply replacements using word-boundary regex, longest first
    for old_name in sorted_names:
        new_name = rename_map[old_name]
        result = re.sub(
            rf"(?<![A-Za-z0-9_]){re.escape(old_name)}(?![A-Za-z0-9_])",
            new_name,
            result,
        )
    # Apply enum tag renames (e.g. enum htsExactFormat -> enum _revert_htsExactFormat)
    if tag_rename_map:
        sorted_tags = sorted(tag_rename_map.keys(), key=len, reverse=True)
        for old_tag in sorted_tags:
            new_tag = tag_rename_map[old_tag]
            rename_map[old_tag] = new_tag
            result = re.sub(
                rf"(?<![A-Za-z0-9_]){re.escape(old_tag)}(?![A-Za-z0-9_])",
                new_tag,
                result,
            )
    return result, rename_map


def _apply_rename_map_to_minus_lines(patch_text: str, rename_map: Dict[str, str]) -> str:
    """In a unified diff's ``-`` lines, replace enum names with prefixed names.

    Only modifies ``-`` prefixed lines (the transplanted code).  Context lines
    and ``+`` lines are left untouched.
    """
    if not rename_map:
        return patch_text
    lines = str(patch_text or "").splitlines()
    # Sort by length descending to avoid partial replacements
    sorted_old = sorted(rename_map.keys(), key=len, reverse=True)
    updated = list(lines)
    changed = False
    for i, line in enumerate(lines):
        if not line.startswith("-") or line.startswith("---"):
            continue
        new_line = line
        for old_name in sorted_old:
            new_name = rename_map[old_name]
            new_line = re.sub(
                rf"(?<![A-Za-z0-9_]){re.escape(old_name)}(?![A-Za-z0-9_])",
                new_name,
                new_line,
            )
        if new_line != line:
            updated[i] = new_line
            changed = True
    if not changed:
        return patch_text
    return "\n".join(updated).rstrip("\n") + "\n"


def _rename_enum_refs_in_bundle(
    bundle: Any, file_path: str, rename_map: Dict[str, str]
) -> List[Dict[str, Any]]:
    """Apply rename_map to ``-`` lines in all regular hunks for the same file.

    Returns list of ``{"patch_key": key, "patch_text": modified_text}`` for
    modified hunks.
    """
    if not rename_map:
        return []
    target_basename = Path(str(file_path or "")).name
    if not target_basename:
        return []
    patches = getattr(bundle, "patches", None)
    if not isinstance(patches, dict):
        return []
    overrides: List[Dict[str, Any]] = []
    for key, patch_info in patches.items():
        key_s = str(key or "")
        if key_s.startswith("_extra_"):
            continue
        pt = str(getattr(patch_info, "patch_text", "") or "")
        if not pt.strip():
            continue
        if target_basename not in pt:
            continue
        modified = _apply_rename_map_to_minus_lines(pt, rename_map)
        if modified != pt:
            overrides.append({"patch_key": key_s, "patch_text": modified})
    return overrides


def _rename_conflicting_enum_constants_in_extra_hunk(
    patch_text: str,
    *,
    kb_index: Any,
    enum_tag: str,
    prefix: str,
) -> Tuple[str, Dict[str, str]]:
    """Prefix conflicting enum constants inside the first `_extra_*` hunk enum block."""
    raw = str(patch_text or "")
    if not raw.strip() or kb_index is None:
        return raw, {}

    lines = raw.splitlines()
    first_hunk = next((i for i, l in enumerate(lines) if l.startswith("@@")), -1)
    if first_hunk < 0:
        return raw, {}

    end = len(lines)
    for i in range(first_hunk + 1, len(lines)):
        if lines[i].startswith("@@") or lines[i].startswith("diff --git "):
            end = i
            break

    body = lines[first_hunk + 1 : end]

    tag_re = re.escape(str(enum_tag or "").strip())
    if tag_re:
        enum_head_re = re.compile(rf"^\s*(?:typedef\s+)?enum\s+{tag_re}\b.*\{{")
    else:
        enum_head_re = re.compile(r"^\s*(?:typedef\s+)?enum\b.*\{")

    start_idx = -1
    for i, raw_line in enumerate(body):
        if not (raw_line.startswith("-") and not raw_line.startswith("---")):
            continue
        if enum_head_re.match(raw_line[1:].strip()):
            start_idx = i
            break
    if start_idx < 0:
        return raw, {}

    block: List[str] = []
    end_idx = -1
    brace_depth = 0
    in_block_comment = False
    saw_open = False
    for i in range(start_idx, len(body)):
        raw_line = body[i]
        if not (raw_line.startswith("-") and not raw_line.startswith("---")):
            if block:
                break
            continue
        code = raw_line[1:]
        block.append(code)
        if "{" in code:
            saw_open = True
        delta, in_block_comment = _brace_delta_ignoring_comments(code, in_block_comment)
        brace_depth += delta
        if saw_open and brace_depth <= 0 and "}" in code:
            end_idx = i
            break
    if end_idx < start_idx or not block:
        return raw, {}

    enum_code = "\n".join(block)
    enum_names = _extract_enum_constant_names(enum_code)

    conflicts = _check_v2_enum_conflict(kb_index, enum_names) if enum_names else set()

    # Also check if the enum tag itself conflicts with V2
    detected_tag = _extract_enum_tag_from_code(enum_code)
    tag_rename_map: Optional[Dict[str, str]] = None
    if detected_tag and _check_v2_enum_tag_conflict(kb_index, detected_tag):
        tag_rename_map = {detected_tag: f"{prefix}{detected_tag}"}

    if not conflicts and not tag_rename_map:
        return raw, {}

    prefixed_code, rename_map = _prefix_enum_source(
        enum_code, sorted(conflicts), prefix, tag_rename_map=tag_rename_map,
    )
    if not rename_map:
        return raw, {}

    replacement = [f"-{line.rstrip()}" for line in prefixed_code.splitlines()]
    if not replacement:
        return raw, {}

    new_body = body[:start_idx] + replacement + body[end_idx + 1 :]
    updated_lines = lines[: first_hunk + 1] + new_body + lines[end:]
    updated_lines = _recompute_hunk_headers(updated_lines)
    return "\n".join(updated_lines).rstrip("\n") + "\n", rename_map


def make_extra_patch_override(
    agent_tools: Any,
    *,
    patch_path: str,
    file_path: str,
    symbol_name: str,
    version: str = "v1",
    prefer_definition: bool = False,
) -> Dict[str, Any]:
    """Deterministically extend an `_extra_*` hunk to provide a missing decl/define/typedef.

    Primary goal: when the build log reports an undeclared symbol (often a generated `__revert_*` function),
    add a forward declaration (or macro/type) into the file's `_extra_<file>` hunk so the agent doesn't
    inline declarations into the active function body.

    When prefer_definition=True and symbol_name is a `__revert_*` function, prefer inserting a full
    function definition (bundle/KB sourced) instead of only a prototype.
    """
    import sys
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
    prefer_definition = bool(prefer_definition)
    # Detect when the LLM accidentally passes a full prototype or declaration
    # instead of a bare symbol name (e.g. "void foo(int x);" instead of "foo").
    if '(' in symbol or symbol.endswith(';'):
        raise ValueError(
            f"symbol_name looks like a prototype or declaration, not a bare "
            f"symbol name. Pass only the identifier (e.g. "
            f"'__revert_<commit>_<func>'), not a full signature. Got: {symbol!r}"
        )
    tag_symbol_match = re.match(r"^(struct|union|enum)\s+(\w+)$", symbol)
    tag_symbol_kind = str(tag_symbol_match.group(1) if tag_symbol_match else "").strip()
    tag_symbol_name = str(tag_symbol_match.group(2) if tag_symbol_match else "").strip()
    kind, underlying = _symbol_underlying_name(symbol)

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
    existing = str(getattr(patch, "patch_text", "") or "") if patch is not None else ""

    normalized_actions: List[str] = []
    enum_rename_overrides: List[Dict[str, Any]] = []

    def _serialize_enum_rename_overrides(overrides: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Return overrides as inline text (no artifact files written).
        # The agent-side consumer filters to active_patch_key and persists only that one.
        serialized: List[Dict[str, Any]] = []
        for ov in overrides:
            ov_key = str(ov.get("patch_key", "")).strip()
            ov_text = str(ov.get("patch_text", "")).strip()
            if not ov_key or not ov_text:
                continue
            serialized.append({
                "patch_key": ov_key,
                "patch_text": ov_text,
            })
        return serialized

    # Clean up corrupted _extra_* hunks that have file-header comment '-' lines
    # (caused by BOM-prefixed files where the skeleton started at line 0).
    _prev_existing = existing
    existing = _strip_comment_minus_lines(existing)
    if existing != _prev_existing:
        normalized_actions.append("strip_leading_comment_minus_lines")

    # Self-heal inherited malformed hunks where __revert_* declarations were
    # inserted into the middle of enum members by older block-splitting logic.
    _prev_existing = existing
    existing = _repair_revert_decls_inserted_inside_enum(existing)
    if existing != _prev_existing:
        normalized_actions.append("move_revert_decls_out_of_enum")

    # Self-heal inherited malformed hunks that disabled transplanted enums via
    # `#if 0 /* enum duplicated ... */ ... #endif`.
    _prev_existing = existing
    existing = _repair_disabled_enum_if0_wrapper(existing)
    if existing != _prev_existing:
        normalized_actions.append("unwrap_disabled_enum_if0")

    # If cleanup left a pure context-only skeleton (no '-' lines), the anchor
    # may be at the wrong position (e.g. line 1 of a BOM file).  Regenerate
    # the skeleton so the insertion point is after includes/comments.
    if existing.strip() and agent_tools is not None:
        ex_lines = existing.splitlines()
        has_minus = any(l.startswith("-") and not l.startswith("---") for l in ex_lines)
        if not has_minus:
            refreshed = _new_extra_patch_skeleton(agent_tools, file_path=file_path_s, symbol_name=symbol, bundle=bundle)
            if refreshed.strip():
                existing = refreshed
                normalized_actions.append("regenerate_empty_extra_skeleton")

    symbol_defined = _symbol_defined_in_extra_hunk(existing, symbol_name=symbol)
    symbol_has_definition = (
        _symbol_function_definition_in_extra_hunk(existing, symbol_name=symbol)
        if kind == "revert_function"
        else False
    )
    can_upgrade_to_definition = (
        prefer_definition
        and kind == "revert_function"
        and symbol_defined
        and not symbol_has_definition
    )
    if symbol_defined and not can_upgrade_to_definition:
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

        if tag_symbol_kind == "enum" and tag_symbol_name and agent_tools is not None:
            kb_index = getattr(agent_tools, "kb_index", None)
            if kb_index is not None:
                renamed_existing, rename_map = _rename_conflicting_enum_constants_in_extra_hunk(
                    existing,
                    kb_index=kb_index,
                    enum_tag=tag_symbol_name,
                    prefix=_ENUM_RENAME_PREFIX,
                )
                if renamed_existing != existing and rename_map:
                    existing = renamed_existing
                    normalized_actions.append("prefix_conflicting_enum_constants")
                    enum_rename_overrides = _rename_enum_refs_in_bundle(bundle, file_path_s, rename_map)

        # Existing enum blocks may already be present but anchored too late
        # (e.g. inherited _extra_* hunk). Re-anchor the whole hunk to Tier 1.
        enum_tag_for_reanchor = ""
        if tag_symbol_kind == "enum" and tag_symbol_name:
            enum_tag_for_reanchor = tag_symbol_name
        elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", symbol) and _extra_hunk_contains_enum_tag(existing, tag_name=symbol):
            enum_tag_for_reanchor = symbol

        if enum_tag_for_reanchor and agent_tools is not None:
            refreshed = _new_extra_patch_skeleton(
                agent_tools,
                file_path=file_path_s,
                symbol_name=symbol,
                bundle=bundle,
                force_tier1=True,
            )
            if refreshed.strip():
                carried_lines = _first_hunk_minus_code_lines(existing)
                carried_blocks = _split_code_lines_into_blocks(carried_lines)
                merged_blocks = _merge_extra_hunk_blocks(carried_blocks)
                merged_lines = _flatten_blocks_with_blank_lines(merged_blocks)
                if merged_lines:
                    reanchored = _insert_minus_block_into_patch_text(
                        refreshed,
                        insert_lines=[""] + merged_lines,
                        prefer_prepend=True,
                    )
                    if reanchored.strip() and reanchored != existing:
                        existing = reanchored
                        normalized_actions.append("reanchor_extra_hunk_tier1_for_enum")

        if normalized_actions or enum_rename_overrides:
            store = ArtifactStore(_artifact_root() / extra_key, overwrite=False)
            ref = store.write_text(
                name=f"make_extra_patch_override_patch_text_{_normalize_file_basename(file_path_s)}_{symbol}",
                text=existing,
                ext=".diff",
            )
            payload: Dict[str, Any] = {
                "patch_path": str(Path(patch_path_s).expanduser().resolve()),
                "file_path": file_path_s,
                "symbol_name": symbol,
                "patch_key": extra_key,
                "insert_kind": "normalize_existing_extra_hunk",
                "inserted_code": "",
                "patch_text": ref.to_dict(),
                "patch_text_truncated": False,
                "patch_text_lines_total": len(existing.splitlines()),
                "normalization_actions": list(normalized_actions),
                "note": "Symbol already present; normalized malformed existing extra hunk.",
            }
            serialized_enum_overrides = _serialize_enum_rename_overrides(enum_rename_overrides)
            if serialized_enum_overrides:
                payload["enum_rename_overrides"] = serialized_enum_overrides
            return payload

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
    enum_rename_overrides = []

    # Helper to extract full type definition from KB for enums/structs/unions
    def _extract_type_definition_from_kb(type_name: str, ver: str) -> Tuple[List[str], str]:
        """Extract full enum/struct/union definition from KB.
        
        Returns (lines, insert_kind) or ([], "") if not found.
        """
        if agent_tools is None:
            return [], ""
        kb_index = getattr(agent_tools, "kb_index", None)
        source_manager = getattr(agent_tools, "source_manager", None)
        if kb_index is None or source_manager is None:
            return [], ""

        # Try to find ENUM_DECL, STRUCT_DECL, or UNION_DECL for this type
        for query_name in [type_name, f"enum {type_name}", f"struct {type_name}", f"union {type_name}"]:
            nodes = (kb_index.query_all(query_name) or {}).get(ver, [])
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                node_kind = str(node.get("kind", "") or "").strip()
                if node_kind not in ("ENUM_DECL", "STRUCT_DECL", "UNION_DECL"):
                    # Check related definitions
                    for cand in kb_index.related_definition_candidates(node, ver, max_depth=2) or []:
                        if isinstance(cand, dict) and str(cand.get("kind", "")).strip() in ("ENUM_DECL", "STRUCT_DECL", "UNION_DECL"):
                            code = str(source_manager.get_function_code(cand, ver) or "").strip()
                            if code and "{" in code:
                                lines = [l.rstrip("\n") for l in code.replace("\r\n", "\n").replace("\r", "\n").splitlines()]
                                lines = [l.rstrip() for l in lines if l is not None]
                                if lines:
                                    return lines, f"{node_kind.lower()}_definition_from_kb:{ver}"
                else:
                    # Direct ENUM_DECL/STRUCT_DECL/UNION_DECL
                    code = str(source_manager.get_function_code(node, ver) or "").strip()
                    if code and "{" in code:
                        lines = [l.rstrip("\n") for l in code.replace("\r\n", "\n").replace("\r", "\n").splitlines()]
                        lines = [l.rstrip() for l in lines if l is not None]
                        if lines:
                            return lines, f"{node_kind.lower()}_definition_from_kb:{ver}"
        return [], ""

    # 0) Handle type definitions: symbol_name like "struct X" or "union Y" or "enum Z".
    #    Try to extract the full type definition from KB instead of just a forward declaration.
    if tag_symbol_kind and tag_symbol_name:
        type_kind = tag_symbol_kind  # struct/union/enum
        type_name = tag_symbol_name  # the type name
        # Try to get full definition from KB first
        for ver in [str(version or "v1").strip().lower(), "v2" if str(version or "v1").strip().lower() == "v1" else "v1"]:
            type_lines, type_insert_kind = _extract_type_definition_from_kb(type_name, ver)
            if type_lines:
                inserted_lines = type_lines
                insert_kind = type_insert_kind
                break
        if not inserted_lines:
            inserted_lines = [f"{type_kind} {type_name};"]
            insert_kind = "forward_tag_declaration"

    # 1) Best-effort for generated __revert_* functions:
    #    - prefer_definition=True: extract full function body from bundle
    #    - otherwise: extract prototype from bundle
    if kind == "revert_function":
        if prefer_definition:
            func_def = _extract_function_definition_from_bundle(bundle, symbol_name=symbol)
            if func_def:
                inserted_lines = func_def
                insert_kind = "function_definition_from_bundle"
        if not inserted_lines:
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
                if kind == "revert_function" and prefer_definition and "{" in code:
                    decl_lines = [l.rstrip("\n") for l in code.replace("\r\n", "\n").replace("\r", "\n").splitlines()]
                else:
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
            if kind == "revert_function" and prefer_definition and "{" in code and "FUNCTION" in chosen_kind:
                insert_kind = f"function_definition_from_kb:{ver}:{chosen_kind}{reason_suffix}"
            else:
                insert_kind = f"declaration_from_kb:{ver}:{chosen_kind}{reason_suffix}"
            break

    # If KB lookup failed for a type name, try harder to extract full enum/struct/union definition
    # This handles cases where the type is defined in a different file (e.g., header file)
    if not inserted_lines and agent_tools is not None:
        requested = str(version or "v1").strip().lower()
        if requested not in {"v1", "v2"}:
            requested = "v1"
        for ver in [requested, ("v2" if requested == "v1" else "v1")]:
            type_lines, type_kind = _extract_type_definition_from_kb(symbol, ver)
            if type_lines:
                inserted_lines = type_lines
                insert_kind = type_kind
                break
        if not inserted_lines and underlying:
            for ver in [requested, ("v2" if requested == "v1" else "v1")]:
                type_lines, type_kind = _extract_type_definition_from_kb(underlying, ver)
                if type_lines:
                    inserted_lines = type_lines
                    insert_kind = type_kind
                    break

    # For inserted enum definitions, proactively prefix conflicting V1 constants
    # and/or the enum tag so they do not collide with V2 in the same translation unit.
    if inserted_lines and agent_tools is not None:
        kb_index = getattr(agent_tools, "kb_index", None)
        enum_code = "\n".join(inserted_lines)
        if (
            kb_index is not None
            and re.search(r"^\s*(?:typedef\s+)?enum\b", enum_code, re.MULTILINE)
            and "{" in enum_code
            and "}" in enum_code
        ):
            enum_names = _extract_enum_constant_names(enum_code)
            conflicts = _check_v2_enum_conflict(kb_index, enum_names) if enum_names else set()

            # Check if the enum tag itself conflicts with V2
            detected_tag = _extract_enum_tag_from_code(enum_code)
            tag_rename_map: Optional[Dict[str, str]] = None
            if detected_tag and _check_v2_enum_tag_conflict(kb_index, detected_tag):
                tag_rename_map = {detected_tag: f"{_ENUM_RENAME_PREFIX}{detected_tag}"}

            if conflicts or tag_rename_map:
                code_prefixed, rename_map = _prefix_enum_source(
                    enum_code,
                    sorted(conflicts),
                    _ENUM_RENAME_PREFIX,
                    tag_rename_map=tag_rename_map,
                )
                inserted_lines = [
                    l.rstrip()
                    for l in code_prefixed.splitlines()
                    if l.strip()
                ]
                enum_rename_overrides = _rename_enum_refs_in_bundle(
                    bundle, file_path_s, rename_map
                )
                suffixes = []
                if conflicts:
                    suffixes.append("enum_values_prefixed")
                if tag_rename_map:
                    suffixes.append("enum_tag_prefixed")
                insert_kind = (insert_kind + ":" + ":".join(suffixes)).strip(":")

    is_function_definition_insert = (
        kind == "revert_function"
        and ("function_definition_" in str(insert_kind or ""))
    )

    # Strip V1-only ALL_CAPS attribute macros (e.g. HTS_OPT3) from prototypes.
    # For full function-definition insertion, keep the body unchanged.
    if inserted_lines and kind == "revert_function" and not is_function_definition_insert:
        inserted_lines = _strip_attribute_macros_from_prototype(inserted_lines, func_name=symbol)

    # For revert functions being inserted into header files, wrap in extern "C"
    # to ensure C++ code can link against the C-defined functions.
    # Use conditional compilation so C files don't see the C++-specific syntax.
    if inserted_lines and kind == "revert_function" and not is_function_definition_insert:
        target_file = str(file_path_s or "").strip()
        if target_file.endswith(".h") or target_file.endswith(".hpp"):
            # Check if already wrapped
            text_to_insert = "\n".join(inserted_lines)
            if 'extern "C"' not in text_to_insert:
                # Wrap the function declaration in extern "C" with __cplusplus guard
                # Handle multi-line prototypes
                if len(inserted_lines) == 1:
                    # Single line prototype - wrap with guards
                    inserted_lines = [
                        '#ifdef __cplusplus',
                        'extern "C" {',
                        '#endif',
                        inserted_lines[0],
                        '#ifdef __cplusplus',
                        '}',
                        '#endif'
                    ]
                else:
                    # Multi-line prototype
                    inserted_lines = [
                        '#ifdef __cplusplus',
                        'extern "C" {',
                        '#endif'
                    ] + inserted_lines + [
                        '#ifdef __cplusplus',
                        '}',
                        '#endif'
                    ]

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

    # For enum insertions, existing `_extra_*` hunks may be anchored too late.
    # Move the hunk to Tier 1 and carry prior inserted declarations with the
    # new enum block so type definitions appear before function declarations.
    if _is_enum_insertion_block(insert_kind=insert_kind, inserted_lines=inserted_lines) and existing.strip() and agent_tools is not None:
        refreshed = _new_extra_patch_skeleton(
            agent_tools,
            file_path=file_path_s,
            symbol_name=symbol,
            bundle=bundle,
            force_tier1=True,
        )
        if refreshed.strip():
            carried_lines = _first_hunk_minus_code_lines(existing)
            carried_blocks = _split_code_lines_into_blocks(carried_lines)
            merged_blocks = _merge_extra_hunk_blocks([list(inserted_lines)], carried_blocks)
            merged_lines = _flatten_blocks_with_blank_lines(merged_blocks)
            if merged_lines:
                existing = refreshed
                inserted_lines = merged_lines
                insert_kind = (insert_kind + ":reanchor_tier1").strip(":")

    # For a brand-new `_extra_*` hunk, generate the skeleton after we know the
    # insertion payload so enum inserts can force Tier 1 anchoring.
    if not existing.strip():
        force_tier1 = _is_enum_insertion_block(insert_kind=insert_kind, inserted_lines=inserted_lines)
        existing = _new_extra_patch_skeleton(
            agent_tools,
            file_path=file_path_s,
            symbol_name=symbol,
            bundle=bundle,
            force_tier1=force_tier1,
        )
        if not existing.strip():
            return {
                "patch_path": str(Path(patch_path_s).expanduser().resolve()),
                "file_path": file_path_s,
                "symbol_name": symbol,
                "patch_key": extra_key,
                "patch_text": "",
                "note": "Failed to create a new _extra_* patch hunk skeleton (could not read V2 source for file).",
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

    # Persist enum rename overrides for regular hunks as artifacts.
    serialized_enum_overrides = _serialize_enum_rename_overrides(enum_rename_overrides)
    inserted_mode = "definition" if "function_definition_" in str(insert_kind or "") else "declaration"

    result: Dict[str, Any] = {
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
        "note": (
            f"Inserted missing {inserted_mode} into the file's _extra_* hunk "
            "and returned an override diff artifact."
        ),
    }
    if serialized_enum_overrides:
        result["enum_rename_overrides"] = serialized_enum_overrides
    return result


# ---------------------------------------------------------------------------
# Proactive forward declarations for ALL __revert_* functions
# ---------------------------------------------------------------------------

_REVERT_CALL_RE = re.compile(
    r"(?<![A-Za-z0-9_])(__revert_[A-Za-z0-9]+_[A-Za-z_][A-Za-z0-9_]*)\s*\("
)


def _enumerate_revert_symbols_by_file(
    patch_path: str,
) -> List[Tuple[str, str, str]]:
    """Scan the patch bundle for __revert_* function references in non-_extra_ patches.

    Returns [(symbol_name, file_path, patch_key), ...] deduplicated by (symbol, file).
    ``file_path`` is derived from the patch's ``file_path_new`` (or ``file_path_old``).
    """
    from migration_tools.patch_bundle import load_patch_bundle  # type: ignore

    bundle = load_patch_bundle(
        str(patch_path), allowed_roots=_allowed_patch_roots_from_env()
    )
    patches = getattr(bundle, "patches", None)
    if not isinstance(patches, dict):
        return []

    seen: set = set()
    results: List[Tuple[str, str, str]] = []

    for key, patch in patches.items():
        key_s = str(key or "")
        # Skip _extra_* hunks – those are the destination, not the source.
        if key_s.startswith("_extra_"):
            continue
        patch_text = str(getattr(patch, "patch_text", "") or "")
        if not patch_text:
            continue

        # Derive file path from patch metadata.
        fp_new = str(getattr(patch, "file_path_new", "") or "").strip()
        fp_old = str(getattr(patch, "file_path_old", "") or "").strip()
        file_path = fp_new or fp_old
        if not file_path:
            continue

        for line in patch_text.splitlines():
            # Only look at '-' lines (code being added in reverse-apply semantics).
            if not line.startswith("-") or line.startswith("---"):
                continue
            for m in _REVERT_CALL_RE.finditer(line):
                sym = m.group(1)
                pair = (sym, file_path)
                if pair not in seen:
                    seen.add(pair)
                    results.append((sym, file_path, key_s))

    return results
