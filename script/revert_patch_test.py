import re
import argparse
import subprocess
import json
import os
import tempfile
import time
import shutil
from git import Repo, GitCommandError
import logging
from pathlib import Path
import gzip
import pickle
import copy
import sys
import hashlib
from collections import defaultdict
from typing import List, Dict, Set, Tuple, Any, Optional
from dataclasses import dataclass, field

from buildAndtest import (
    checkout_latest_commit,
    get_latest_images_before_year,
    resolve_commit_hash,
)
from run_fuzz_test import read_json_file, py3
from compare_trace import extract_function_calls
from compare_trace import compare_traces
from monitor_crash import (
    extract_function_stack,
    build_stack_patterns,
    _stack_matches_patterns,
    _clean_function_name,
)
from utils import (
    minimize_greedy,
    minimize_func_list_greedy,
    apply_unified_diff_to_string,
    split_function_parts,
    diff_strings,
    save_patches_pickle,
    load_patches_pickle,
    extract_extra_patches,
    filter_patches_by_trace,
    binary_search_missing_patches,
)
from fuzzer_correct_test import test_fuzzer_build
from gumtree import get_corresponding_lines, get_delete_lines
from migration_tools.types import FunctionLocation, PatchInfo
from migration_tools.tools import is_rename_only_hunk

HERE = os.path.dirname(__file__)               # script/
OPENAI_DIR = os.path.join(HERE, "openai")     # script/openai
sys.path.insert(0, OPENAI_DIR)
from handle_struct_use import solve_code_migration
from handle_func_sig_change import handle_func_sig_change, handle_renaming_patch_sig_change

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

current_file_path = os.path.dirname(os.path.abspath(__file__))
ossfuzz_path = os.path.abspath(os.path.join(current_file_path, '..', 'oss-fuzz'))
data_path = os.environ.get('DATA_PATH') or os.path.abspath(os.path.join(current_file_path, '..', 'data'))


@dataclass(frozen=True)
class FunctionInfo:
    """
    A hashable dataclass to store function metadata including signature, name, and special keywords.
    """
    name: str
    signature: str
    file_path_old: str
    func_used_file: str
    keywords: tuple[str, ...] = ()
    
    def __post_init__(self):
        """Ensure keywords is always a tuple (for immutability)."""
        if not isinstance(self.keywords, tuple):
            # Use object.__setattr__ because the dataclass is frozen
            object.__setattr__(self, 'keywords', tuple(self.keywords))
    
    def has_keyword(self, keyword: str) -> bool:
        """Check if a specific keyword is present."""
        return keyword in self.keywords
    
    def is_static(self) -> bool:
        """Check if function is static."""
        return 'static' in self.keywords
    
    def is_classmethod(self) -> bool:
        """Check if function is a classmethod."""
        return 'classmethod' in self.keywords
    
    def is_async(self) -> bool:
        """Check if function is async."""
        return 'async' in self.keywords


def stable_hash(s: str) -> str:
    # Convert the string to bytes
    data = s.encode('utf-8')
    # Use SHA-256 to generate a deterministic hash
    digest = hashlib.sha256(data).hexdigest()
    return str(int(digest, 16) % (10 ** 12))


def is_function_static(source_code: str) -> bool:
    # source_code should be a c function source code
    for line in source_code.split('\n'):
        if 'static ' in line:
            return True
        if '{' in line:
            return False


def rename_func(patch_text, fname, commit, replacement_string=None):
    logger.debug(f'Renaming function {fname}')
    modified_lines = []
    regex = r'(?<![\w.])' + re.escape(fname) + r'(?!\w)'
    if not replacement_string:
        replacement_string = f"__revert_{commit}_{fname}"

    for line in patch_text.splitlines():
        if line.startswith('-') and not line.startswith('--- ') and not line.startswith('diff --git '):
            # Only modify lines that represent removed code, not diff headers
            modified_line = re.sub(regex, replacement_string, line)
            modified_lines.append(modified_line)
        else:
            modified_lines.append(line)
    return modified_lines


_HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx"}
_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}
_HUNK_HEADER_RE = re.compile(
    r'^@@\s*-(?P<old_start>\d+)(?:,(?P<old_len>\d+))?\s+\+(?P<new_start>\d+)(?:,(?P<new_len>\d+))?\s*@@'
)
_REVERT_FUNC_RE = re.compile(r'(?<![\w.])(?P<sym>__revert_[A-Za-z0-9]+_[A-Za-z_][A-Za-z0-9_]*)\s*\(')


def _is_header_file_path(file_path: str) -> bool:
    suffix = os.path.splitext(str(file_path or "").strip())[1].lower()
    return suffix in _HEADER_SUFFIXES


def _is_source_file_path(file_path: str) -> bool:
    suffix = os.path.splitext(str(file_path or "").strip())[1].lower()
    return suffix in _SOURCE_SUFFIXES


def _extract_revert_removed_function_blocks_from_header_patch(patch_text: str) -> List[Dict[str, Any]]:
    """Extract removed `static ... __revert_* (...) { ... }` function blocks from one patch text."""
    lines = str(patch_text or "").split('\n')
    blocks: List[Dict[str, Any]] = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        if not raw.startswith('-') or raw.startswith('---'):
            i += 1
            continue
        code = raw[1:]
        m = _REVERT_FUNC_RE.search(code)
        if not m:
            i += 1
            continue
        if not re.search(r'^\s*static\b', code):
            i += 1
            continue

        symbol = str(m.group('sym') or '').strip()
        start = i
        j = i
        found_open = False
        brace_depth = 0
        block_lines: List[str] = []

        while j < len(lines):
            cur = lines[j]
            if not cur.startswith('-') or cur.startswith('---'):
                # Keep extraction conservative; stop at first non-removed line.
                break
            cur_code = cur[1:]
            block_lines.append(cur)
            if '{' in cur_code:
                found_open = True
            if found_open:
                brace_depth += cur_code.count('{')
                brace_depth -= cur_code.count('}')
                if brace_depth <= 0:
                    break
            j += 1

        if found_open and brace_depth <= 0 and block_lines:
            blocks.append({
                'symbol': symbol,
                'start': start,
                'end': j,
                'lines': block_lines,
            })
            i = j + 1
            continue

        i += 1

    return blocks


def _patch_has_nonblock_hunk_content(patch_text: str, blocks: List[Dict[str, Any]]) -> bool:
    """Return True when patch text has changed hunk content outside extracted block ranges.

    Context lines (' ') are ignored here. We only treat added/removed lines
    outside the extracted function blocks as mixed content.
    """
    lines = str(patch_text or "").split('\n')
    covered: Set[int] = set()
    for b in blocks:
        st = int(b.get('start', -1))
        ed = int(b.get('end', -1))
        if st < 0 or ed < st:
            continue
        for idx in range(st, ed + 1):
            covered.add(idx)

    for idx, line in enumerate(lines):
        if idx in covered:
            continue
        if not line:
            continue
        if line.startswith('diff --git ') or line.startswith('--- ') or line.startswith('+++ ') or line.startswith('@@'):
            continue
        if line.startswith('+') and not line.startswith('+++'):
            return True
        if line.startswith('-') and not line.startswith('---'):
            return True
    return False


def _is_static_revert_block(block: Dict[str, Any]) -> bool:
    """Return True when the `__revert_*` definition line in block is static."""
    symbol = str(block.get('symbol') or '').strip()
    if not symbol:
        return False
    sym_re = re.compile(r'(?<![\w.])' + re.escape(symbol) + r'\s*\(')
    for raw in (block.get('lines') or []):
        line = str(raw or "")
        if not line.startswith('-') or line.startswith('---'):
            continue
        code = line[1:]
        if sym_re.search(code):
            return bool(re.search(r'^\s*static\b', code))
    return False


def _find_symbol_callsites_in_patch(patch_text: str, symbol: str) -> List[Tuple[int, str]]:
    """Find callsite line numbers for `symbol` in one patch hunk (old/new coordinates)."""
    if not symbol:
        return []
    sym_re = re.compile(r'(?<![\w.])' + re.escape(symbol) + r'\s*\(')
    lines = str(patch_text or "").split('\n')
    out: List[Tuple[int, str]] = []
    i = 0
    while i < len(lines):
        m = _HUNK_HEADER_RE.match(lines[i].strip())
        if not m:
            i += 1
            continue

        old_line = int(m.group('old_start') or 0)
        new_line = int(m.group('new_start') or 0)
        i += 1

        while i < len(lines):
            line = lines[i]
            if line.startswith('@@') or line.startswith('diff --git ') or line.startswith('--- ') or line.startswith('+++ '):
                break
            if line.startswith('-') and not line.startswith('---'):
                code = line[1:]
                if sym_re.search(code):
                    out.append((old_line, 'old'))
                old_line += 1
            elif line.startswith('+') and not line.startswith('+++'):
                code = line[1:]
                if sym_re.search(code):
                    out.append((new_line, 'new'))
                new_line += 1
            elif line.startswith(' '):
                code = line[1:]
                if sym_re.search(code):
                    out.append((old_line, 'ctx'))
                old_line += 1
                new_line += 1
            i += 1
    return out


def _choose_insert_line_for_callsite(patch: PatchInfo, *, line_no: int, line_kind: str) -> int:
    old_fn = int(getattr(patch, 'old_function_start_line', 0) or 0)
    new_fn = int(getattr(patch, 'new_function_start_line', 0) or 0)
    if line_kind == 'old' and old_fn > 0:
        return old_fn
    if line_kind == 'new' and new_fn > 0:
        return new_fn
    if old_fn > 0 and new_fn > 0:
        return min(old_fn, new_fn)
    if old_fn > 0:
        return old_fn
    if new_fn > 0:
        return new_fn
    return max(1, int(line_no or 1))


def _select_best_symbol_callsite_target(
    diff_results: Dict[str, PatchInfo],
    patch_keys: List[str],
    *,
    skip_key: str,
    symbol: str,
) -> Optional[Dict[str, Any]]:
    """Pick earliest callsite target for a `__revert_*` symbol across current hunks."""
    best: Optional[Tuple[int, int, str, str, str]] = None
    best_payload: Optional[Dict[str, Any]] = None

    for key in patch_keys:
        if key == skip_key:
            continue
        patch = diff_results.get(key)
        if patch is None:
            continue
        target_file = str(patch.file_path_new or patch.file_path_old or "").strip()
        if not target_file or target_file == '/dev/null':
            continue
        target_file = os.path.normpath(target_file)
        if not _is_source_file_path(target_file):
            continue

        for line_no, line_kind in _find_symbol_callsites_in_patch(patch.patch_text, symbol):
            if int(line_no or 0) <= 0:
                continue
            insert_line = _choose_insert_line_for_callsite(patch, line_no=int(line_no), line_kind=line_kind)
            rank = (int(line_no), int(insert_line), target_file, str(key), line_kind)
            if best is None or rank < best:
                best = rank
                best_payload = {
                    'key': key,
                    'file_path': target_file,
                    'call_line': int(line_no),
                    'insert_line': int(insert_line),
                    'line_kind': line_kind,
                }

    return best_payload


def _allocate_unique_patch_key(diff_results: Dict[str, PatchInfo], patch_text: str) -> str:
    """Return a stable unique key for patch_text."""
    base = stable_hash(patch_text)
    if base not in diff_results:
        return base
    if str(getattr(diff_results[base], 'patch_text', '') or '') == patch_text:
        return base
    i = 1
    while True:
        cand = f'{base}_{i}'
        if cand not in diff_results:
            return cand
        if str(getattr(diff_results[cand], 'patch_text', '') or '') == patch_text:
            return cand
        i += 1


def relocate_header_revert_defs_before_add_context(
    diff_results: Dict[str, PatchInfo],
    patch_keys: List[str],
    *,
    commit_id: str,
) -> List[str]:
    """Move header `__revert_*` function definitions into caller source-file hunks.

    Conservative mode: only relocate when the header patch consists solely of one or more
    extracted revert definition blocks (no mixed extra content).
    """
    updated_keys = list(patch_keys)

    for key in list(updated_keys):
        patch = diff_results.get(key)
        if patch is None:
            continue
        header_file = str(patch.file_path_new or patch.file_path_old or "").strip()
        if not header_file or not _is_header_file_path(header_file):
            continue

        blocks = _extract_revert_removed_function_blocks_from_header_patch(patch.patch_text)
        if not blocks:
            continue

        static_blocks: List[Dict[str, Any]] = []
        movable_blocks: List[Dict[str, Any]] = []
        for b in blocks:
            if _is_static_revert_block(b):
                static_blocks.append(b)
            else:
                movable_blocks.append(b)
        if static_blocks:
            logger.info(
                f"Header revert relocation skipped for {key} ({header_file}): "
                f"static __revert_* definitions stay in header."
            )
            blocks = movable_blocks
            if not blocks:
                continue

        if _patch_has_nonblock_hunk_content(patch.patch_text, blocks):
            logger.info(f"Header revert relocation skipped for {key} ({header_file}): mixed hunk content.")
            continue

        selected_targets: List[Dict[str, Any]] = []
        failed = False
        for b in blocks:
            symbol = str(b.get('symbol') or '').strip()
            if not symbol:
                failed = True
                break
            target = _select_best_symbol_callsite_target(
                diff_results,
                updated_keys,
                skip_key=str(key),
                symbol=symbol,
            )
            if target is None:
                failed = True
                logger.info(f"Header revert relocation skipped for {key}: no callsite target for {symbol}.")
                break
            selected_targets.append(target)

        if failed:
            continue

        for b, target in zip(blocks, selected_targets):
            symbol = str(b.get('symbol') or '').strip()
            target_file = str(target.get('file_path') or '').strip()
            insert_line = int(target.get('insert_line') or 0)
            if not target_file or insert_line <= 0:
                logger.info(f"Header revert relocation skipped for {symbol}: invalid target.")
                continue

            block_lines = [str(l) for l in (b.get('lines') or []) if str(l)]
            block_len = sum(1 for l in block_lines if l.startswith('-') and not l.startswith('---'))
            if block_len <= 0:
                logger.info(f"Header revert relocation skipped for {symbol}: empty block.")
                continue

            patch_header = (
                f"diff --git a/{target_file} b/{target_file}\n"
                f"--- a/{target_file}\n"
                f"+++ b/{target_file}\n"
                f"@@ -{insert_line},{block_len} +{insert_line},0 @@\n"
            )
            relocated_text = patch_header + '\n'.join(block_lines) + '\n'

            target_suffix = os.path.splitext(target_file)[1].lower()
            target_type = patch.file_type
            if target_suffix in _SOURCE_SUFFIXES:
                target_type = 'c'
            elif target_suffix in _HEADER_SUFFIXES:
                target_type = 'h'

            relocated_patch = PatchInfo(
                file_path_old=target_file,
                file_path_new=target_file,
                file_type=target_type,
                patch_text=relocated_text,
                old_signature=patch.old_signature,
                patch_type={'Function removed', 'Function body change', 'Recreated function'},
                dependent_func=set(),
                new_start_line=insert_line,
                new_end_line=insert_line,
                old_start_line=insert_line,
                old_end_line=insert_line + block_len,
                old_function_start_line=insert_line,
                old_function_end_line=insert_line + block_len,
            )
            new_key = _allocate_unique_patch_key(diff_results, relocated_patch.patch_text)
            diff_results[new_key] = relocated_patch
            if new_key not in updated_keys:
                updated_keys.append(new_key)
            logger.info(
                f"Relocated header revert definition {symbol} from {header_file} "
                f"to {target_file}:{insert_line} (new key: {new_key})"
            )

        # Candidate patch contained only moved definition blocks; drop it from apply list.
        if key in updated_keys:
            updated_keys.remove(key)
            logger.info(f"Dropped original header definition patch key {key} ({header_file}) after relocation.")

    return updated_keys


def normalize_function_pointer_params(signature: str) -> str:
    """
    Fix libclang's function-pointer parameter syntax:
      'int (*)(struct hFILE_plugin *) init'
    → 'int (*init)(struct hFILE_plugin *)'
    """
    pattern = r'(\w[\w\s\*]*?)\s*\(\*\)\s*\((.*?)\)\s+(\w+)'
    repl = r'\1 (*\3)(\2)'
    return re.sub(pattern, repl, signature)


def _ensure_static_inline_signature(sig: str) -> str:
    """Ensure `sig` is prefixed with `static inline` (best-effort).

    In header files, rewriting macro-generated function headers into concrete
    signatures without `static` can easily create multiple-definition linker
    errors because the header is included by many translation units.
    """
    s = str(sig or "").lstrip()
    if not s:
        return s
    if re.match(r"^static\b", s):
        if re.search(r"\binline\b", s.split("(", 1)[0]):
            return s
        # Insert inline after static.
        return re.sub(r"^static\b", "static inline", s, count=1)
    if re.match(r"^inline\b", s):
        return "static " + s
    return "static inline " + s


def replace_function_header(func_code: str, signature: str, *, file_path: str | None = None) -> str:
    """
    Replace the function header in func_code with the libclang signature,
    BUT ONLY IF the signature's function name is NOT found before the
    first '{' in func_code.

    If the name is already present in the header, do nothing.
    """
    brace_idx = func_code.find('{')
    if brace_idx == -1:
        # no body? just bail
        return func_code

    header = func_code[:brace_idx]
    body = func_code[brace_idx:]

    func_name = signature.split('(')[0].split()[-1]
    if not func_name:
        # Can't parse name, safest is to do nothing
        return func_code

    # Is the function name already in the header (as an identifier)?
    pattern = r'\b' + re.escape(func_name) + r'\b'
    if re.search(pattern, header):
        # Normal case: header already uses the canonical name -> don't touch it
        return func_code

    # Weird case (e.g. PLUGIN_GLOBAL): name not found in source header.
    # Here we DO want to replace the header with the signature.

    # Optionally fix libclang's function-pointer param syntax
    cleaned_sig = normalize_function_pointer_params(signature)
    # If we're rewriting a header-defined function (common: macro-generated ops)
    # into a concrete signature, ensure internal linkage to avoid duplicate
    # symbols at link time.
    if file_path and str(file_path).lower().endswith((".h", ".hh", ".hpp", ".hxx")):
        cleaned_sig = _ensure_static_inline_signature(cleaned_sig)

    # Build new header: 'int foo(...)' (no '{' yet)
    new_header = cleaned_sig.rstrip() + " "

    return new_header + body


def looks_like_real_function(code: str) -> bool:
    return '{' in code and '}' in code


def find_macro_block(file_content, start_line):
    define_line = None
    undef_line = None

    # Ensure we have valid content
    if not file_content or start_line < 1:
        return None

    # Search upward for #define XML_OP
    # Clamp search_start to valid range [0, len(file_content)-1]
    search_start = min(start_line - 2, len(file_content) - 1)
    search_start = max(0, search_start)

    for i in range(search_start, -1, -1):
        if '#define XML_OP' in file_content[i]:
            define_line = i + 1
            break

    # Search downward for #undef XML_OP
    if define_line is not None:
        # Clamp search_start_down to valid range
        search_start_down = min(start_line - 1, len(file_content) - 1)
        search_start_down = max(0, search_start_down)

        for i in range(search_start_down, len(file_content)):
            if '#undef XML_OP' in file_content[i]:
                undef_line = i + 1
                break

    if define_line and undef_line:
        return define_line, undef_line
    return None


def _extract_function_code_from_node(ast_node, target_repo_path, file_path):
    '''Extract function code from a single AST node. Returns (func_code, func_length, start_line) or None.'''
    src_path = os.path.join(target_repo_path, ast_node["extent"]["start"]["file"])
    with open(src_path, "r", encoding="utf-8", errors="strict") as f:
        file_content = f.readlines()

    start_line = ast_node["extent"]["start"]["line"]
    end_line = ast_node["extent"]["end"]["line"]

    # -------- #if / #endif balancing logic --------
    block_depth = 0
    min_depth = 0
    for line in file_content[start_line - 1:end_line]:
        stripped = line.lstrip()
        if stripped.startswith(("#if", "#ifdef", "#ifndef")):
            block_depth += 1
        elif stripped.startswith("#endif"):
            block_depth -= 1
        min_depth = min(min_depth, block_depth)

    if min_depth < 0:
        unmatched = -min_depth
        for idx in range(start_line - 2, -1, -1):
            stripped = file_content[idx].lstrip()
            if stripped.startswith("#endif"):
                unmatched += 1
            elif stripped.startswith(("#if", "#ifdef", "#ifndef")):
                unmatched -= 1
                if unmatched == 0:
                    start_line = idx + 1
                    break

    func_code = "".join(file_content[start_line - 1:end_line])

    # -------- handle macro-generated "functions" --------
    if not looks_like_real_function(func_code):
        macro_block = find_macro_block(file_content, start_line)
        if macro_block is not None:
            block_start, block_end = macro_block
            func_code = "".join(file_content[block_start - 1:block_end])
            start_line = block_start
            end_line = block_end

    # Only try to rewrite the header if this really looks like a function.
    if looks_like_real_function(func_code):
        func_code = replace_function_header(func_code, ast_node["signature"], file_path=file_path)

    # Compute length
    func_length = func_code.count("\n")
    if func_code and func_code[-1] != "\n":
        func_length += 1

    return func_code, func_length, start_line


def get_function_code_from_old_commit(target_repo_path, commit, data_path, file_path, func_sig):
    os.chdir(target_repo_path)
    subprocess.run(["git", "clean", "-fdx"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", "-f", commit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Use short commit hash (6 chars) for directory name to match fuzz_helper.py
    short_commit = commit[:8] if len(commit) > 8 else commit
    parsing_path = os.path.join(
        data_path,
        f'{target_repo_path.split("/")[-1]}-{short_commit}',
        f'{file_path}_analysis.json'
    )
    with open(parsing_path, "r") as f:
        ast_nodes = json.load(f)

    # Collect all matching AST nodes — the analysis JSON may contain duplicate
    # entries from different preprocessing contexts with overlapping extents.
    func_name = func_sig.split('(')[0].split()[-1] if '(' in func_sig else ''
    candidates = []
    for ast_node in ast_nodes:
        if ast_node.get("kind") not in {"FUNCTION_DEFI", "CXX_METHOD", "FUNCTION_TEMPLATE"}:
            continue
        if not compare_function_signatures(ast_node["signature"], func_sig, True):
            continue
        candidates.append(ast_node)

    if not candidates:
        return None, 0, 0

    # Among multiple matching nodes, prefer the one whose RAW source code
    # (before replace_function_header) already contains the function name
    # before the first '{'.  Duplicate AST entries with wrong extents often
    # include a *different* function's definition first, causing
    # replace_function_header to silently overwrite the wrong header.
    if len(candidates) > 1 and func_name:
        name_pat = re.compile(r'\b' + re.escape(func_name) + r'\b')
        preferred = []
        fallback = []
        for node in candidates:
            # Read raw source to check header BEFORE replace_function_header
            src_path = os.path.join(target_repo_path, node["extent"]["start"]["file"])
            try:
                with open(src_path, "r", encoding="utf-8", errors="strict") as f:
                    raw_lines = f.readlines()
                raw_code = "".join(raw_lines[node["extent"]["start"]["line"] - 1 : node["extent"]["end"]["line"]])
            except (OSError, IndexError):
                fallback.append(node)
                continue
            brace_idx = raw_code.find('{')
            header = raw_code[:brace_idx] if brace_idx != -1 else raw_code
            if name_pat.search(header):
                preferred.append(node)
            else:
                fallback.append(node)
        pick = preferred[0] if preferred else (fallback[0] if fallback else None)
        if pick is None:
            return None, 0, 0
        result = _extract_function_code_from_node(pick, target_repo_path, file_path)
        if result is not None:
            return result
        return None, 0, 0

    # Single candidate — fast path
    result = _extract_function_code_from_node(candidates[0], target_repo_path, file_path)
    if result is not None:
        return result
    return None, 0, 0


def _find_include_guard_endif_line(file_lines):
    """Return the 1-based line number of the closing #endif of an include guard, or -1.

    Detects ``#ifndef X / #define X / ... / #endif`` patterns with optional
    leading comments (including multi-line ``/* ... */`` blocks).
    """
    if not file_lines:
        return -1
    _pp_if_re = re.compile(r"^#\s*(?:if|ifdef|ifndef)\b")
    _pp_endif_re = re.compile(r"^#\s*endif\b")

    # Check that the first meaningful line is #ifndef
    in_block_comment = False
    guard_found = False
    for raw in file_lines:
        stripped = raw.lstrip().lstrip("\ufeff")
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
            guard_found = True
        break

    if not guard_found:
        return -1

    # Track preprocessor nesting; find last #endif that returns to level 0.
    pp_nesting = 0
    last_zero_endif = -1
    for i, raw in enumerate(file_lines):
        stripped = raw.lstrip()
        if _pp_if_re.match(stripped):
            pp_nesting += 1
        elif _pp_endif_re.match(stripped):
            pp_nesting -= 1
            if pp_nesting == 0:
                last_zero_endif = i

    if last_zero_endif < 0:
        return -1
    # Only treat it as a guard if nothing meaningful follows.
    for i in range(last_zero_endif + 1, len(file_lines)):
        stripped = file_lines[i].strip()
        if stripped and not stripped.startswith("//") and not stripped.startswith("/*"):
            return -1
    return last_zero_endif + 1  # 1-based


def get_patch_insert_line_number(target_repo_path, next_commit, data_path, file_path, func_sig):
    """Get patch insert line number from new commit for the Artificial patch"""
    if not func_sig:
        # Try to insert after the last function definition in V2
        parsing_path = os.path.join(
            data_path,
            f"{target_repo_path.split('/')[-1]}-{next_commit}",
            f"{file_path}_analysis.json",
        )
        last_func_end = -1
        try:
            with open(parsing_path, 'r') as f:
                ast_nodes = json.load(f)
            for ast_node in ast_nodes:
                if ast_node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
                    continue
                if ast_node['extent']['start']['file'] == file_path:
                    end_line = ast_node['extent']['end']['line']
                    if end_line > last_func_end:
                        last_func_end = end_line
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            pass

        if last_func_end > 0:
            insert_point = last_func_end + 1
            # For header files, clamp inside the include guard.
            insert_point = _clamp_insert_before_include_guard(
                target_repo_path, next_commit, file_path, insert_point
            )
            return insert_point

        # Fallback: end of file (no AST or no functions found)
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', next_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(os.path.join(target_repo_path, file_path), 'r') as fsrc:
            file_content = fsrc.readlines()
            insert_point = len(file_content) + 1
            # For header files, clamp inside the include guard.
            insert_point = _clamp_insert_before_include_guard(
                target_repo_path, next_commit, file_path, insert_point,
                file_lines=[l.rstrip('\n') for l in file_content],
            )
            return insert_point
    # Use short commit hash (6 chars) for directory name to match fuzz_helper.py
    short_next_commit = next_commit[:8] if len(next_commit) > 8 else next_commit
    parsing_path = os.path.join(
        data_path,
        f"{target_repo_path.split('/')[-1]}-{short_next_commit}",
        f"{file_path}_analysis.json",
    )
    with open(parsing_path, 'r') as f:
        ast_nodes = json.load(f)
    artificial_patch_insert_point = -1
    for ast_node in ast_nodes:
        if ast_node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
            continue
        if ast_node['extent']['start']['file'] == file_path and compare_function_signatures(ast_node['signature'], func_sig, True):
            artificial_patch_insert_point = ast_node['extent']['end']['line'] + 1
            break
    if artificial_patch_insert_point > 0:
        artificial_patch_insert_point = _clamp_insert_before_include_guard(
            target_repo_path, next_commit, file_path, artificial_patch_insert_point
        )
    return artificial_patch_insert_point


def _clamp_insert_before_include_guard(target_repo_path, next_commit, file_path, insert_point, file_lines=None):
    """For header files, clamp insert_point to stay inside the include guard.

    Also skips backward past trailing ``#ifdef __cplusplus / } / #endif``
    blocks so the insertion stays inside extern "C" scopes.

    The insert_point is a 1-based line number where the recreated function's
    diff hunk will be anchored.  Because the hunk uses context lines *after*
    the anchor, even an insert_point a few lines before ``#endif`` can cause
    the function to land outside the guard.  We compute a safe ceiling and
    clamp to it.
    """
    suffix = os.path.splitext(file_path)[1].lower()
    if suffix not in {'.h', '.hh', '.hpp', '.hxx'}:
        return insert_point
    if file_lines is None:
        try:
            src_path = os.path.join(target_repo_path, file_path)
            with open(src_path, 'r', encoding='utf-8', errors='replace') as f:
                file_lines = [l.rstrip('\n') for l in f.readlines()]
        except (FileNotFoundError, OSError):
            return insert_point
    guard_endif = _find_include_guard_endif_line(file_lines)
    if guard_endif <= 0:
        return insert_point
    # Walk backward from the guard #endif to find the safe ceiling: skip
    # trailing blank lines, preprocessor blocks (``#ifdef __cplusplus / } /
    # #endif``), and the guard's own ``#endif``.
    ceiling = guard_endif  # 1-based line of the guard #endif
    for i in range(guard_endif - 2, -1, -1):  # 0-based index
        stripped = file_lines[i].strip()
        if not stripped:
            ceiling = i + 1  # 1-based
            continue
        # #ifdef / #ifndef mark the START of a preprocessor conditional block.
        # Include this line in the ceiling but stop walking — everything above
        # is real code that must not be swallowed (e.g. a function closing '}'
        # separated from the guard block by blank lines).
        if re.match(r'^#\s*(?:ifdef|ifndef)\b', stripped):
            ceiling = i + 1
            break
        if stripped in ('}', '#endif') or re.match(r'^#\s*(?:else|endif)\b', stripped):
            ceiling = i + 1
            continue
        if stripped.startswith('extern') and '{' in stripped:
            ceiling = i + 1
            continue
        break
    if insert_point >= ceiling:
        return ceiling
    return insert_point


def get_diff_unified(repo_path, commit1, commit2, patch_path, context_lines=3):

    repo = Repo(repo_path)

    # Determine what to restore to: branch or commit
    try:
        orig_ref = repo.active_branch.name
    except TypeError:
        # Detached HEAD; fallback to current commit hash
        orig_ref = repo.head.commit.hexsha

    tmp_branch = f"tmp_patch_{os.getpid()}"

    if patch_path:
        # Create temp branch from commit2
        repo.git.checkout(commit2, b=tmp_branch)
        # Apply patch in reverse
        repo.git.apply(patch_path, reverse=True)
        # Diff with commit1
        diff_output = repo.git.diff(
            '--minimal', '--no-prefix', f'{commit1}', '.', unified=context_lines
        )
        # Clean up
        repo.git.checkout(orig_ref)
        repo.git.branch('-D', tmp_branch)
    else:
        diff_output = repo.git.diff('--minimal', '--no-prefix', commit1, commit2, unified=context_lines)

    return diff_output


def parse_arguments():
    parser = argparse.ArgumentParser(description='Run fuzzing tests with trace collection')
    parser.add_argument('target_test_result',
                        help='Csv file that contains all poc test result on all commits of a target project')
    parser.add_argument('--bug_info', required=True,
                        help='JSON config all bug info details')
    parser.add_argument('--build_csv', required=True,
                        help='this file contains a target project commit id and corresponding commit id')
    parser.add_argument('--target', required=True,
                        help='target project name')
    parser.add_argument('--bug_id', 
                        help='Optional: specific bug ID to process')
    parser.add_argument('--buggy_commit',
                        help='Optional: specific buggy commit to process')
    parser.add_argument('--fixed-image', type=int, metavar='YEAR',
                        help='Pin Docker images to latest versions before the given year (e.g., 2022). '
                             'Uses get_latest_images_before_year() from buildAndtest.py')
    parser.add_argument('--auto-select-images', action='store_true',
                        help='Automatically select Docker images based on commit timestamp for collect_trace/collect_crash. '
                             'By default, images are not automatically selected unless this flag is set or --fixed-image is used.')
    parser.add_argument(
        '--react-agent-max-steps',
        type=int,
        default=int(os.environ.get("REACT_AGENT_MAX_STEPS", "200") or 200),
        help='Max steps for a single ReAct agent run (default: REACT_AGENT_MAX_STEPS or 200).',
    )
    parser.add_argument(
        '--react-agent-max-restarts-per-hunk',
        type=int,
        default=int(os.environ.get("REACT_AGENT_MAX_RESTARTS_PER_HUNK", "3") or 3),
        help='Max clean-slate reruns per patch hunk (default: REACT_AGENT_MAX_RESTARTS_PER_HUNK or 3).',
    )
    parser.add_argument(
        '--react-agent-max-multi-agent-rounds',
        type=int,
        default=int(os.environ.get("REACT_AGENT_MAX_MULTI_AGENT_ROUNDS", "100") or 100),
        help='Max iterative multi-agent rounds (default: REACT_AGENT_MAX_MULTI_AGENT_ROUNDS or 100).',
    )
    parser.add_argument(
        '--ignore-crash-leaks',
        action='store_true',
        help='Pass --ignore-leaks to fuzz_helper collect_crash so LeakSanitizer does not fail crash collection.',
    )
    parser.add_argument(
        '--crash-stack-only',
        action='store_true',
        help='Only revert functions that appear in the crash stack (instead of the full execution trace).',
    )
    parser.add_argument(
        '--target-commit',
        help='Override the target commit to migrate bugs to (default: latest commit in CSV).',
    )
    return parser.parse_args()


def parse_csv_file(file_path):
    with open(file_path, 'r') as file:
        csv_content = file.read()
    return parse_csv_data(csv_content)


def parse_csv_data(csv_content):
    lines = csv_content.strip().split('\n')
    headers = lines[0].split(',')
    data = []
    
    for line in lines[1:]:
        values = line.split(',')
        if len(values) >= 2:  # Ensure there are at least commit ID and one OSV column
            row = {
                'commit_id': values[0],
                'osv_statuses': {},  # Store all OSV statuses in a dictionary
                'poc_count': 0
            }
            
            # Process all OSV columns (skipping first and last columns)
            for i in range(1, len(headers)):
                bug_id = headers[i]
                row['osv_statuses'][bug_id] = values[i] if values[i] else None
                if values[i] and values[i] == '1|1':
                    row['poc_count'] += 1
            
            data.append(row)
    
    return data


def select_crash_test_input(bug_id: str, testcases_dir: str) -> str:
    """Return preferred testcase filename for crash collection."""
    base_name = f'testcase-{bug_id}'
    if not testcases_dir:
        return base_name
    original_candidate = f'{base_name}-original'
    original_path = os.path.join(testcases_dir, original_candidate)
    if os.path.exists(original_path):
        return original_candidate
    return base_name


def get_crash_stack(
    bug_id: str,
    commit_id: str,
    crash_test_input: str,
    sanitizer: str,
    build_csv: str,
    arch: str,
    testcases_env: str,
    target: str,
    fuzzer: str,
    target_repo_path: str = None,
    fixed_builder_digest: Optional[str] = None,
    auto_select_images: bool = False,
    ignore_crash_leaks: bool = False,
) -> str:
    """
    Ensure the crash log for the given commit/input exists, invoking the helper script if needed.
    Returns the path to the crash log (exists or best-effort generated).
    """
    crash_dir = os.path.join(data_path, 'crash')
    os.makedirs(crash_dir, exist_ok=True)
    crash_log_path = os.path.join(
        crash_dir,
        f'target_crash-{commit_id[:8]}-{crash_test_input}.txt',
    )
    if os.path.exists(crash_log_path):
        return crash_log_path

    collect_crash_cmd = [
        py3,
        f'{current_file_path}/fuzz_helper.py',
        'collect_crash',
        '--commit',
        commit_id,
        '--sanitizer',
        sanitizer,
        '--build_csv',
        build_csv,
        '--architecture',
        arch,
    ]
    if ignore_crash_leaks:
        collect_crash_cmd.append('--ignore-leaks')

    # Add Docker image selection based on flags
    # collect_crash uses base-builder image
    if fixed_builder_digest:
        # Use the single fixed builder image digest for all commits
        collect_crash_cmd.extend(['--runner-image', fixed_builder_digest])
    else:
        # fuzz_helper.py will auto-derive commit_date from oss_fuzz_commit in builds.csv
        collect_crash_cmd.extend(['--runner-image', 'auto'])

    collect_crash_cmd.extend([
        '--testcases',
        testcases_env,
        '--test_input',
        crash_test_input,
        target,
        fuzzer,
    ])
    logger.info(
        "Collecting crash log for bug %s using input %s: %s",
        bug_id,
        crash_test_input,
        " ".join(collect_crash_cmd),
    )
    try:
        subprocess.run(
            collect_crash_cmd,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as e:
        logger.info("Collect crash command failed with exit code %s", e.returncode)
    return crash_log_path


def crashes_match(test_output: str, baseline_path: str, signature_file: Optional[str]) -> bool:
    """Compare crash logs using stack traces and optional signature mapping."""
    if not os.path.exists(baseline_path):
        logger.warning("Baseline crash log %s not found; skipping comparison.", baseline_path)
        return True
    signature_arg = signature_file if signature_file and os.path.exists(signature_file) else None
    try:
        baseline_stack, signature_map = extract_function_stack(
            baseline_path,
            signature_file=signature_arg,
            apply_signatures=False,
            return_signature_map=True,
        )
    except Exception:
        logger.exception("Failed to parse baseline crash log %s", baseline_path)
        return True
    if not baseline_stack:
        logger.error("Baseline crash stack empty for %s; skipping comparison.", baseline_path)
        return False

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
            tmp.write(test_output.encode('utf-8', errors='ignore'))
            tmp_path = tmp.name
        current_stack = extract_function_stack(
            tmp_path,
            signature_file=signature_arg,
            apply_signatures=False,
        )
    except Exception:
        logger.exception("Failed to parse reproduced crash output.")
        return False
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)

    signature_map = signature_map or {}
    alias_adj: Dict[str, Set[str]] = defaultdict(set)
    for base, mapped_list in signature_map.items():
        base_clean = _clean_function_name(base)
        alias_adj[base_clean].add(base_clean)
        for mapped in mapped_list:
            mapped_clean = _clean_function_name(mapped)
            alias_adj[base_clean].add(mapped_clean)
            alias_adj[mapped_clean].add(mapped_clean)
            alias_adj[mapped_clean].add(base_clean)

    def resolve_aliases(name: str) -> Set[str]:
        clean = _clean_function_name(name)
        visited: Set[str] = set()
        stack = [clean]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            stack.extend(alias_adj.get(current, []))
        if not visited:
            visited.add(clean)
        return visited

    baseline_clean = [_clean_function_name(func) for func in baseline_stack]
    current_clean = [_clean_function_name(func) for func in current_stack]

    if not baseline_clean or not current_clean:
        logger.info(
            "Crash stack missing frames (baseline %d, current %d). Treating as mismatch.\nBaseline: %s\nCurrent: %s",
            len(baseline_clean),
            len(current_clean),
            baseline_stack,
            current_stack,
        )
        return False

    def frames_match(base_frame: str, current_frame: str) -> bool:
        allowed = resolve_aliases(base_frame)
        if current_frame in allowed:
            return True
        reverse_allowed = resolve_aliases(current_frame)
        return base_frame in reverse_allowed

    # Filter out sanitizer-internal frames for matching purposes.
    # These frames are runtime infrastructure (ASAN, LSAN, TSAN, MSAN,
    # UBSAN) whose names vary across compiler/sanitizer versions and are
    # not part of the actual bug signature.
    _SANITIZER_FRAME_RE = re.compile(
        r'^(__asan::|__lsan::|__tsan::|__msan::|__ubsan::|__sanitizer::'
        r'|__interception::'
        r'|Atomically\w*Allocated'
        r'|atomic_compare_exchange_strong<__sanitizer::)'
    )

    def _is_sanitizer_frame(frame: str) -> bool:
        return bool(_SANITIZER_FRAME_RE.match(frame))

    baseline_app = [f for f in baseline_clean if not _is_sanitizer_frame(f)]
    current_app = [f for f in current_clean if not _is_sanitizer_frame(f)]

    logger.debug(f'signature_map: {signature_map}')

    # Top-frame check on application frames (fall back to full stack if
    # all frames were sanitizer-internal).
    top_baseline = baseline_app[0] if baseline_app else baseline_clean[0]
    top_current = current_app[0] if current_app else current_clean[0]
    top_match = frames_match(top_baseline, top_current)
    if not top_match:
        logger.info(
            "Crash stack top frame mismatch: baseline '%s' vs current '%s'.",
            top_baseline,
            top_current,
        )
        # Fall through to LCS check instead of rejecting immediately.
        # Inlining, partial inlining, and version-specific refactors can
        # shift the top frame while the rest of the stack is identical.

    # Use DP-based LCS (longest common subsequence) on application frames.
    # The old greedy forward scan could cascade-fail: one unmatched frame
    # (e.g. __interceptor_free vs free) would exhaust the scan pointer and
    # lose all subsequent matches.
    def _lcs_length(seq_a: List[str], seq_b: List[str]) -> int:
        n, m = len(seq_a), len(seq_b)
        if n == 0 or m == 0:
            return 0
        prev = [0] * (m + 1)
        for i in range(1, n + 1):
            curr = [0] * (m + 1)
            for j in range(1, m + 1):
                if frames_match(seq_a[i - 1], seq_b[j - 1]):
                    curr[j] = prev[j - 1] + 1
                else:
                    curr[j] = max(prev[j], curr[j - 1])
            prev = curr
        return prev[m]

    lcs_len = _lcs_length(baseline_app, current_app)
    denom = max(len(baseline_app), len(current_app), 1)
    match_ratio = lcs_len / denom
    STACK_MATCH_THRESHOLD = 0.6
    if match_ratio >= STACK_MATCH_THRESHOLD:
        if not top_match:
            logger.info(
                "Top frame mismatch overridden by LCS ratio %.2f (>= %.2f).",
                match_ratio,
                STACK_MATCH_THRESHOLD,
            )
        return True

    logger.info(
        "Crash stack mismatch (ratio %.2f < %.2f).\nBaseline: %s\nCurrent: %s",
        match_ratio,
        STACK_MATCH_THRESHOLD,
        baseline_app,
        current_app,
    )
    return False


def is_ancestor(repo_path: str, older_commit: str, newer_commit: str) -> bool:
    """
    Return True if `older_commit` is an ancestor of `newer_commit`,
    False otherwise.
    """
    repo = Repo(repo_path)
    try:
        repo.git.merge_base('--is-ancestor', older_commit, newer_commit)
        return True
    except GitCommandError:
        return False


def prepare_transplant(data, repo_path):
    strong_trigger_statuses = {'1|1', '1|0', '0.5|1'}
    weak_trigger_statuses = {'0.5|1'}

    def trigger_rank(status):
        if status in strong_trigger_statuses:
            return 2
        if status in weak_trigger_statuses:
            return 1
        return 0

    # Target = user-specified commit, or latest commit in CSV.
    target_commit_override = getattr(args, 'target_commit', None)
    if target_commit_override:
        target_row = None
        for row in data:
            if row['commit_id'].startswith(target_commit_override):
                target_row = row
                break
        if target_row is None:
            logger.error(f'--target-commit {target_commit_override} not found in CSV')
            return {}, {}
        logger.info(f'target commit (user-specified): {target_row["commit_id"][:12]}')
    else:
        # Determine ordering by checking if first commit is ancestor of last.
        if is_ancestor(repo_path, data[0]['commit_id'], data[-1]['commit_id']):
            target_row = data[-1]  # CSV is old-to-new
        else:
            target_row = data[0]   # CSV is new-to-old
        logger.info(f'target commit (latest in CSV): {target_row["commit_id"][:12]}')

    # Count poc stats for the target row
    for row in data:
        row['poc_count'] = 0
        row['weak_poc_count'] = 0
        for bug_id in row['osv_statuses'].keys():
            status = row['osv_statuses'][bug_id]
            if status in strong_trigger_statuses:
                row['poc_count'] += 1
            elif status in weak_trigger_statuses:
                row['weak_poc_count'] += 1

    bug_ids_trigger = set()  # already trigger at target, no transplant needed
    bug_ids_other = set()

    for bug_id in target_row['osv_statuses'].keys():
        if target_row['osv_statuses'][bug_id] in strong_trigger_statuses:
            bug_ids_trigger.add(bug_id)
        else:
            bug_ids_other.add(bug_id)

    # For each bug not triggering at target, find the closest commit
    # (latest ancestor of target) where it triggers.
    bugs_need_transplant = dict()  # key: bug_id; value: row closest to target where bug triggers
    bug_best_rank = dict()
    bugs_cant_use = set()
    for row in data:
        for bug_id in bug_ids_other:
            status = row['osv_statuses'][bug_id]
            rank = trigger_rank(status)
            if rank == 0:
                continue
            if rank > bug_best_rank.get(bug_id, 0):
                bugs_need_transplant[bug_id] = row
                bug_best_rank[bug_id] = rank
                continue
            # Same rank: prefer the later commit (closer to target)
            if rank == bug_best_rank.get(bug_id, 0) and bug_id in bugs_need_transplant:
                if is_ancestor(repo_path, bugs_need_transplant[bug_id]['commit_id'], row['commit_id']):
                    bugs_need_transplant[bug_id] = row
    for bug_id in bug_ids_other:
        if bug_id not in bugs_need_transplant and bug_id != 'poc count':
            bugs_cant_use.add(bug_id)
    logger.info(f'all bugs count: {len(target_row["osv_statuses"])}')
    logger.info(f'target_row (latest) strong/weak poc_count: {target_row["poc_count"]}/{target_row["weak_poc_count"]}')
    logger.info(f'bug_ids_trigger: {len(bug_ids_trigger)} {bug_ids_trigger}')
    logger.info(f'bugs need transplant count: {len(bugs_need_transplant)} {bugs_need_transplant.keys()}')
    logger.info(f'bugs cant use count: {len(bugs_cant_use)} {bugs_cant_use}\n')

    return bug_ids_trigger, bugs_need_transplant, target_row


def extract_revert_patch(h, line_start, line_end, version):
    """
    Extract and create a partial revert patch from a given diff hunk.
    
    Args:
        h: String containing the hunk content
        line_start: Starting line number to extract
        line_end: Ending line number to extract
        version: Version of the code (old or new or both)
    
    Returns:
        String containing the extracted patch
    """
    # Split the hunk content into lines
    lines = h.split('\n')
    logger.debug(f'line_start: {line_start}, line_end: {line_end} version: {version}')
    
    inside_hunk = True  # We're already inside a hunk
    patch_lines = []
    new_line_cursor = {"num": 0} # next line to be check
    old_line_cursor = {"num": 0} # next line to be check
    # line to be check
    if version == 'old':
        target_line_cursor = old_line_cursor
    elif version == 'new':
        target_line_cursor = new_line_cursor
    elif version == 'both':
        target_line_cursor = None
    else:
        raise ValueError("Version must be 'old' or 'new'")
    
    # First line contains the hunk header
    header_line = lines[0]
    
    # Parse header line like: " -1223,17 +1224,73 @@"
    match = re.match(r'^.*-(\d+),?\d* \+(\d+),?(\d*) .*', header_line)
    if match:
        old_line_cursor['num'] = int(match.group(1))
        new_line_cursor['num'] = int(match.group(2))
        
    get_sub_patch_start = False
    old_line_start = 0
    new_line_start = 0
    
    # Process the actual diff content
    for line in lines[1:]:
        if not line:
            continue
        
        logger.debug(f'version: {version} old_line_cursor: {old_line_cursor["num"]} new_line_cursor: {new_line_cursor["num"]}')
        
        if (not target_line_cursor and old_line_cursor['num'] >= line_start and new_line_cursor['num'] <= line_end) or (target_line_cursor and target_line_cursor['num'] >= line_start and target_line_cursor['num'] <= line_end):
            if not get_sub_patch_start:
                if not target_line_cursor or version == 'new' and line.startswith('+') or version == 'old' and line.startswith('-'):
                    get_sub_patch_start = True
                    new_line_start = new_line_cursor['num']
                    old_line_start = old_line_cursor['num']
            if get_sub_patch_start:
                patch_lines.append(line)
                logger.debug(f'add line: {line}')
            
        if target_line_cursor and target_line_cursor['num'] > line_end or not target_line_cursor and new_line_cursor['num'] > line_end:
            # We've reached the end of the target lines
            break
        
        # Check the first character of the line to determine the type of change
        if line.startswith(' '):
            # Context line, increment both cursors
                new_line_cursor['num'] += 1
                old_line_cursor['num'] += 1
        elif line.startswith('+'):
            # Added line, increment new line cursor
            new_line_cursor['num'] += 1
        elif line.startswith('-'):
            # Removed line, increment old line cursor
            old_line_cursor['num'] += 1
    
    # handle a case where subpatch ends with '-...\n+...'.  
    if old_line_start == old_line_cursor['num']:
        old_line_start = old_line_cursor['num'] = old_line_cursor['num'] - 1
    new_header_line = f"@@ -{old_line_start},{old_line_cursor['num']-old_line_start} +{new_line_start},{new_line_cursor['num']-new_line_start} @@"
    patch_lines.insert(0, new_header_line)
    
    if not get_sub_patch_start:
        # get nothing
        return '', 0, 0, 0, 0
    
    return '\n'.join(patch_lines), old_line_start, old_line_cursor['num'], new_line_start, new_line_cursor['num']


def analyze_diffindex(diff_text, target_repo_path: str, new_commit: str, old_commit: str, target: str, signature_change_list: list):
    """
    Analyze a GitPython DiffIndex and return metadata per hunk.
    Target repo checkout to fix commit here.
    """
    results = dict()
    no_merge = set() # A set of keys, means they should not be considered to merge. Because this patch is a whole function
    func_kinds = {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}
    for diff in diff_text.split('diff --git')[1:]:
        # Choose the post-change path if available, else pre-change:
        diff_lines = diff.splitlines()
        if len(diff_lines) < 5:
            logger.debug(f'diff is too short, skipping: {diff}')
            # Skip if the diff is too short to contain valid information, like binary files or empty diffs
            continue

        # Check for binary files and skip them
        if any('Binary files' in line for line in diff_lines):
            logger.debug(f'Skipping binary file diff')
            continue

        path_a = None
        path_b = None
        for diff_line in diff_lines:
            if diff_line.startswith('---'):
                path_a = diff_line.split(' ')[-1]
            elif diff_line.startswith('+++'):
                path_b = diff_line.split(' ')[-1]
            if path_a and path_b:
                break

        # Skip if we couldn't parse paths (e.g., malformed diffs)
        if not path_a and not path_b:
            logger.debug(f'Could not parse file paths from diff, skipping')
            continue

        path = path_b if (path_b and 'dev/null' not in path_b) else path_a
        # Derive file extension/type from path:
        ext  = path.rsplit('.', 1)[-1] if '.' in path else ''
        if ext not in ['c', 'h', 'cc', 'cpp', 'cxx', 'hh', 'hpp', 'hxx']:
            # Skip non-C/C++ files
            logger.debug(f'Skipping non-C/C++ file: {path}')
            continue

        patch_text = diff

        # Split into hunks on lines starting with '@@'
        hunks = re.split(r'(?m)^@@', patch_text)
        # The first element is the header before any hunk; skip it
        
        # checkout target repo to the new commit, and parse the code from that
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', new_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for h in hunks[1:]:
            # diff codes have extra 3 lines
            if len(h.split('\n')) >= 8:
                # The hunk header is before the first newline
                header, body = h.split('\n', 1)
                old_line_num = header.split('@@')[-2].strip().split(' ')[0][1:]
                lines_body = body.split('\n')
                first_index = None
                last_index = None
                for idx, line in enumerate(lines_body):
                    if line.startswith('-') or line.startswith('+'):
                        first_index = idx
                        break
                
                for idx, line in enumerate(lines_body[::-1]):
                    if line.startswith('-') or line.startswith('+'):
                        last_index = idx-1
                        break
                old_begin_num = int(old_line_num.split(',')[0]) + first_index
                old_end_num = max(old_begin_num, old_begin_num + int(old_line_num.split(',')[1]) - first_index - last_index - 1)

                new_line_num = header.split('@@')[-2].strip().split('+')[1].strip()
                new_line_num = '1,0' if new_line_num == '1' else new_line_num
                begin_num = int(new_line_num.split(',')[0]) + first_index
                end_num = max(begin_num, begin_num + int(new_line_num.split(',')[1]) - first_index - last_index - 1)
            else:
                # If the hunk is too short, skip it TODO: maybe find a better way to handle this
                logger.debug(f'Skipping short hunk: {h}')
                continue
                
            file_path = os.path.join(target_repo_path, path_b)
            # Use short commit hash (6 chars) for directory name to match fuzz_helper.py
            short_new_commit = new_commit[:8] if len(new_commit) > 8 else new_commit
            parsing_path = os.path.join(data_path, f'{target}-{short_new_commit}', f'{path_b}_analysis.json')
            if not os.path.exists(file_path) or not os.path.exists(parsing_path):
                logger.debug(f"File {file_path} or {parsing_path} does not exist, skipping parsing")
                continue
            
            # read data for function signature mapping
            with open(parsing_path, 'r') as f:
                ast_nodes = json.load(f)

            patch_header = f"diff --git a/{path_b if path_a != '/dev/null' else path_b} b/{path_b if path_b != '/dev/null' else path_a}\n"
            patch_header += f"--- {f'a/{path_b}' if path_a != '/dev/null' else '/dev/null'}\n+++ {'b/' if path_b != '/dev/null' else ''}{path_b}\n"
            signature = 'unknown'
            # filter for function‐like nodes (clang cursors for functions, methods, etc.)
            for node in ast_nodes:
                if node.get('kind') not in func_kinds:
                    continue
                if node['location']['file'] == path_b and node['extent']['end']['line'] >= begin_num and node['extent']['start']['line'] <= end_num:
                    signature = node['signature']
                    diff_result_begin = max(node['extent']['start']['line'], begin_num)
                    diff_result_end = min(node['extent']['end']['line'], end_num)
                    # not include context lines, because they may add some changes not related to the function
                    sub_patch, old_line_start, old_line_cursor, new_line_start, new_line_cursor = extract_revert_patch(h, diff_result_begin, diff_result_end, 'new')
                    if not sub_patch:
                        # no changes in this function, skip
                        continue
                    key_new = f'{path_a}{path_b}-{old_line_start},{old_line_cursor-old_line_start}+{new_line_start},{new_line_cursor-new_line_start}'
                    patch_text = patch_header + sub_patch
                    type_set = {'Function body change'}
                    if node['extent']['start']['line'] == new_line_start and node['extent']['end']['line'] == new_line_cursor-1:
                        no_merge.add(key_new)
                    
                    results[key_new] = PatchInfo(
                        file_path_old=path_a,
                        file_path_new=path_b,
                        file_type=ext,
                        patch_text=patch_text,
                        new_signature=signature,
                        patch_type=type_set,
                        new_start_line=int(new_line_start),
                        new_end_line=int(new_line_cursor),
                        old_start_line=int(old_line_start),
                        old_end_line=int(old_line_cursor),
                        new_function_start_line=int(node['extent']['start']['line']),
                        new_function_end_line=int(node['extent']['end']['line']),
                    )
        
        # checkout target repo to the old commit, and parse the code from that
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', old_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        for h in hunks[1:]:
            # The hunk header is before the first newline
            header, body = h.split('\n', 1)
            old_line_num = header.split('@@')[-2].strip().split(' ')[0][1:]
            old_line_num = old_line_num if old_line_num.count(',') else '0,' + old_line_num

            lines_body = body.split('\n')
            first_index = 0
            last_index = 0
            for idx, line in enumerate(lines_body):
                if line.startswith('-') or line.startswith('+'):
                    first_index = idx
                    break
            
            for idx, line in enumerate(lines_body[::-1]):
                if line.startswith('-') or line.startswith('+'):
                    last_index = idx-1
                    break
            
            old_begin_num = int(old_line_num.split(',')[0]) + first_index
            old_end_num = max(old_begin_num, old_begin_num + int(old_line_num.split(',')[1]) - first_index - last_index - 1)

            new_line_num = header.split('@@')[-2].strip().split('+')[1].strip()

            file_path = os.path.join(target_repo_path, path_a)
            # Use short commit hash (6 chars) for directory name to match fuzz_helper.py
            short_old_commit = old_commit[:8] if len(old_commit) > 8 else old_commit
            parsing_path = os.path.join(data_path, f'{target}-{short_old_commit}', f'{path_a}_analysis.json')

            if not os.path.exists(file_path) or not os.path.exists(parsing_path):
                logger.debug(f"File {file_path} or {parsing_path} does not exist, skipping parsing")
                continue
            
            # read data for function signature mapping
            with open(parsing_path, 'r') as f:
                ast_nodes = json.load(f)
            
            patch_header = f"diff --git a/{path_b if path_a != '/dev/null' else path_b} b/{path_b if path_b != '/dev/null' else path_a}\n"
            patch_header += f"--- {f'a/{path_b}' if path_a != '/dev/null' else '/dev/null'}\n+++ {'b/' if path_b != '/dev/null' else ''}{path_b}\n"
            signature = 'unknown'
            # filter for function‐like nodes (clang cursors for functions, methods, etc.)
            func_kinds = {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}
            for node in ast_nodes:
                if node.get('kind') not in func_kinds:
                    continue
                if node['location']['file'] == path_a and node['extent']['end']['line'] >= old_begin_num and node['extent']['start']['line'] <= old_end_num:
                    signature = node['signature']
                    diff_result_begin = max(node['extent']['start']['line'], old_begin_num)
                    diff_result_end = min(node['extent']['end']['line'], old_end_num)
                    # not include context lines, because they may add some changes not related to the function
                    sub_patch, old_line_start, old_line_cursor, new_line_start, new_line_cursor = extract_revert_patch(h, diff_result_begin, diff_result_end, 'old')
                    k_old = f'{path_a}{path_b}-{old_line_start},{old_line_cursor-old_line_start}+{new_line_start},{new_line_cursor-new_line_start}'
                    # check if there is a patch that has overlapped with the current patch
                    key_merged = dict()
                    if k_old not in results:
                        for k, v in results.items():
                            if k in no_merge:
                                continue
                            if f'{path_a}{path_b}' not in k:
                                # not same file, skip
                                continue
                            if v.new_signature is None:
                                continue
                            old_start_i, old_end_i, new_start_i, new_end_i = v.old_start_line, v.old_end_line, v.new_start_line, v.new_end_line
                            if new_start_i == new_end_i:
                                # this situation is handled in add_context()
                                continue
                            if sub_patch == '':
                                # patch only add lines, no lines removed
                                old_line_start = old_line_cursor = diff_result_begin-1
                                new_line_start = new_line_cursor = new_end_i
                            # <= because line_start and line_cursor may be the same then subpatch only contains '+' or only '-'
                            if (max(old_start_i, old_line_start) <= min(old_end_i, old_line_cursor) and
                                max(new_start_i, new_line_start) <= min(new_end_i, new_line_cursor)):
                                # update the boundaries: take min start and max end for both old and new
                                old_start = min(old_start_i, old_line_start)
                                old_end = max(old_end_i, old_line_cursor)
                                new_start = min(new_start_i, new_line_start)
                                new_end = max(new_end_i, new_line_cursor)
                                sub_patch, old_line_start, old_line_cursor, new_line_start, new_line_cursor = extract_revert_patch(h, old_start, new_end, 'both')
                                k_old = f'{path_a}{path_b}-{old_line_start},{old_line_cursor-old_line_start}+{new_line_start},{new_line_cursor-new_line_start}'
                                key_merged[k] = k_old
                                break
                        
                    if not sub_patch:
                        # no changes in this function, skip
                        continue
                    patch_text = patch_header + sub_patch
                    type_set = {'Function body change'}
                    
                    if k_old in results:
                        results[k_old].old_signature = signature
                    else:
                        results[k_old] = PatchInfo(
                            file_path_old=path_a,
                            file_path_new=path_b,
                            file_type=ext,
                            patch_text=patch_text,
                            old_signature=signature,
                            patch_type=type_set,
                            new_start_line=int(new_line_start),
                            new_end_line=int(new_line_cursor),
                            old_start_line=int(old_line_start),
                            old_end_line=int(old_line_cursor),
                            old_function_start_line=int(node['extent']['start']['line']),
                            old_function_end_line=int(node['extent']['end']['line']),
                        )
                    
                    for k_new, k_old in key_merged.items():
                        patch_old = results[k_old]
                        patch_new = results[k_new]
                        if patch_old.old_function_name != patch_new.new_function_name:
                            signature_change_list.append((patch_old.old_function_name, patch_new.new_function_name))
                        patch_old.new_signature = patch_new.new_signature
                        patch_old.new_start_line = patch_new.new_start_line
                        patch_old.new_end_line = patch_new.new_end_line
                        del results[k_new]

    for patch in results.values():
        if patch.old_signature and patch.new_signature and patch.old_signature != patch.new_signature:
            patch.patch_type.add('Function added')
            patch.patch_type.add('Function removed')
            patch.patch_type.add('Function signature change')
        if patch.is_file_deletion:
            patch.patch_type.add('Function removed')
            patch.patch_type.add('File removed')

    return results


def clean_log(text: str) -> str:
    _ANSI_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')  # ANSI CSI sequences
    _BACKSPACE_RE = re.compile(r'.\x08')               # overstrike patterns

    if not text:
        return ''
    # normalize carriage returns from progress bars
    text = text.replace('\r', '\n')
    # remove backspace overstrikes
    text = _BACKSPACE_RE.sub('', text)
    # strip ANSI escape codes
    text = _ANSI_RE.sub('', text)
    # collapse duplicate newlines
    return re.sub(r'\n{3,}', '\n\n', text)


def build_fuzzer(target, commit_id, sanitizer, bug_id, patch_file_path, fuzzer, build_csv, arch,
                 runner_image='auto', commit_date=None):
    cmd = [
        "python3", f"{current_file_path}/fuzz_helper.py", "build_version", "--commit", commit_id, "--sanitizer", sanitizer,
        "--patch", patch_file_path, '--build_csv', build_csv, '--architecture', arch
    ]
    if runner_image:
        cmd.extend(['--runner-image', str(runner_image)])
    if commit_date:
        cmd.extend(['--commit-date', str(commit_date)])
    cmd.append(target)
    cmd.extend(['-e', 'CFLAGS=-Wl,--allow-multiple-definition -Wno-unused-command-line-argument',
                '-e', 'CXXFLAGS=-Wl,--allow-multiple-definition -Wno-unused-command-line-argument'])

    cmd = [str(x) for x in cmd]
    logger.info(' '.join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    stdout = clean_log(result.stdout)

    build_error_patterns = [
        "Building fuzzers failed",
        "Docker build failed",
        "clang++: error:",
        "g++: error:",
        "cmake: error:",
        "fatal error:",
        "undefined reference to",
        "cannot find -l",
        "No such file or directory",
        "error: 'struct",
        "error: conflicting types",
        "error: invalid conversion",
        "error: patch failed:",
        "error: git",
        "error: corrupt patch",
        "make: *** [Makefile:",
        "ninja: build stopped:",
        "Compilation failed",
        "failed with exit status",
        "CMake Error",
    ]

    pattern = r"ERROR:.*Sanitizer"
    fuzzer_path = os.path.join(ossfuzz_path, 'build/out', target, fuzzer)
    sanitizer_error_seen = bool(re.search(pattern, stdout))
    fuzzer_exists = os.path.exists(fuzzer_path)
    has_build_error = any(p in stdout for p in build_error_patterns)
    patch_label = os.path.basename(patch_file_path)
    if ((not sanitizer_error_seen and not fuzzer_exists) or has_build_error or
            result.returncode != 0):
        if sanitizer_error_seen:
            logger.info(f"Successfully built fuzzer after reverting patch {patch_label}")
            return True, ''
        logger.info(f"Build failed after patch reversion for {patch_label}\n")
        return False, stdout

    logger.info(f"Successfully built fuzzer after reverting patch {patch_label}")
    return True, ''


def prepare_v1_v2_repos(
    source_repo_path: str,
    v1_repo_base: str,
    v2_repo_base: str,
    target: str,
    v1_commit: str,
    v2_commit: str,
) -> tuple:
    """Prepare separate V1 and V2 source directories by checkout and copy.

    The react agent needs two separate source trees to read code from both versions.
    This function checks out each commit in the source repo and copies the source
    files to the V1/V2 directories.

    Args:
        source_repo_path: Path to the source repo (REPO_PATH/<target>)
        v1_repo_base: Base directory for V1 source (e.g., /home/user/tasks-git-v1)
        v2_repo_base: Base directory for V2 source (e.g., /home/user/tasks-git-v2)
        target: Project name (e.g., libxml2)
        v1_commit: Commit hash for V1 (old version)
        v2_commit: Commit hash for V2 (new version)

    Returns:
        Tuple of (v1_src_path, v2_src_path)
    """
    v1_target_path = os.path.join(v1_repo_base, target)
    v2_target_path = os.path.join(v2_repo_base, target)

    def _checkout_with_submodules(commit: str, label: str) -> None:
        logger.info(f"Checking out {label} commit {commit} in {source_repo_path}")
        subprocess.run(
            ["git", "clean", "-fdx"],
            cwd=source_repo_path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["git", "checkout", "-f", commit],
            cwd=source_repo_path,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Keep submodules aligned with the checked-out superproject commit so
        # copied V1/V2 trees include required nested sources (e.g. htscodecs).
        subprocess.run(
            ["git", "submodule", "update", "--init", "--recursive"],
            cwd=source_repo_path,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    # Checkout V1 commit in source repo and copy to V1 path
    _checkout_with_submodules(v1_commit, "V1")

    # Remove old V1 target and copy fresh
    if os.path.exists(v1_target_path):
        shutil.rmtree(v1_target_path)
    os.makedirs(v1_repo_base, exist_ok=True)
    logger.info(f"Copying source to {v1_target_path}")
    shutil.copytree(source_repo_path, v1_target_path, symlinks=True)

    # Checkout V2 commit in source repo and copy to V2 path
    _checkout_with_submodules(v2_commit, "V2")

    # Remove old V2 target and copy fresh
    if os.path.exists(v2_target_path):
        shutil.rmtree(v2_target_path)
    os.makedirs(v2_repo_base, exist_ok=True)
    logger.info(f"Copying source to {v2_target_path}")
    shutil.copytree(source_repo_path, v2_target_path, symlinks=True)

    return v1_target_path, v2_target_path


def _has_sanitizer_error(build_log_text: str) -> bool:
    """Check if build log contains sanitizer runtime errors (which means build succeeded)."""
    import re
    # Sanitizer errors like "ERROR: AddressSanitizer", "ERROR: MemorySanitizer", etc.
    return bool(re.search(r"ERROR:\s*\w*Sanitizer", build_log_text))


_ARG_COUNT_ERROR_RE = re.compile(r"too (?:few|many) arguments to function call", re.IGNORECASE)
_REVERT_NAME_RE = re.compile(r"__revert_[A-Za-z0-9]+_[A-Za-z_][A-Za-z0-9_]*")


def _extract_revert_names_from_arg_errors(error_log: str) -> set[str]:
    """Extract ``__revert_*`` function names associated with arg-count errors.

    Scans the build log for "too few/many arguments" error lines and collects
    any ``__revert_*`` function name that appears in the error line itself or in
    the 10 lines that follow (source snippets / ``note:`` lines).
    """
    lines = error_log.splitlines()
    names: set[str] = set()
    i = 0
    while i < len(lines):
        if _ARG_COUNT_ERROR_RE.search(lines[i]):
            # Scan this line + up to 10 following lines for __revert_* names
            for j in range(i, min(i + 11, len(lines))):
                for m in _REVERT_NAME_RE.finditer(lines[j]):
                    names.add(m.group(0))
            i += 11  # skip past the window we just scanned
        else:
            i += 1
    return names


def _remove_rename_only_hunks(
    patches: dict,
    error_log: str,
    patch_file_path: str,
    patch_file_binary: str,
) -> bool:
    """Detect rename-only hunks that cause argument-count errors and remove them.

    Strategy: extract ``__revert_*`` function names from arg-count error contexts
    in the build log, then remove any rename-only hunk whose patch text references
    one of those functions.

    Modifies *patches* in-place, rewrites *patch_file_path* (.diff) and
    *patch_file_binary* (.patch2).  Returns True if any hunks were removed.
    """
    error_func_names = _extract_revert_names_from_arg_errors(error_log)
    if not error_func_names:
        return False

    # Find rename-only hunks that reference the problematic functions.
    removed: list[str] = []
    for key in list(patches.keys()):
        patch = patches[key]
        if not is_rename_only_hunk(patch.patch_text):
            continue
        # Check if this hunk renames calls to any of the error functions.
        if any(fn in patch.patch_text for fn in error_func_names):
            removed.append(key)
            del patches[key]

    if not removed:
        return False

    logger.info(f"Removed {len(removed)} rename-only hunk(s) with argument mismatch: {removed}")

    # Rewrite the .diff and .patch2 files without the removed hunks.
    remaining_keys = sorted(
        patches.keys(),
        key=lambda k: getattr(patches[k], "new_start_line", 0),
        reverse=True,
    )
    with open(patch_file_path, "w") as f:
        for key in remaining_keys:
            f.write(patches[key].patch_text)
            f.write("\n\n")
    save_patches_pickle(patches, patch_file_binary)

    return True


def _run_single_multi_agent_round(
    build_log_path: str,
    patch_path: str,
    project: str,
    new_commit: str,
    build_csv: str,
    fuzz_target: str,
    v1_json_dir: str,
    v2_json_dir: str,
    v1_src: str,
    v2_src: str,
    sanitizer: str,
    arch: str,
    max_steps: int,
    jobs: int,
    max_groups: int,
    ossfuzz_loop_max: int,
    max_restarts_per_hunk: int,
    openai_model: str,
    openai_max_tokens: int,
) -> dict:
    """Run a single round of multi-agent fixing."""
    agent_script = os.path.join(current_file_path, "react_agent", "multi_agent.py")

    cmd = [
        sys.executable,
        agent_script,
        build_log_path,
        "--patch-path", patch_path,
        "--jobs", str(jobs),
        "--max-groups", str(max_groups),
        "--model", "openai",
        "--tools", "real",
        "--max-steps", str(max_steps),
        "--recursion-limit", "0",
        "--ossfuzz-project", project,
        "--ossfuzz-commit", new_commit,
        "--ossfuzz-build-csv", build_csv,
        "--ossfuzz-sanitizer", sanitizer,
        "--ossfuzz-arch", arch,
        "--ossfuzz-engine", "libfuzzer",
        "--ossfuzz-fuzz-target", fuzz_target,
        "--ossfuzz-use-sudo",
        "--auto-ossfuzz-loop",
        "--ossfuzz-loop-max", str(ossfuzz_loop_max),
        "--v1-json-dir", v1_json_dir,
        "--v2-json-dir", v2_json_dir,
        "--v1-src", v1_src,
        "--v2-src", v2_src,
        "--openai-model", openai_model,
        "--openai-base-url", "https://api.openai.com/v1",
        "--openai-max-tokens", str(openai_max_tokens),
        "--output-format", "none",
        "--max-restarts-per-hunk", str(max_restarts_per_hunk),
    ]

    logger.info(f"Calling react multi-agent: {' '.join(cmd)}")
    start_time = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)

    try:
        output = json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        output = {"raw_stdout": result.stdout, "raw_stderr": result.stderr}

    # Find the latest multi_* artifacts directory created after start_time
    artifacts_base = os.path.join(data_path, "react_agent_artifacts")
    merged_diff_path = ""
    merged_patch_bundle_path = ""
    artifacts_dir = ""
    summary = {}
    final_build_log_path = ""
    not_fixed = []

    if os.path.isdir(artifacts_base):
        multi_dirs = sorted(
            [d for d in os.listdir(artifacts_base) if d.startswith("multi_")],
            key=lambda x: os.path.getmtime(os.path.join(artifacts_base, x)),
            reverse=True,
        )
        for d in multi_dirs:
            dir_path = os.path.join(artifacts_base, d)
            if os.path.getmtime(dir_path) >= start_time:
                summary_path = os.path.join(dir_path, "summary.json")
                if os.path.isfile(summary_path):
                    try:
                        with open(summary_path) as f:
                            summary = json.load(f)
                        final_ossfuzz = summary.get("final_ossfuzz_test", {})
                        merged_diff_path = final_ossfuzz.get("merged_patch_file_path", "")
                        merged_patch_bundle_path = final_ossfuzz.get("merged_patch_bundle_path", "")
                        final_build_log_path = final_ossfuzz.get("build_output_path", "")
                        not_fixed = summary.get("not_fixed", [])
                        artifacts_dir = dir_path
                        break
                    except Exception:
                        pass

    return {
        "success": result.returncode == 0,
        "output": output,
        "returncode": result.returncode,
        "merged_diff_path": merged_diff_path,
        "merged_patch_bundle_path": merged_patch_bundle_path,
        "artifacts_dir": artifacts_dir,
        "summary": summary,
        "final_build_log_path": final_build_log_path,
        "not_fixed": not_fixed,
    }


def _run_proactive_revert_declarations(
    *,
    patch_path: str,
    v1_json_dir: str,
    v2_json_dir: str,
    v1_src: str,
    v2_src: str,
) -> dict:
    """Round 0: scan the patch bundle and add forward declarations for all __revert_* functions.

    Returns a dict with: total_symbols, declared, skipped, updated_patch_path, details.
    """
    result: Dict[str, Any] = {
        "total_symbols": 0,
        "declared": 0,
        "skipped": 0,
        "updated_patch_path": "",
        "details": [],
    }

    react_agent_dir = os.path.join(current_file_path, "react_agent")
    if react_agent_dir not in sys.path:
        sys.path.insert(0, react_agent_dir)
    if current_file_path not in sys.path:
        sys.path.insert(0, current_file_path)

    try:
        from tools.extra_patch_tools import (
            _enumerate_revert_symbols_by_file,
            _infer_extra_patch_key,
            _symbol_defined_in_extra_hunk,
            make_extra_patch_override,
        )
        from migration_tools.patch_bundle import load_patch_bundle as _lpb
    except Exception as exc:
        logger.warning(f"Round 0: import error, skipping proactive declarations: {exc}")
        return result

    # Enumerate all __revert_* references in non-_extra_* patches.
    try:
        symbols = _enumerate_revert_symbols_by_file(patch_path)
    except Exception as exc:
        logger.warning(f"Round 0: failed to enumerate symbols: {exc}")
        return result

    if not symbols:
        return result

    # Filter out symbols already declared in the bundle.
    try:
        pre_bundle = _lpb(patch_path)
        filtered = []
        for sym, file_path, source_key in symbols:
            ek = _infer_extra_patch_key(bundle=pre_bundle, file_path=file_path)
            if ek:
                ep = (pre_bundle.patches or {}).get(ek)
                existing_text = str(getattr(ep, "patch_text", "") or "") if ep else ""
                if existing_text and _symbol_defined_in_extra_hunk(existing_text, symbol_name=sym):
                    continue
            filtered.append((sym, file_path, source_key))
        result["skipped"] = len(symbols) - len(filtered)
        symbols = filtered
    except Exception as exc:
        logger.warning(f"Round 0: pre-filter failed ({exc}), processing all")

    result["total_symbols"] = len(symbols) + result["skipped"]
    if not symbols:
        return result

    # Build AgentTools for KB-backed prototype extraction.
    agent_tools = None
    try:
        from agent_tools import AgentTools, KbIndex, SourceManager
        if v1_json_dir and v2_json_dir and v1_src and v2_src:
            kb = KbIndex(v1_json_dir, v2_json_dir)
            sm = SourceManager(v1_src, v2_src)
            agent_tools = AgentTools(kb, sm)
    except Exception as exc:
        logger.warning(f"Round 0: AgentTools unavailable ({exc}), proceeding without KB")

    current_patch_path = patch_path
    declared = 0

    for sym, file_path, _source_key in symbols:
        try:
            res = make_extra_patch_override(
                agent_tools,
                patch_path=current_patch_path,
                file_path=file_path,
                symbol_name=sym,
            )
        except Exception as exc:
            logger.warning(f"Round 0: make_extra_patch_override failed for {sym}: {exc}")
            result["details"].append({"symbol": sym, "file": file_path, "status": "error", "error": str(exc)})
            continue

        extra_key = str(res.get("patch_key", "") or "").strip()
        patch_text = ""
        pt = res.get("patch_text")
        if isinstance(pt, dict):
            pt_path = str(pt.get("artifact_path", "") or "").strip()
            if pt_path:
                try:
                    patch_text = Path(pt_path).read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass
        elif isinstance(pt, str):
            patch_text = pt

        if not extra_key or not patch_text.strip():
            result["details"].append({
                "symbol": sym, "file": file_path, "status": "no_patch",
                "note": res.get("note", ""),
            })
            continue

        # Write updated bundle with the new declaration.
        try:
            from migration_tools.types import PatchInfo as _PatchInfo
            bundle = _lpb(current_patch_path)
            patches = bundle.patches if isinstance(getattr(bundle, "patches", None), dict) else {}

            if extra_key not in patches:
                fp_old = fp_new = ""
                for line in patch_text.splitlines():
                    if line.startswith("--- "):
                        fp_old = line[4:].strip()
                        if fp_old.startswith("a/"):
                            fp_old = fp_old[2:]
                    elif line.startswith("+++ "):
                        fp_new = line[4:].strip()
                        if fp_new.startswith("b/"):
                            fp_new = fp_new[2:]
                    if fp_old and fp_new:
                        break
                fp_new = fp_new or file_path
                fp_old = fp_old or fp_new
                suffix = Path(fp_new).suffix.lower()
                file_type = suffix.lstrip(".") if suffix else "unknown"
                patches[extra_key] = _PatchInfo(
                    file_path_old=fp_old,
                    file_path_new=fp_new,
                    patch_text="",
                    file_type=file_type,
                    old_start_line=1, old_end_line=1,
                    new_start_line=1, new_end_line=1,
                    patch_type={"Extra"},
                    old_signature="",
                    dependent_func=set(),
                    hiden_func_dict={},
                )

            patches[extra_key].patch_text = patch_text.rstrip("\n") + "\n"

            # Always write to the same file to avoid name explosion.
            base_stem = Path(patch_path).stem or "bundle"
            # Strip any prior suffixes like .split_extra, .proactive_decls, .effective, etc.
            base_stem = re.sub(r'\.(split_extra|proactive_decls|effective|merged_overrides)(\.\d+)?$', '', base_stem)
            out_path = Path(patch_path).parent / f"{base_stem}.proactive_decls.patch2"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "wb") as f:
                pickle.dump(dict(patches), f, protocol=pickle.HIGHEST_PROTOCOL)

            current_patch_path = str(out_path)
            declared += 1
            result["details"].append({"symbol": sym, "file": file_path, "extra_key": extra_key, "status": "ok"})
        except Exception as exc:
            logger.warning(f"Round 0: failed to write bundle for {sym}: {exc}")
            result["details"].append({"symbol": sym, "file": file_path, "status": "error", "error": str(exc)})

    result["declared"] = declared
    if declared > 0:
        result["updated_patch_path"] = current_patch_path
    return result


def call_react_agent(
    build_log_path: str,
    patch_path: str,
    project: str,
    old_commit: str,
    new_commit: str,
    build_csv: str,
    fuzz_target: str,
    v1_json_dir: str,
    v2_json_dir: str,
    v1_src: str,
    v2_src: str,
    sanitizer: str = "address",
    arch: str = "x86_64",
    max_steps: int = int(os.environ.get("REACT_AGENT_MAX_STEPS", "200") or 200),
    jobs: int = int(os.environ.get("REACT_AGENT_JOBS", "4")),
    max_groups: int = 100,
    ossfuzz_loop_max: int = 40,
    max_restarts_per_hunk: int = int(os.environ.get("REACT_AGENT_MAX_RESTARTS_PER_HUNK", "3") or 3),
    openai_model: str = "gpt-5-mini",
    openai_max_tokens: int = 64000,
    max_multi_agent_rounds: int = int(os.environ.get("REACT_AGENT_MAX_MULTI_AGENT_ROUNDS", "100") or 100),
    # Extra params needed for rebuild after round 0
    bug_id: str = "",
    patch_file_path: str = "",
    runner_image: str = "auto",
    commit_date: str = "",
) -> dict:
    """Call the multi-agent to fix build errors with iterative rounds.

    Iterates multiple rounds if:
    - All individual errors in a round are fixed (not_fixed is empty)
    - The merged build still fails with new errors
    - The build log does NOT contain sanitizer errors (which indicates runtime success)

    Returns dict with keys: success, output, returncode, merged_diff_path, artifacts_dir, rounds
    """
    current_build_log = build_log_path
    current_patch = patch_path
    rounds = []
    final_result = None
    agent_succeeded = False  # True only when the final build actually passed

    # --- Round 0: Proactive forward declarations for __revert_* functions ---
    # Scan the patch bundle for __revert_* calls and add forward declarations
    # into _extra_* hunks before any agent runs.  No build log needed.
    round0_ts = time.strftime("%Y%m%d_%H%M%S")
    round0_dir = os.path.join(data_path, "react_agent_artifacts", f"round0_{round0_ts}")
    os.makedirs(round0_dir, exist_ok=True)

    round0_result = _run_proactive_revert_declarations(
        patch_path=current_patch,
        v1_json_dir=v1_json_dir,
        v2_json_dir=v2_json_dir,
        v1_src=v1_src,
        v2_src=v2_src,
    )
    round0_result["round"] = 0
    round0_result["artifacts_dir"] = round0_dir

    updated_patch = round0_result.get("updated_patch_path", "")
    if updated_patch and os.path.isfile(updated_patch):
        current_patch = updated_patch
        declared = round0_result.get("declared", 0)
        total = round0_result.get("total_symbols", 0)
        logger.info(f"Round 0: {declared}/{total} forward declarations added -> {current_patch}")

        # Regenerate .diff from updated bundle to a separate round0 file
        # so that the original patch_file_path is preserved for debugging.
        if patch_file_path and bug_id:
            try:
                updated_patches = load_patches_pickle(current_patch)
                round0_diff_path = patch_file_path.replace('.diff', '_round0.diff') if patch_file_path.endswith('.diff') else patch_file_path + '_round0'
                with open(round0_diff_path, "w") as f:
                    for key in sorted(
                        updated_patches.keys(),
                        key=lambda k: getattr(updated_patches[k], "new_start_line", 0),
                        reverse=True,
                    ):
                        f.write(updated_patches[key].patch_text)
                        f.write("\n\n")
                patch_file_path = round0_diff_path
                logger.info(f"Round 0: regenerated {patch_file_path} from updated bundle (original preserved)")

                # Rebuild to get fresh error lines
                logger.info("Round 0: rebuilding to get updated build log...")
                build_ok, new_error_log = build_fuzzer(
                    project, new_commit, sanitizer, bug_id,
                    patch_file_path, fuzz_target, build_csv, arch,
                    runner_image=runner_image, commit_date=commit_date,
                )
                round0_result["build_success"] = build_ok

                if build_ok:
                    logger.info("Round 0: build succeeded after proactive declarations!")
                    agent_succeeded = True
                else:
                    # Write fresh build log
                    fresh_log = os.path.join(round0_dir, "build_output.log")
                    with open(fresh_log, "w") as f:
                        f.write(new_error_log)
                    current_build_log = fresh_log
                    round0_result["build_log"] = fresh_log
                    logger.info(f"Round 0: build still fails, updated build log -> {fresh_log}")
            except Exception as exc:
                logger.warning(f"Round 0: rebuild failed ({exc}), keeping original build log")
        else:
            logger.info("Round 0: no patch_file_path/bug_id, skipping rebuild")
    else:
        logger.info(f"Round 0: no declarations needed (symbols={round0_result.get('total_symbols', 0)})")

    # Save round 0 summary
    try:
        import json as _json
        with open(os.path.join(round0_dir, "summary.json"), "w") as f:
            _json.dump(round0_result, f, indent=2, default=str)
    except Exception:
        pass

    rounds.append(round0_result)

    if agent_succeeded:
        # Round 0 alone fixed the build — return early
        return {
            "success": True,
            "output": round0_result,
            "returncode": 0,
            "merged_diff_path": patch_file_path,
            "merged_patch_bundle_path": current_patch,
            "artifacts_dir": round0_dir,
            "rounds": rounds,
        }

    for round_num in range(1, max_multi_agent_rounds + 1):
        logger.info(f"=== Multi-agent round {round_num}/{max_multi_agent_rounds} ===")
        logger.info(f"  Build log: {current_build_log}")
        logger.info(f"  Patch: {current_patch}")

        round_result = _run_single_multi_agent_round(
            build_log_path=current_build_log,
            patch_path=current_patch,
            project=project,
            new_commit=new_commit,
            build_csv=build_csv,
            fuzz_target=fuzz_target,
            v1_json_dir=v1_json_dir,
            v2_json_dir=v2_json_dir,
            v1_src=v1_src,
            v2_src=v2_src,
            sanitizer=sanitizer,
            arch=arch,
            max_steps=max_steps,
            jobs=jobs,
            max_groups=max_groups,
            ossfuzz_loop_max=ossfuzz_loop_max,
            max_restarts_per_hunk=max_restarts_per_hunk,
            openai_model=openai_model,
            openai_max_tokens=openai_max_tokens,
        )
        round_result["round"] = round_num
        rounds.append(round_result)
        final_result = round_result

        # Check if we should continue to next round
        not_fixed = round_result.get("not_fixed", [])
        summary = round_result.get("summary", {})
        final_ossfuzz = summary.get("final_ossfuzz_test", {})
        final_status = final_ossfuzz.get("status", "")

        # If some individual errors couldn't be fixed, stop
        if not_fixed:
            logger.info(f"Round {round_num}: {len(not_fixed)} errors not fixed individually, stopping")
            break

        # If final build succeeded, we're done
        if final_status == "ok":
            logger.info(f"Round {round_num}: Build succeeded!")
            agent_succeeded = True
            break

        # Check if build log has sanitizer errors (means build succeeded, runtime issue)
        final_build_log_path = round_result.get("final_build_log_path", "")
        if final_build_log_path and os.path.isfile(final_build_log_path):
            with open(final_build_log_path, 'r') as f:
                final_build_log_text = f.read()
            if _has_sanitizer_error(final_build_log_text):
                logger.info(f"Round {round_num}: Sanitizer error detected (build succeeded), stopping")
                agent_succeeded = True
                break

        # Check if we have output for next round
        merged_patch_bundle = round_result.get("merged_patch_bundle_path", "")
        if not merged_patch_bundle or not os.path.isfile(merged_patch_bundle):
            logger.info(f"Round {round_num}: No merged patch bundle found, stopping")
            break

        if not final_build_log_path or not os.path.isfile(final_build_log_path):
            logger.info(f"Round {round_num}: No final build log found, stopping")
            break

        # Setup for next round
        current_patch = merged_patch_bundle
        current_build_log = final_build_log_path
        logger.info(f"Round {round_num}: Individual errors fixed but build still fails, continuing to next round")

    # Build final result from last round
    if final_result is None:
        return {
            "success": False,
            "output": {},
            "returncode": 1,
            "merged_diff_path": "",
            "artifacts_dir": "",
            "rounds": rounds,
            "total_rounds": 0,
        }

    return {
        "success": agent_succeeded,
        "output": final_result.get("output", {}),
        "returncode": final_result.get("returncode", 1),
        "merged_diff_path": final_result.get("merged_diff_path", ""),
        "merged_patch_bundle_path": final_result.get("merged_patch_bundle_path", ""),
        "artifacts_dir": final_result.get("artifacts_dir", ""),
        "rounds": rounds,
        "total_rounds": len(rounds),
    }


def patch_patcher(diff_results, patch_to_apply : list, dependence_graph, commit, next_commit, target_repo_path):
    # Create artificial patch for function signature change or function removed
    new_patch_to_apply = []
    handle_func_signature_change = set()
    function_declarations = set() # a set of 'recreated' function declarations
    
    removed_old_signatures = set()
    removed_new_signatures = set()
    reserved_keys = set()
    recreated_functions = set() # a set of functions that are recreated by the artificial patch, and may be called by other functions
    key_to_newkey = dict() # a mapping from old key to new key for recreated functions, used to update function name in caller patches
    
    for key in patch_to_apply:
        patch = diff_results[key]
        if not patch.old_signature:
            # skip for a added function
            continue
        fname = patch.old_function_name
        
        if fname == 'LLVMFuzzerTestOneInput':
            # skip LLVMFuzzerTestOneInput, because it is a special function for fuzzing
            if patch.file_path_new == '/dev/null':
                # Fuzzer file was deleted between commits, skip entirely
                continue
            patch_lines = patch.patch_text.split('\n')
            old_start = int(patch_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[0].split('-')[-1])
            old_offset = int(patch_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
            new_start = int(patch_lines[3].split('@@')[-2].strip().split('+')[1].split(',')[0])
            new_offset = int(patch_lines[3].split('@@')[-2].strip().split(',')[-1])
            patch_lines[3] = f'@@ -{new_start},{old_offset} +{new_start},{new_offset} @@'
            patch.patch_text = '\n'.join(patch_lines)
            new_patch_to_apply.append(key)
            continue
        if 'Function body change' in patch.patch_type:
            if 'Function removed' in patch.patch_type and 'Function added' not in patch.patch_type:
                # TODO: remove this part
                # add prefix to function being deleted
                modified_lines = rename_func(patch.patch_text, fname, commit)
                if patch.file_path_new == '/dev/null':
                    # This file is deleted, can't handle now
                    continue
                function_declarations.add(patch.old_signature.replace(fname, f'__revert_{commit}_{fname}')) # do not use rename_func here, because it only change line starting with '-'
                patch.patch_text = '\n'.join(modified_lines)
                # iterate through the dependent functions and rename them
                for dep_key in dependence_graph.get(key, []):
                    modified_lines = rename_func(diff_results[dep_key].patch_text, fname, commit)
                    diff_results[dep_key].patch_text = '\n'.join(modified_lines)
                new_patch_to_apply.append(key)
                recreated_functions.add(FunctionInfo(name=fname, signature=patch.old_signature, func_used_file=patch.file_path_new, file_path_old=patch.file_path_old, keywords=['static'] if is_function_static(patch.patch_text) else []))
                key_to_newkey[key] = key
            
            elif patch.old_signature:
                if (patch.old_signature, patch.file_path_old) in handle_func_signature_change:
                    continue
                # Delete all other patches that have the same signature
                removed_old_signatures.add(patch.old_signature)
                removed_new_signatures.add(patch.new_signature)
                                
                handle_func_signature_change.add((patch.old_signature, patch.file_path_old))
                # Need a Artificial patch, to create the old function

                func_code, func_length, start_line = get_function_code_from_old_commit(target_repo_path, commit, data_path, patch.file_path_old, patch.old_signature)
                func_code = '\n'.join([f'-{line}' for line in func_code.splitlines()]) + '\n'  # Add a \n at the end to avoid patch fail
                func_loc = FunctionLocation(file_path=patch.file_path_old, start_line=start_line, end_line=start_line + func_length - 1)

                artificial_patch_insert_point = get_patch_insert_line_number(target_repo_path, next_commit, data_path, patch.file_path_new, patch.new_signature)

                def create_artificial_patch_data(patch, fname, artificial_patch_insert_point, func_length, func_code, func_loc):
                    """Create the Artificial patch data structure"""
                    patch_header = f'diff --git a/{patch.file_path_new} b/{patch.file_path_new}\n--- a/{patch.file_path_new}\n+++ b/{patch.file_path_new}\n'
                    patch_header += f'@@ -{artificial_patch_insert_point},{func_length} +{artificial_patch_insert_point},0 @@\n'
                    artificial_patch = PatchInfo(
                        file_path_old=patch.file_path_old,
                        file_path_new=patch.file_path_new,
                        file_type=patch.file_type,
                        patch_text='\n'.join(rename_func(patch_header + func_code, fname, commit)),
                        old_signature=patch.old_signature, # __revert_commit_{fname} is not added here
                        patch_type={'Function removed', 'Function body change', 'Recreated function'},
                        dependent_func=set(),
                        new_start_line=artificial_patch_insert_point,
                        new_end_line=artificial_patch_insert_point,
                        old_start_line=artificial_patch_insert_point,
                        old_end_line=artificial_patch_insert_point + func_length,
                        old_function_start_line=artificial_patch_insert_point,
                        old_function_end_line=artificial_patch_insert_point + func_length,
                        recreated_function_locations={patch.old_signature: func_loc},
                    )
                    new_key = stable_hash(artificial_patch.patch_text)
                    return artificial_patch, new_key
                artificial_patch, new_key = create_artificial_patch_data(patch, fname, artificial_patch_insert_point, func_length, func_code, func_loc)
                recreated_functions.add(FunctionInfo(name=fname, signature=artificial_patch.old_signature, file_path_old=artificial_patch.file_path_old, func_used_file=patch.file_path_new, keywords=['static'] if is_function_static(func_code) else []))
                diff_results[new_key] = artificial_patch
                function_declarations.add(patch.old_signature.replace(fname, f'__revert_{commit}_{fname}'))
                new_patch_to_apply.append(new_key)
                reserved_keys.add(new_key)
                key_to_newkey[key] = new_key
                
        else:
            logger.info(f"Skipping non-function body change for {key}")
            
    # Rename the function by dependency graph, find the caller of the recreated function
    for key in key_to_newkey:
        patch = diff_results[key]
        artificial_patch = diff_results[key_to_newkey[key]]
        fname = patch.old_function_name
        for caller_key in dependence_graph.get(key, []):
            # rename functions in patches that depend on (call) this function
            caller_key = key_to_newkey.get(caller_key, caller_key)
            if caller_key not in diff_results:
                # for minimal patch
                continue
            if 'Static Function' in artificial_patch.patch_type and artificial_patch.file_path_old != diff_results[caller_key].file_path_old:
                # If recreate function is static, it is only seen to that file
                continue
            modified_lines = rename_func(diff_results[caller_key].patch_text, fname, commit)
            diff_results[caller_key].patch_text = '\n'.join(modified_lines)
    
    # Remove patches that are not needed anymore
    for key in new_patch_to_apply:
        if key in reserved_keys:
            continue
        patch = diff_results[key]
        if patch.old_signature and patch.old_signature in removed_old_signatures:
            new_patch_to_apply.remove(key)
            continue
        if patch.new_signature and patch.new_signature in removed_new_signatures:
            new_patch_to_apply.remove(key)
    return new_patch_to_apply, function_declarations, recreated_functions


def normalize_signature(signature):
    """
    Parse and normalize a C-style function signature.
    Returns a tuple: (return_type, function_name, list of param types)
    """
    # Skip error messages from AST analysis
    if not signature or 'error generated' in signature:
        raise ValueError(f"Invalid function signature: {signature}")
    
    # Remove extra spaces
    signature = re.sub(r'\s+', ' ', signature.strip())

    # Match return type, function name, and argument list
    match = re.match(r'(.+?)\s+(\w+)\s*\((.*?)\)', signature)
    if not match:
        raise ValueError(f"Invalid function signature: {signature}")

    ret_type, func_name, args = match.groups()
    ret_type = ret_type.strip()
    func_name = func_name.strip()

    # Normalize arguments: keep only types, ignore parameter names
    arg_types = []
    args = args.strip()
    if args and args != 'void':
        for arg in args.split(','):
            # Remove default values and extract type
            parts = arg.strip().split()
            if len(parts) >= 1:
                # Keep all parts except the last (parameter name)
                arg_type = ' '.join(parts[:-1]) if len(parts) > 1 else parts[0]
                arg_types.append(arg_type.strip())

    return ret_type, func_name, tuple(arg_types)


def compare_function_signatures(sig1, sig2, ignore_arg_types=False):
    """Returns True if two C function signatures are the same (ignoring parameter names)."""
    s1 = normalize_signature(sig1)
    s2 = normalize_signature(sig2)
    if ignore_arg_types:
        ret_type1, func_name1, args_types1 = s1
        ret_type2, func_name2, args_types2 = s2
        ret = (ret_type1 == ret_type2 and func_name1 == func_name2 and
               len(args_types1) == len(args_types2))
        return ret
    else:    
        return s1 == s2


def build_dependency_graph(diff_results, patch_to_apply, target_repo_path, old_commit, trace1):
    # Starts with patch_to_apply are patches of common part of trace1 and trace2.
    # Find callees of patch_to_apply functions, if they are in trace1 add an edge from
    # the callee definition patch to this patch(caller). Specifically, do this for the 
    # patches remove the function definition or change the function definition.
    os.chdir(target_repo_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", '-f', old_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dependence_graph = dict()
    patch_list = list(patch_to_apply)
    new_patch_to_patch = []
    visited_patches = set()
    trace_function_names = set()
    for index, func in trace1:
        trace_function_names.add(func.split(' ')[0].split('(')[0])
    while patch_list:
        key = patch_list.pop()
        if key in visited_patches:
            # skip if this patch has been visited
            continue
        visited_patches.add(key)
        new_patch_to_patch.append(key)
        logger.debug(
            f"Analyzing patch {key}\n{diff_results[key].patch_text}"
        )
        patch = diff_results[key]
        if 'Function body change' in patch.patch_type and patch.file_path_old:
            # Use short commit hash (6 chars) for directory name to match fuzz_helper.py
            short_old_commit = old_commit[:8] if len(old_commit) > 8 else old_commit
            parsing_path = os.path.join(data_path, f"{target_repo_path.split('/')[-1]}-{short_old_commit}", f'{patch.file_path_old}_analysis.json')
            with open(parsing_path, 'r') as f:
                ast_nodes = json.load(f)
            # filter for call expressions (clang cursors for function calls)
            call_kinds = {'CALL_EXPR', 'CXX_METHOD_CALL_EXPR'}
            def_kinds = {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}
            decl_kinds = {'FUNCTION_DECL'}
            for node in ast_nodes:
                if node.get('kind') not in call_kinds:
                    continue
                if not patch.old_function_start_line or not patch.old_function_end_line:
                    # this patch is not related to a function in old version
                    continue
                # check if the call is within the patch range
                if node['extent']['end']['line'] <= patch.old_function_end_line and node['extent']['start']['line'] >= patch.old_function_start_line:
                    if 'callee' not in node:
                        # indirect call, can get the callee. skip now
                        continue
                    if 'signature' not in node['callee']:
                        # function like zalloc
                        continue
                    if node['spelling'] not in trace_function_names:
                        # if the function is not in the trace, skip it
                        continue
                    logger.debug(f'Found call expression in patch {key}: {node["callee"]}')
                    # find the definition of this function in the diff results
                    for key1, diff_result in diff_results.items():
                        if diff_result.old_signature and compare_function_signatures(node['callee']['signature'], diff_result.old_signature):
                            patch_list.append(key1)
                            dependence_graph.setdefault(key1, set()).add(key)
                            
    return dependence_graph, new_patch_to_patch


def remove_context(patches: Dict[str, PatchInfo]) -> Dict[str, PatchInfo]:
    """
    Remove context lines from every hunk while keeping the original structure
    intact by splitting each hunk into the minimal set of context-free hunks.
    The returned patches only contain +/- lines and updated headers that point
    precisely to the affected ranges so that they can be reapplied without
    relying on extra context.
    """
    header_pattern = re.compile(
        r'@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? '
        r'\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?P<suffix>.*)'
    )

    def _flush_block(block_lines: List[str], block_old_start: int, block_new_start: int,
                     block_old_count: int, block_new_count: int, suffix: str,
                     output: List[str],
                     span_tracker: Dict[str, Tuple[Optional[int], Optional[int]]]):
        if not block_lines:
            return
        header = (
            f'@@ -{block_old_start},{block_old_count} '
            f'+{block_new_start},{block_new_count} @@{suffix}'
        )
        output.append(header)
        output.extend(block_lines)
        old_start, old_end = span_tracker['old']
        new_start, new_end = span_tracker['new']
        block_old_end = block_old_start + block_old_count
        block_new_end = block_new_start + block_new_count
        span_tracker['old'] = (
            block_old_start if old_start is None else min(old_start, block_old_start),
            block_old_end if old_end is None else max(old_end, block_old_end),
        )
        span_tracker['new'] = (
            block_new_start if new_start is None else min(new_start, block_new_start),
            block_new_end if new_end is None else max(new_end, block_new_end),
        )

    stripped_patches: Dict[str, PatchInfo] = {}
    for key, patch in patches.items():
        patch_copy = copy.deepcopy(patch)
        lines = patch_copy.patch_text.split('\n')
        output_lines: List[str] = []
        span_tracker = {
            'old': (None, None),
            'new': (None, None),
        }
        i = 0
        while i < len(lines):
            line = lines[i]
            if not line.startswith('@@'):
                output_lines.append(line)
                i += 1
                continue

            match = header_pattern.match(line)
            if not match:
                output_lines.append(line)
                i += 1
                continue

            suffix = match.group('suffix') or ''
            old_start = int(match.group('old_start'))
            new_start = int(match.group('new_start'))

            body_lines: List[str] = []
            i += 1
            hunk_terminators = ('@@', 'diff --', 'Index: ', 'index ', '+++ ', '--- ')
            while i < len(lines):
                next_line = lines[i]
                if any(next_line.startswith(prefix) for prefix in hunk_terminators):
                    break
                body_lines.append(next_line)
                i += 1

            while body_lines and body_lines[0] == '':
                body_lines.pop(0)
            while body_lines and body_lines[-1] == '':
                body_lines.pop()

            def _is_context_line(hunk_line: str) -> bool:
                """Context lines in unified diffs start with a single space."""
                return hunk_line.startswith(' ')

            # Remove all leading context lines.
            while body_lines and _is_context_line(body_lines[0]):
                body_lines.pop(0)
                old_start += 1
                new_start += 1

            # Remove all trailing context lines.
            while body_lines and _is_context_line(body_lines[-1]):
                body_lines.pop()

            if not body_lines:
                continue

            old_count = 0
            new_count = 0
            for body_line in body_lines:
                if body_line.startswith('-'):
                    old_count += 1
                elif body_line.startswith('+'):
                    new_count += 1
                elif body_line.startswith('\\'):
                    # Metadata line; does not affect line counters.
                    continue
                else:
                    # Context line affects both old and new positions.
                    old_count += 1
                    new_count += 1

            _flush_block(
                body_lines,
                old_start,
                new_start,
                old_count,
                new_count,
                suffix,
                output_lines,
                span_tracker,
            )

        patch_copy.patch_text = '\n'.join(output_lines)
        old_span_start, old_span_end = span_tracker['old']
        new_span_start, new_span_end = span_tracker['new']
        if old_span_start is not None:
            patch_copy.old_start_line = old_span_start
        if old_span_end is not None:
            patch_copy.old_end_line = old_span_end
        if new_span_start is not None:
            patch_copy.new_start_line = new_span_start
        if new_span_end is not None:
            patch_copy.new_end_line = new_span_end
        stripped_patches[key] = patch_copy

    return stripped_patches


def add_context(diff_results, final_patches, new_commit, target_repo_path):
    patch_prev_key = None
    removed_patches = set()
    
    os.chdir(target_repo_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", '-f', new_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # 1. Merge the patches that have overlap, note that the overlap here is just the simple ones
    prev_new_start_line = dict()
    prev_new_end_line = dict()
    patch_prev_key = dict()
    for key in reversed(final_patches):
        patch = diff_results[key]
        patch_text = patch.patch_text
        lines = patch_text.splitlines()
        if len(lines) < 5:
            logger.error(f'patch_text is too short, skip: {patch_text}')
            continue
        if lines[4] and lines[4][0] in {'-', '+'}: # meaning this patch has no context
            if patch.file_path_new in patch_prev_key and patch.new_start_line <= prev_new_end_line[patch.file_path_new]+3:
                # merge the patches that have overlap
                patch_prev = diff_results[patch_prev_key[patch.file_path_new]]
                patch_prev_lines = patch_prev.patch_text.splitlines()
                if len(patch_prev_lines) < 5:
                    logger.error(f'patch_prev_text is too short, skip merge: {patch_prev.patch_text}')
                    prev_new_start_line[diff_results[key].file_path_new] = diff_results[key].new_start_line
                    prev_new_end_line[diff_results[key].file_path_new] = diff_results[key].new_end_line
                    patch_prev_key[diff_results[key].file_path_new] = key
                    continue
                connect_lines_end = int(lines[3].split('@@')[-2].strip().split('+')[1].split(',')[0])
                # In most cases, patch_prev.new_end_line is the actually line number+1, except patch_prev.new_end_line = patch_prev.new_start_line
                connect_lines_begin = int(patch_prev_lines[3].split('@@')[-2].strip().split('+')[1].split(',')[0]) + int(patch_prev_lines[3].split('@@')[-2].strip().split(',')[-1])
                if connect_lines_begin < connect_lines_end:
                    with open(os.path.join(target_repo_path, patch.file_path_new), 'r', encoding="latin-1") as f:
                        connect_lines = [f' {line[:-1]}' for line in f.readlines()[connect_lines_begin-1:connect_lines_end-1]]
                else:
                    connect_lines = []
                merged_lines = patch_prev_lines[4:] + connect_lines + lines[4:]
                # Keep unified-diff body lines well-formed (no raw empty lines).
                merged_lines = [line for line in merged_lines if line != ""]
                
                patch_prev_old_start = int(patch_prev_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[0].split('-')[-1])
                patch_prev_old_offset = int(patch_prev_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
                if not any(line[0] != '+' for line in patch_prev.patch_text.split('\n')[4:]):
                    patch_prev_new_start = int(patch_prev_lines[3].split('@@')[-2].strip().split('+')[1].split(',')[0])
                else:
                    patch_prev_new_start = int(patch_prev_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[0].split('-')[-1])
                patch_prev_new_start = int(patch_prev_lines[3].split('@@')[-2].strip().split('+')[1].split(',')[0])
                patch_prev_new_offset = int(patch_prev_lines[3].split('@@')[-2].strip().split(',')[-1])
                
                prev_front_context_len = 0
                for line in patch_prev_lines[4:]:
                    if line.startswith('+') or line.startswith('-'):
                        break
                    prev_front_context_len += 1
                
                patch_old_offset = int(lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
                patch_new_offset = int(lines[3].split('@@')[-2].strip().split(',')[-1])
                patch_prev.patch_type = {'Merged functions'}.union(patch.patch_type).union(patch_prev.patch_type)
                if not patch.hiden_func_dict:
                    patch_front_context_len = 0
                    for line in lines[4:]:
                        if line.startswith('+') or line.startswith('-'):
                            break
                        patch_front_context_len += 1
                    patch.hiden_func_dict.setdefault(patch.old_signature, patch_front_context_len)
                patch_prev.hiden_func_dict.update({key: offset+ len(patch_prev_lines[4:]) for key, offset in patch.hiden_func_dict.items()})
                patch_prev.hiden_func_dict[patch_prev.old_signature] = prev_front_context_len
                patch_prev.hiden_func_dict = dict(
                    sorted(patch_prev.hiden_func_dict.items(), key=lambda x: x[1])  # ascending by offset
                )
                patch_prev.patch_text = '\n'.join(lines[:3] + [f'@@ -{patch_prev_old_start},{patch_old_offset+patch_prev_old_offset+max(0, connect_lines_end-connect_lines_begin)} +{patch_prev_new_start},{patch_prev_new_offset+patch_new_offset+max(0, connect_lines_end-connect_lines_begin)} @@'] + merged_lines)
                patch_prev.new_start_line = patch_prev_new_start
                patch_prev.new_end_line = patch_prev_new_start + patch_prev_new_offset + patch_new_offset + max(0, connect_lines_end-connect_lines_begin)
                patch_prev.old_start_line = patch_prev_old_start
                patch_prev.old_end_line = patch_prev_old_start + patch_old_offset + patch_prev_old_offset + max(0, connect_lines_end-connect_lines_begin)
                patch_prev.recreated_function_locations.update(patch.recreated_function_locations)
                # Use the merged patch, remove the previous patch
                diff_results[key] = patch_prev
                removed_patches.add(patch_prev_key[patch.file_path_new])
        prev_new_start_line[diff_results[key].file_path_new] = diff_results[key].new_start_line
        prev_new_end_line[diff_results[key].file_path_new] = diff_results[key].new_end_line
        patch_prev_key[diff_results[key].file_path_new] = key

    for key in removed_patches:
        final_patches.remove(key)
        
    # 2. Add context lines to the patches
    for key in final_patches:
        patch = diff_results[key]
        patch_text = patch.patch_text
        lines = patch_text.splitlines()
        if len(lines) < 5:
            logger.error(f'patch_text is too short in context pass, skip: {patch_text}')
            continue
        if not patch.file_path_new or patch.file_path_new == '/dev/null':
            # a patch delete a file, skip now
            continue
        context_lines1 = []
        context_lines2 = []
        file_path = os.path.join(target_repo_path, patch.file_path_new)
        with open(file_path, 'r', encoding="latin-1") as f:
            content = [line.rstrip('\n') for line in f.readlines()]
        
        old_line_begin_nocontext = int(lines[3].split('@@')[-2].strip().split('-')[1].split(',')[0])
        old_offset_nocontext = int(lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
        new_line_begin_nocontext = int(lines[3].split('@@')[-2].strip().split('+')[1].split(',')[0])
        new_offset_nocontext = int(lines[3].split('@@')[-2].strip().split(',')[-1])
        new_line_begin = new_line_begin_nocontext
        new_offset = new_offset_nocontext
        old_line_begin = old_line_begin_nocontext
        old_offset = old_offset_nocontext

        if lines[4] and lines[4][0] in {'-', '+'}:
            # No context lines before the patch: add context_lines1.
            new_line_begin = max(new_line_begin_nocontext - 3, 1)
            new_offset = new_offset_nocontext + (new_line_begin_nocontext - new_line_begin)
            old_line_begin = max(old_line_begin_nocontext - 3, 1)
            old_offset = old_offset_nocontext + new_offset - new_offset_nocontext
            context_lines1 = [f' {line}' for line in content[new_line_begin-1: new_line_begin_nocontext-1]]
            # Used for context_lines2
            new_line_begin_nocontext = new_line_begin
            new_offset_nocontext = new_offset
            old_line_begin_nocontext = old_line_begin
            old_offset_nocontext = old_offset
            
        if lines[-1] and (lines[-1][0] in {'-', '+'} or lines[-2][0] in {'-', '+'} or lines[-3][0] in {'-', '+'}):
            # No context lines or context less than 3 lines after the patch: add context_lines2.
            new_line_begin = new_line_begin_nocontext
            new_offset = new_offset_nocontext + max(0, min(3, len(content) - new_line_begin_nocontext - new_offset_nocontext + 1))
            old_line_begin = old_line_begin_nocontext
            old_offset = old_offset_nocontext + new_offset - new_offset_nocontext
            if new_offset == new_offset_nocontext:
                context_lines2 = []
            else:
                context_lines2 = [f' {line}' for line in content[new_line_begin_nocontext+new_offset_nocontext-1: new_line_begin + new_offset-1]]

        lines = lines[:3] + [f'@@ -{old_line_begin},{old_offset} +{new_line_begin},{new_offset} @@']\
            + context_lines1 + lines[4:] + context_lines2
        for func_sig in patch.hiden_func_dict:
            patch.hiden_func_dict[func_sig] += len(context_lines1)
        patch.patch_text = '\n'.join(lines)
        patch.old_start_line = old_line_begin
        patch.old_end_line = old_line_begin + old_offset
        patch.new_start_line = new_line_begin
        patch.new_end_line = new_line_begin + new_offset


def handle_file_change(diff_results, patch_to_apply):
    for key in diff_results:
        patch = diff_results[key]
        # Delete and add file
        if patch.file_path_new == '/dev/null':
            lines = patch.patch_text.split('\n')
            lines.insert(2, 'deleted file mode 100644')
            patch.patch_text = '\n'.join(lines)
        if patch.file_path_old == '/dev/null':
            lines = patch.patch_text.split('\n')
            lines.insert(1, 'new file mode 100644')
            patch.patch_text = '\n'.join(lines)


def add_patch_for_trace_funcs(diff_results, final_patches, trace1, recreated_functions, target_repo_path, commit, next_commit, target):
    # For function do not change but appear in trace, add a patch if they should call recreated functions
    # Assume target_repo in new commit
    new_patch_to_apply = set()
    trace_set = set() # avoid duplicate functions in loop
    recreated_names = {func.name for func in recreated_functions}
    for index, func in trace1:
        fname = func.split(' ')[0].split('(')[0]
        if fname in recreated_names:
            continue
        location = func.split(' ')[-1]
        file_path = location.split(':')[0][1:]  # remove leading /
        file_path = os.path.normpath(file_path)  # normalize paths like tests/../stb_image.h to stb_image.h
        trace_set.add((fname, file_path))
    for fname, file_path in trace_set:
        old_line_begin = None
        old_line_end = None
        flag = False # flag to indicate if the function is changed between commit and next_commit
        for key in final_patches:
            if diff_results[key].old_signature and fname == diff_results[key].old_function_name and file_path == diff_results[key].file_path_old:
                flag = True
                break
        if flag:
            continue
        # Use short commit hash (6 chars) for directory name to match fuzz_helper.py
        short_next_commit = next_commit[:8] if len(next_commit) > 8 else next_commit
        parsing_path = os.path.join(data_path, f'{target}-{short_next_commit}', f'{file_path}_analysis.json')
        if os.path.exists(parsing_path):
            with open(parsing_path, 'r') as f:
                ast_nodes = json.load(f)
            for node in ast_nodes:
                if node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
                    continue
                if node['extent']['start']['file'] == file_path and (node['signature'].split('(')[0].split(' ')[-1] == fname or node['spelling'] == fname):
                    # Found the function definition
                    old_line_begin = node['extent']['start']['line']
                    old_line_end = node['extent']['end']['line']
                    break
        if old_line_begin and old_line_end:
            # Create a patch to add the function call
            patch_header = f"diff --git a/{file_path} b/{file_path}\n"
            patch_header += f"--- a/{file_path}\n+++ b/{file_path}\n"
            os.chdir(target_repo_path)
            subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["git", "checkout", '-f', next_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            source_file = os.path.join(target_repo_path, file_path)
            if not os.path.exists(source_file) and file_path.endswith('.h'):
                # Try .h.in template (e.g. CMake configure_file generates .h from .h.in)
                source_file_in = source_file + '.in'
                if os.path.exists(source_file_in):
                    logger.debug(f"Using template {source_file_in} instead of missing {source_file}")
                    source_file = source_file_in
            if not os.path.exists(source_file):
                logger.debug(f"Source file {source_file} not found at commit {next_commit}, skipping trace function {fname}")
                continue
            with open(source_file, 'r', encoding="latin-1") as f:
                content = f.readlines()
                function_lines = content[old_line_begin-1:old_line_end]
            # Build list of recreated functions visible to this file
            visible_recreated = [fi for fi in recreated_functions
                                 if not (fi.is_static() and fi.file_path_old != file_path)]
            # Track absolute line numbers already covered by a call-site patch
            # to avoid creating overlapping patches when multiple recreated
            # functions appear in the same multi-line call.
            covered_lines = set()
            for func_info in visible_recreated:
                recreated_fname = func_info.name
                function_head_flag = False
                for i, line in enumerate(function_lines):
                    if '{' in line:
                        function_head_flag = True
                    if not function_head_flag:
                        # Skip the function head
                        continue
                    abs_line = old_line_begin + i
                    if abs_line in covered_lines:
                        continue
                    if re.search(r'(?<![\w.])' + re.escape(recreated_fname) + r'(?!\w)', line) is not None:
                        # If the function is recreated, add a call to it.
                        # Detect multi-line calls by counting parentheses.
                        call_lines = [line]
                        paren_depth = line.count('(') - line.count(')')
                        j = i + 1
                        while paren_depth > 0 and j < len(function_lines):
                            call_lines.append(function_lines[j])
                            paren_depth += function_lines[j].count('(') - function_lines[j].count(')')
                            j += 1
                        num_call_lines = len(call_lines)
                        start_line = old_line_begin + i
                        end_line = start_line + num_call_lines

                        # Check if any line in the collected call range
                        # is already covered by a previous call-site patch.
                        new_range = set(range(start_line, end_line))
                        overlap = new_range & covered_lines
                        if overlap:
                            if not (new_range - covered_lines):
                                # New patch is entirely within already-covered
                                # lines (a smaller/equal duplicate); skip it.
                                continue
                            # The new patch covers uncovered lines too, so it
                            # is a broader multi-line call that subsumes the
                            # previous smaller patch(es).  Remove the old
                            # overlapping patches and fall through to create
                            # the replacement.
                            keys_to_remove = []
                            for key in list(new_patch_to_apply):
                                p = diff_results[key]
                                if p.file_path_old == file_path:
                                    old_range = set(range(p.old_start_line, p.old_end_line))
                                    if old_range & new_range:
                                        keys_to_remove.append(key)
                                        covered_lines -= old_range
                            for key in keys_to_remove:
                                new_patch_to_apply.discard(key)
                                del diff_results[key]

                        # Mark these lines as covered
                        for l in range(start_line, end_line):
                            covered_lines.add(l)

                        # Build -/+ pairs for all lines of the call,
                        # renaming ALL visible recreated functions (not just
                        # the triggering one) to avoid overlapping patches.
                        minus_lines = []
                        plus_lines = []
                        for cl in call_lines:
                            ml = '-' + cl.rstrip('\n')
                            for rf in visible_recreated:
                                if re.search(r'(?<![\w.])' + re.escape(rf.name) + r'(?!\w)', cl):
                                    ml = rename_func(ml, rf.name, commit)[0]
                            minus_lines.append(ml)
                            plus_lines.append('+' + cl.rstrip('\n'))
                        patch_body = '\n'.join(minus_lines + plus_lines)
                        patch_text = patch_header + f"@@ -{start_line},{num_call_lines} +{start_line},{num_call_lines} @@\n" + patch_body

                        patch = PatchInfo(
                            file_path_old=file_path,
                            file_path_new=file_path,
                            file_type='c',
                            patch_text=patch_text,
                            old_signature=f'no change trace function {recreated_fname}',
                            new_signature=f'no change trace function {recreated_fname}',
                            patch_type={'Function body change'},
                            dependent_func=set(),
                            new_start_line=start_line,
                            new_end_line=end_line,
                            old_start_line=start_line,
                            old_end_line=end_line,
                            new_function_start_line=old_line_begin,
                            new_function_end_line=old_line_end,
                        )
                        new_key = f'{file_path}{file_path}-{start_line},{num_call_lines}+{start_line},{num_call_lines}'

                        diff_results[new_key] = patch
                        new_patch_to_apply.add(new_key)

    final_patches.extend(list(new_patch_to_apply))


def find_analysis_file(data_path: str, target_commit_dir: str, fuzzer_file_path: str) -> Tuple[str, str]:
    """
    Find the analysis JSON file for a fuzzer, trying different extensions and paths.
    
    The trace may report a different path/extension than the actual analysis file due to:
    - File extension changes (.cc vs .cpp)
    - Path changes (src/ vs ossfuzz/ vs root)
    
    Args:
        data_path: Base data directory path
        target_commit_dir: Directory name for target commit (e.g., 'matio-44c26a')
        fuzzer_file_path: File path from trace (e.g., 'src/matio_fuzzer.cc')
        
    Returns:
        Tuple of (analysis_file_path, actual_source_path) where actual_source_path
        is the correct path to use for patch generation (from the analysis file content)
        
    Raises:
        FileNotFoundError: If no matching analysis file is found
    """
    base_dir = os.path.join(data_path, target_commit_dir)
    
    # Try the exact path first
    exact_path = os.path.join(base_dir, f'{fuzzer_file_path}_analysis.json')
    if os.path.exists(exact_path):
        actual_path = _get_actual_source_path_from_analysis(exact_path, fuzzer_file_path)
        if actual_path:
            return exact_path, actual_path
    
    # Parse the fuzzer file path
    dir_name = os.path.dirname(fuzzer_file_path)  # e.g., 'src' or ''
    file_name = os.path.basename(fuzzer_file_path)  # e.g., 'matio_fuzzer.cc'
    
    # Try different extensions
    name_without_ext = file_name
    for ext in ['.cc', '.cpp', '.c', '.cxx']:
        if file_name.endswith(ext):
            name_without_ext = file_name[:-len(ext)]
            break
    
    # List of alternative paths to try
    alternatives = []
    
    # Same directory, different extensions
    for ext in ['.cc', '.cpp', '.c', '.cxx']:
        alternatives.append(os.path.join(dir_name, f'{name_without_ext}{ext}'))
    
    # Different directories: try without 'src/', with 'ossfuzz/', or root
    if dir_name == 'src':
        for ext in ['.cc', '.cpp', '.c', '.cxx']:
            alternatives.append(f'ossfuzz/{name_without_ext}{ext}')
            alternatives.append(f'{name_without_ext}{ext}')  # root
    elif dir_name == '':
        for ext in ['.cc', '.cpp', '.c', '.cxx']:
            alternatives.append(f'ossfuzz/{name_without_ext}{ext}')
            alternatives.append(f'src/{name_without_ext}{ext}')
    elif dir_name == 'ossfuzz':
        for ext in ['.cc', '.cpp', '.c', '.cxx']:
            alternatives.append(f'{name_without_ext}{ext}')  # root
            alternatives.append(f'src/{name_without_ext}{ext}')

    # Handle src/<project-name>/... paths (e.g., src/php-src/sapi/fuzzer/file.c)
    # In Docker, source is at /src/<project>/, but analysis files use project-relative paths
    parts = fuzzer_file_path.split('/')
    if len(parts) >= 3 and parts[0] == 'src':
        # Strip src/<project>/ prefix to get project-relative path
        stripped_path = '/'.join(parts[2:])
        stripped_dir = os.path.dirname(stripped_path)
        stripped_name = os.path.basename(stripped_path)
        stripped_name_without_ext = stripped_name
        for ext in ['.cc', '.cpp', '.c', '.cxx']:
            if stripped_name.endswith(ext):
                stripped_name_without_ext = stripped_name[:-len(ext)]
                break
        for ext in ['.cc', '.cpp', '.c', '.cxx']:
            if stripped_dir:
                alternatives.append(os.path.join(stripped_dir, f'{stripped_name_without_ext}{ext}'))
            else:
                alternatives.append(f'{stripped_name_without_ext}{ext}')
    
    # Try all alternatives and find one that has LLVMFuzzerTestOneInput definition
    for alt_path in alternatives:
        full_path = os.path.join(base_dir, f'{alt_path}_analysis.json')
        if os.path.exists(full_path):
            actual_path = _get_actual_source_path_from_analysis(full_path, fuzzer_file_path)
            if actual_path:  # Only return if we found the function definition
                return full_path, actual_path
    
    # If nothing found with function definition, fall back to first existing file
    for alt_path in alternatives:
        full_path = os.path.join(base_dir, f'{alt_path}_analysis.json')
        if os.path.exists(full_path):
            return full_path, fuzzer_file_path
    
    # If nothing found, return the original path (which will fail with FileNotFoundError)
    return exact_path, fuzzer_file_path


def _get_actual_source_path_from_analysis(analysis_path: str, default_path: str = None) -> Optional[str]:
    """
    Extract the actual source file path from the analysis file.
    
    The analysis file contains AST nodes with file paths that reflect the actual
    source structure. We use this to get the correct path for patch generation.
    
    Args:
        analysis_path: Path to the analysis JSON file
        default_path: Fallback path if extraction fails
        
    Returns:
        The actual source file path to use for patches, or None if
        LLVMFuzzerTestOneInput function definition is not found in this file
    """
    try:
        with open(analysis_path, 'r') as f:
            ast_nodes = json.load(f)
        
        # Look for LLVMFuzzerTestOneInput function to get the correct file path
        for node in ast_nodes:
            if node.get('kind') in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
                if node.get('spelling') == 'LLVMFuzzerTestOneInput':
                    # Get the file path from the extent or location
                    extent = node.get('extent', {})
                    location_file = extent.get('start', {}).get('file') if extent else None
                    if not location_file:
                        location_file = node.get('location', {}).get('file')
                    
                    if location_file and location_file != 'None':
                        # Normalize the path (remove any absolute prefix)
                        if location_file.startswith('/src/'):
                            return location_file[5:]  # Remove /src/ prefix
                        elif location_file.startswith('/'):
                            # Try to find the relative path
                            parts = location_file.split('/')
                            if 'src' in parts:
                                src_idx = parts.index('src')
                                return '/'.join(parts[src_idx + 1:])
                            else:
                                return '/'.join(parts[1:])  # Remove leading empty part
                        else:
                            return location_file
        
        # LLVMFuzzerTestOneInput not found in this file - return None to indicate
        # caller should try another file
        return None
                
    except Exception as e:
        return None


def llvm_fuzzer_test_one_input_patch_update(diff_results, patch_to_apply, recreated_functions, target_repo_path, commit, next_commit, target, trace1):
    """
    Updates patches within LLVMFuzzerTestOneInput function to handle function call replacements when reverting patches.
    
    This function ensures that function calls within the fuzzer are properly mapped from their __revert_commit prefixed 
    versions back to their original names when patches are being reverted. It handles both existing patches that 
    need updating and creates new patches for function calls that aren't covered by existing patches.
    
    Args:
        diff_results: Dictionary containing all patch information
        patch_to_apply: List of patch keys to be applied
        recreated_functions: List of function signatures that have been recreated with __revert_commit prefix
        target_repo_path: Path to the target repository
        commit: Current commit hash
        next_commit: Next commit hash
        target: Target project name
    """
    # Assume target_repo in new commit
    fuzzer_keys = set()
    
    # Step 0: Get harness file path
    for _, trace in trace1:
        if 'LLVMFuzzerTestOneInput' in trace:
            location = trace.split(' ')[1]
            fuzzer_file_path = location.split(':')[0][1:]  # remove leading /
            fuzzer_file_path = os.path.normpath(fuzzer_file_path)  # normalize paths like tests/../file.h
            break
    
    # Step 1: Identify all patches that affect LLVMFuzzerTestOneInput function
    for key in patch_to_apply:
        patch = diff_results[key]
        if not (patch.old_signature and patch.new_signature):
            # This patch is not a function body change, skip it
            continue
        if patch.file_path_new != fuzzer_file_path:
            continue
        if ('LLVMFuzzerTestOneInput' in patch.old_signature or 'LLVMFuzzerTestOneInput' in patch.new_signature):
            # This is a patch for LLVMFuzzerTestOneInput, we need to update the function calls
            fuzzer_keys.add(key)

    # Step 2: Load AST analysis and locate LLVMFuzzerTestOneInput function boundaries
    # Use short commit hash (6 chars) for directory name to match fuzz_helper.py
    short_next_commit = next_commit[:8] if len(next_commit) > 8 else next_commit
    parsing_path, actual_fuzzer_path = find_analysis_file(data_path, f'{target}-{short_next_commit}', fuzzer_file_path)
    with open(parsing_path, 'r') as f:
        ast_nodes = json.load(f)
    for node in ast_nodes:
        if node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
            continue
        if node['spelling'] == 'LLVMFuzzerTestOneInput':
            # Found the function definition
            fuzzer_start_line = node['extent']['start']['line']
            fuzzer_end_line = node['extent']['end']['line']
            fuzzer_new_signature = node['signature']
            fuzzer_old_signature = node['signature']
            break
    
    # Use the actual source path from analysis for patch generation
    fuzzer_file_path = actual_fuzzer_path
    
    # Step 3: Process all function calls within LLVMFuzzerTestOneInput that reference recreated functions
    for node in ast_nodes:
        if node.get('kind') not in {'CALL_EXPR', 'CXX_METHOD_CALL_EXPR'}:
            continue
        if 'type_ref' not in node:
            continue
        
        # Check if this call is within the LLVMFuzzerTestOneInput function and references a recreated function
        if node['location']['file'] == fuzzer_file_path and fuzzer_start_line <= node['location']['line'] <= fuzzer_end_line and any(node['spelling'] == func_info.name for func_info in recreated_functions):
            
            # Track whether this call is already covered by an existing patch
            Inpatch_flag = False
            
            # Step 3a: Check if this call is within any existing patch
            for key in fuzzer_keys:
                patch = diff_results[key]
                lines = patch.patch_text.split('\n')
                new_lines = []
                new_start_line = int(lines[3].split('@@')[-2].strip().split('+')[1].split(',')[0])
                new_offset = int(lines[3].split('@@')[-2].strip().split(',')[-1])
                if new_start_line <= node['location']['line'] < new_start_line + new_offset:
                    # This call is within a patch, we need to update the patch.
                    # For multi-line calls, also convert continuation context lines to -/+ pairs.
                    Inpatch_flag = True
                    i = 0
                    while i < len(lines):
                        line = lines[i]
                        if line and line[0] not in {'-', '+', '@', 'd'} and re.search(r'(?<![\w.])' + re.escape(node['spelling']) + r'(?!\w)', line) is not None:
                            # Found the function name on a context line — convert it and continuations
                            rm_line = rename_func(f'-{line[1:]}', node['spelling'], commit)[0]
                            add_line = f'+{line[1:]}'
                            new_lines.append(rm_line)
                            new_lines.append(add_line)
                            # Use paren counting to find how many continuation lines belong
                            # to this call (AST extent may only cover the function name).
                            paren_depth = line.count('(') - line.count(')')
                            k = 1
                            while paren_depth > 0 and i + k < len(lines):
                                next_line = lines[i + k]
                                if not next_line or next_line[0] != ' ':
                                    break
                                new_lines.append(f'-{next_line[1:]}')
                                new_lines.append(f'+{next_line[1:]}')
                                paren_depth += next_line.count('(') - next_line.count(')')
                                k += 1
                            i += k
                        else:
                            new_lines.append(line)
                            i += 1
                    patch.patch_text = '\n'.join(new_lines)
            
            # Step 3b: Create new patch for calls not covered by existing patches
            if not Inpatch_flag:
                # This call is not in any patch, we need to create a new patch
                call_start = node['location']['line']

                # Skip if add_patch_for_trace_funcs already created a patch for this call
                if any(k.startswith(f'{fuzzer_file_path}{fuzzer_file_path}-{call_start},') for k in diff_results):
                    continue

                # Read the call from source and use paren counting to find the full
                # multi-line span (AST extent may only cover the function name).
                with open(os.path.join(target_repo_path, fuzzer_file_path), 'r', encoding="latin-1") as f:
                    content = f.readlines()
                first_line = content[call_start - 1]
                call_lines = [first_line]
                paren_depth = first_line.count('(') - first_line.count(')')
                j = call_start  # 0-based index of next line
                while paren_depth > 0 and j < len(content):
                    call_lines.append(content[j])
                    paren_depth += content[j].count('(') - content[j].count(')')
                    j += 1
                num_lines = len(call_lines)

                # Create -/+ pairs for each line of the call
                minus_lines = []
                plus_lines = []
                for cl in call_lines:
                    minus_lines.append(rename_func(f'-{cl}', node['spelling'], commit)[0])
                    plus_lines.append('+' + cl.rstrip('\n'))
                patch_body = '\n'.join(minus_lines + plus_lines)

                # Construct complete patch text
                patch_text = f'diff --git a/{fuzzer_file_path} b/{fuzzer_file_path}\n--- a/{fuzzer_file_path}\n+++ b/{fuzzer_file_path}\n@@ -{call_start},{num_lines} +{call_start},{num_lines} @@\n{patch_body}'
                # Create new patch entry
                patch = PatchInfo(
                    file_path_old=fuzzer_file_path,
                    file_path_new=fuzzer_file_path,
                    file_type='c',
                    patch_text=patch_text,
                    old_signature=fuzzer_old_signature,
                    new_signature=fuzzer_new_signature,
                    patch_type={'Function body change'},
                    dependent_func=set(),
                    new_start_line=call_start,
                    new_end_line=call_start + num_lines,
                    old_start_line=call_start,
                    old_end_line=call_start + num_lines,
                    old_function_start_line=fuzzer_start_line,
                    old_function_end_line=fuzzer_end_line,
                )

                # Add new patch to diff_results and patch_to_apply list
                new_key = f'{fuzzer_file_path}{fuzzer_file_path}-{call_start},{num_lines}+{call_start},{num_lines}'
                diff_results[new_key] = patch
                patch_to_apply.append(new_key)


def update_function_mappings(recreated_functions, signature_change_list, commit: str):
    # add mapping for recreated functions
    for func_info in recreated_functions:
        signature_change_list.append((func_info.name, f'__revert_{commit}_{func_info.name}'))


def get_full_funsig(patch, target, commit, version:str):
    # version is either 'old' or 'new'
    patch_file_path = getattr(patch, f'file_path_{version}')
    patch_start_line = getattr(patch, f'{version}_start_line')
    patch_end_line = getattr(patch, f'{version}_end_line')
    # Use short commit hash (6 chars) for directory name to match fuzz_helper.py
    short_commit = commit[:8] if len(commit) > 8 else commit
    parsing_path = os.path.join(data_path, f'{target}-{short_commit}', f'{patch_file_path}_analysis.json')
    with open(parsing_path, 'r') as f:
        ast_nodes = json.load(f)
    midpoint = (patch_start_line + patch_end_line) / 2
    # Collect all matching nodes — the AST JSON may have duplicate entries from
    # different preprocessing contexts with overlapping extents.  Pick the
    # tightest (smallest) extent to avoid including code from adjacent functions.
    best = None
    best_span = float('inf')
    for node in ast_nodes:
        if node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
            continue
        if node['extent']['start']['file'] == patch_file_path and node['extent']['start']['line'] <= midpoint <= node['extent']['end']['line']:
            span = node['extent']['end']['line'] - node['extent']['start']['line']
            if span < best_span:
                best = node
                best_span = span
    if best is not None:
        return best['signature'], best['extent']['start']['line'], best['extent']['end']['line']
    return None, 0, 0


def get_file_path_pairs(diff_results):
    file_path_pairs = dict() # key: new file path; value: old file path
    for key, patch in diff_results.items():
        if patch.file_path_old != patch.file_path_new and patch.file_path_new != '/dev/null' and patch.file_path_old != '/dev/null':
            file_path_pairs[patch.file_path_new] = patch.file_path_old
    return file_path_pairs


def build_with_cached_extras(
    patch_keys: List[str],
    diff_results: Dict[str, Any],
    extra_patches_cache: Dict[str, Any],
    target: str,
    next_commit_id: str,
    sanitizer: str,
    bug_id: str,
    fuzzer: str,
    build_csv: str,
    arch: str,
    runner_image: Optional[str] = None,
    commit_date: Optional[int] = None,
) -> Tuple[bool, str]:
    """Build with a subset of patches, including cached extra patches."""
    combined_patches = {}

    for key in patch_keys:
        if key in diff_results:
            combined_patches[key] = diff_results[key]

    combined_patches.update(extra_patches_cache)

    patch_folder = os.path.abspath(os.path.join(current_file_path, '..', 'patch'))
    patch_file_path = os.path.join(patch_folder, f"{bug_id}_{next_commit_id}_min_trial.diff")

    sorted_keys = sorted(
        combined_patches.keys(),
        key=lambda k: getattr(combined_patches[k], 'new_start_line', 0),
        reverse=True
    )

    with open(patch_file_path, 'w') as f:
        for key in sorted_keys:
            patch = combined_patches[key]
            f.write(patch.patch_text)
            f.write('\n\n')

    return build_fuzzer(
        target, next_commit_id, sanitizer, bug_id,
        patch_file_path, fuzzer, build_csv, arch,
        runner_image=runner_image, commit_date=commit_date
    )


def minimize_with_trace_and_cached_extras(
    patch_pair_list: List[Tuple[str, ...]],
    patches_without_context: Dict[str, Any],
    diff_results: Dict[str, Any],
    trace1: List[Tuple[int, str]],
    depen_graph: Dict[str, Set[str]],
    target: str,
    next_commit: Dict,
    sanitizer: str,
    bug_id: str,
    fuzzer: str,
    build_csv: str,
    arch: str,
    runner_image: Optional[str] = None,
    commit_date: Optional[int] = None,
) -> Tuple[List[Tuple[str, ...]], Dict[str, Any]]:
    """Minimize patches using trace-based filtering with cached extra patches."""

    # Phase 0: Extract cached extra patches (already populated by first build)
    extra_patches_cache = extract_extra_patches(patches_without_context)
    logger.info(f"Cached {len(extra_patches_cache)} extra patches")

    # Phase 1: Static trace-based filtering
    all_patch_keys = [key for keys in patch_pair_list for key in keys]
    trace_func_list = [(func.split('(')[0], func.split(' ')[-1]) for _, func in trace1]

    filtered_keys = filter_patches_by_trace(
        all_patch_keys, diff_results, trace_func_list, depen_graph
    )
    logger.info(f"Static filter: {len(all_patch_keys)} -> {len(filtered_keys)} patches")

    filtered_patch_pairs = [
        tuple(k for k in keys if k in filtered_keys)
        for keys in patch_pair_list
    ]
    filtered_patch_pairs = [t for t in filtered_patch_pairs if t]

    if not filtered_patch_pairs:
        logger.warning("Static filter removed all patches, using original")
        return patch_pair_list, extra_patches_cache

    # Phase 2: Single verification build
    filtered_flat = [k for keys in filtered_patch_pairs for k in keys]
    success, _ = build_with_cached_extras(
        filtered_flat, diff_results, extra_patches_cache,
        target, next_commit['commit_id'], sanitizer, bug_id,
        fuzzer, build_csv, arch,
        runner_image=runner_image, commit_date=commit_date
    )

    if success:
        logger.info(f"Minimized from {len(all_patch_keys)} to {len(filtered_flat)}")
        return filtered_patch_pairs, extra_patches_cache

    # Phase 3: Binary search for missing patches
    candidates = [k for k in all_patch_keys if k not in filtered_keys]
    logger.info(f"Binary search: {len(filtered_keys)} base + {len(candidates)} candidates")

    trial_count = [0]  # Use list to allow mutation in closure

    def test_fn(keys: List[str]) -> bool:
        trial_count[0] += 1
        logger.info(f"Trial {trial_count[0]}: testing {len(keys)} patches")
        ok, _ = build_with_cached_extras(
            keys, diff_results, extra_patches_cache,
            target, next_commit['commit_id'], sanitizer, bug_id,
            fuzzer, build_csv, arch,
            runner_image=runner_image, commit_date=commit_date
        )
        return ok

    additional = binary_search_missing_patches(set(filtered_keys), candidates, test_fn)
    logger.info(f"Binary search found {len(additional)} additional patches needed")

    if additional:
        final_keys = set(filtered_keys + additional)
        logger.info(f"Final patch count: {len(final_keys)} ({len(filtered_keys)} filtered + {len(additional)} additional)")
        final_pairs = [tuple(k for k in keys if k in final_keys) for keys in patch_pair_list]
        final_pairs = [t for t in final_pairs if t]
        return final_pairs, extra_patches_cache

    return patch_pair_list, extra_patches_cache


def apply_and_test_patches(
    patch_pair_list,
    func_list, # list of function signatures, use source code from next_commit
    patches_without_context,
    get_patched_traces,
    transitions,
    signature_change_list,
    diff_results,
    trace1,
    target_repo_path,
    commit,
    next_commit,
    target,
    sanitizer,
    bug_id,
    fuzzer,
    args,
    arch,
    file_path_pairs,
    data_path,
    depen_graph,
    v1_repo_path,
    v2_repo_path,
    runner_image=None,
    commit_date=None,
    ):
    if not patch_pair_list:
        logger.error("No patch pairs to apply")
        return
    
    patch_key_list = [key for keys in patch_pair_list for key in keys]
    patch_folder = os.path.abspath(os.path.join(current_file_path, '..', 'patch'))
    if not os.path.exists(patch_folder):
        os.makedirs(patch_folder, exist_ok=True)
    logger.info(f'Patch_pair_list: {patch_pair_list}')
    logger.info(f'Applying and testing {len(patch_pair_list)} {[diff_results[key].old_signature for key in patch_key_list]} ')
    
    patch_to_apply, function_declarations, recreated_functions = patch_patcher(diff_results, patch_key_list, depen_graph, commit['commit_id'], next_commit['commit_id'], target_repo_path)
    update_function_mappings(recreated_functions, signature_change_list, commit['commit_id'])
    patch_file_path = os.path.join(patch_folder, f"{bug_id}_{next_commit['commit_id']}_patches{len(get_patched_traces[bug_id]) if bug_id in get_patched_traces else ''}.diff")
    patch_key_list = list(set(patch_to_apply))
    add_patch_for_trace_funcs(diff_results, patch_key_list, trace1, recreated_functions, target_repo_path, commit['commit_id'], next_commit['commit_id'], target)
    llvm_fuzzer_test_one_input_patch_update(diff_results, patch_key_list, recreated_functions, target_repo_path, commit['commit_id'], next_commit['commit_id'], target, trace1)
    patch_key_list = relocate_header_revert_defs_before_add_context(
        diff_results,
        patch_key_list,
        commit_id=commit['commit_id'],
    )
    # Sort patch_key_list by new_start_line
    patch_key_list = list(set(patch_key_list))
    patch_key_list = sorted(patch_key_list, key=lambda key: diff_results[key].new_start_line, reverse=True)
    add_context(diff_results, patch_key_list, next_commit['commit_id'], target_repo_path)
    handle_file_change(diff_results, patch_key_list)
    with open(patch_file_path, 'w') as patch_file:
        for key in patch_key_list:
            patch = diff_results[key]   
            patches_without_context.update({key: patch})
            patch_file.write(patch.patch_text)
            patch_file.write('\n\n')  # Add separator between patches
    if not os.path.exists(os.path.join(data_path, "tmp_patch")):
        os.makedirs(os.path.join(data_path, "tmp_patch"), exist_ok=True)
    patch_file_binary = os.path.join(data_path, "tmp_patch", f"{target}.patch2")
    # Only save patches for keys in current patch_key_list (avoid stale entries from previous attempts)
    current_patches = {key: patches_without_context[key] for key in patch_key_list}
    save_patches_pickle(current_patches, patch_file_binary)

    # --- Proactive forward declarations for __revert_* functions ---
    # Must run before the first build so that even successful builds
    # include correct prototypes (avoids implicit-declaration pointer truncation).
    _v1_sha = commit['commit_id'][:8] if len(commit['commit_id']) > 8 else commit['commit_id']
    _v2_sha = next_commit['commit_id'][:8] if len(next_commit['commit_id']) > 8 else next_commit['commit_id']
    _v1_json_dir = os.path.join(data_path, f"{target}-{_v1_sha}")
    _v2_json_dir = os.path.join(data_path, f"{target}-{_v2_sha}")
    _v1_src_path, _v2_src_path = "", ""
    try:
        _v1_src_path, _v2_src_path = prepare_v1_v2_repos(
            source_repo_path=target_repo_path,
            v1_repo_base=v1_repo_path,
            v2_repo_base=v2_repo_path,
            target=target,
            v1_commit=commit['commit_id'],
            v2_commit=next_commit['commit_id'],
        )
    except Exception as exc:
        logger.warning(f"Proactive decls: prepare_v1_v2_repos failed ({exc}), skipping")

    round0_result = _run_proactive_revert_declarations(
        patch_path=patch_file_binary,
        v1_json_dir=_v1_json_dir,
        v2_json_dir=_v2_json_dir,
        v1_src=_v1_src_path,
        v2_src=_v2_src_path,
    )
    _r0_updated = round0_result.get("updated_patch_path", "")
    if _r0_updated and os.path.isfile(_r0_updated):
        # Reload updated bundle and regenerate .diff to a separate round0 file
        # so that the original patch_file_path is preserved for debugging.
        _r0_patches = load_patches_pickle(_r0_updated)
        patches_without_context.update(_r0_patches)
        patch_file_binary = _r0_updated  # use updated bundle for subsequent builds
        _r0_diff_path = patch_file_path.replace('.diff', '_round0.diff')
        with open(_r0_diff_path, 'w') as f:
            for key in sorted(
                _r0_patches.keys(),
                key=lambda k: getattr(_r0_patches[k], "new_start_line", 0),
                reverse=True,
            ):
                f.write(_r0_patches[key].patch_text)
                f.write('\n\n')
        patch_file_path = _r0_diff_path
        logger.info(f"Proactive decls: {round0_result.get('declared', 0)} declarations added, "
                     f"regenerated {patch_file_path} (original preserved)")

    #TODO: update the comments
    con_to_add = dict() # key: file path, value: set of enum/macro locations (use key in dict to achieve ordered set)
    func_decl_to_add = dict() # key: file path, value: set of function declarations
    func_decl_to_add_moveforward = dict() # key: file path, value: set of function declarations that need to be added before function use in the extra patch
    extra_patches = dict() # key: file path, value: patch; include patches for enum/macro/function declaration
    var_del_to_add = dict() # key: file path, value: set of variable declarations
    union_to_add = dict() # key: file path, value: set of union declarations
    type_def_to_add = dict() # key: file path, value: set of type definitions
    incomplete_type_to_add = dict() # key: file path, value: set of incomplete types
    func_def_to_add = dict() # key: (file path, function def location), value: insert line number
    last_type_def_to_add = dict()
    recreated_cons = set()
    recreated_var = set()
    error_last_round = ''
    check_patch_using_llm = False
    # build and test if it works, oss-fuzz version has been set in collect_trace_cmd
    error_log = 'undeclared identifier'
    count = 0
    # Store previous handle_build_error results to detect when results stop changing
    prev_build_error_results = None
    while (
        'undeclared identifier' in error_log
        or 'undeclared function' in error_log
        or 'too few arguments to function call' in error_log
        or 'member named' in error_log
        or 'unknown type name' in error_log
        or 'will not be visible' in error_log
    ):
        count += 1
        build_success, error_log = build_fuzzer(target, next_commit['commit_id'], sanitizer, bug_id, patch_file_path, fuzzer, args.build_csv, arch,
                                                runner_image=runner_image, commit_date=commit_date)
        if build_success:
            break

        # NOTE: rename-only hunks with argument-count mismatches are no longer removed.
        # The agent will attempt to fix them using the existing patch override tools.

        # Write build log to temp file for agent
        build_log_temp = os.path.join(data_path, "tmp_patch", f"{target}_build.log")
        with open(build_log_temp, 'w') as f:
            f.write(error_log)

        # Call react multi-agent to fix build errors
        _v1_sha = commit['commit_id'][:8] if len(commit['commit_id']) > 8 else commit['commit_id']
        _v2_sha = next_commit['commit_id'][:8] if len(next_commit['commit_id']) > 8 else next_commit['commit_id']
        v1_json_dir = os.path.join(data_path, f"{target}-{_v1_sha}")
        v2_json_dir = os.path.join(data_path, f"{target}-{_v2_sha}")

        # Prepare separate V1/V2 source trees checked out to correct commits
        v1_src_path, v2_src_path = prepare_v1_v2_repos(
            source_repo_path=target_repo_path,
            v1_repo_base=v1_repo_path,
            v2_repo_base=v2_repo_path,
            target=target,
            v1_commit=commit['commit_id'],
            v2_commit=next_commit['commit_id'],
        )

        agent_result = call_react_agent(
            build_log_path=build_log_temp,
            patch_path=patch_file_binary,
            project=target,
            old_commit=commit['commit_id'],
            new_commit=next_commit['commit_id'],
            build_csv=args.build_csv,
            fuzz_target=fuzzer,
            v1_json_dir=v1_json_dir,
            v2_json_dir=v2_json_dir,
            v1_src=v1_src_path,
            v2_src=v2_src_path,
            sanitizer=sanitizer,
            arch=arch,
            max_steps=max(1, int(getattr(args, "react_agent_max_steps", 200) or 200)),
            max_restarts_per_hunk=max(0, int(getattr(args, "react_agent_max_restarts_per_hunk", 3) or 3)),
            max_multi_agent_rounds=max(1, int(getattr(args, "react_agent_max_multi_agent_rounds", 100) or 100)),
            bug_id=bug_id,
            patch_file_path=patch_file_path,
            runner_image=runner_image or "auto",
            commit_date=commit_date or "",
        )

        # If the agent failed to fix all errors, skip copy and verification build
        if not agent_result.get("success", False):
            logger.info("React multi-agent failed to fix all errors, skipping verification build")
            break

        # Use the merged diff from the agent directly
        merged_diff = agent_result.get("merged_diff_path", "")
        if merged_diff and os.path.isfile(merged_diff):
            shutil.copy(merged_diff, patch_file_path)
            logger.info(f"Copied merged diff from {merged_diff} to {patch_file_path}")
            # Also load the merged patch bundle so patches_without_context includes
            # react agent's _extra_* patches for later minimization
            merged_bundle = agent_result.get("merged_patch_bundle_path", "")
            if merged_bundle and os.path.isfile(merged_bundle):
                updated_patches = load_patches_pickle(merged_bundle)
                patches_without_context.update(updated_patches)
                logger.info(f"Loaded {len(updated_patches)} patches from merged bundle for minimization")
        else:
            # Fallback: reload the updated patch bundle and regenerate the .diff file
            updated_patches = load_patches_pickle(patch_file_binary)
            patches_without_context.update(updated_patches)
            with open(patch_file_path, 'w') as patch_file:
                for key in updated_patches:
                    patch = updated_patches[key]
                    patch_file.write(patch.patch_text)
                    patch_file.write('\n\n')
            logger.info(f"Regenerated {patch_file_path} from updated patch bundle (fallback)")
        # Rebuild to verify
        build_success, error_log = build_fuzzer(target, next_commit['commit_id'], sanitizer, bug_id, patch_file_path, fuzzer, args.build_csv, arch,
                                                runner_image=runner_image, commit_date=commit_date)
        if build_success:
            logger.info("React multi-agent successfully fixed build errors")
            break
        else:
            logger.info(f"React multi-agent did not fully fix errors, build still fails")
            # Write verification build errors to a separate log
            verify_log_path = os.path.join(data_path, "tmp_patch", f"{target}_verify_build.log")
            with open(verify_log_path, 'w') as f:
                f.write(error_log)
            logger.info(f"Verification build errors written to {verify_log_path}")
        
    testcases_env = os.getenv('TESTCASES', '')
    if not testcases_env:
        logger.info("TESTCASES environment variable not set. Exiting.")
        exit(1)
    crash_test_input = select_crash_test_input(bug_id, testcases_env)
    baseline_crash_path = os.path.join(
        data_path,
        'crash',
        f'target_crash-{commit["commit_id"][:8]}-{crash_test_input}.txt',
    )
    signature_file = os.path.join(
        data_path,
        'signature_change_list',
        f'{bug_id}_{next_commit["commit_id"]}.json',
    )
    with open(signature_file, 'w') as sig_file:
        json.dump(signature_change_list, sig_file, indent=2)
    if build_success:
        # Run the fuzzer to test if the bug is reproduced
        testcase_path = os.path.join(testcases_env, 'testcase-' + bug_id)
        reproduce_cmd = [
            py3, f'{current_file_path}/fuzz_helper.py', 'reproduce', target, fuzzer, testcase_path, '-e', 'ASAN_OPTIONS=detect_leaks=0'
        ]
        logger.info(f"Running reproduce command: {' '.join(reproduce_cmd)}")
        test_result = subprocess.run(reproduce_cmd, capture_output=True)
        test_stdout = (test_result.stdout or b'').decode('utf-8', errors='replace')
        test_stderr = (test_result.stderr or b'').decode('utf-8', errors='replace')
        if 'sanitizer' in test_stderr.lower()+test_stdout.lower() and sanitizer in test_stderr.lower()+test_stdout.lower():
            # trigger the bug
            combined_output = test_stderr + test_stdout
            if not crashes_match(combined_output, baseline_crash_path, signature_file):
                logger.info(
                    "Crash for bug %s on commit %s does not match baseline stack; skipping.",
                    bug_id,
                    next_commit['commit_id'],
                )
                return 'crash_mismatch'
            # Reproduce passed (bug triggered) - this is the main success criterion
            # check_build is optional; just warn if it fails
            short_next = next_commit['commit_id'][:8] if len(next_commit['commit_id']) > 8 else next_commit['commit_id']
            if not test_fuzzer_build(target, sanitizer, arch):
                logger.warning(f"check_build failed for bug {bug_id} on commit {short_next}, but reproduce passed - treating as success")
            else:
                logger.info(f"Fuzzer build check passed for bug {bug_id} on commit {short_next}")
            get_patched_traces.setdefault(bug_id, []).append(patch_file_path)
            return 'trigger_and_fuzzer_build'
        else:
            short_next = next_commit['commit_id'][:8] if len(next_commit['commit_id']) > 8 else next_commit['commit_id']
            logger.info(f"Bug {bug_id} not triggered with fuzzer {fuzzer} on commit {short_next}\n")
            return 'not_trigger'
    else:
        short_next = next_commit['commit_id'][:8] if len(next_commit['commit_id']) > 8 else next_commit['commit_id']
        logger.info(f"Build failed for bug {bug_id} on commit {short_next}\n")
        return 'build_fail'


def test_fuzzer(args, bug_id, target, commit_id, patch_path, need_build = True,
                runner_image=None, commit_date=None):
    # Run the fuzzer to test if the bug is reproduced
    bug_info_path = args.bug_info
    testcases_env = os.getenv('TESTCASES', '')
    bug_info_dataset = read_json_file(bug_info_path)
    bug_info = bug_info_dataset[bug_id]
    crash_type = bug_info['reproduce']['crash_type'].split(' ')[0]
    fuzzer = bug_info['reproduce']['fuzz_target']
    sanitizer = bug_info['reproduce']['sanitizer'].split(' ')[0]
    arch = 'i386' if 'i386' in bug_info['reproduce']['job_type'] else 'x86_64'
    
    if need_build:
        build_fuzzer(target, commit_id, sanitizer, bug_id, patch_path, fuzzer, args.build_csv, arch,
                     runner_image=runner_image, commit_date=commit_date)
    
    testcase_path = os.path.join(testcases_env, 'testcase-' + bug_id)
    reproduce_cmd = [
        py3, f'{current_file_path}/fuzz_helper.py', 'reproduce', target, fuzzer, testcase_path, '-e', 'ASAN_OPTIONS=detect_leaks=0'
    ]
    logger.info(f"Running reproduce command: {' '.join(reproduce_cmd)}")
    test_result = subprocess.run(reproduce_cmd, capture_output=True)
    combined_output = (
        (test_result.stderr or b'').decode('utf-8', errors='replace')
        + (test_result.stdout or b'').decode('utf-8', errors='replace')
    )
    lowered = combined_output.lower()
    sanitizer_lower = sanitizer.lower()
    # Detect sanitizer-reported crashes (e.g. AddressSanitizer, MemorySanitizer)
    sanitizer_triggered = 'sanitizer' in lowered and sanitizer_lower in lowered
    # Also detect libFuzzer-reported errors (out-of-memory, timeout, deadly signal)
    libfuzzer_triggered = 'summary: libfuzzer:' in lowered
    if sanitizer_triggered or libfuzzer_triggered:
        # trigger the bug
        confidence_level = '0.5'
        if crash_type.lower() in lowered:
            confidence_level = '1'
        return f'trigger with confidence level: {confidence_level}', combined_output
    else:
        return 'not trigger', combined_output


def update_type_set(patch_info):
    """Update the patch_type set based on the patch content."""
    if patch_info.old_signature and patch_info.new_signature and patch_info.old_signature != patch_info.new_signature:
        patch_info.patch_type.add('Function signature change')
    if patch_info.is_file_deletion:
        patch_info.patch_type.add('File removed')
    if patch_info.is_file_addition:
        patch_info.patch_type.add('File added')


def revert_patch_test(args):
    csv_file_path = args.target_test_result
    bug_info_dataset = read_json_file(args.bug_info)
    checkout_latest_commit(ossfuzz_path)
    revert_and_trigger_set = set()
    patches_without_contexts = dict()

    # Load existing cache if available for incremental processing
    cache_file = os.path.join(data_path, "patches", f"{args.target}_patches.pkl.gz")
    if not os.path.exists(os.path.dirname(cache_file)):
        os.makedirs(os.path.dirname(cache_file), exist_ok=True)
    if os.path.exists(cache_file):
        try:
            patches_without_contexts = load_patches_pickle(cache_file)
            logger.info(f"Loaded cache with {len(patches_without_contexts)} existing bug results from {cache_file}")
        except Exception as e:
            logger.warning(f"Failed to load cache file {cache_file}: {e}")
            patches_without_contexts = dict()

    revert_and_trigger_fail_set = set()
    build_success_no_trigger_set = set()
    patch_build_fail_set = set()
    min_path_dict = dict()
    # Pre-load existing min_patch file so single-bug runs don't lose other bugs' data
    min_patch_file_path = os.path.join(data_path, 'min_patch', f'{args.target}.json')
    if os.path.exists(min_patch_file_path):
        try:
            with open(min_patch_file_path, 'r') as f:
                min_path_dict = json.load(f)
            logger.info(f"Loaded {len(min_path_dict)} existing entries from {min_patch_file_path}")
        except Exception as e:
            logger.warning(f"Failed to load existing min_patch file: {e}")
    # Get repo path from environment variable
    repo_path = os.getenv('REPO_PATH')
    if not repo_path:
        logger.info("REPO_PATH environment variable not set. Exiting.")
        exit(1)
    # Get separate V1/V2 repo paths for react agent (old and new source versions)
    v1_repo_path = os.getenv('V1_REPO_PATH', '')
    v2_repo_path = os.getenv('V2_REPO_PATH', '')
    if not v1_repo_path or not v2_repo_path:
        logger.warning("V1_REPO_PATH or V2_REPO_PATH not set. React agent may not work correctly.")
        v1_repo_path = v1_repo_path or repo_path
        v2_repo_path = v2_repo_path or repo_path
    testcases_env = os.getenv('TESTCASES', '')
    if not testcases_env:
        logger.info("TESTCASES environment variable not set. Exiting.")
        exit(1)

    parsed_data = parse_csv_file(csv_file_path)
    target = args.target
    target_repo_path = os.path.join(repo_path, target)
    os.makedirs(os.path.dirname(min_patch_file_path), exist_ok=True)
    target_dockerfile_path = f'{ossfuzz_path}/projects/{target}/Dockerfile'

    # Handle fixed image selection if --fixed-image is specified
    fixed_builder_digest = None
    fixed_runner_digest = None
    if args.fixed_image:
        fixed_builder_digest, fixed_runner_digest = get_latest_images_before_year(args.fixed_image)
        logger.info(f"Using fixed images (latest before {args.fixed_image}):")
        logger.info(f"  base-builder: {fixed_builder_digest}")
        logger.info(f"  base-runner:  {fixed_runner_digest}")
        logger.info(f"  collect_trace/collect_crash will use base-builder")
        logger.info(f"  reproduce will use base-runner")

    bug_ids_trigger, bugs_need_transplant, target_row = prepare_transplant(parsed_data, target_repo_path)
    
    get_patched_traces = dict()
    previous_bug = ''
    previous_trace_func_list = []
    signature_change_list = []
    transitions = []
    
    for bug_id, row in bugs_need_transplant.items():
        commit = dict()
        next_commit = dict()
        # Store full commit IDs to avoid ambiguity in git commands
        # Short IDs (for display/filenames) will be generated on-the-fly
        commit['commit_id'] = row['commit_id']
        next_commit['commit_id'] = target_row['commit_id']
        transitions.append((commit, next_commit, bug_id))

    # Pre-generate compile_commands (AST analysis JSONs) for all unique
    # commits so that analyze_diffindex in the sorting step can find them.
    _cc_commits_done = set()
    for _commit, _next_commit, _bug_id in transitions:
        for _cid in (_commit['commit_id'], _next_commit['commit_id']):
            if _cid in _cc_commits_done:
                continue
            _cc_commits_done.add(_cid)
            _bug_info = bug_info_dataset.get(_bug_id, {})
            _reproduce = _bug_info.get('reproduce', {})
            _sanitizer = _reproduce.get('sanitizer', 'address').split(' ')[0]
            _job_type = _reproduce.get('job_type', '')
            _arch = _job_type.split('_')[2] if len(_job_type.split('_')) > 3 else 'x86_64'
            get_compile_commands(target, _cid, _sanitizer, args.build_csv, _arch)

    # Sort transitions by diff size (smallest first) so that
    # bugs with fewer diffs (simpler transplants) are attempted first.
    # Use cached analyze_diffindex results when available, otherwise
    # fall back to raw git diff line count (fast, avoids expensive AST analysis).
    def _diff_results_size(transition):
        _commit, _next_commit, _bug_id = transition
        diff_path = os.path.join(
            data_path, 'diff',
            f'revert_patch_{_bug_id}_{_commit["commit_id"]}_to_{_next_commit["commit_id"]}.diff',
        )
        if os.path.exists(diff_path):
            try:
                cached = load_patches_pickle(diff_path)
                if len(cached) > 0:
                    return len(cached)
            except Exception:
                pass
        # Uncached bugs: use raw diff line count as a fast proxy
        try:
            _diffs = get_diff_unified(target_repo_path, _commit['commit_id'], _next_commit['commit_id'], '')
            return len(_diffs.splitlines())
        except Exception:
            return float('inf')

    transitions.sort(key=_diff_results_size)
    logger.info(f"Sorted {len(transitions)} transitions by diff size (smallest first)")

    flag = False
    test_local_bug_after_patch = dict() # key: bug_id, value: test result, whether the local bug is triggered after applying the patch
    for commit, next_commit, bug_id in transitions:
        if args.bug_id and bug_id != args.bug_id:
            continue
        if args.buggy_commit:
            commit['commit_id'] = args.buggy_commit
        # Use short IDs for logging readability
        short_commit = commit['commit_id'][:8] if len(commit['commit_id']) > 8 else commit['commit_id']
        short_next_commit = next_commit['commit_id'][:8] if len(next_commit['commit_id']) > 8 else next_commit['commit_id']
        logger.info(f'bug trigger commit: {short_commit}')
        logger.info(f'target commit id: {short_next_commit}')
        bug_info = bug_info_dataset[bug_id]
        fuzzer = bug_info['reproduce']['fuzz_target']

        # Check if bug is already cached - skip expensive processing if found
        # Cache key is (bug_id, commit_id, fuzzer, function_names_tuple)
        # We check if any cached key matches the first 3 elements
        bug_partial_key = (bug_id, commit['commit_id'], fuzzer)
        bug_already_cached = any(
            key[:3] == bug_partial_key
            for key in patches_without_contexts.keys()
        )
        if bug_already_cached:
            logger.info(f"Bug {bug_id} (commit {short_commit}, fuzzer {fuzzer}) already cached, skipping patch generation...")
            # Reconstruct get_patched_traces from existing patch files so
            # the local bug test section below can still run.
            patch_folder = os.path.abspath(os.path.join(current_file_path, '..', 'patch'))
            prefix = f"{bug_id}_{next_commit['commit_id']}_patches"
            existing_patches = sorted(
                (p for p in os.listdir(patch_folder)
                 if p.startswith(prefix) and p.endswith('.diff')),
                key=lambda p: int(p[len(prefix):].split('.')[0]) if p[len(prefix):].split('.')[0].isdigit() else 0,
            )
            if existing_patches:
                get_patched_traces[bug_id] = [
                    os.path.join(patch_folder, p) for p in existing_patches
                ]
                logger.info(f"Found {len(existing_patches)} existing patch files for local bug test")
                # Run self-trigger test so cached bugs appear in the summary
                last_patch = get_patched_traces[bug_id][-1]
                # Determine Docker image for test_fuzzer
                _test_runner_image = fixed_builder_digest if fixed_builder_digest else 'auto'
                result, _ = test_fuzzer(args, bug_id, target, next_commit['commit_id'], last_patch, need_build=True,
                                        runner_image=_test_runner_image)
                if 'trigger' in result and 'not trigger' not in result:
                    revert_and_trigger_set.add((bug_id, next_commit['commit_id'], fuzzer))
                    logger.info(f"Cached bug {bug_id} self-trigger test passed")
                else:
                    revert_and_trigger_fail_set.add((bug_id, next_commit['commit_id'], fuzzer))
                    build_success_no_trigger_set.add((bug_id, next_commit['commit_id'], fuzzer))
                    logger.info(f"Cached bug {bug_id} self-trigger test: {result}")
            # Skip expensive patch generation / build / minimize
            continue

        sanitizer = bug_info['reproduce']['sanitizer'].split(' ')[0]
        bug_type = bug_info['reproduce']['crash_type']
        job_type = bug_info['reproduce']['job_type']
        patch_path_list = []
        if len(job_type.split('_')) > 3:
            arch = job_type.split('_')[2]
        else:
            arch = 'x86_64'
        crash_test_input = select_crash_test_input(bug_id, testcases_env)
        # Use short commit IDs (6 chars) for trace filenames to match get_trace_log_bash
        short_commit_id = commit['commit_id'][:8] if len(commit['commit_id']) > 8 else commit['commit_id']
        short_next_commit_id = next_commit['commit_id'][:8] if len(next_commit['commit_id']) > 8 else next_commit['commit_id']
        trace_path1 = os.path.join(data_path, f"target_trace-{short_commit_id}-{crash_test_input}.txt")
        trace_path2 = os.path.join(data_path, f"target_trace-{short_next_commit_id}-{crash_test_input}.txt")
        if bug_id in get_patched_traces:
            patch_path_list = get_patched_traces[bug_id]
            trace_path2 = os.path.join(data_path, f"target_trace-{short_next_commit_id}-{crash_test_input}{patch_path_list[-1].split('/')[-1].split('.diff')[0]}.txt")
            short_c = commit['commit_id'][:8] if len(commit['commit_id']) > 8 else commit['commit_id']
            short_n = next_commit['commit_id'][:8] if len(next_commit['commit_id']) > 8 else next_commit['commit_id']
            logger.info(f"Processing transition for bug {bug_id} from commit {short_c} to {short_n} with patch {patch_path_list[-1]}")
        else:
            short_c = commit['commit_id'][:8] if len(commit['commit_id']) > 8 else commit['commit_id']
            short_n = next_commit['commit_id'][:8] if len(next_commit['commit_id']) > 8 else next_commit['commit_id']
            logger.info(f"Processing transition for bug {bug_id} from commit {short_c} to {short_n}")

        if bug_id in get_patched_traces:
            collect_trace_cmd = [py3, f'{current_file_path}/fuzz_helper.py', 'collect_trace', '--commit', next_commit['commit_id'], '--sanitizer', sanitizer,
                                '--build_csv', args.build_csv, '--architecture', arch]
            # Add Docker image selection based on flags
            if fixed_builder_digest:
                collect_trace_cmd.extend(['--runner-image', fixed_builder_digest])
            else:
                collect_trace_cmd.extend(['--runner-image', 'auto'])
            collect_trace_cmd.extend(['--patch', get_patched_traces[bug_id][-1]])
        else:
            collect_trace_cmd = [py3, f'{current_file_path}/fuzz_helper.py', 'collect_trace', '--commit', commit['commit_id'], '--sanitizer', sanitizer,
                                '--build_csv', args.build_csv, '--architecture', arch]
            # Add Docker image selection based on flags
            if fixed_builder_digest:
                collect_trace_cmd.extend(['--runner-image', fixed_builder_digest])
            else:
                collect_trace_cmd.extend(['--runner-image', 'auto'])
        collect_trace_cmd.extend(['--testcases', testcases_env])

        collect_trace_cmd.extend(['--build_csv', args.build_csv])

        collect_trace_cmd.extend(['--test_input', crash_test_input])

        collect_trace_cmd.append(target)

        collect_trace_cmd.append(fuzzer)

        collect_trace_cmd.extend(['-e', 'ASAN_OPTIONS=detect_leaks=0'])

        if not os.path.exists(trace_path1) or os.path.exists(trace_path1) and 'No such file or directory' in open(trace_path1).read():
            # logger.info the command being executed
            logger.info(f"Running command: {' '.join(collect_trace_cmd)}")
            # Execute the command
            try:
                result = subprocess.run(collect_trace_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError as e:
                logger.info(f"Command failed with exit code {e.returncode}")
                
        if not os.path.exists(trace_path2):
            # Rebuild command for next_commit (trace2)
            collect_trace_cmd_2 = [py3, f'{current_file_path}/fuzz_helper.py', 'collect_trace', '--commit', next_commit['commit_id'], '--sanitizer', sanitizer,
                                '--build_csv', args.build_csv, '--architecture', arch]
            # Add Docker image selection based on flags
            if fixed_builder_digest:
                collect_trace_cmd_2.extend(['--runner-image', fixed_builder_digest])
            else:
                collect_trace_cmd_2.extend(['--runner-image', 'auto'])
            collect_trace_cmd_2.extend(['--testcases', testcases_env])
            collect_trace_cmd_2.extend(['--build_csv', args.build_csv])
            collect_trace_cmd_2.extend(['--test_input', crash_test_input])
            collect_trace_cmd_2.append(target)
            collect_trace_cmd_2.append(fuzzer)
            collect_trace_cmd_2.extend(['-e', 'ASAN_OPTIONS=detect_leaks=0'])
            # logger.info the command being executed
            logger.info(f"Running command: {' '.join(collect_trace_cmd_2)}")
            # Execute the command
            try:
                result = subprocess.run(collect_trace_cmd_2, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError as e:
                logger.info(f"Command failed with exit code {e.returncode}")
        
        # may cannot get trace, in new commit
        if not os.path.exists(trace_path2):
            logger.info(f"Trace file {trace_path2} does not exist, skipping bug {bug_id}")
            continue
        crash_log_path = get_crash_stack(
            bug_id=bug_id,
            commit_id=commit['commit_id'],
            crash_test_input=crash_test_input,
            sanitizer=sanitizer,
            build_csv=args.build_csv,
            arch=arch,
            testcases_env=testcases_env,
            target=target,
            fuzzer=fuzzer,
            target_repo_path=target_repo_path,
            fixed_builder_digest=fixed_builder_digest,
            auto_select_images=args.auto_select_images,
            ignore_crash_leaks=args.ignore_crash_leaks,
        )
        
        trace1 = extract_function_calls(trace_path1)
        trace2 = extract_function_calls(trace_path2)
        common_part = compare_traces(trace1, trace2, signature_change_list)
        diffs = get_diff_unified(target_repo_path, commit['commit_id'], next_commit['commit_id'], '') # every file get a diff
        get_compile_commands(target, next_commit['commit_id'], sanitizer, args.build_csv, arch)
        get_compile_commands(target, commit['commit_id'], sanitizer, args.build_csv, arch)
        diff_path = os.path.join(data_path, 'diff', f'revert_patch_{bug_id}_{commit["commit_id"]}_to_{next_commit["commit_id"]}.diff')
        os.makedirs(os.path.dirname(diff_path), exist_ok=True)
        diff_results = None
        if os.path.exists(diff_path):
            try:
                diff_results = load_patches_pickle(diff_path)
                logger.info(f"Loaded cached diff analysis from {diff_path}")
            except (pickle.UnpicklingError, EOFError, OSError, gzip.BadGzipFile) as exc:
                logger.warning(f"Failed to load cached diff from {diff_path}: {exc}")
                diff_results = None
        if diff_results is None:
            diff_results = analyze_diffindex(diffs, target_repo_path, next_commit['commit_id'], commit['commit_id'], target, signature_change_list)
            try:
                save_patches_pickle(diff_results, diff_path)
                logger.info(f"Saved diff analysis cache to {diff_path}")
            except OSError as exc:
                logger.warning(f"Failed to save diff analysis cache to {diff_path}: {exc}")
        file_path_pairs = get_file_path_pairs(diff_results)

        trace_func_list = []
        # checkout target repo to the bug commit, get function signature from source code using code location
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', commit['commit_id']], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        func_dict = dict()
        for _, func in trace1:
            if func in func_dict:
                continue
            func_loc = func.split(' ')[-1]
            func_dict[func] = func.split(' ')[0].split('(')[0]
            trace_func_list.append((func_dict[func], func_loc))
            
        # --crash-stack-only: filter trace_func_list to only functions in the crash stack
        if getattr(args, 'crash_stack_only', False) and crash_log_path and os.path.exists(crash_log_path):
            crash_stack_funcs = set(extract_function_stack(crash_log_path, apply_signatures=False))
            if crash_stack_funcs:
                filtered = [(fn, loc) for fn, loc in trace_func_list if fn.split('(')[0] in crash_stack_funcs]
                logger.info(f"Crash-stack-only: {len(trace_func_list)} trace funcs -> {len(filtered)} crash-stack funcs (crash stack: {crash_stack_funcs})")
                trace_func_list = filtered
            else:
                logger.warning(f"Crash stack empty from {crash_log_path}, using full trace")

        logger.info(f"Trace function set: {len(trace_func_list)} {trace_func_list}")
        logger.info(f"Total diff results: {len(diff_results)}")
        if not trace_func_list:
            logger.info(f'No function signatures found in trace for bug {bug_id}\n')
            continue

        if previous_bug == bug_id and previous_trace_func_list == trace_func_list:
            # Try to add trace funcs for this bug fail
            logger.info(f"Skipping bug {bug_id} as it has the same trace functions as the previous bug")
            continue
        previous_trace_func_list = trace_func_list
        previous_bug = bug_id

        # checkout target repo to the new commit, get function signature from source code using code location
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', next_commit['commit_id']], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        patch_to_apply = []
        for key, diff_result in diff_results.items():
            patch_func_new = ''
            patch_func_old = ''
            patch_file_path = ''
            if diff_result.new_signature:
                logger.debug(f'newsignature{diff_result.new_signature}')
                patch_func_new = diff_result.new_function_name
            elif diff_result.old_signature:
                logger.debug(f'oldsignature{diff_result.old_signature}')
                patch_func_old = diff_result.old_function_name
            else:
                continue
            if diff_result.file_path_old:
                patch_file_path = diff_result.file_path_old
            else:
                patch_file_path = diff_result.file_path_new
            update_type_set(diff_result)

            # Extract just the filename from patch_file_path for comparison
            # patch_file_path might be like "b/stb_image.h" or "a/stb_image.h"
            patch_filename = os.path.basename(patch_file_path)
            # If both bug commit's and fix commit's trace contain this patched function,
            # the patch of the function is likely related to the bug fixing. So try to
            # revert it.
            matched = False
            for trace_func, func_loc in trace_func_list:
                # func_loc is like "/tests/../stb_image.h:7538:0", extract the filename part
                func_loc_file = func_loc.split(':')[0]  # Remove :line:col part
                func_loc_filename = os.path.basename(func_loc_file)
                # trace_func might have parameters like "stbi__bmp_load(stbi__context*,"
                # Extract just the function name by splitting on '('
                trace_func_name = trace_func.split('(')[0]
                if patch_filename == func_loc_filename and (trace_func_name == patch_func_old or trace_func_name == patch_func_new):
                    matched = True
                    if not diff_result.old_signature:
                        diff_result.old_signature, diff_result.old_function_start_line, diff_result.old_function_end_line = get_full_funsig(diff_result, target, commit['commit_id'], 'old')
                    if not diff_result.new_signature and diff_result.file_path_new != '/dev/null':
                        diff_result.new_signature, _, _ = get_full_funsig(diff_result, target, next_commit['commit_id'], 'new')
                    if diff_result.old_signature:
                        patch_to_apply.append(key)
                    break

        depen_graph, patch_to_apply = build_dependency_graph(diff_results, patch_to_apply, target_repo_path, commit['commit_id'], trace1)

        # Determine Docker image selection for builds
        # Default to 'auto' so fuzz_helper.py derives the image from builds.csv
        build_runner_image = 'auto'
        build_commit_date = None
        if fixed_builder_digest:
            build_runner_image = fixed_builder_digest

        inmutable_args = (diff_results, trace1, target_repo_path, commit, next_commit, target,
            sanitizer, bug_id, fuzzer, args, arch, file_path_pairs, data_path, depen_graph,
            v1_repo_path, v2_repo_path, build_runner_image, build_commit_date)
        signature_change_list = []
        mutable_args = (get_patched_traces, transitions, signature_change_list)
        patch_by_func = dict()
        for key in patch_to_apply[:]:
            if diff_results[key].new_signature:
                patch_by_func.setdefault(diff_results[key].new_signature, []).append(key)
            else:
                patch_by_func.setdefault(diff_results[key].old_signature, []).append(key)
        patch_pair_list = [tuple(v) for v in patch_by_func.values()]

        used_min_patch_cache = False
        if os.path.exists(min_patch_file_path):
            with open(min_patch_file_path, 'r') as f:
                cached_patches = json.load(f)
                if bug_id in cached_patches:
                    patch_pair_list = cached_patches[bug_id]
                    used_min_patch_cache = True

        patches_without_context = dict()
        tmp = copy.deepcopy(inmutable_args)
        result = apply_and_test_patches(patch_pair_list, [], patches_without_context, *mutable_args, *tmp)
        if result not in {'trigger_but_fuzzer_build_fail', 'trigger_and_fuzzer_build'}:
            revert_and_trigger_fail_set.add((bug_id, next_commit['commit_id'], fuzzer))
            if result == 'not_trigger' or result == 'crash_mismatch':
                build_success_no_trigger_set.add((bug_id, next_commit['commit_id'], fuzzer))
                # Save patch file for later fuzzing (get_poc_for_new_version)
                get_patched_traces_ref = mutable_args[0]
                suffix = len(get_patched_traces_ref[bug_id]) if bug_id in get_patched_traces_ref else ''
                patch_dir = os.path.abspath(os.path.join(current_file_path, '..', 'patch'))
                # Prefer round0 diff (with proactive declarations) over original
                src_patch_round0 = os.path.join(patch_dir, f"{bug_id}_{next_commit['commit_id']}_patches{suffix}_round0.diff")
                src_patch_orig = os.path.join(patch_dir, f"{bug_id}_{next_commit['commit_id']}_patches{suffix}.diff")
                src_patch = src_patch_round0 if os.path.exists(src_patch_round0) else src_patch_orig
                if os.path.exists(src_patch):
                    save_dir = os.path.join(data_path, 'build_success_patches')
                    os.makedirs(save_dir, exist_ok=True)
                    dst_patch = os.path.join(save_dir, f'{bug_id}.diff')
                    shutil.copy(src_patch, dst_patch)
                    logger.info(f"Saved patch for untriggered bug {bug_id} to {dst_patch}")
                else:
                    logger.warning(f"Patch file {src_patch} not found for bug {bug_id}")
            else:
                patch_build_fail_set.add((bug_id, next_commit['commit_id'], fuzzer))
            minimal_fast = patch_pair_list  # Use original if initial build fails
        else:
            revert_and_trigger_set.add((bug_id, next_commit['commit_id'], fuzzer))
            logger.info(f'Initial revert patch set: {len(patch_pair_list)} {patch_pair_list}')

            if used_min_patch_cache:
                # Skip minimization — patch_pair_list is already minimized from cache
                minimal_fast = patch_pair_list
                logger.info(f'Skipping minimization, using cached min_patch: {len(minimal_fast)}')
            else:
                # Use greedy minimization
                tmp = copy.deepcopy(inmutable_args)
                minimal_fast = minimize_greedy(
                    patch_pair_list, apply_and_test_patches, patches_without_context,
                    mutable_args, tmp
                )
                logger.info(f'Minimal patch set after greedy minimization: {len(minimal_fast)}')

        # Only cache bugs that were triggered correctly
        if result in {'trigger_but_fuzzer_build_fail', 'trigger_and_fuzzer_build'}:
            min_path_dict[bug_id] = minimal_fast
            patches_without_contexts[
                (bug_id, commit['commit_id'], fuzzer,
                tuple(diff_results[key].old_function_name for keys in minimal_fast for key in keys))
            ] = patches_without_context

            # Save cache incrementally after each bug completes
            try:
                save_patches_pickle(patches_without_contexts, cache_file)
                logger.info(f"Saved cache with {len(patches_without_contexts)} bug results to {cache_file}")
            except Exception as e:
                logger.warning(f"Failed to save cache for bug {bug_id}: {e}")

            # Save min_patch JSON incrementally so results survive interruptions
            try:
                os.makedirs(os.path.dirname(min_patch_file_path), exist_ok=True)
                with open(min_patch_file_path, 'w') as f:
                    json.dump(min_path_dict, f, indent=4)
                logger.info(f"Saved min_patch with {len(min_path_dict)} entries to {min_patch_file_path}")
            except Exception as e:
                logger.warning(f"Failed to save min_patch for bug {bug_id}: {e}")
        else:
            logger.info(f"Bug {bug_id} not triggered correctly (result={result}), skipping cache save")

        get_patched_traces, transitions, signature_change_list = mutable_args

        if not os.path.exists(os.path.join(data_path, 'signature_change_list')):
            os.makedirs(os.path.join(data_path, 'signature_change_list'))
        with open(os.path.join(data_path, 'signature_change_list', f"{bug_id}_{next_commit['commit_id']}.json"), 'w') as f:
            json.dump(signature_change_list, f, indent=4)

    # --- Local bug test loop (runs for all bugs with patches, including cached) ---
    patch_folder = os.path.abspath(os.path.join(current_file_path, '..', 'patch'))
    # Pre-collect crash logs for all local bugs so that get_crash_stack()
    # inside the test loop never triggers a rebuild that would override
    # the patched build produced by test_fuzzer(need_build=True).
    for bug_id_trigger in bug_ids_trigger:
        trigger_info = bug_info_dataset[bug_id_trigger]
        trigger_fuzzer = trigger_info['reproduce']['fuzz_target']
        trigger_sanitizer = trigger_info['reproduce']['sanitizer'].split(' ')[0]
        trigger_job_type = trigger_info['reproduce']['job_type']
        trigger_arch = trigger_job_type.split('_')[2] if len(trigger_job_type.split('_')) > 3 else 'x86_64'
        trigger_input = select_crash_test_input(bug_id_trigger, testcases_env)
        for commit, next_commit, bug_id in transitions:
            get_crash_stack(
                bug_id=bug_id_trigger,
                commit_id=next_commit['commit_id'],
                crash_test_input=trigger_input,
                sanitizer=trigger_sanitizer,
                build_csv=args.build_csv,
                arch=trigger_arch,
                testcases_env=testcases_env,
                target=target,
                fuzzer=trigger_fuzzer,
                target_repo_path=target_repo_path,
                fixed_builder_digest=fixed_builder_digest,
                auto_select_images=args.auto_select_images,
                ignore_crash_leaks=args.ignore_crash_leaks,
            )
            break  # all transitions share the same next_commit for a given target

    for commit, next_commit, bug_id in transitions:
        if args.bug_id and bug_id != args.bug_id:
            continue
        if bug_id not in get_patched_traces:
            continue
        logger.info('-' * 20)
        # Only test the final patch (last entry in the list), not all intermediate variants
        i = len(get_patched_traces[bug_id]) - 1
        patch_file_path = os.path.join(patch_folder, f"{bug_id}_{next_commit['commit_id']}_patches{i if i != 0 else ''}.diff")
        last_sanitizer = None
        count = 0
        for bug_id_trigger in bug_ids_trigger:
            trigger_san = bug_info_dataset[bug_id_trigger]['reproduce']['sanitizer'].split(' ')[0]
            need_build = (trigger_san != last_sanitizer)
            last_sanitizer = trigger_san
            # Determine Docker image for test_fuzzer
            _tf_runner_image = fixed_builder_digest if fixed_builder_digest else 'auto'
            result, crash_output = test_fuzzer(
                args,
                bug_id_trigger,
                target,
                next_commit['commit_id'],
                patch_file_path,
                need_build=need_build,
                runner_image=_tf_runner_image,
            )
            if result == 'not trigger':
                logger.info(f'\t{bug_id} not trigger local bug {bug_id_trigger}')
                continue

            trigger_info = bug_info_dataset[bug_id_trigger]
            trigger_fuzzer = trigger_info['reproduce']['fuzz_target']
            trigger_sanitizer = trigger_info['reproduce']['sanitizer'].split(' ')[0]
            trigger_job_type = trigger_info['reproduce']['job_type']
            trigger_arch = trigger_job_type.split('_')[2] if len(trigger_job_type.split('_')) > 3 else 'x86_64'
            trigger_input = select_crash_test_input(bug_id_trigger, testcases_env)
            baseline_crash_path = get_crash_stack(
                bug_id=bug_id_trigger,
                commit_id=next_commit['commit_id'],
                crash_test_input=trigger_input,
                sanitizer=trigger_sanitizer,
                build_csv=args.build_csv,
                arch=trigger_arch,
                testcases_env=testcases_env,
                target=target,
                fuzzer=trigger_fuzzer,
                target_repo_path=target_repo_path,
                fixed_builder_digest=fixed_builder_digest,
                auto_select_images=args.auto_select_images,
                ignore_crash_leaks=args.ignore_crash_leaks,
            )
            signature_file_trigger = os.path.join(
                data_path,
                'signature_change_list',
                f'{bug_id}_{next_commit["commit_id"]}.json',
            )
            if crashes_match(crash_output, baseline_crash_path, signature_file_trigger):
                logger.info(f'\t{bug_id} trigger local bug {bug_id_trigger} (stack match)\n')
                count += 1
                test_local_bug_after_patch.setdefault(bug_id_trigger, set()).add(bug_id)
            else:
                logger.info(f'\t{bug_id} trigger local bug {bug_id_trigger} but stack mismatch\n')
        logger.info(f'\t{bug_id} total local bugs triggered: {count}\n')

    os.makedirs(os.path.dirname(min_patch_file_path), exist_ok=True)
    with open(min_patch_file_path, 'w') as f:
        json.dump(min_path_dict, f, indent=4)
    logger.info(f"Revert and trigger set: {len(revert_and_trigger_set)} {revert_and_trigger_set}")
    logger.info(f"Revert and trigger fail set: {len(revert_and_trigger_fail_set)} {revert_and_trigger_fail_set}")
    logger.info(f"  - Build success but bug not triggered: {len(build_success_no_trigger_set)} {build_success_no_trigger_set}")
    logger.info(f"  - Patch build failed: {len(patch_build_fail_set)} {patch_build_fail_set}")
    
    return patches_without_contexts, test_local_bug_after_patch


def get_compile_commands(target, commit_id, sanitizer, build_csv, arch):
    # use libclang to parse, and save results to files
    cmd = [
        py3, f"{current_file_path}/fuzz_helper.py", "build_version", "--commit", commit_id, "--sanitizer", sanitizer,
        '--build_csv', build_csv, '--compile_commands', '--architecture', arch , target
    ]
    
    # Use short commit hash (6 chars) for directory name to match fuzz_helper.py
    short_commit_id = commit_id[:8] if len(commit_id) > 8 else commit_id
    if not os.path.exists(os.path.join(data_path, f'{target}-{short_commit_id}')):
        logger.info(' '.join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        

if __name__ == "__main__":
    args = parse_arguments()
    # Note: Cache loading/saving is now handled incrementally inside revert_patch_test()
    # The function loads existing cache at start and saves after each bug completes
    patches_without_contexts, test_local_bug_after_patch = revert_patch_test(args)

    # Save local bug compatibility for patch_merge.py
    # test_local_bug_after_patch is {local_bug: set(remote_bugs)}
    # patch_merge.py expects {remote_bug: [local_bugs]}
    if test_local_bug_after_patch:
        local_compat_dir = os.path.join(data_path, 'local_compatibility')
        os.makedirs(local_compat_dir, exist_ok=True)
        local_compat_file = os.path.join(local_compat_dir, f'{args.target}.json')
        # Merge with existing file so single-bug runs don't lose other data
        existing = {}
        if os.path.exists(local_compat_file):
            try:
                with open(local_compat_file, 'r') as f:
                    existing = json.load(f)
            except Exception:
                pass
        # Invert: local_bug -> {remote_bugs} becomes remote_bug -> [local_bugs]
        for local_bug, remote_bugs in test_local_bug_after_patch.items():
            for remote_bug in remote_bugs:
                existing.setdefault(remote_bug, [])
                if local_bug not in existing[remote_bug]:
                    existing[remote_bug].append(local_bug)
        for key in existing:
            existing[key] = sorted(existing[key])
        with open(local_compat_file, 'w') as f:
            json.dump(existing, f, indent=4)
        logger.info(f"Saved local bug compatibility to {local_compat_file}")

    # Log compatibility results
    for bug_id, affected_bugs in test_local_bug_after_patch.items():
        logger.info(f'local bug {bug_id} is compatible with: {len(affected_bugs)} {affected_bugs}')
