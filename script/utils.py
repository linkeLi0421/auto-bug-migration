from typing import List, Any, Callable, Dict, Tuple, Set
import copy
import re
import difflib
import gzip
import pickle
import logging
from pathlib import Path

# Type: test_fn takes a list of patches (order preserved) and returns True/False
TestFn = Callable[[List[Any]], bool]

logger = logging.getLogger(__name__)


def extract_extra_patches(patches_without_context: Dict[str, Any]) -> Dict[str, Any]:
    """Extract _extra_* patches from the patch dictionary."""
    return {
        key: copy.deepcopy(patch)
        for key, patch in patches_without_context.items()
        if key.startswith('_extra_')
    }


def _extract_func_name(signature_or_name: str) -> str:
    """
    Extract function name from a signature or bare name.

    Examples:
        'void xmlTextReaderFreeNode(xmlTextReaderPtr reader, xmlNodePtr cur)' -> 'xmlTextReaderFreeNode'
        'int foo(void)' -> 'foo'
        'xmlTextReaderFreeNode' -> 'xmlTextReaderFreeNode'
    """
    if not signature_or_name:
        return ''
    # If it contains '(', it's a signature - extract name before '('
    if '(' in signature_or_name:
        # Get the part before '('
        before_paren = signature_or_name.split('(')[0].strip()
        # The function name is the last word (after return type, pointer symbols, etc.)
        parts = before_paren.split()
        if parts:
            # Remove any leading * or & from the name
            name = parts[-1].lstrip('*&')
            return name
    # Otherwise it's already just a name
    return signature_or_name.strip()


def filter_patches_by_trace(
    all_patch_keys: List[str],
    diff_results: Dict[str, Any],
    trace_func_list: List[Tuple[str, str]],
    depen_graph: Dict[str, Set[str]],
) -> List[str]:
    """
    Filter patches to only those whose functions appear in the execution trace
    or are dependencies of trace-related functions.
    """
    trace_functions = {func for func, _ in trace_func_list}
    # Extract trace file basenames (strip leading / and get filename)
    trace_file_basenames = set()
    for _, loc in trace_func_list:
        if ':' in loc:
            file_part = loc.split(':')[0].lstrip('/')
            # Get basename for matching
            basename = file_part.split('/')[-1] if '/' in file_part else file_part
            trace_file_basenames.add(basename)

    # First pass: find patches directly in trace
    direct_matches = set()
    for key in all_patch_keys:
        patch = diff_results.get(key)
        if not patch:
            continue
        patch_file = getattr(patch, 'file_path_old', None) or getattr(patch, 'file_path_new', None)
        # Extract function names - handle both bare names and full signatures
        func_old_raw = getattr(patch, 'old_function_name', '') or ''
        func_new_raw = getattr(patch, 'new_function_name', '') or ''
        func_old = _extract_func_name(func_old_raw)
        func_new = _extract_func_name(func_new_raw)

        # Check if function matches trace
        if func_old in trace_functions or func_new in trace_functions:
            # Check if file matches trace (compare basenames)
            if patch_file:
                patch_basename = patch_file.split('/')[-1] if '/' in patch_file else patch_file
                if patch_basename in trace_file_basenames:
                    direct_matches.add(key)
                    logger.debug(f"Matched patch {key}: func={func_old or func_new}, file={patch_basename}")

    # Second pass: expand with dependency graph (transitive closure)
    result = set(direct_matches)
    worklist = list(direct_matches)
    while worklist:
        key = worklist.pop()
        for callee_key in depen_graph.get(key, set()):
            if callee_key not in result:
                result.add(callee_key)
                worklist.append(callee_key)

    return list(result)


def binary_search_missing_patches(
    known_good: Set[str],
    candidates: List[str],
    test_fn: Callable[[List[str]], bool],
) -> List[str]:
    """Binary search to find minimal additional patches needed for build success."""
    if not candidates:
        return []

    full_set = list(known_good) + candidates
    logger.info(f"Testing full set ({len(known_good)} base + {len(candidates)} candidates = {len(full_set)} total)")
    if not test_fn(full_set):
        logger.info("Full set fails, cannot find minimal set")
        return []  # Even with all patches it fails

    logger.info(f"Testing base set only ({len(known_good)} patches)")
    if test_fn(list(known_good)):
        logger.info("Base set already works, no additional patches needed")
        return []  # Already works without candidates

    needed = []
    remaining = list(candidates)
    iteration = 0

    while remaining:
        iteration += 1
        mid = len(remaining) // 2
        if mid == 0:
            logger.info(f"Iteration {iteration}: adding last candidate, needed={len(needed)+1}")
            needed.append(remaining[0])
            remaining = remaining[1:]
            continue

        first_half = remaining[:mid]
        second_half = remaining[mid:]

        logger.info(f"Iteration {iteration}: testing first half ({mid} patches), remaining={len(remaining)}, needed={len(needed)}")
        test_set = list(known_good) + needed + first_half
        if test_fn(test_set):
            remaining = first_half
        else:
            logger.info(f"Iteration {iteration}: testing second half ({len(second_half)} patches)")
            test_set = list(known_good) + needed + second_half
            if test_fn(test_set):
                remaining = second_half
            else:
                logger.info(f"Iteration {iteration}: both halves needed, adding first half ({mid} patches)")
                needed.extend(first_half)
                remaining = second_half

    logger.info(f"Binary search complete: found {len(needed)} additional patches needed")
    return needed

def minimize_greedy(patches: List[Any], test_fn: TestFn, patches_without_context: Dict[str, Any], mutable_args: Tuple, inmutable_args: Tuple) -> List[Any]:
    """
    Fast heuristic: try removing one patch at a time (left-to-right),
    keep the removal if test_fn still returns True. Repeat until stable.
    """
    cur = list(patches)
    changed = True
    cache: Dict[Tuple[int, ...], bool] = {}

    def cached_test(items: List[Any]) -> bool:
        key = tuple(id(x) for x in items)  # identity-based; avoids equals() surprises
        if key not in cache:
            items_copy = copy.deepcopy(items)
            ctx_copy   = copy.deepcopy(inmutable_args)
            cache[key] = test_fn(items_copy, [], patches_without_context, *mutable_args, *ctx_copy)
        return cache[key]

    while changed:
        changed = False
        i = 0
        while i < len(cur):
            trial = cur[:i] + cur[i+1:]
            if cached_test(trial) == 'trigger_and_fuzzer_build':
                cur = trial
                changed = True
                break
                # do not increment i; the next element shifted into position i
            else:
                i += 1
    return cur


def minimize_func_list_greedy(func_list: List[Any], patch_pair_list: List[Any], test_fn: TestFn, patches_without_context: Dict[str, Any], mutable_args: Tuple, inmutable_args: Tuple) -> List[Any]:
    """
    Variant of minimize_greedy that shrinks func_list while keeping patch_pair_list fixed.
    Tests subsets of func_list with test_fn until no further removals keep the desired result.
    """
    cur_funcs = list(func_list)
    cache: Dict[Tuple[int, ...], bool] = {}
    baseline_patches = copy.deepcopy(patch_pair_list)

    def cached_test(func_subset: List[Any]) -> bool:
        key = tuple(id(x) for x in func_subset)
        if key not in cache:
            funcs_copy = copy.deepcopy(func_subset)
            patches_copy = copy.deepcopy(baseline_patches)
            ctx_copy = copy.deepcopy(inmutable_args)
            cache[key] = test_fn(patches_copy, funcs_copy, patches_without_context, *mutable_args, *ctx_copy)
        return cache[key]

    changed = True
    while changed:
        changed = False
        i = 0
        while i < len(cur_funcs):
            trial = cur_funcs[:i] + cur_funcs[i+1:]
            if cached_test(trial) == 'trigger_and_fuzzer_build':
                cur_funcs = trial
                changed = True
                break  # restart after successful removal
            i += 1

    return cur_funcs


def save_patches_pickle(patches: Dict[str, Dict[str, Any]], path: str | Path) -> None:
    """Persist the patches dictionary to a pickle file (gzip-aware)."""
    target_path = Path(path)
    logger.info(target_path)
    with gzip.open(target_path, "wb") if str(target_path).endswith(".gz") else open(target_path, "wb") as f:
        pickle.dump(patches, f, protocol=pickle.HIGHEST_PROTOCOL)


def load_patches_pickle(path: str | Path) -> Dict[str, Dict[str, Any]]:
    """Load patches dictionary previously stored with `save_patches_pickle`."""
    source_path = Path(path)
    with gzip.open(source_path, "rb") if str(source_path).endswith(".gz") else open(source_path, "rb") as f:
        return pickle.load(f)


def minimize_ddmin(patches: List[Any], test_fn: TestFn, patches_without_context: Dict[str, Any], context: Tuple) -> List[Any]:
    """
    Zeller's ddmin: returns a 1-minimal subset S ⊆ patches such that test_fn(S) is True,
    and for every single element e in S, test_fn(S \\ {e}) is False.
    """
    cur = list(patches)
    cache: Dict[Tuple[int, ...], bool] = {}

    def cached_test(items: List[Any]) -> bool:
        key = tuple(id(x) for x in items)
        if key not in cache:
            items_copy = copy.deepcopy(items)
            ctx_copy   = copy.deepcopy(context)
            cache[key] = test_fn(items_copy, patches_without_context, *ctx_copy)
        return cache[key]
    
    n = 2
    while len(cur) >= 2:
        chunk_size = max(1, len(cur) // n)
        # Partition cur into n (approximately) equal contiguous chunks
        chunks = [cur[i:i+chunk_size] for i in range(0, len(cur), chunk_size)]
        removed_any = False

        # Try to eliminate whole chunks
        for idx in range(len(chunks)):
            complement = []
            for j, ch in enumerate(chunks):
                if j != idx:
                    complement.extend(ch)
            if cached_test(complement) == 'trigger_and_fuzzer_build':
                cur = complement
                n = max(2, n - 1)  # decrease granularity after success
                removed_any = True
                break  # restart with new partition

        if removed_any:
            continue

        # No chunk removable; increase granularity (finer splits)
        if n >= len(cur):
            break
        n = min(len(cur), n * 2)

    # Optional: final single-removal sweep to ensure 1-minimal
    i = 0
    while i < len(cur):
        trial = cur[:i] + cur[i+1:]
        if cached_test(trial) == 'trigger_and_fuzzer_build':
            cur = trial
        else:
            i += 1

    return cur


def apply_unified_diff_to_string(original_text: str, diff_text: str, *, reverse: bool=False) -> str:
    """
    Apply a unified diff (single file) to original_text and return the patched text.
    Set reverse=True to apply the diff in reverse (i.e., unpatch).

    Robust features:
      - Correct side anchoring (old vs new) based on reverse flag
      - EOL normalization (handles files with/without trailing newline)
      - Fuzzy context matching around the nominal anchor (±20 lines), then global fallback
      - Skips common git headers (diff --git, index, ---/+++)
    """
    HUNK_RE = re.compile(r'^@@ -(?P<old_start>\d+)(?:,(?P<old_len>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_len>\d+)? )?@@')

    # Normalize to \n for matching; remember if file used \r\n
    used_crlf = '\r\n' in original_text and original_text.count('\r\n') >= original_text.count('\n')/2
    norm_original = original_text.replace('\r\n', '\n')
    orig_lines = norm_original.splitlines(keepends=True)
    if original_text and not original_text.endswith('\n'):
        # splitlines(keepends=True) keeps last line without \n; that’s fine
        pass

    lines = diff_text.splitlines(keepends=False)
    idx = 0

    # Skip headers
    def _is_header(s: str) -> bool:
        return (
            s.startswith('diff --git') or
            s.startswith('index ') or
            s.startswith('--- ') or
            s.startswith('+++ ') or
            s.startswith('new file mode') or
            s.startswith('deleted file mode') or
            s.startswith('rename from') or
            s.startswith('rename to')
        )

    while idx < len(lines) and _is_header(lines[idx]):
        idx += 1

    out = []
    cur = 0  # index into orig_lines

    def collect_hunk(start_idx: int):
        """Collect hunk body lines from start_idx+1 until next @@ or EOF."""
        j = start_idx + 1
        body = []
        while j < len(lines) and not lines[j].startswith('@@'):
            if lines[j] and lines[j].startswith('\\ No newline at end of file'):
                j += 1
                continue
            body.append(lines[j])
            j += 1
        return body, j

    def transform_tags(hunk_body, reverse: bool):
        """Return list of (tag, payload_with_newline)."""
        out = []
        for raw in hunk_body:
            if not raw:
                # Empty line in a diff is still a context/add/del marker; treat as empty payload following a tag
                tag, rest = ' ', ''
            else:
                tag, rest = raw[0], raw[1:]
            # swap only for +/- when reversing
            if reverse:
                if tag == '+': tag = '-'
                elif tag == '-': tag = '+'
            # Always compare with a trailing \n because orig_lines elements are keepends=True
            payload = rest + '\n'
            out.append((tag, payload))
        return out

    def build_base_seq(tagged_lines):
        """Base side is composed of context ' ' and deletions '-' AFTER tag transform."""
        return [p for t, p in tagged_lines if t in (' ', '-')]

    def find_anchor(nominal_idx: int, base_seq):
        """Try to match base_seq in orig_lines starting near nominal_idx."""
        if not base_seq:
            return nominal_idx  # pure insertion hunk: apply right at nominal

        # Helper to check match at position k
        def matches_at(k):
            if k < 0 or k + len(base_seq) > len(orig_lines):
                return False
            for off, expected in enumerate(base_seq):
                if orig_lines[k + off] != expected:
                    return False
            return True

        # 1) Try exact nominal
        if matches_at(nominal_idx):
            return nominal_idx

        # 2) Fuzzy window search around nominal (±20)
        WINDOW = 20
        start = max(0, nominal_idx - WINDOW)
        end = min(len(orig_lines) - len(base_seq), nominal_idx + WINDOW)
        for k in range(start, end + 1):
            if matches_at(k):
                return k

        # 3) Global fallback (can be expensive, but diffs are small)
        end = len(orig_lines) - len(base_seq)
        for k in range(0, max(0, end) + 1):
            if matches_at(k):
                return k

        return None  # not found

    while idx < len(lines):
        m = HUNK_RE.match(lines[idx])
        if not m:
            # skip stray lines until the next hunk
            idx += 1
            continue

        old_start = int(m.group('old_start'))
        new_start = int(m.group('new_start'))
        hunk_body, idx = collect_hunk(idx)

        tagged = transform_tags(hunk_body, reverse=reverse)
        base_seq = build_base_seq(tagged)

        # Choose side to anchor on
        nominal_line_1_based = new_start if reverse else old_start
        nominal_pos = max(0, nominal_line_1_based - 1)

        # Copy unchanged region up to where this hunk should apply (we will re-anchor below)
        # But first, actually find where the base_seq matches.
        anchor = find_anchor(nominal_pos, base_seq)
        if anchor is None:
            # Helpful diagnostics
            want_side = "new" if reverse else "old"
            raise ValueError(
                f"Hunk context not found near {want_side} line {nominal_line_1_based} "
                f"(base_seq length {len(base_seq)}, file has {len(orig_lines)-cur} remaining lines)"
            )

        # Emit everything from current cursor to anchor unchanged
        if anchor < cur:
            # This can happen if earlier hunks consumed beyond; in unified diffs hunks must be forward-only.
            raise ValueError(f"Hunk goes backward: anchor={anchor}, current={cur}")
        out.extend(orig_lines[cur:anchor])
        cur = anchor

        # Apply the hunk at 'cur'
        for tag, payload in tagged:
            if tag == ' ':
                # must match
                if cur >= len(orig_lines):
                    raise ValueError('Context extends past end of original')
                if orig_lines[cur] != payload:
                    raise ValueError('Context mismatch while applying hunk')
                out.append(orig_lines[cur])
                cur += 1
            elif tag == '-':
                # delete from original
                if cur >= len(orig_lines):
                    raise ValueError('Deletion extends past end of original')
                if orig_lines[cur] != payload:
                    raise ValueError('Deletion mismatch while applying hunk')
                cur += 1
            elif tag == '+':
                # insert into output
                out.append(payload)
            else:
                raise ValueError(f'Unexpected hunk line tag: {tag!r}')

    # Copy the remainder
    out.extend(orig_lines[cur:])

    result = ''.join(out)
    # Reconstitute CRLF if the original looked CRLF-ish
    if used_crlf:
        result = result.replace('\n', '\r\n')
        # Avoid doubling: the last CRLF would be fine; if the file originally had mixed endings, this normalizes to CRLF.
    return result


def split_function_parts(code: str) -> Tuple[str, str, str]:
    """
    Split function code into (prefix, body, suffix).

    - prefix: everything up to and including the first '{'
    - body: everything inside the outermost braces
    - suffix: everything from the last '}' onward

    If braces are unbalanced, returns (code, "", "").
    """
    start = code.find('{')
    end = code.rfind('}')
    if start == -1 or end == -1 or end <= start:
        return code, "", ""

    prefix = code[:start+1]
    body = code[start+1:end]
    suffix = code[end:]
    return prefix, body, suffix


def diff_strings(a_text: str, file_path_a: str, b_text: str, file_path_b: str, context_line: int = 3, line_number: int = 1) -> List[str]:
    """
    Generate a git-style unified diff between two strings.
    
    Args:
        a_text: content of old file
        b_text: content of new file
        file_path_a: relative path for the old file (e.g., 'blosc/schunk.c')
        file_path_b: relative path for the new file
        context_line: number of context lines around each hunk
        line_number: 1-based line number where the snippet starts in the real file
    
    Returns:
        A unified diff string with 'diff --git' header.
    """
    a_lines = a_text.splitlines(keepends=True)
    b_lines = b_text.splitlines(keepends=True)

    diff = list(difflib.unified_diff(
        a_lines,
        b_lines,
        fromfile=f"a/{file_path_a}",
        tofile=f"b/{file_path_b}",
        n=context_line,
    ))

    if not diff:
        return ""  # no differences

    # Prepend the git header
    git_header = f"diff --git a/{file_path_a} b/{file_path_b}\n" + diff[0] + diff[1][:-1]
    patches = []
    fir_line = ''
    rest_line = ''
    line_offset = max(line_number, 1) - 1
    hunk_header_re = re.compile(r'^@@ -(?P<old_start>\d+)(?:,(?P<old_len>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_len>\d+))? @@(?P<tail>.*)$')

    for line in diff[2:]:
        if line.startswith("@@"):
            if fir_line != '':
                patches.append(git_header + "\n" + fir_line + rest_line[:-1])
                rest_line = ''
            match = hunk_header_re.match(line)
            if not match:
                fir_line = line
                continue
            old_start = int(match.group('old_start')) + line_offset
            new_start = int(match.group('new_start')) + line_offset
            old_len = int(match.group('old_len')) if match.group('old_len') else 1
            new_len = int(match.group('new_len')) if match.group('new_len') else 1
            tail = match.group('tail')
            fir_line = f'@@ -{old_start},{old_len} +{new_start},{new_len} @@{tail}\n'
        else:
            rest_line += line
    patches.append(git_header + "\n" + fir_line + rest_line[:-1])
    
    return patches
