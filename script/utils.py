from typing import List, Any, Callable, Dict, Tuple
import copy
import re
import difflib

# Type: test_fn takes a list of patches (order preserved) and returns True/False
TestFn = Callable[[List[Any]], bool]

def minimize_greedy(patches: List[Any], test_fn: TestFn, patches_without_context: Dict[str, Any], context: Tuple) -> List[Any]:
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
            ctx_copy   = copy.deepcopy(context)
            cache[key] = test_fn(items_copy, patches_without_context, *ctx_copy)
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


def diff_strings(a_text: str, file_path_a: str, b_text: str, file_path_b: str, context_line = 3) -> List[str]:
    """
    Generate a git-style unified diff between two strings.
    
    Args:
        a_text: content of old file
        b_text: content of new file
        path: relative file path (e.g., 'blosc/schunk.c')
    
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
    for line in diff[2:]:
        if line.startswith("@@"):
            if fir_line != '':
                patches.append(git_header + "\n" + fir_line + rest_line[:-1])
                rest_line = ''
            old_line_info = line.split('@@')[1].strip().split(' ')[0]
            if old_line_info.count(',') < 1:
                # If old_line_info is not in the format 'old_start,old_end'
                old_line_info += ',1'
            new_line_info = line.split('@@')[1].strip().split(' ')[1]
            if new_line_info.count(',') < 1:
                # If new_line_info is not in the format 'new_start,new_end'
                new_line_info += ',1'
            old_offset = old_line_info.split(',')[1]
            new_start = new_line_info.split(',')[0].split('+')[1]
            fir_line = f'@@ -{new_start},{old_offset} {new_line_info} @@\n'
        else:
            rest_line += line
    patches.append(git_header + "\n" + fir_line + rest_line[:-1])
    
    return patches
