from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from artifacts import ArtifactStore
from build_log import iter_linker_errors


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_DIFF_GIT_RE = re.compile(r"^diff --git a/(?P<old>\S+) b/(?P<new>\S+)$")
_HUNK_HEADER_RE = re.compile(
    r"^@@\s+-(?P<old_start>\d+)(?:,(?P<old_len>\d+))?\s+\+(?P<new_start>\d+)(?:,(?P<new_len>\d+))?\s+@@(?P<suffix>.*)$"
)
_MAX_OVERLAP_MERGE_SPAN = 1500
_PATCH_APPLY_ERROR_PATTERNS = [
    re.compile(r"^error:\s+corrupt patch(?:\s+at\s+line\s+\d+)?\s*$", re.IGNORECASE),
    re.compile(r"^error:\s+patch failed:\s+.*$", re.IGNORECASE),
    re.compile(r"^error:\s+.*:\s+patch does not apply\s*$", re.IGNORECASE),
    re.compile(r"^error:\s+no valid patches in input.*$", re.IGNORECASE),
    re.compile(r"^patch:\s+\*{4}.*$", re.IGNORECASE),
    re.compile(r"^fatal:\s+patch failed.*$", re.IGNORECASE),
    # fuzz_helper strict reverse-apply guardrails
    re.compile(r"^oss-fuzz patch apply failed(?:\s*\(.*\))?\s*$", re.IGNORECASE),
    # `patch(1)` apply failures that may not be prefixed with "error:"
    re.compile(r"^can't find file to patch(?:\s+at\s+input\s+line\s+\d+)?\s*$", re.IGNORECASE),
    re.compile(r"^no file to patch\.\s+skipping patch\.\s*$", re.IGNORECASE),
    re.compile(r"^hunk\s+#\d+\s+ignored\s+at\s+\d+\.?\s*$", re.IGNORECASE),
    re.compile(r"^\d+\s+out of\s+\d+\s+hunks?\s+ignored\b.*$", re.IGNORECASE),
]
_PATCH_INPUT_LINE_RE = re.compile(r"\binput line (?P<line>\d+)\b", re.IGNORECASE)
# Warnings about undeclared functions (treated as errors for build_ok)
_UNDECLARED_FUNC_WARNING_PATTERNS = [
    "call to undeclared function",
    "implicit declaration of function",
]
# Regex to detect compiler errors in build output (file:line:col: error: msg)
_COMPILER_ERROR_RE = re.compile(r"^[^:\n]+:\d+:\d+:\s*(?:fatal\s+)?error:", re.MULTILINE)
_SCRIPT_DIR = Path(__file__).resolve().parents[2]
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from migration_tools.patch_bundle import load_patch_bundle  # noqa: E402


def _repo_root() -> Path:
    # script/react_agent/tools/ossfuzz_tools.py -> script/react_agent/tools -> script/react_agent -> script -> repo
    return Path(__file__).resolve().parents[3]


def _ossfuzz_lock_path() -> Path:
    """Return a stable lock path for OSS-Fuzz Docker test runs.

    This lock is used to serialize `ossfuzz_apply_patch_and_test` calls across concurrent agent processes that share
    the same repo checkout (and therefore the same `oss-fuzz/` working tree and `oss-fuzz/build/*` directories).

    Override with:
      - `REACT_AGENT_OSSFUZZ_LOCK_PATH`: absolute/relative lock file path
      - `REACT_AGENT_OSSFUZZ_LOCK_DIR`: directory to place the default lock file in
    """
    raw_path = str(os.environ.get("REACT_AGENT_OSSFUZZ_LOCK_PATH", "") or "").strip()
    if raw_path:
        return Path(raw_path).expanduser().resolve()

    raw_dir = str(os.environ.get("REACT_AGENT_OSSFUZZ_LOCK_DIR", "") or "").strip()
    lock_dir = Path(raw_dir).expanduser().resolve() if raw_dir else (_repo_root() / "data" / "react_agent_locks").resolve()
    return (lock_dir / "ossfuzz_apply_patch_and_test.lock").resolve()


class _FileLock:
    """Cross-process advisory file lock (best-effort, blocks until acquired)."""

    def __init__(self, lock_path: Path, *, wait_message: str) -> None:
        """Initialize a lock over `lock_path`."""
        self.lock_path = Path(lock_path)
        self.wait_message = str(wait_message or "").rstrip("\n")
        self._fd: Optional[int] = None

    def __enter__(self) -> "_FileLock":
        """Acquire the lock, blocking until available."""
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        self._fd = fd

        try:
            import fcntl  # Unix-only

            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if self.wait_message:
                    sys.stderr.write(self.wait_message + "\n")
                    sys.stderr.flush()
                fcntl.flock(fd, fcntl.LOCK_EX)
        except Exception:
            # If locking is unavailable (e.g., non-Unix), proceed without blocking; callers still work,
            # but OSS-Fuzz runs may clobber shared build/out directories when concurrent.
            pass

        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        """Release the lock."""
        fd = self._fd
        self._fd = None
        if fd is None:
            return
        try:
            import fcntl  # Unix-only

            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except Exception:
                pass
        except Exception:
            pass
        try:
            os.close(fd)
        except Exception:
            pass


def _artifact_allow_root() -> Path:
    root = str(os.environ.get("REACT_AGENT_ARTIFACT_ROOT", "") or "").strip()
    if root:
        return Path(root).expanduser().resolve()
    return (_repo_root() / "data" / "react_agent_artifacts").resolve()


def _env_flag(name: str) -> bool:
    return str(os.environ.get(name, "") or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _safe_filename(name: str, *, max_len: int = 160) -> str:
    raw = str(name or "").strip()
    raw = raw.replace(os.sep, "_")
    cleaned = _SAFE_NAME_RE.sub("_", raw).strip("._-")
    if not cleaned:
        cleaned = "artifact"
    return cleaned[:max_len]


def _validate_under_root(path: Path, root: Path) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Path must be under artifact root: {root}") from exc


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    for i in range(1, 10_000):
        candidate = parent / f"{stem}.{i}{suffix}"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not allocate unique artifact path for: {path}")


def _find_patch_apply_error(text: str) -> str:
    raw = str(text or "")
    if not raw.strip():
        return ""
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        for pat in _PATCH_APPLY_ERROR_PATTERNS:
            if pat.search(stripped):
                return stripped
    return ""


def _extract_last_patch_input_line(text: str) -> int:
    """Return the last `input line N` value from patch output."""
    raw = str(text or "")
    if not raw.strip():
        return 0
    last = 0
    for m in _PATCH_INPUT_LINE_RE.finditer(raw):
        try:
            n = int(m.group("line") or 0)
        except Exception:
            continue
        if n > 0:
            last = n
    return last


def _extract_diff_block_for_line(patch_text: str, line_no: int) -> str:
    """Return the `diff --git` block that contains `line_no` (1-based)."""
    lines = str(patch_text or "").splitlines()
    if not lines:
        return ""
    n = int(line_no or 0)
    if n <= 0:
        return ""
    if n > len(lines):
        n = len(lines)

    start = -1
    for i in range(n - 1, -1, -1):
        if str(lines[i] or "").startswith("diff --git "):
            start = i
            break
    if start < 0:
        return ""

    end = len(lines)
    for j in range(start + 1, len(lines)):
        if str(lines[j] or "").startswith("diff --git "):
            end = j
            break

    block = lines[start:end]
    if not block:
        return ""
    return "\n".join(block).rstrip("\n") + "\n"


def _has_undeclared_func_warning(text: str) -> bool:
    """Check if build output contains undeclared function warnings (treated as errors)."""
    raw = str(text or "").lower()
    return any(pattern in raw for pattern in _UNDECLARED_FUNC_WARNING_PATTERNS)


def _has_compiler_errors(text: str) -> bool:
    """Check if build output contains compiler errors (file:line:col: error: msg)."""
    return bool(_COMPILER_ERROR_RE.search(text or ""))


def _has_linker_errors(text: str) -> bool:
    """Check if build output contains linker errors (undefined reference)."""
    return bool(iter_linker_errors(text or ""))


def _allowed_patch_roots_from_env() -> list[str] | None:
    raw = os.environ.get("REACT_AGENT_PATCH_ALLOWED_ROOTS", "").strip()
    if not raw:
        return None
    roots = [r.strip() for r in raw.split(os.pathsep) if r.strip()]
    return roots or None


def _infer_patch_key_from_path(path: Path, patch_keys: set[str]) -> str:
    # Build reverse mapping: safe_name -> original patch_key
    safe_to_original: Dict[str, str] = {}
    for pk in patch_keys:
        safe_name = _safe_filename(pk)
        safe_to_original[safe_name] = pk

    for parent in [path.parent, *path.parents]:
        name = str(parent.name or "").strip()
        if name and name in patch_keys:
            return name
        # Check if directory name is a safe-ified version of a patch_key
        if name and name in safe_to_original:
            return safe_to_original[name]
        if name.startswith("_extra_"):
            return name
    raise ValueError(
        "Could not infer patch_key for override patch file. "
        "Put override artifacts under a directory named <patch_key> (e.g. data/react_agent_artifacts/<patch_key>/...)."
    )


def _infer_primary_patch_key_from_path(path: Path, patch_keys: set[str]) -> str:
    """Infer a non-_extra_ patch_key from a path's parent directories (best-effort)."""
    # Build reverse mapping: safe_name -> original patch_key
    safe_to_original: Dict[str, str] = {}
    for pk in patch_keys:
        safe_name = _safe_filename(pk)
        safe_to_original[safe_name] = pk

    for parent in [path.parent, *path.parents]:
        name = str(parent.name or "").strip()
        if not name:
            continue
        # Check direct match
        if name in patch_keys and not name.startswith("_extra_"):
            return name
        # Check safe-ified match
        if name in safe_to_original:
            original = safe_to_original[name]
            if not original.startswith("_extra_"):
                return original
    return ""


def _strip_diff_path_prefix(path: str) -> str:
    out = str(path or "").strip()
    if out.startswith("a/") or out.startswith("b/"):
        return out[2:]
    return out


def _parse_diff_block(block_lines: list[str]) -> Optional[Dict[str, Any]]:
    """Parse one `diff --git ...` block with unified hunks."""
    if not block_lines:
        return None
    first = str(block_lines[0] or "").strip()
    m0 = _DIFF_GIT_RE.match(first)
    old_path = str(m0.group("old") or "") if m0 else ""
    new_path = str(m0.group("new") or "") if m0 else ""

    header_lines: list[str] = []
    hunks: list[Dict[str, Any]] = []
    i = 0
    while i < len(block_lines):
        line = block_lines[i]
        if line.startswith("@@"):
            mh = _HUNK_HEADER_RE.match(line.strip())
            if not mh:
                return None
            old_start = int(mh.group("old_start"))
            old_len = int(mh.group("old_len") or 1)
            new_start = int(mh.group("new_start"))
            new_len = int(mh.group("new_len") or 1)
            suffix = str(mh.group("suffix") or "")
            body: list[str] = []
            i += 1
            while i < len(block_lines) and not block_lines[i].startswith("@@"):
                if block_lines[i] == "":
                    i += 1
                    continue
                body.append(block_lines[i])
                i += 1
            hunks.append(
                {
                    "old_start": old_start,
                    "old_len": old_len,
                    "new_start": new_start,
                    "new_len": new_len,
                    "suffix": suffix,
                    "body": body,
                }
            )
            continue
        header_lines.append(line)
        stripped = line.strip()
        if stripped.startswith("--- "):
            old_path = _strip_diff_path_prefix(stripped[len("--- ") :].strip())
        elif stripped.startswith("+++ "):
            new_path = _strip_diff_path_prefix(stripped[len("+++ ") :].strip())
        i += 1

    if not hunks:
        return None

    old_path = _strip_diff_path_prefix(old_path)
    new_path = _strip_diff_path_prefix(new_path)
    file_key = new_path if new_path and new_path != "/dev/null" else old_path
    if not file_key:
        return None

    return {
        "file_key": file_key,
        "old_path": old_path,
        "new_path": new_path,
        "header_lines": header_lines,
        "hunks": hunks,
    }


def _merge_overlapping_hunk_cluster(cluster: list[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Merge a cluster of overlapping/adjacent hunks anchored to old-file line numbers."""
    if not cluster:
        return None
    if len(cluster) == 1:
        return cluster[0]

    deltas = {int(h["new_start"]) - int(h["old_start"]) for h in cluster}
    if len(deltas) != 1:
        return None
    delta = next(iter(deltas))

    old_begin = min(int(h["old_start"]) for h in cluster)
    old_end = max(int(h["old_start"]) + int(h["old_len"]) for h in cluster)
    if (old_end - old_begin) > _MAX_OVERLAP_MERGE_SPAN:
        return None

    old_line_scores: Dict[int, Dict[str, int]] = {}
    for h in cluster:
        pos = int(h["old_start"])
        for raw in list(h.get("body") or []):
            if not raw:
                prefix = " "
                text = ""
            else:
                prefix = raw[0]
                text = raw[1:]
            if prefix in {" ", "-"}:
                score = 10 if prefix == "-" else 1
                scores = old_line_scores.setdefault(pos, {})
                scores[text] = int(scores.get(text, 0)) + score
                pos += 1
            elif prefix in {"+", "\\"}:
                continue
            else:
                scores = old_line_scores.setdefault(pos, {})
                scores[raw] = int(scores.get(raw, 0)) + 1
                pos += 1

    base_old_lines: Dict[int, str] = {}
    if old_end > old_begin:
        for pos in range(old_begin, old_end):
            choices = old_line_scores.get(pos, {})
            if not choices:
                return None
            best = max(choices.values())
            winners = [line for line, score in choices.items() if score == best]
            if len(winners) != 1:
                return None
            base_old_lines[pos] = winners[0]

    insert_before: Dict[int, list[str]] = {}
    delete_pos: set[int] = set()
    for h in sorted(cluster, key=lambda it: int(it.get("_order", 0))):
        pos = int(h["old_start"])
        for raw in list(h.get("body") or []):
            if not raw:
                prefix = " "
                text = ""
            else:
                prefix = raw[0]
                text = raw[1:]
            if prefix == "+":
                insert_before.setdefault(pos, []).append(text)
            elif prefix == "-":
                delete_pos.add(pos)
                pos += 1
            elif prefix == " ":
                pos += 1
            elif prefix == "\\":
                continue
            else:
                pos += 1

    merged_body: list[str] = []
    if old_end == old_begin:
        for text in insert_before.get(old_begin, []):
            merged_body.append("+" + text if text else "+")
    else:
        for pos in range(old_begin, old_end):
            for text in insert_before.get(pos, []):
                merged_body.append("+" + text if text else "+")
            old_line = base_old_lines[pos]
            if pos in delete_pos:
                merged_body.append("-" + old_line if old_line else "-")
            else:
                merged_body.append(" " + old_line if old_line else " ")
        for text in insert_before.get(old_end, []):
            merged_body.append("+" + text if text else "+")

    if not merged_body:
        return None

    old_len = sum(1 for line in merged_body if line and line[0] not in {"+", "\\"})
    new_len = sum(1 for line in merged_body if line and line[0] not in {"-", "\\"})
    suffix = next((str(h.get("suffix") or "") for h in cluster if str(h.get("suffix") or "").strip()), "")

    return {
        "old_start": old_begin,
        "old_len": old_len,
        "new_start": old_begin + delta,
        "new_len": new_len,
        "suffix": suffix,
        "body": merged_body,
        "_order": min(int(h.get("_order", 0)) for h in cluster),
    }


def _flip_hunk_direction(hunk: Dict[str, Any]) -> Dict[str, Any]:
    """Swap old/new sides of a unified-diff hunk."""
    flipped_body: list[str] = []
    for raw in list(hunk.get("body") or []):
        if not raw:
            flipped_body.append(raw)
            continue
        prefix = raw[0]
        rest = raw[1:]
        if prefix == "+":
            flipped_body.append("-" + rest)
        elif prefix == "-":
            flipped_body.append("+" + rest)
        else:
            flipped_body.append(raw)
    return {
        "old_start": int(hunk["new_start"]),
        "old_len": int(hunk["new_len"]),
        "new_start": int(hunk["old_start"]),
        "new_len": int(hunk["old_len"]),
        "suffix": str(hunk.get("suffix") or ""),
        "body": flipped_body,
        "_order": int(hunk.get("_order", 0)),
    }


def _merge_overlapping_hunk_cluster_via_reverse(cluster: list[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Fallback merge: merge in reverse-apply space, then flip back."""
    reversed_cluster = [_flip_hunk_direction(h) for h in cluster]
    merged_reversed = _merge_overlapping_hunk_cluster(reversed_cluster)
    if merged_reversed is None:
        return None
    merged = _flip_hunk_direction(merged_reversed)
    merged["_order"] = min(int(h.get("_order", 0)) for h in cluster)
    return merged


def _coalesce_overlapping_file_hunks(hunks: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    if len(hunks) <= 1:
        return hunks

    indexed: list[Dict[str, Any]] = []
    for idx, h in enumerate(hunks):
        h2 = dict(h)
        h2["_order"] = idx
        indexed.append(h2)

    indexed.sort(
        key=lambda h: (
            int(h["old_start"]),
            int(h["old_start"]) + int(h["old_len"]),
            int(h.get("_order", 0)),
        )
    )

    merged: list[Dict[str, Any]] = []
    cluster: list[Dict[str, Any]] = []
    cluster_end = 0

    def _flush_cluster() -> None:
        nonlocal cluster
        if not cluster:
            return
        if len(cluster) == 1:
            merged.append(cluster[0])
        else:
            merged_hunk = _merge_overlapping_hunk_cluster(cluster)
            if merged_hunk is None:
                merged_hunk = _merge_overlapping_hunk_cluster_via_reverse(cluster)
            if merged_hunk is None:
                merged.extend(cluster)
            else:
                merged.append(merged_hunk)
        cluster = []

    for h in indexed:
        start = int(h["old_start"])
        end = int(h["old_start"]) + int(h["old_len"])
        if not cluster:
            cluster = [h]
            cluster_end = end
            continue
        if start <= cluster_end:
            cluster.append(h)
            if end > cluster_end:
                cluster_end = end
            continue
        _flush_cluster()
        cluster = [h]
        cluster_end = end
    _flush_cluster()

    merged.sort(
        key=lambda h: (
            int(h["old_start"]),
            int(h["old_start"]) + int(h["old_len"]),
            int(h.get("_order", 0)),
        )
    )
    return merged


def _consolidate_same_file_diff_blocks(patch_text: str) -> str:
    """Merge only overlapping single-hunk pairs from consecutive same-file occurrences."""
    raw = str(patch_text or "").rstrip("\n")
    if not raw.strip():
        return ""

    lines = raw.splitlines()
    blocks: list[list[str]] = []
    i = 0
    while i < len(lines):
        if not lines[i].startswith("diff --git "):
            if lines[i].strip():
                return raw + "\n"
            i += 1
            continue
        start = i
        i += 1
        while i < len(lines) and not lines[i].startswith("diff --git "):
            i += 1
        block = list(lines[start:i])
        while block and block[-1] == "":
            block.pop()
        if block:
            blocks.append(block)

    if not blocks:
        return raw + "\n"

    parsed_blocks: list[Dict[str, Any]] = []
    for block in blocks:
        parsed = _parse_diff_block(block)
        if parsed is None:
            return raw + "\n"
        parsed_blocks.append({"raw_lines": block, "parsed": parsed, "file_key": str(parsed.get("file_key") or "")})

    def _old_span(h: Dict[str, Any]) -> tuple[int, int]:
        start = int(h.get("old_start", 0) or 0)
        end = start + int(h.get("old_len", 0) or 0)
        return start, end

    def _old_ranges_overlap(h1: Dict[str, Any], h2: Dict[str, Any]) -> bool:
        s1, e1 = _old_span(h1)
        s2, e2 = _old_span(h2)
        if e1 <= s1 or e2 <= s2:
            return False
        return max(s1, s2) < min(e1, e2)

    def _old_side_deletion_span(h: Dict[str, Any]) -> tuple[int, int]:
        """Return the old-side line range covered by ``-`` lines in the hunk."""
        pos = int(h.get("old_start", 0) or 0)
        first: Optional[int] = None
        last = pos
        for line in (h.get("body") or []):
            if str(line).startswith("-"):
                if first is None:
                    first = pos
                last = pos + 1
                pos += 1
            elif str(line).startswith("+"):
                pass  # ``+`` lines don't consume old-side positions
            else:
                pos += 1
        if first is None:
            return (0, 0)
        return (first, last)

    def _reverse_apply_would_conflict(h1: Dict[str, Any], h2: Dict[str, Any]) -> bool:
        """Check if two blocks would conflict when reverse-applied separately.

        In ``patch -R`` mode the forward ``+`` (new) side becomes the "match"
        side.  If two blocks' new-side ranges overlap, the first one processed
        corrupts the context that the second one expects.

        Exception: when both hunks are deletion-only (no ``+`` lines) and their
        actual deletion ranges do not overlap (only shared context), they are
        safe to apply separately in bottom-up order.  Merging them risks
        dropping original file content from the context between deletion sites.
        """
        s1 = int(h1.get("new_start", 0) or 0)
        e1 = s1 + int(h1.get("new_len", 0) or 0)
        s2 = int(h2.get("new_start", 0) or 0)
        e2 = s2 + int(h2.get("new_len", 0) or 0)
        if e1 <= s1 or e2 <= s2:
            return False
        if not (max(s1, s2) < min(e1, e2)):
            return False  # new-side ranges don't overlap at all

        # New-side ranges overlap.  If both hunks are deletion-only and
        # their actual ``-`` line ranges don't overlap, the overlap is
        # purely in context lines — safe to apply separately.
        h1_has_plus = any(str(l).startswith("+") for l in (h1.get("body") or []))
        h2_has_plus = any(str(l).startswith("+") for l in (h2.get("body") or []))
        if not h1_has_plus and not h2_has_plus:
            ds1, de1 = _old_side_deletion_span(h1)
            ds2, de2 = _old_side_deletion_span(h2)
            if ds1 < de1 and ds2 < de2 and not (max(ds1, ds2) < min(de1, de2)):
                return False  # context-only overlap, safe separately

        return True

    file_to_indices: Dict[str, list[int]] = {}
    for idx, entry in enumerate(parsed_blocks):
        key = str(entry.get("file_key") or "")
        if not key:
            continue
        file_to_indices.setdefault(key, []).append(idx)

    replaced_blocks: Dict[int, Dict[str, Any]] = {}
    removed_indices: set[int] = set()
    changed = False

    for key, idxs in file_to_indices.items():
        if len(idxs) < 2:
            continue
        j = 0
        while j < len(idxs) - 1:
            i1 = idxs[j]
            if i1 in removed_indices:
                j += 1
                continue
            # Find the next non-removed partner.
            k = j + 1
            while k < len(idxs) and idxs[k] in removed_indices:
                k += 1
            if k >= len(idxs):
                break
            i2 = idxs[k]
            cur = replaced_blocks.get(i1, parsed_blocks[i1])
            nxt = replaced_blocks.get(i2, parsed_blocks[i2])
            cur_hunks = list(cur["parsed"].get("hunks") or [])
            nxt_hunks = list(nxt["parsed"].get("hunks") or [])
            if len(cur_hunks) != 1 or len(nxt_hunks) != 1:
                j = k
                continue

            h1 = dict(cur_hunks[0])
            h2 = dict(nxt_hunks[0])
            if not _old_ranges_overlap(h1, h2):
                j = k
                continue

            # Only merge if reverse-applying them separately would conflict.
            # In -R mode, overlapping new-side ranges corrupt each other's context.
            if not _reverse_apply_would_conflict(h1, h2):
                j = k
                continue

            h1["_order"] = 0
            h2["_order"] = 1
            merged = _merge_overlapping_hunk_cluster([h1, h2])
            if merged is None:
                merged = _merge_overlapping_hunk_cluster_via_reverse([h1, h2])
            if merged is None:
                j = k
                continue

            header_lines = list(cur["parsed"].get("header_lines") or [])
            merged_lines: list[str] = []
            merged_lines.extend(header_lines)
            suffix = str(merged.get("suffix") or "")
            merged_lines.append(
                f"@@ -{int(merged['old_start'])},{int(merged['old_len'])} +{int(merged['new_start'])},{int(merged['new_len'])} @@{suffix}".rstrip()
            )
            merged_lines.extend(list(merged.get("body") or []))
            reparsed = _parse_diff_block(merged_lines)
            if reparsed is None:
                j = k
                continue

            replaced_blocks[i1] = {
                "raw_lines": merged_lines,
                "parsed": reparsed,
                "file_key": str(reparsed.get("file_key") or key),
            }
            removed_indices.add(i2)
            changed = True
            # Keep i1 as the current anchor; it may overlap with the next same-file block.
            continue

    if not changed:
        return raw + "\n"

    out_lines: list[str] = []
    for idx, entry in enumerate(parsed_blocks):
        if idx in removed_indices:
            continue
        block = replaced_blocks.get(idx, entry)
        out_lines.extend(list(block.get("raw_lines") or []))
        out_lines.append("")

    return "\n".join(out_lines).rstrip("\n") + "\n"


def _split_multi_hunk_diff_blocks(patch_text: str) -> str:
    """Split each multi-hunk `diff --git` block into one block per hunk.

    This keeps each hunk independently addressable in downstream tooling that
    consumes merged OSS-Fuzz diff artifacts.
    """
    raw = str(patch_text or "").rstrip("\n")
    if not raw.strip():
        return ""

    lines = raw.splitlines()
    blocks: list[list[str]] = []
    i = 0
    while i < len(lines):
        if not lines[i].startswith("diff --git "):
            if lines[i].strip():
                return raw + "\n"
            i += 1
            continue
        start = i
        i += 1
        while i < len(lines) and not lines[i].startswith("diff --git "):
            i += 1
        block = list(lines[start:i])
        while block and block[-1] == "":
            block.pop()
        if block:
            blocks.append(block)

    if not blocks:
        return raw + "\n"

    changed = False
    out_blocks: list[list[str]] = []
    for block in blocks:
        parsed = _parse_diff_block(block)
        if parsed is None:
            return raw + "\n"
        hunks = list(parsed.get("hunks") or [])
        if len(hunks) <= 1:
            out_blocks.append(block)
            continue

        changed = True
        header_lines = list(parsed.get("header_lines") or [])
        for hunk in hunks:
            suffix = str(hunk.get("suffix") or "")
            single: list[str] = []
            single.extend(header_lines)
            single.append(
                f"@@ -{int(hunk['old_start'])},{int(hunk['old_len'])} +{int(hunk['new_start'])},{int(hunk['new_len'])} @@{suffix}".rstrip()
            )
            single.extend(list(hunk.get("body") or []))
            out_blocks.append(single)

    if not changed:
        return raw + "\n"

    # Re-sort blocks by new_start descending (bottom-up) so that split hunks
    # from multi-hunk entries land in the correct position among other blocks.
    def _block_new_start(blk: list[str]) -> int:
        for ln in blk:
            m = _HUNK_HEADER_RE.match(ln.strip())
            if m:
                return int(m.group("new_start"))
        return 0

    out_blocks.sort(key=lambda blk: (-_block_new_start(blk), ""))

    out_lines: list[str] = []
    for block in out_blocks:
        out_lines.extend(block)
        out_lines.append("")
    return "\n".join(out_lines).rstrip("\n") + "\n"


def _extra_hunk_minus_lines(patch_text: str) -> list[str]:
    """Return raw code lines for all '-' diff lines (excluding '---' headers)."""
    out: list[str] = []
    for raw in str(patch_text or "").splitlines():
        if not raw.startswith("-") or raw.startswith("---"):
            continue
        out.append("" if raw == "-" else raw[1:])
    return out


def _extra_hunk_minus_blocks_first_hunk(patch_text: str) -> list[list[str]]:
    """Return inserted blocks (raw code, no diff prefix) for the first hunk.

    Blocks are split on blank '-' lines only at file scope (brace depth 0).
    This keeps tag/type bodies (enum/struct/union) atomic even when they
    contain internal blank lines, preventing merge-time reordering from
    interleaving declarations into the middle of a type definition.
    """
    raw = str(patch_text or "")
    if not raw.strip():
        return []

    lines = raw.splitlines()
    first_hunk = next((i for i, l in enumerate(lines) if l.startswith("@@")), -1)
    if first_hunk < 0:
        return []

    end = len(lines)
    for i in range(first_hunk + 1, len(lines)):
        if lines[i].startswith("@@") or lines[i].startswith("diff --git "):
            end = i
            break

    minus: list[str] = []
    for l in lines[first_hunk + 1 : end]:
        if not l.startswith("-") or l.startswith("---"):
            continue
        minus.append("" if l == "-" else l[1:])

    def _brace_delta_ignoring_comments(code: str, in_block_comment: bool) -> tuple[int, bool]:
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

    blocks: list[list[str]] = []
    cur: list[str] = []
    brace_depth = 0
    in_block_comment = False
    for line in minus:
        if line == "":
            if brace_depth == 0:
                if cur:
                    blocks.append(cur)
                    cur = []
            elif cur:
                # Preserve blank lines that are inside multi-line declarations.
                cur.append("")
            continue

        cur.append(line)
        delta, in_block_comment = _brace_delta_ignoring_comments(line, in_block_comment)
        brace_depth += delta
        if brace_depth < 0:
            brace_depth = 0
    if cur:
        blocks.append(cur)
    return blocks


def _strip_first_hunk_minus_lines(patch_text: str) -> str:
    """Return patch_text with '-' diff lines removed from the first hunk body (keeps headers and context)."""
    raw = str(patch_text or "")
    if not raw.strip():
        return ""
    lines = raw.splitlines()
    first_hunk = next((i for i, l in enumerate(lines) if l.startswith("@@")), -1)
    if first_hunk < 0:
        return raw.rstrip("\n") + "\n"

    end = len(lines)
    for i in range(first_hunk + 1, len(lines)):
        if lines[i].startswith("@@") or lines[i].startswith("diff --git "):
            end = i
            break

    body = [l for l in lines[first_hunk + 1 : end] if not (l.startswith("-") and not l.startswith("---"))]
    updated = lines[: first_hunk + 1] + body + lines[end:]
    return "\n".join(updated).rstrip("\n") + "\n"


_EXTRA_DEFINE_RE = re.compile(r"^#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b")
_EXTRA_TAG_RE = re.compile(r"^(?:typedef\s+)?(?P<kind>struct|union|enum)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b")
_EXTRA_FUNC_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_EXTRA_CONTROL_WORDS = {
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
_EXTRA_TYPE_FRAGMENT_TOKENS = {
    "char",
    "const",
    "double",
    "float",
    "int",
    "long",
    "short",
    "signed",
    "static",
    "unsigned",
    "void",
    "volatile",
}


def _typedef_declared_name(lines: list[str]) -> str:
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


def _is_comment_line(line: str) -> bool:
    """Return True if line is a C/C++ comment line (not code)."""
    s = line.strip()
    if not s:
        return False
    # Single-line comment or block-comment start/continuation
    if s.startswith("//") or s.startswith("/*") or s.startswith("*"):
        return True
    # Multi-line comment continuation/end that doesn't start with /* or *
    # e.g., "   some text */" is the end of a block comment
    if s.endswith("*/") and "/*" not in s:
        return True
    return False


def _extra_insert_block_semantic_id(block: list[str]) -> tuple[str, str]:
    """Return (kind, name) for a file-scope insertion block in an `_extra_*` hunk."""
    # Skip comment lines to find the first meaningful line for classification
    head = next((str(l).strip() for l in (block or []) if str(l).strip() and not _is_comment_line(str(l))), "")
    if not head:
        return ("text", "")

    m = _EXTRA_DEFINE_RE.match(head)
    if m:
        return ("define", str(m.group(1) or ""))

    if head.startswith("typedef"):
        name = _typedef_declared_name(block)
        return ("typedef", name or "\n".join(block).strip())

    m = _EXTRA_TAG_RE.match(head)
    if m:
        kind = str(m.group("kind") or "")
        name = str(m.group("name") or "")
        return ("tag", f"{kind} {name}".strip())

    func_name = ""
    for raw in block:
        for m2 in _EXTRA_FUNC_NAME_RE.finditer(str(raw or "")):
            cand = str(m2.group(1) or "")
            if cand and cand not in _EXTRA_CONTROL_WORDS:
                func_name = cand
                break
        if func_name:
            break
    if func_name:
        return ("prototype", func_name)

    return ("text", "\n".join(block).strip())


def _extra_block_is_static_prototype(block: list[str]) -> bool:
    joined = " ".join(str(l).strip() for l in (block or []) if str(l).strip())
    return bool(re.search(r"(?<![A-Za-z0-9_])static(?![A-Za-z0-9_])", joined))


def _choose_better_extra_block(kind: str, *, current: list[str], candidate: list[str]) -> list[str]:
    if kind == "prototype":
        cur_static = _extra_block_is_static_prototype(current)
        cand_static = _extra_block_is_static_prototype(candidate)
        if cur_static != cand_static:
            return candidate if cand_static else current
        # Prefer blocks that end in ';' (prototype) and then "more complete" (more text).
        cur_tail = next((str(l).strip() for l in reversed(current) if str(l).strip()), "")
        cand_tail = next((str(l).strip() for l in reversed(candidate) if str(l).strip()), "")
        cur_semicolon = cur_tail.endswith(";")
        cand_semicolon = cand_tail.endswith(";")
        if cur_semicolon != cand_semicolon:
            return candidate if cand_semicolon else current
        return candidate if len("\n".join(candidate)) > len("\n".join(current)) else current

    if kind in {"typedef", "tag"}:
        cur_def = any("{" in str(l) for l in current)
        cand_def = any("{" in str(l) for l in candidate)
        if cur_def != cand_def:
            return candidate if cand_def else current
        return candidate if len("\n".join(candidate)) > len("\n".join(current)) else current

    # For defines (and unknown), keep the first-seen block unless the candidate is strictly longer.
    return candidate if len("\n".join(candidate)) > len("\n".join(current)) else current


def _extra_hunk_merge_sanity_issues(patch_text: str) -> list[str]:
    issues: list[str] = []

    def is_type_fragment_line(line: str) -> bool:
        stripped = str(line or "").strip()
        if not stripped:
            return False
        if any(ch in stripped for ch in (";", "(", ")", "{", "}", "[", "]", "=", ",", "#")):
            return False
        toks = [t for t in stripped.split() if t]
        return bool(toks) and all(t in _EXTRA_TYPE_FRAGMENT_TOKENS for t in toks)

    for block in _extra_hunk_minus_blocks_first_hunk(patch_text):
        if not block:
            continue
        if len(block) == 1 and is_type_fragment_line(block[0]):
            issues.append(f"stray type fragment block: {block[0]!r}")
            continue

        kind, _name = _extra_insert_block_semantic_id(block)
        if kind != "prototype":
            continue

        tail = next((str(l).strip() for l in reversed(block) if str(l).strip()), "")
        if tail and not tail.endswith(";"):
            issues.append(f"incomplete prototype (missing ';'): {tail!r}")
    return issues


def _maybe_llm_repair_extra_hunk_insert_lines(*, insert_lines: list[str], issues: list[str]) -> list[str] | None:
    """Best-effort LLM repair pass for `_extra_*` merge corruption (disabled by default)."""
    if not issues or not _env_flag("REACT_AGENT_ENABLE_EXTRA_MERGE_REPAIR"):
        return None

    try:
        import json  # noqa: PLC0415

        from react_agent.models import ModelError, OpenAIChatCompletionsModel  # type: ignore
    except Exception:
        return None

    try:
        model = OpenAIChatCompletionsModel.from_env()
        override_model = str(os.environ.get("REACT_AGENT_EXTRA_MERGE_REPAIR_MODEL", "") or "").strip()
        if override_model:
            model.model = override_model
        try:
            model.max_tokens = int(os.environ.get("REACT_AGENT_EXTRA_MERGE_REPAIR_MAX_TOKENS", "") or "") or model.max_tokens
        except Exception:
            pass

        payload = {"issues": issues[:20], "insert_lines": insert_lines}
        messages = [
            {
                "role": "system",
                "content": (
                    "You repair file-scope C insertion snippets for an OSS-Fuzz revert patch `_extra_*` hunk.\n"
                    "Input is a list of code lines (no diff prefixes). Empty-string entries represent blank lines.\n"
                    "Rewrite into a coherent set of declarations/macros:\n"
                    "- Never output partial type fragments (e.g. `int`, `unsigned`, `static int`).\n"
                    "- Keep multi-line prototypes atomic.\n"
                    "- Deduplicate by semantic key: function name (prefer `static` variants), macro name, typedef/tag name.\n"
                    "Return ONLY valid JSON: {\"insert_lines\": [..]}.\n"
                ),
            },
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ]

        raw = model.complete(messages)
        data = json.loads(raw)
        repaired = data.get("insert_lines") if isinstance(data, dict) else None
        if not isinstance(repaired, list) or not repaired:
            return None
        out: list[str] = []
        for item in repaired:
            if item is None:
                continue
            out.append(str(item))
        return out or None
    except ModelError:
        return None
    except Exception:
        return None


def _extract_override_anchor(text: str) -> int:
    """Return ``old_start`` from the first ``@@`` hunk header, or 0 on failure."""
    for line in str(text or "").splitlines():
        m = _HUNK_HEADER_RE.match(line)
        if m:
            return int(m.group("old_start"))
    return 0


def _extract_diff_header(text: str) -> str:
    """Return diff header lines (``diff --git``, ``---``, ``+++``) before the first ``@@``."""
    out: list[str] = []
    for line in str(text or "").splitlines():
        if line.startswith("@@"):
            break
        out.append(line)
    return "\n".join(out) + "\n" if out else ""


def _extract_hunk_body(text: str) -> str:
    """Return everything starting from the first ``@@`` line."""
    lines = str(text or "").splitlines()
    idx = next((i for i, l in enumerate(lines) if l.startswith("@@")), -1)
    if idx < 0:
        return text
    return "\n".join(lines[idx:])


def _merge_single_anchor_group(unique_overrides: list[str]) -> str:
    """Merge override texts that share the same anchor line into one hunk.

    This is the original block-level merge logic extracted into a helper.
    """
    if len(unique_overrides) == 1:
        return unique_overrides[0]

    try:
        from tools.extra_patch_tools import _insert_minus_block_into_patch_text  # type: ignore
    except Exception:
        _insert_minus_block_into_patch_text = None  # type: ignore[assignment]

    primary = unique_overrides[-1]
    primary_blocks = _extra_hunk_minus_blocks_first_hunk(primary)

    all_blocks: dict[str, list[str]] = {}
    for ovr in unique_overrides:
        for block in _extra_hunk_minus_blocks_first_hunk(ovr):
            kind, name = _extra_insert_block_semantic_id(block)
            key = f"{kind}:{name}"
            if key not in all_blocks:
                all_blocks[key] = list(block)
            else:
                all_blocks[key] = list(_choose_better_extra_block(kind, current=all_blocks[key], candidate=block))

    merged_blocks: list[list[str]] = []
    used_keys: set[str] = set()
    for block in primary_blocks:
        kind, name = _extra_insert_block_semantic_id(block)
        key = f"{kind}:{name}"
        if key in all_blocks:
            merged_blocks.append(all_blocks[key])
            used_keys.add(key)

    for ovr in unique_overrides[:-1]:
        for block in _extra_hunk_minus_blocks_first_hunk(ovr):
            kind, name = _extra_insert_block_semantic_id(block)
            key = f"{kind}:{name}"
            if key not in used_keys and key in all_blocks:
                merged_blocks.append(all_blocks[key])
                used_keys.add(key)

    kind_pri = {"define": 0, "typedef": 1, "tag": 2, "prototype": 3, "text": 4}
    merged_blocks = [
        block
        for _pri, _idx, block in sorted(
            (
                (kind_pri.get(_extra_insert_block_semantic_id(block)[0], 9), idx, block)
                for idx, block in enumerate(merged_blocks)
            ),
            key=lambda t: (t[0], t[1]),
        )
    ]
    insert_lines: list[str] = []
    for idx, block in enumerate(merged_blocks):
        if not block:
            continue
        if idx > 0 and insert_lines:
            insert_lines.append("")
        insert_lines.extend([str(l) for l in block])

    if not insert_lines:
        return primary

    stripped = _strip_first_hunk_minus_lines(primary)
    if _insert_minus_block_into_patch_text is None:
        merged = stripped.rstrip("\n") + "\n" + "\n".join("-" + l if l else "-" for l in insert_lines) + "\n"
    else:
        merged = _insert_minus_block_into_patch_text(stripped, insert_lines=insert_lines, prefer_prepend=True)

    issues = _extra_hunk_merge_sanity_issues(merged)
    if issues and _insert_minus_block_into_patch_text is not None:
        repaired_lines = _maybe_llm_repair_extra_hunk_insert_lines(insert_lines=insert_lines, issues=issues)
        if repaired_lines:
            repaired = _insert_minus_block_into_patch_text(stripped, insert_lines=repaired_lines, prefer_prepend=True)
            repaired_issues = _extra_hunk_merge_sanity_issues(repaired)
            if not repaired_issues:
                merged = repaired
                issues = []
            else:
                issues = repaired_issues

    if issues:
        sys.stderr.write("[_extra_* merge] sanity issues: " + "; ".join(issues[:5]) + "\n")
        sys.stderr.flush()
    return merged


_ANCHOR_TOLERANCE = 15  # lines


def _llm_merge_cross_group_blocks(
    sem_key: str,
    occurrences: list[tuple[int, list[str]]],
) -> "list[str] | None":
    """Use LLM to merge near-duplicate blocks from different anchor groups.

    Returns the merged block lines (raw code, no diff prefix) or ``None`` on failure.
    """
    try:
        import json as _json  # noqa: PLC0415

        from react_agent.models import ModelError, OpenAIChatCompletionsModel  # type: ignore
    except Exception:
        return None

    try:
        model = OpenAIChatCompletionsModel.from_env()
        override_model = str(os.environ.get("REACT_AGENT_EXTRA_MERGE_REPAIR_MODEL", "") or "").strip()
        if override_model:
            model.model = override_model
        try:
            model.max_tokens = (
                int(os.environ.get("REACT_AGENT_EXTRA_MERGE_REPAIR_MAX_TOKENS", "") or "")
                or model.max_tokens
            )
        except Exception:
            pass

        versions = [{"anchor_line": anchor, "lines": block} for anchor, block in occurrences]
        messages = [
            {
                "role": "system",
                "content": (
                    "You merge near-duplicate C/C++ definitions that appear at different "
                    "insertion points in an OSS-Fuzz revert-patch `_extra_*` hunk.\n"
                    "The same definition (semantic key: `" + sem_key + "`) appears with "
                    "slightly different content at different anchor lines.\n"
                    "Produce a single merged version that:\n"
                    "- Includes all unique members/fields/enumerators from all versions\n"
                    "- Preserves the most complete signature/body\n"
                    "- Is valid C/C++ code\n"
                    "Return ONLY valid JSON: {\"merged_lines\": [\"line1\", \"line2\", ...]}\n"
                    "Each line is raw code (no diff prefix).\n"
                ),
            },
            {
                "role": "user",
                "content": _json.dumps(
                    {"semantic_key": sem_key, "versions": versions},
                    ensure_ascii=False,
                ),
            },
        ]

        raw = model.complete(messages)
        data = _json.loads(raw)
        merged = data.get("merged_lines") if isinstance(data, dict) else None
        if isinstance(merged, list) and merged:
            return [str(l) for l in merged]
        return None
    except ModelError:
        return None
    except Exception:
        return None


def _find_definition_span(
    lines: "list[str]", kind: str, name: str
) -> "tuple[int, int] | None":
    """Find the line range ``[start, end)`` of a definition in raw code lines (no diff prefix).

    Returns ``None`` if the definition is not found.
    """
    for i, raw in enumerate(lines):
        stripped = raw.strip()
        if kind == "tag":
            m = _EXTRA_TAG_RE.match(stripped)
            if m and f"{m.group('kind')} {m.group('name')}".strip() == name:
                # Walk forward to closing `};` (brace-depth tracking)
                brace_depth = 0
                for j in range(i, len(lines)):
                    code = re.sub(r"//.*$", "", lines[j])
                    code = re.sub(r"/\*.*?\*/", "", code)
                    brace_depth += code.count("{") - code.count("}")
                    if brace_depth <= 0 and "}" in code:
                        return (i, j + 1)
                return (i, len(lines))
        elif kind == "define":
            dm = _EXTRA_DEFINE_RE.match(stripped)
            if dm and dm.group(1) == name:
                j = i
                while j < len(lines) and lines[j].rstrip().endswith("\\"):
                    j += 1
                return (i, j + 1)
        elif kind == "prototype":
            for fm in _EXTRA_FUNC_NAME_RE.finditer(stripped):
                cand = fm.group(1)
                if cand == name and cand not in _EXTRA_CONTROL_WORDS:
                    # Walk forward to the `;` that closes the prototype.
                    j = i
                    while j < len(lines) and ";" not in lines[j]:
                        j += 1
                    # Walk backward to include preceding return-type lines
                    # (e.g. "ndpi_patricia_tree_t *" on the line before the
                    # function name).  Stop at blank lines, preprocessor
                    # directives, semicolons, or closing braces.
                    start = i
                    while start > 0:
                        prev = lines[start - 1].strip()
                        if not prev or prev.startswith("#") or ";" in prev or prev.endswith("}"):
                            break
                        start -= 1
                    return (start, j + 1 if j < len(lines) else j)
        elif kind == "typedef":
            if stripped.startswith("typedef"):
                tname = _typedef_declared_name([stripped])
                if tname == name:
                    brace_depth = 0
                    for j in range(i, len(lines)):
                        code = re.sub(r"//.*$", "", lines[j])
                        code = re.sub(r"/\*.*?\*/", "", code)
                        brace_depth += code.count("{") - code.count("}")
                        if ";" in lines[j] and brace_depth <= 0:
                            return (i, j + 1)
                    return (i, len(lines))
    return None


def _extract_minus_lines(patch_text: str) -> "list[str]":
    """Return raw code lines (no diff prefix) from the first hunk's '-' lines."""
    lines = str(patch_text or "").splitlines()
    first_hunk = next((i for i, l in enumerate(lines) if l.startswith("@@")), -1)
    if first_hunk < 0:
        return []
    end = len(lines)
    for i in range(first_hunk + 1, len(lines)):
        if lines[i].startswith("@@") or lines[i].startswith("diff --git "):
            end = i
            break
    result: list[str] = []
    for l in lines[first_hunk + 1 : end]:
        if not l.startswith("-") or l.startswith("---"):
            continue
        result.append("" if l == "-" else l[1:])
    return result


def _dedup_across_anchor_groups(merged_hunks: "dict[int, str]") -> "dict[int, str]":
    """Remove duplicate semantic blocks that appear across different anchor groups.

    When the same definition (enum, struct, typedef, macro, prototype) is present
    in more than one anchor group, keep only the best version in the topmost
    (lowest line-number) group and delete it from all others.

    Works at the raw ``-`` line level rather than at the block level so that
    definitions sharing a block with other declarations (e.g. an enum followed
    by a prototype with no separating blank line) are surgically removed without
    affecting the surrounding declarations.

    For near-duplicates (same semantic ID, different content) an LLM merge is
    attempted when available; the best version is placed in the topmost group.
    """
    if len(merged_hunks) <= 1:
        return merged_hunks

    try:
        from tools.extra_patch_tools import _insert_minus_block_into_patch_text  # type: ignore
    except Exception:
        _insert_minus_block_into_patch_text = None  # type: ignore[assignment]

    sorted_anchors = sorted(merged_hunks.keys())

    # --- Phase 1: extract blocks from each hunk (for semantic ID detection) ---
    blocks_per_anchor: "dict[int, list[tuple[str, str, list[str]]]]" = {}
    for anchor in sorted_anchors:
        raw_blocks = _extra_hunk_minus_blocks_first_hunk(merged_hunks[anchor])
        entries: "list[tuple[str, str, list[str]]]" = []
        for block in raw_blocks:
            kind, name = _extra_insert_block_semantic_id(block)
            sem_key = f"{kind}:{name}"
            entries.append((sem_key, kind, block))
        blocks_per_anchor[anchor] = entries

    # --- Phase 2: find semantic IDs in >1 anchor group ---
    sem_key_by_anchor: "dict[str, list[tuple[int, list[str]]]]" = {}
    for anchor in sorted_anchors:
        for sem_key, _kind, block in blocks_per_anchor[anchor]:
            sem_key_by_anchor.setdefault(sem_key, []).append((anchor, block))

    cross_dupes: "dict[str, list[tuple[int, list[str]]]]" = {}
    for sem_key, occ_list in sem_key_by_anchor.items():
        if len(set(a for a, _ in occ_list)) > 1:
            cross_dupes[sem_key] = occ_list

    if not cross_dupes:
        return merged_hunks

    # --- Phase 3: determine best version per duplicate and what to remove ---
    # Extract raw `-` lines per anchor for definition-level comparison.
    minus_lines_cache: "dict[int, list[str]]" = {}
    for anchor in sorted_anchors:
        minus_lines_cache[anchor] = _extract_minus_lines(merged_hunks[anchor])

    # sem_key -> (topmost_anchor, best_definition_lines)
    best_per_key: "dict[str, tuple[int, list[str]]]" = {}
    anchors_to_edit: "dict[int, set[str]]" = {}

    for sem_key, occ_list in cross_dupes.items():
        sorted_occ = sorted(occ_list, key=lambda t: t[0])
        topmost_anchor = sorted_occ[0][0]
        kind = sem_key.split(":", 1)[0]
        name = sem_key.split(":", 1)[1] if ":" in sem_key else ""

        # Extract only the definition lines (not trailing content) from each occurrence.
        def_versions: "list[tuple[int, list[str]]]" = []
        for anchor, _block in sorted_occ:
            span = _find_definition_span(minus_lines_cache[anchor], kind, name)
            if span:
                def_versions.append((anchor, minus_lines_cache[anchor][span[0]:span[1]]))
            else:
                def_versions.append((anchor, _block))

        # Pick the best definition (heuristic, then optional LLM)
        best_def = def_versions[0][1]
        all_identical = True
        for _, dlines in def_versions[1:]:
            if dlines != best_def:
                all_identical = False
            best_def = _choose_better_extra_block(kind, current=best_def, candidate=dlines)

        if not all_identical:
            llm_result = _llm_merge_cross_group_blocks(sem_key, def_versions)
            if llm_result is not None:
                best_def = llm_result

        best_per_key[sem_key] = (topmost_anchor, best_def)

        # Mark removal from all non-topmost anchors
        for anchor, _ in sorted_occ[1:]:
            anchors_to_edit.setdefault(anchor, set()).add(sem_key)

        # If the best definition differs from the topmost's current, mark topmost for edit too
        if best_def != def_versions[0][1]:
            anchors_to_edit.setdefault(topmost_anchor, set()).add(sem_key)

    # --- Phase 4: surgically edit raw `-` lines in affected hunks ---
    result: "dict[int, str]" = {}
    dedup_log: list[str] = []

    for anchor in sorted_anchors:
        if anchor not in anchors_to_edit:
            result[anchor] = merged_hunks[anchor]
            continue

        minus_lines = _extract_minus_lines(merged_hunks[anchor])
        edits = anchors_to_edit[anchor]

        for sem_key in edits:
            kind = sem_key.split(":", 1)[0]
            name = sem_key.split(":", 1)[1] if ":" in sem_key else ""
            topmost_anchor, best_block = best_per_key[sem_key]

            span = _find_definition_span(minus_lines, kind, name)
            if span is None:
                continue

            start, end = span
            if anchor == topmost_anchor:
                # Replace with best version
                minus_lines[start:end] = best_block
                dedup_log.append(f"replaced {sem_key} at anchor {anchor} with best version")
            else:
                # Remove the definition lines; also remove an adjacent blank separator
                minus_lines[start:end] = []
                # Clean up: remove a leading blank line left by the removal
                if start < len(minus_lines) and start > 0 and minus_lines[start - 1] == "":
                    del minus_lines[start - 1]
                elif start == 0 and minus_lines and minus_lines[0] == "":
                    del minus_lines[0]
                dedup_log.append(f"removed {sem_key} from anchor {anchor}")

        # Rebuild hunk from edited minus_lines
        if not minus_lines or all(l == "" for l in minus_lines):
            dedup_log.append(f"dropped empty hunk at anchor {anchor}")
            continue

        # Strip trailing blank lines
        while minus_lines and minus_lines[-1] == "":
            minus_lines.pop()
        # Strip leading blank lines
        while minus_lines and minus_lines[0] == "":
            minus_lines.pop(0)

        stripped = _strip_first_hunk_minus_lines(merged_hunks[anchor])
        if _insert_minus_block_into_patch_text is not None:
            result[anchor] = _insert_minus_block_into_patch_text(
                stripped, insert_lines=minus_lines, prefer_prepend=True
            )
        else:
            result[anchor] = (
                stripped.rstrip("\n") + "\n"
                + "\n".join("-" + l if l else "-" for l in minus_lines) + "\n"
            )

    if dedup_log:
        sys.stderr.write(
            "[_extra_* merge] cross-anchor dedup: " + "; ".join(dedup_log[:10]) + "\n"
        )
        sys.stderr.flush()

    return result


def _merge_extra_hunk_override_texts(*, base_text: str, override_texts: list[str]) -> str:
    """Merge multiple `_extra_*` override diffs into one by unioning inserted blocks (never partial lines).

    In patch-scope runs, `_extra_*` hunks are reverse-applied: '-' lines become additions. Multiple agents can
    independently extend the same `_extra_*` hunk; we must not drop earlier insertions.

    Strategy: preserve the order from overrides rather than sorting by category. If there's one override,
    just use it. If multiple different overrides exist, union their blocks while preserving appearance order.

    When overrides originate from different anchor lines (different ``@@`` positions), the result is a
    multi-hunk diff so that each anchor group keeps its original position in the file.
    """
    texts = [str(t or "") for t in (override_texts or []) if str(t or "").strip()]
    base = str(base_text or "")
    if not texts:
        return base

    base_from_override = False
    if not base.strip():
        base = texts[0]
        texts = texts[1:]
        base_from_override = True
        if not texts:
            return base

    # Deduplicate override texts (keep first occurrence of each unique text).
    unique_overrides: list[str] = []
    seen: set[str] = set()
    if base_from_override and base.strip():
        texts = [base] + texts
    for t in texts:
        key = t.strip()
        if key not in seen:
            seen.add(key)
            unique_overrides.append(t)

    # If there's exactly one unique override, just use it directly - no block-level merge.
    # This preserves the agent's intended ordering (e.g., typedef before prototypes).
    if len(unique_overrides) == 1:
        return unique_overrides[0]

    # ---- Group overrides by anchor line (±_ANCHOR_TOLERANCE) ----
    anchor_groups: dict[int, list[str]] = {}
    for ovr in unique_overrides:
        anchor = _extract_override_anchor(ovr)
        matched_anchor: int | None = None
        for existing_anchor in anchor_groups:
            if abs(anchor - existing_anchor) <= _ANCHOR_TOLERANCE:
                matched_anchor = existing_anchor
                break
        if matched_anchor is not None:
            anchor_groups[matched_anchor].append(ovr)
        else:
            anchor_groups[anchor] = [ovr]

    # Single anchor group: existing behaviour (single hunk merge).
    if len(anchor_groups) <= 1:
        return _merge_single_anchor_group(unique_overrides)

    # Multiple anchor groups: merge each independently, then dedup across groups.
    diff_header = ""
    merged_hunks: dict[int, str] = {}
    for anchor in sorted(anchor_groups.keys()):
        group = anchor_groups[anchor]
        merged_hunk = _merge_single_anchor_group(group)
        if not diff_header:
            diff_header = _extract_diff_header(merged_hunk)
        merged_hunks[anchor] = merged_hunk

    # Cross-anchor deduplication: remove definitions that appear in multiple hunks,
    # keeping only the topmost (lowest line-number) occurrence.
    merged_hunks = _dedup_across_anchor_groups(merged_hunks)

    hunk_bodies: list[str] = []
    for anchor in sorted(merged_hunks.keys()):
        body = _extract_hunk_body(merged_hunks[anchor])
        if body.strip():
            hunk_bodies.append(body)

    if not hunk_bodies:
        return diff_header.rstrip("\n") + "\n" if diff_header else ""

    return (diff_header + "\n".join(hunk_bodies)).rstrip("\n") + "\n"


def merge_patch_bundle_with_overrides(
    *,
    patch_path: str,
    patch_override_paths: List[str],
    output_name: str,
) -> Dict[str, Any]:
    """Write a merged unified-diff file from a tmp_patch bundle plus override patch files.

    - Loads `patch_path` (a `*.patch2` bundle).
    - For each override file path, infers the `patch_key` from its parent directories and replaces
      that patch entry's `patch_text`.
    - Writes the merged patch file under the artifact allow-root, allocating a unique name if needed.
    """
    bundle = load_patch_bundle(patch_path, allowed_roots=_allowed_patch_roots_from_env())
    patch_keys = set(bundle.patches.keys())

    allow_root = _artifact_allow_root()
    allow_root.mkdir(parents=True, exist_ok=True)

    overrides_by_key: dict[str, list[dict[str, str]]] = {}
    override_files: list[Dict[str, Any]] = []
    for raw in patch_override_paths or []:
        rp = str(raw or "").strip()
        if not rp:
            continue
        p = Path(rp).expanduser().resolve()
        _validate_under_root(p, allow_root)
        if not p.is_file():
            raise FileNotFoundError(f"Override patch file not found: {p}")
        text = p.read_text(encoding="utf-8", errors="replace")
        if "diff --git " not in text:
            raise ValueError(f"Override patch file does not look like a unified diff (missing 'diff --git'): {p}")
        patch_key = _infer_patch_key_from_path(p, patch_keys)
        overrides_by_key.setdefault(patch_key, []).append({"path": str(p), "text": text})
        override_files.append({"patch_key": patch_key, "path": str(p)})

    overrides: dict[str, str] = {}
    extra_override_merges: list[dict[str, Any]] = []
    for key, items in overrides_by_key.items():
        if not items:
            continue
        # Deterministic ordering: sort by file path.
        items_sorted = sorted(items, key=lambda it: str(it.get("path", "") or ""))
        sorted_paths = [str(it.get("path", "") or "") for it in items_sorted if str(it.get("path", "") or "").strip()]
        texts = [str(it.get("text", "") or "") for it in items_sorted if str(it.get("text", "") or "").strip()]
        if not texts:
            continue
        if len(texts) == 1:
            overrides[key] = texts[0]
            continue
        if str(key).startswith("_extra_"):
            base_text = ""
            if key in bundle.patches:
                base_text = str(getattr(bundle.patches[key], "patch_text", "") or "")
            overrides[key] = _merge_extra_hunk_override_texts(base_text=base_text, override_texts=texts)
            extra_override_merges.append(
                {"patch_key": str(key), "override_count": len(texts), "override_paths": sorted_paths, "merged": True}
            )
        else:
            # Non-extra hunks should not normally have multiple overrides; keep the last one (sorted) deterministically.
            overrides[key] = texts[-1]

    # If we have override diffs for a patch_key not present in the base bundle (common for brand-new `_extra_*` hunks),
    # create a new PatchInfo entry so the merged unified diff includes it.
    for key, text in list(overrides.items()):
        if key in bundle.patches:
            continue
        if not str(key).startswith("_extra_"):
            continue
        try:
            from migration_tools.types import PatchInfo  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"Failed to import PatchInfo for new patch_key: {type(exc).__name__}: {exc}") from exc

        old_fp = ""
        new_fp = ""
        for line in str(text or "").splitlines():
            if line.startswith("diff --git "):
                m = re.match(r"^diff --git a/(?P<old>\\S+) b/(?P<new>\\S+)$", line.strip())
                if m:
                    old_fp = str(m.group("old") or "")
                    new_fp = str(m.group("new") or "")
                    break
        if not new_fp:
            for line in str(text or "").splitlines():
                if line.startswith("--- "):
                    old_fp = line[len("--- ") :].strip()
                    if old_fp.startswith("a/"):
                        old_fp = old_fp[2:]
                if line.startswith("+++ "):
                    new_fp = line[len("+++ ") :].strip()
                    if new_fp.startswith("b/"):
                        new_fp = new_fp[2:]
                if old_fp and new_fp:
                    break
        old_fp = str(old_fp or "").strip() or str(new_fp or "").strip()
        new_fp = str(new_fp or "").strip()
        if not new_fp or new_fp == "/dev/null":
            continue

        suffix = Path(new_fp).suffix.lower()
        file_type = suffix.lstrip(".") if suffix else "unknown"
        patch = PatchInfo(
            file_path_old=old_fp,
            file_path_new=new_fp,
            patch_text=str(text or "").rstrip("\n") + "\n",
            file_type=file_type,
            old_start_line=1,
            old_end_line=1,
            new_start_line=1,
            new_end_line=1,
            patch_type={"Extra"},
            old_signature="",
            dependent_func=set(),
            hiden_func_dict={},
        )
        _update_patchinfo_ranges_from_diff(patch, patch.patch_text)
        bundle.patches[key] = patch

    parts: list[str] = []
    keys_sorted = sorted(bundle.patches.keys(), key=lambda k: (-int(getattr(bundle.patches[k], "new_start_line", 0) or 0), str(k)))
    for key in keys_sorted:
        patch_text = overrides.get(key, bundle.patches[key].patch_text or "")
        patch_text = str(patch_text or "").rstrip("\n")
        if not patch_text:
            continue
        # Skip context-only hunks (no actual changes) — patch(1) rejects them as malformed.
        has_change = any(
            ln.startswith(("+", "-")) and not ln.startswith(("+++", "---"))
            for ln in patch_text.splitlines()
            if ln and not ln.startswith("diff --git ") and not ln.startswith("@@")
        )
        if has_change:
            parts.append(patch_text)

    merged_text = ("\n\n".join(parts).rstrip("\n") + "\n") if parts else ""
    if merged_text:
        # Keep each hunk in its own block first, then only merge truly overlapping
        # same-file blocks (to reduce accidental cross-hunk coupling).
        merged_text = _split_multi_hunk_diff_blocks(merged_text)
        if not _env_flag("REACT_AGENT_DISABLE_OVERLAP_HUNK_MERGE"):
            merged_text = _consolidate_same_file_diff_blocks(merged_text)


    out_name = _safe_filename(str(output_name or "ossfuzz_merged.diff"))
    # Avoid collisions across parallel agents by writing the merged patch file under the inferred patch_key
    # directory when possible (single-hunk overrides are the common case). If the allow-root is already the
    # per-hunk patch_key directory, do not nest patch_key/patch_key.
    out_dir = allow_root
    unique_keys = {str(o.get("patch_key", "")).strip() for o in override_files if str(o.get("patch_key", "")).strip()}
    inferred_key = ""
    if not unique_keys:
        # Common case: patch_override_paths may be empty when the caller uses an "effective" *.patch2 that already
        # contains the updated patch_text for the active patch_key. In that scenario, infer the patch_key from the
        # bundle path on disk so merged patch output stays under the per-hunk artifacts dir.
        try:
            bundle_path = Path(patch_path).expanduser().resolve()
            inferred_key = _infer_primary_patch_key_from_path(bundle_path, patch_keys) or _infer_patch_key_from_path(
                bundle_path, patch_keys
            )
        except Exception:
            inferred_key = ""
    elif len(unique_keys) == 1:
        inferred_key = next(iter(unique_keys))
        if inferred_key.startswith("_extra_"):
            # Common case: only an `_extra_*` hunk is overridden, but the override diff lives under
            # `<patch_key>/_extra_*/...`. Prefer writing the merged patch under the primary patch_key
            # directory rather than `_extra_*`.
            primary_from_paths = set()
            for o in override_files:
                p = Path(str(o.get("path", "") or "")).expanduser()
                try:
                    p = p.resolve()
                except Exception:
                    continue
                k = _infer_primary_patch_key_from_path(p, patch_keys)
                if k:
                    primary_from_paths.add(k)
            if len(primary_from_paths) == 1:
                inferred_key = next(iter(primary_from_paths))
    else:
        # Common case: a run may override both the primary patch_key and one or more `_extra_*` hunks.
        # Prefer writing merged output under the primary (non-_extra_) patch_key directory.
        primary = {k for k in unique_keys if k and not k.startswith("_extra_")}
        if len(primary) == 1:
            inferred_key = next(iter(primary))
        else:
            # Even if the override patch_key is `_extra_*`, the override diff is often nested under
            # `<patch_key>/_extra_*/...`; use that as a hint.
            primary_from_paths = set()
            for o in override_files:
                p = Path(str(o.get("path", "") or "")).expanduser()
                try:
                    p = p.resolve()
                except Exception:
                    continue
                k = _infer_primary_patch_key_from_path(p, patch_keys)
                if k:
                    primary_from_paths.add(k)
            if len(primary_from_paths) == 1:
                inferred_key = next(iter(primary_from_paths))
    # NOTE: Always write merged patch to the root artifact directory (not in subdirectories)
    # to make it easier to find and use the merged patch file.
    out_path = _unique_path((allow_root / out_name).resolve())
    _validate_under_root(out_path, allow_root)
    out_path.write_text(merged_text, encoding="utf-8", errors="replace")

    return {
        "patch_path": str(Path(patch_path).expanduser().resolve()),
        "merged_patch_file_path": str(out_path),
        "patch_count_total": len(bundle.patches),
        "override_count": len(override_files),
        "override_files": override_files,
        "overridden_patch_keys": sorted({o["patch_key"] for o in override_files}),
        "extra_override_merges": extra_override_merges,
    }


def _update_patchinfo_ranges_from_diff(patch: Any, patch_text: str) -> None:
    """Best-effort refresh of PatchInfo old/new line ranges from unified-diff hunk headers."""
    old_starts: list[int] = []
    old_ends: list[int] = []
    new_starts: list[int] = []
    new_ends: list[int] = []

    hdr = re.compile(
        r"^@@\s+-(?P<old_start>\d+)(?:,(?P<old_len>\d+))?\s+\+(?P<new_start>\d+)(?:,(?P<new_len>\d+))?\s+@@"
    )
    for line in str(patch_text or "").splitlines():
        if not line.startswith("@@"):
            continue
        m = hdr.match(line.strip())
        if not m:
            continue
        try:
            old_start = int(m.group("old_start"))
            old_len = int(m.group("old_len") or 1)
            new_start = int(m.group("new_start"))
            new_len = int(m.group("new_len") or 1)
        except Exception:
            continue
        old_starts.append(old_start)
        old_ends.append(old_start + max(old_len, 0))
        new_starts.append(new_start)
        new_ends.append(new_start + max(new_len, 0))

    if not old_starts or not new_starts:
        return
    try:
        patch.old_start_line = min(old_starts)
        patch.old_end_line = max(old_ends)
        patch.new_start_line = min(new_starts)
        patch.new_end_line = max(new_ends)
    except Exception:
        return


def write_patch_bundle_with_overrides(
    *,
    patch_path: str,
    patch_override_paths: List[str],
    output_name: str,
) -> Dict[str, Any]:
    """Write an updated `*.patch2` bundle with per-hunk override diffs applied.

    This is like `merge_patch_bundle_with_overrides`, but instead of returning a single merged unified-diff
    (applyable patch), it persists a new patch bundle (pickle) with selected patch entries replaced.
    """
    bundle = load_patch_bundle(patch_path, allowed_roots=_allowed_patch_roots_from_env())
    patch_keys = set(bundle.patches.keys())

    allow_root = _artifact_allow_root()
    allow_root.mkdir(parents=True, exist_ok=True)

    overrides_by_key: dict[str, list[dict[str, str]]] = {}
    override_files: list[Dict[str, Any]] = []
    for raw in patch_override_paths or []:
        rp = str(raw or "").strip()
        if not rp:
            continue
        p = Path(rp).expanduser().resolve()
        _validate_under_root(p, allow_root)
        if not p.is_file():
            raise FileNotFoundError(f"Override patch file not found: {p}")
        text = p.read_text(encoding="utf-8", errors="replace")
        if "diff --git " not in text:
            raise ValueError(f"Override patch file does not look like a unified diff (missing 'diff --git'): {p}")
        patch_key = _infer_patch_key_from_path(p, patch_keys)
        overrides_by_key.setdefault(patch_key, []).append({"path": str(p), "text": text})
        override_files.append({"patch_key": patch_key, "path": str(p)})

    overrides: dict[str, str] = {}
    extra_override_merges: list[dict[str, Any]] = []
    for key, items in overrides_by_key.items():
        if not items:
            continue
        items_sorted = sorted(items, key=lambda it: str(it.get("path", "") or ""))
        sorted_paths = [str(it.get("path", "") or "") for it in items_sorted if str(it.get("path", "") or "").strip()]
        texts = [str(it.get("text", "") or "") for it in items_sorted if str(it.get("text", "") or "").strip()]
        if not texts:
            continue
        if len(texts) == 1:
            overrides[key] = texts[0]
            continue
        if str(key).startswith("_extra_"):
            base_text = ""
            if key in bundle.patches:
                base_text = str(getattr(bundle.patches[key], "patch_text", "") or "")
            overrides[key] = _merge_extra_hunk_override_texts(base_text=base_text, override_texts=texts)
            extra_override_merges.append(
                {"patch_key": str(key), "override_count": len(texts), "override_paths": sorted_paths, "merged": True}
            )
        else:
            overrides[key] = texts[-1]

    # Brand-new `_extra_*` keys can appear as override diffs even when the base bundle lacks them; add PatchInfo entries.
    for key, text in list(overrides.items()):
        if key in bundle.patches:
            continue
        if not str(key).startswith("_extra_"):
            continue
        try:
            from migration_tools.types import PatchInfo  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"Failed to import PatchInfo for new patch_key: {type(exc).__name__}: {exc}") from exc

        old_fp = ""
        new_fp = ""
        for line in str(text or "").splitlines():
            if line.startswith("diff --git "):
                m = re.match(r"^diff --git a/(?P<old>\\S+) b/(?P<new>\\S+)$", line.strip())
                if m:
                    old_fp = str(m.group("old") or "")
                    new_fp = str(m.group("new") or "")
                    break
        if not new_fp:
            for line in str(text or "").splitlines():
                if line.startswith("--- "):
                    old_fp = line[len("--- ") :].strip()
                    if old_fp.startswith("a/"):
                        old_fp = old_fp[2:]
                if line.startswith("+++ "):
                    new_fp = line[len("+++ ") :].strip()
                    if new_fp.startswith("b/"):
                        new_fp = new_fp[2:]
                if old_fp and new_fp:
                    break
        old_fp = str(old_fp or "").strip() or str(new_fp or "").strip()
        new_fp = str(new_fp or "").strip()
        if not new_fp or new_fp == "/dev/null":
            continue

        suffix = Path(new_fp).suffix.lower()
        file_type = suffix.lstrip(".") if suffix else "unknown"
        patch = PatchInfo(
            file_path_old=old_fp,
            file_path_new=new_fp,
            patch_text=str(text or "").rstrip("\n") + "\n",
            file_type=file_type,
            old_start_line=1,
            old_end_line=1,
            new_start_line=1,
            new_end_line=1,
            patch_type={"Extra"},
            old_signature="",
            dependent_func=set(),
            hiden_func_dict={},
        )
        _update_patchinfo_ranges_from_diff(patch, patch.patch_text)
        bundle.patches[key] = patch

    for key, text in overrides.items():
        patch = bundle.patches.get(key)
        if patch is None:
            continue
        patch.patch_text = str(text or "").rstrip("\n") + "\n"
        _update_patchinfo_ranges_from_diff(patch, patch.patch_text)

    out_name = str(output_name or "").strip() or "merged_bundle.patch2"
    if not out_name.endswith(".patch2"):
        out_name += ".patch2"
    out_name = _safe_filename(out_name, max_len=200)
    if not out_name.endswith(".patch2"):
        out_name += ".patch2"

    out_dir = allow_root
    unique_keys = {str(o.get("patch_key", "")).strip() for o in override_files if str(o.get("patch_key", "")).strip()}
    if len(unique_keys) == 1:
        inferred_key = next(iter(unique_keys))
        if inferred_key and str(allow_root.name) != str(inferred_key):
            # Use safe directory name to avoid nested directories from patch_keys with slashes
            safe_key_dir = _safe_filename(inferred_key)
            out_dir = (allow_root / safe_key_dir).resolve()
            out_dir.mkdir(parents=True, exist_ok=True)
    out_path = _unique_path((out_dir / out_name).resolve())
    _validate_under_root(out_path, allow_root)

    try:
        import pickle  # noqa: PLC0415

        out_path.write_bytes(pickle.dumps(dict(bundle.patches), protocol=pickle.HIGHEST_PROTOCOL))
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Failed to write patch bundle: {type(exc).__name__}: {exc}") from exc

    return {
        "patch_path": str(Path(patch_path).expanduser().resolve()),
        "merged_patch_bundle_path": str(out_path),
        "patch_count_total": len(bundle.patches),
        "override_count": len(override_files),
        "override_files": override_files,
        "overridden_patch_keys": sorted({o["patch_key"] for o in override_files}),
        "extra_override_merges": extra_override_merges,
    }


def _run(
    cmd: List[str],
    *,
    label: str = "",
    cwd: Optional[str] = None,
    timeout_seconds: int = 1800,
) -> Dict[str, Any]:
    rendered = shlex.join([str(x) for x in cmd])
    prefix = f"[ossfuzz_apply_patch_and_test] {label}: " if str(label or "").strip() else "[ossfuzz_apply_patch_and_test] "
    # Avoid polluting stdout: the agent process may be emitting JSON on stdout.
    sys.stderr.write(prefix + rendered + "\n")
    sys.stderr.flush()
    proc = subprocess.run(
        [str(x) for x in cmd],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=max(1, int(timeout_seconds or 0)),
    )
    return {"returncode": int(proc.returncode), "output": str(proc.stdout or "")}


def _maybe_prefix_sudo(cmd: List[str], *, use_sudo: bool) -> List[str]:
    return (["sudo", "-E"] + cmd) if use_sudo else cmd


def ossfuzz_apply_patch_and_test(
    *,
    project: str,
    commit: str,
    patch_path: str,
    patch_override_paths: List[str] | None = None,
    build_csv: str = "",
    sanitizer: str = "address",
    architecture: str = "x86_64",
    engine: str = "libfuzzer",
    fuzz_target: str = "",
    timeout_seconds: int = 1800,
    use_sudo: bool = False,
) -> Dict[str, Any]:
    """Apply a patch (in reverse) and run OSS-Fuzz build/test inside Docker.

    This reuses the same workflow used by script/revert_patch_test.py via script/fuzz_helper.py and oss-fuzz/infra/helper.py.
    """
    project_name = str(project or "").strip()
    commit_id = str(commit or "").strip()
    if not project_name:
        raise ValueError("project must be non-empty")
    if not commit_id:
        raise ValueError("commit must be non-empty")

    bundle_path = str(patch_path or "").strip()
    if not bundle_path:
        raise ValueError("patch_path must be non-empty")

    allow_root = _artifact_allow_root()
    merged = merge_patch_bundle_with_overrides(
        patch_path=bundle_path,
        patch_override_paths=list(patch_override_paths or []),
        output_name=f"ossfuzz_merged_{project_name}_{commit_id[:12]}.diff",
    )
    merged_patch_path = str(merged.get("merged_patch_file_path", "") or "").strip()
    patch_file = Path(merged_patch_path).expanduser().resolve()
    _validate_under_root(patch_file, allow_root)
    if not patch_file.is_file():
        raise FileNotFoundError(f"Merged patch file not found: {patch_file}")

    build_csv_path = str(build_csv or "").strip()
    if build_csv_path and not Path(build_csv_path).expanduser().is_file():
        raise FileNotFoundError(f"build_csv not found: {build_csv_path}")

    repo_root = _repo_root()
    script_dir = repo_root / "script"
    oss_fuzz_dir = repo_root / "oss-fuzz"
    fuzz_helper = script_dir / "fuzz_helper.py"
    helper_py = oss_fuzz_dir / "infra" / "helper.py"

    lock_path = _ossfuzz_lock_path()
    wait_message = (
        f"[ossfuzz_apply_patch_and_test] waiting for OSS-Fuzz lock (another agent is testing): {lock_path}"
    )

    build_cmd: List[str] = [
        sys.executable,
        str(fuzz_helper),
        "build_version",
        "--commit",
        commit_id,
        "--patch",
        str(patch_file),
        "--no_corpus",
        "--architecture",
        str(architecture or "x86_64"),
        "--engine",
        str(engine or "libfuzzer"),
        "--sanitizer",
        str(sanitizer or "address"),
    ]
    if build_csv_path:
        build_cmd += ["--build_csv", build_csv_path]
    build_cmd.append(project_name)
    build_cmd.extend(['-e', 'CFLAGS=-Wl,--allow-multiple-definition',
                      '-e', 'CXXFLAGS=-Wl,--allow-multiple-definition'])
    build_cmd = _maybe_prefix_sudo(build_cmd, use_sudo=use_sudo)

    with _FileLock(lock_path, wait_message=wait_message):
        build_res = _run(build_cmd, label="build_version", cwd=str(repo_root), timeout_seconds=timeout_seconds)
        build_output = build_res.get("output", "")
        build_returncode = int(build_res.get("returncode", 1) or 0)
        patch_apply_error = _find_patch_apply_error(build_output)
        patch_apply_ok = not bool(patch_apply_error)
        # Keep log-based checks for rich diagnostics, but never report success when the command
        # failed or strict patch-apply checks reported an apply failure.
        build_ok = (
            build_returncode == 0
            and patch_apply_ok
            and not _has_compiler_errors(build_output)
            and not _has_linker_errors(build_output)
        )

    # Write build outputs as artifacts under the same directory as the merged patch
    artifact_dir = patch_file.parent
    store = ArtifactStore(artifact_dir, overwrite=False)

    build_output_ref = store.write_text(
        name="ossfuzz_apply_patch_and_test_build_output",
        text=build_res["output"],
        ext=".log",
    )
    failed_hunk_ref: Optional[Dict[str, Any]] = None
    failed_hunk_input_line = 0
    if not patch_apply_ok:
        failed_hunk_input_line = _extract_last_patch_input_line(build_output)
        try:
            merged_patch_text = patch_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            merged_patch_text = ""
        failed_hunk_text = _extract_diff_block_for_line(merged_patch_text, failed_hunk_input_line)
        if failed_hunk_text:
            ref = store.write_text(
                name="ossfuzz_apply_patch_and_test_failed_hunk",
                text=failed_hunk_text,
                ext=".diff",
            )
            failed_hunk_ref = ref.to_dict()
            sys.stderr.write("[ossfuzz_apply_patch_and_test] failing patch hunk:\n")
            sys.stderr.write(failed_hunk_text)
            if not failed_hunk_text.endswith("\n"):
                sys.stderr.write("\n")
            sys.stderr.flush()

    return {
        "project": project_name,
        "commit": commit_id,
        "patch_path": str(Path(bundle_path).expanduser().resolve()),
        "patch_override_paths": [str(p) for p in (patch_override_paths or []) if str(p).strip()],
        "merged_patch_file_path": str(patch_file),
        "overridden_patch_keys": merged.get("overridden_patch_keys", []),
        "patch_apply_ok": patch_apply_ok,
        "patch_apply_error": patch_apply_error,
        "build_ok": build_ok,
        "build_returncode": build_returncode,
        "build_cmd": build_cmd,
        "build_output": build_output_ref.to_dict(),
        "failed_hunk_input_line": failed_hunk_input_line,
        "failed_hunk": failed_hunk_ref,
    }
