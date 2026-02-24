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
_MAX_OVERLAP_MERGE_SPAN = 12
_PATCH_APPLY_ERROR_PATTERNS = [
    re.compile(r"^error:\s+corrupt patch(?:\s+at\s+line\s+\d+)?\s*$", re.IGNORECASE),
    re.compile(r"^error:\s+patch failed:\s+.*$", re.IGNORECASE),
    re.compile(r"^error:\s+.*:\s+patch does not apply\s*$", re.IGNORECASE),
    re.compile(r"^error:\s+no valid patches in input.*$", re.IGNORECASE),
    re.compile(r"^patch:\s+\*{4}.*$", re.IGNORECASE),
    re.compile(r"^fatal:\s+patch failed.*$", re.IGNORECASE),
]
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
            i2 = idxs[j + 1]
            if i1 in removed_indices or i2 in removed_indices:
                j += 1
                continue
            cur = replaced_blocks.get(i1, parsed_blocks[i1])
            nxt = replaced_blocks.get(i2, parsed_blocks[i2])
            cur_hunks = list(cur["parsed"].get("hunks") or [])
            nxt_hunks = list(nxt["parsed"].get("hunks") or [])
            if len(cur_hunks) != 1 or len(nxt_hunks) != 1:
                j += 1
                continue

            h1 = dict(cur_hunks[0])
            h2 = dict(nxt_hunks[0])
            if not _old_ranges_overlap(h1, h2):
                j += 1
                continue

            h1["_order"] = 0
            h2["_order"] = 1
            merged = _merge_overlapping_hunk_cluster([h1, h2])
            if merged is None:
                merged = _merge_overlapping_hunk_cluster_via_reverse([h1, h2])
            if merged is None:
                j += 1
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
                j += 1
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


def _merge_extra_hunk_override_texts(*, base_text: str, override_texts: list[str]) -> str:
    """Merge multiple `_extra_*` override diffs into one by unioning inserted blocks (never partial lines).

    In patch-scope runs, `_extra_*` hunks are reverse-applied: '-' lines become additions. Multiple agents can
    independently extend the same `_extra_*` hunk; we must not drop earlier insertions.

    Strategy: preserve the order from overrides rather than sorting by category. If there's one override,
    just use it. If multiple different overrides exist, union their blocks while preserving appearance order.
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

    # Multiple different overrides: union blocks, preserving order from the last (most recent) override.
    # Import late to avoid tool-level import cycles.
    try:
        from tools.extra_patch_tools import _insert_minus_block_into_patch_text  # type: ignore
    except Exception:
        _insert_minus_block_into_patch_text = None  # type: ignore[assignment]

    # Use the last override as the "primary" ordering source, then add any missing blocks from earlier overrides.
    primary = unique_overrides[-1]
    primary_blocks = _extra_hunk_minus_blocks_first_hunk(primary)

    # Collect blocks from all overrides, keyed by semantic ID.
    all_blocks: dict[str, list[str]] = {}
    for ovr in unique_overrides:
        for block in _extra_hunk_minus_blocks_first_hunk(ovr):
            kind, name = _extra_insert_block_semantic_id(block)
            key = f"{kind}:{name}"
            if key not in all_blocks:
                all_blocks[key] = list(block)
            else:
                # Keep the better version.
                all_blocks[key] = list(_choose_better_extra_block(kind, current=all_blocks[key], candidate=block))

    # Build merged block list: start with primary's order, then append any extra blocks from earlier overrides.
    merged_blocks: list[list[str]] = []
    used_keys: set[str] = set()
    for block in primary_blocks:
        kind, name = _extra_insert_block_semantic_id(block)
        key = f"{kind}:{name}"
        if key in all_blocks:
            merged_blocks.append(all_blocks[key])
            used_keys.add(key)

    # Add blocks that exist in earlier overrides but not in primary.
    for ovr in unique_overrides[:-1]:
        for block in _extra_hunk_minus_blocks_first_hunk(ovr):
            kind, name = _extra_insert_block_semantic_id(block)
            key = f"{kind}:{name}"
            if key not in used_keys and key in all_blocks:
                merged_blocks.append(all_blocks[key])
                used_keys.add(key)

    # Enforce sane ordering across categories. Even when a newer override introduces a prototype before
    # a dependent typedef/tag, merged output should keep macros/typedefs/tags before prototypes.
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
        if patch_text:
            parts.append(patch_text)

    merged_text = ("\n\n".join(parts).rstrip("\n") + "\n") if parts else ""
    if merged_text:
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
    build_cmd = _maybe_prefix_sudo(build_cmd, use_sudo=use_sudo)

    with _FileLock(lock_path, wait_message=wait_message):
        build_res = _run(build_cmd, label="build_version", cwd=str(repo_root), timeout_seconds=timeout_seconds)
        build_output = build_res.get("output", "")
        # build_ok is based on parsing the build output for actual errors, not the return code.
        # This ensures accurate status even if the subprocess exit code is unreliable.
        build_ok = (
            not _has_compiler_errors(build_output)
            and not _has_undeclared_func_warning(build_output)
            and not _has_linker_errors(build_output)
        )
        patch_apply_error = _find_patch_apply_error(build_output)
        patch_apply_ok = not bool(patch_apply_error)

    # Write build outputs as artifacts under the same directory as the merged patch
    artifact_dir = patch_file.parent
    store = ArtifactStore(artifact_dir, overwrite=False)

    build_output_ref = store.write_text(
        name="ossfuzz_apply_patch_and_test_build_output",
        text=build_res["output"],
        ext=".log",
    )

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
        "build_cmd": build_cmd,
        "build_output": build_output_ref.to_dict(),
    }
