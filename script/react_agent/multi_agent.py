#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from artifacts import default_run_id
from build_log import iter_compiler_errors, iter_linker_errors, load_build_log
from tools.migration_tools import get_link_error_patch


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

# Strip accumulated merge suffixes like ".merged_overrides"
# from patch bundle stems so filenames stay short across rounds.
_MERGE_SUFFIX_RE = re.compile(r"(\.merged_overrides)+$")


def _patch_base_name(patch_path: str) -> str:
    """Return a short base name from *patch_path*, stripping accumulated merge suffixes."""
    stem = Path(patch_path).stem or "bundle"
    return _MERGE_SUFFIX_RE.sub("", stem) or "bundle"


def _safe_patch_key_dirname(name: str, *, max_len: int = 160) -> str:
    raw = str(name or "").strip()
    raw = raw.replace(os.sep, "_")
    # Keep leading/trailing "_" intact (patch_key can legitimately start/end with "_");
    # strip only "."/"-" to avoid hidden/awkward names.
    cleaned = _SAFE_NAME_RE.sub("_", raw).strip(".-")
    if not cleaned:
        cleaned = "patch_key"
    return cleaned[:max_len]


def _redact_cmd_for_log(cmd: List[str]) -> str:
    """Build a copy-pasteable command string, stripping secret flags entirely."""
    redacted: List[str] = []
    skip_next = False
    for token in cmd:
        if skip_next:
            skip_next = False
            continue
        if token == "--openai-api-key":
            skip_next = True
            continue
        redacted.append(token)
    return " ".join(redacted) + "\n"


def _resolve_output_format(value: str) -> str:
    if value == "auto":
        return "json-pretty" if sys.stdout.isatty() else "json"
    return value


def _emit(obj: Dict[str, Any], output_format: str) -> None:
    fmt = _resolve_output_format(output_format)
    if fmt == "none":
        return
    if fmt == "text":
        sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
        return
    if fmt == "json-pretty":
        sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
        return
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _try_parse_agent_output(stdout: str) -> tuple[Any, Optional[str]]:
    raw = str(stdout or "").strip()
    if not raw:
        return None, None
    try:
        return json.loads(raw), None
    except json.JSONDecodeError as exc:
        idx = raw.find("{")
        if idx > 0:
            try:
                return json.loads(raw[idx:]), None
            except json.JSONDecodeError:
                pass
        return None, f"{type(exc).__name__}: {exc}"


def _extract_next_step_path(text: str, *, prefix: str) -> str:
    want = str(prefix or "").strip()
    if not want:
        return ""
    for raw in str(text or "").splitlines():
        line = str(raw or "").strip()
        if not line:
            continue
        if line.startswith(want):
            return line[len(want) :].strip()
    return ""


def _extract_override_diff_from_agent_stdout(agent_stdout_path: Path) -> str:
    try:
        payload = json.loads(agent_stdout_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return ""
    next_step = payload.get("next_step") if isinstance(payload, dict) else None
    override = _extract_next_step_path(str(next_step or ""), prefix="Override diff:")
    if not override:
        return ""
    p = Path(override).expanduser()
    if p.is_file():
        return str(p.resolve())
    return ""


def _extract_override_diffs_from_agent_stdout_steps(agent_stdout_path: Path) -> List[Dict[str, Any]]:
    """Extract override diff artifacts emitted by patch tools from an agent_stdout.json file.

    We prefer parsing tool observations over next_step text because patch-scope agents may generate multiple
    override diffs (e.g. a make_error_patch_override for the primary hunk plus make_extra_patch_override
    diffs for `_extra_*` hunks). next_step typically only reports the *last* override diff.
    """
    try:
        payload = json.loads(agent_stdout_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    if not isinstance(payload, dict):
        return []
    steps = payload.get("steps")
    if not isinstance(steps, list):
        return []

    out: List[Dict[str, Any]] = []

    def normalize_path(value: Any) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        if "\n" in raw or "\r" in raw:
            return ""
        if raw.lstrip().startswith("diff --git "):
            return ""
        # Avoid Path/stat on obviously-not-path payloads (e.g. unified diffs).
        if len(raw) > 4096:
            return ""

        path = Path(raw).expanduser()
        try:
            if not path.is_absolute():
                # Most runs emit absolute artifact paths; best-effort resolve relative ones from the cwd.
                path = (Path.cwd() / path).resolve()
            else:
                path = path.resolve()
        except OSError:
            return ""
        try:
            return str(path) if path.is_file() else ""
        except OSError:
            return ""

    def maybe_add(output: Any, *, method: str) -> None:
        if not isinstance(output, dict):
            return
        patch_key = str(output.get("patch_key", "") or "").strip()
        patch_text = output.get("patch_text")
        override_path = ""
        if isinstance(patch_text, dict):
            override_path = normalize_path(patch_text.get("artifact_path"))
        elif isinstance(patch_text, str):
            # Some "no change" cases return the current patch text as a string. That's not an override diff.
            candidate = patch_text.strip()
            if "\n" not in candidate and "\r" not in candidate and len(candidate) <= 1024:
                override_path = normalize_path(candidate)
        if not override_path:
            return
        if not patch_key:
            # Last resort: infer from directory name (expected to match patch_key for override diffs).
            patch_key = Path(override_path).resolve().parent.name
        if not patch_key:
            return
        out.append({"patch_key": patch_key, "override_diff": override_path, "method": method})

    for idx, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        obs = step.get("observation")
        if not isinstance(obs, dict) or obs.get("ok") is not True:
            continue
        tool = str(obs.get("tool", "") or "").strip()
        if tool not in {"make_error_patch_override", "make_extra_patch_override"}:
            continue
        maybe_add(obs.get("output"), method=f"agent_stdout.steps:{tool}:{idx}")

    return out


def _latest_make_error_patch_override_diff(artifacts_dir: Path) -> Optional[Path]:
    patterns = [
        "make_error_patch_override_patch_text_*.diff",
        "make_error_patch_override_patch_text*.diff",
        "revise_patch_hunk_patch_text_*.diff",
        "revise_patch_hunk_patch_text*.diff",
    ]
    candidates: List[Path] = []
    for pat in patterns:
        candidates.extend([p for p in artifacts_dir.glob(pat) if p.is_file()])
    if not candidates:
        return None

    def version(p: Path) -> int:
        name = p.name
        if not name.endswith(".diff"):
            return 0
        base = name[: -len(".diff")]
        last = base.rsplit(".", 1)[-1]
        if last.isdigit():
            try:
                return int(last)
            except ValueError:
                return 0
        return 0

    # Prefer the latest timestamp; break ties by numeric suffix (e.g. ".8.diff" > ".diff").
    return max(candidates, key=lambda p: (p.stat().st_mtime, version(p), p.name))


def _latest_override_diff(artifacts_dir: Path) -> Optional[Path]:
    """Return the latest `override*.diff` file under artifacts_dir (best-effort)."""
    candidates = [p for p in artifacts_dir.glob("override*.diff") if p.is_file()]
    if not candidates:
        return None

    def version(p: Path) -> int:
        name = p.name
        if not name.endswith(".diff"):
            return 0
        base = name[: -len(".diff")]
        last = base.rsplit(".", 1)[-1]
        if last.isdigit():
            try:
                return int(last)
            except ValueError:
                return 0
        return 0

    return max(candidates, key=lambda p: (p.stat().st_mtime, version(p), p.name))

def _collect_final_override_diffs(results: List[Dict[str, Any]], *, patch_path: str) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []
    missing: List[str] = []
    sort_err = ""
    patch_key_new_start_line: Dict[str, int] = {}

    try:
        bundle, _ = _load_bundle(str(patch_path))
        patches = getattr(bundle, "patches", None)
        if isinstance(patches, dict):
            for k, v in patches.items():
                if not isinstance(k, str):
                    continue
                try:
                    patch_key_new_start_line[k] = int(getattr(v, "new_start_line", 0) or 0)
                except Exception:
                    patch_key_new_start_line[k] = 0
    except Exception as exc:  # noqa: BLE001
        sort_err = f"failed to load patch bundle for ordering: {type(exc).__name__}: {exc}"

    for r in results or []:
        patch_key = str(r.get("patch_key", "") or "").strip()
        artifacts_dir_raw = str(r.get("artifacts_dir", "") or "").strip()
        if not patch_key or not artifacts_dir_raw:
            continue
        artifacts_dir = Path(artifacts_dir_raw).expanduser().resolve()
        if not artifacts_dir.is_dir():
            missing.append(patch_key)
            continue

        found_any = False
        agent_stdout_path = artifacts_dir / "agent_stdout.json"
        if agent_stdout_path.is_file():
            # Prefer override_*.diff files under the per-hunk artifacts dir (named by patch_key, not symbol).
            extracted = _extract_override_diffs_from_agent_stdout_steps(agent_stdout_path)
            if extracted:
                for item in extracted:
                    item["origin_patch_key"] = patch_key
                candidates.extend(extracted)
                found_any = True
            else:
                # Fallback: parse the override diff path from next_step text (older agent outputs).
                chosen = _extract_override_diff_from_agent_stdout(agent_stdout_path)
                if chosen:
                    inferred_key = Path(chosen).resolve().parent.name
                    candidates.append(
                        {
                            "patch_key": inferred_key or patch_key,
                            "override_diff": str(Path(chosen).resolve()),
                            "method": "agent_stdout.next_step",
                            "origin_patch_key": patch_key,
                        }
                    )
                    found_any = True

        # Best-effort: prefer the latest override_*.diff in the per-hunk root (this is the main hunk override).
        latest_override = _latest_override_diff(artifacts_dir)
        if latest_override is not None:
            candidates.append(
                {
                    "patch_key": patch_key,
                    "override_diff": str(latest_override.resolve()),
                    "method": "glob_latest_override",
                }
            )
            found_any = True

        # Also collect the latest nested override for each `_extra_*` directory under this hunk.
        # Some runs store overrides at:
        #   <artifacts_dir>/<patch_key>/_extra_<file>/override_*.diff
        # so we scan both direct children and one nested level.
        # Additionally, collect rename overrides (enum/macro) for regular hunks stored at:
        #   <artifacts_dir>/<patch_key>/override_<hunk_key>_*_rename.diff
        try:
            roots: List[Path] = [artifacts_dir]
            for child in artifacts_dir.iterdir():
                if child.is_dir():
                    roots.append(child)

            seen_extra_dirs: set[str] = set()
            for root in roots:
                # Scan override*.diff files in non-root child dirs (e.g. patch_key subdir).
                # These are rename overrides (enum/macro) for regular hunks written by
                # agent_langgraph.py when processing make_extra_patch_override results.
                if root != artifacts_dir:
                    latest_child_override = _latest_override_diff(root)
                    if latest_child_override is not None:
                        # Infer the target patch_key from the override filename:
                        # override_<patch_key>_<rename_label>.diff
                        child_name = latest_child_override.name
                        inferred_key = root.name
                        # Try to extract the target patch_key from the filename pattern
                        # "override_<key>_enum_rename.diff" or "override_<key>_macro_rename.diff"
                        _m = re.match(r"override_(.+?)_(?:enum|macro)_rename\.diff$", child_name)
                        if _m:
                            inferred_key = _m.group(1)
                        candidates.append(
                            {
                                "patch_key": inferred_key,
                                "override_diff": str(latest_child_override.resolve()),
                                "method": "glob_latest_nested_rename_override",
                                "origin_patch_key": patch_key,
                            }
                        )
                        found_any = True

                for child in root.iterdir():
                    if not child.is_dir():
                        continue
                    name = str(child.name or "").strip()
                    if not name.startswith("_extra_"):
                        continue
                    key = str(child.resolve())
                    if key in seen_extra_dirs:
                        continue
                    seen_extra_dirs.add(key)

                    latest_extra = _latest_override_diff(child)
                    if latest_extra is None:
                        continue
                    candidates.append(
                        {
                            "patch_key": name,
                            "override_diff": str(latest_extra.resolve()),
                            "method": "glob_latest_nested_override",
                            "origin_patch_key": patch_key,
                        }
                    )
                    found_any = True
        except Exception:
            pass

        # Always include the latest make_error_patch_override diff in the per-hunk artifact dir if present;
        # many patch-scope runs end with a make_extra_patch_override, so next_step may not mention the
        # main hunk's last make_error_patch_override diff.
        latest = _latest_make_error_patch_override_diff(artifacts_dir)
        if latest is not None:
            candidates.append(
                {"patch_key": patch_key, "override_diff": str(latest.resolve()), "method": "glob_latest"}
            )
            found_any = True

        if not found_any:
            missing.append(patch_key)
            continue

    # Pick the best (latest) override per patch_key.
    per_hunk: List[Dict[str, Any]] = []
    by_key: Dict[str, Dict[str, Any]] = {}
    by_extra_origin: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def version_suffix(p: Path) -> int:
        name = p.name
        if not name.endswith(".diff"):
            return 0
        base = name[: -len(".diff")]
        last = base.rsplit(".", 1)[-1]
        if last.isdigit():
            try:
                return int(last)
            except ValueError:
                return 0
        return 0

    def score(path: str) -> Tuple[float, int, str]:
        try:
            p = Path(path).expanduser().resolve()
            st = p.stat()
            return (float(st.st_mtime), version_suffix(p), str(p))
        except Exception:
            return (0.0, 0, str(path))

    def _path_contains_dir(path: str, dirname: str) -> bool:
        want = str(dirname or "").strip()
        if not want:
            return False
        try:
            p = Path(path).expanduser().resolve()
        except Exception:
            p = Path(str(path))
        for parent in [p.parent, *p.parents]:
            if str(parent.name or "").strip() == want:
                return True
        return False

    def _extra_origin_rank(path: str, *, extra_key: str, method: str) -> Tuple[int, int, float, int, str]:
        """Ranking for `_extra_*` override candidates for one origin hunk.

        Prefer paths physically scoped under the `_extra_*` directory so downstream
        patch-key inference cannot mis-map them to the origin patch key.
        """
        scoped = 1 if _path_contains_dir(path, extra_key) else 0
        m = str(method or "").strip()
        if "nested_override" in m:
            method_pri = 2
        elif "steps:make_extra_patch_override" in m:
            method_pri = 1
        else:
            method_pri = 0
        mt, ver, rp = score(path)
        return (scoped, method_pri, mt, ver, rp)

    for c in candidates:
        key = str(c.get("patch_key", "") or "").strip()
        path = str(c.get("override_diff", "") or "").strip()
        if not key or not path:
            continue
        rp = str(Path(path).expanduser().resolve())
        method = str(c.get("method", "") or "").strip()
        origin = str(c.get("origin_patch_key", "") or "").strip()

        if key.startswith("_extra_") and origin:
            extra_key = (key, origin)
            existing = by_extra_origin.get(extra_key)
            existing_path = str(existing.get("override_diff", "") or "") if isinstance(existing, dict) else ""
            existing_method = str(existing.get("method", "") or "") if isinstance(existing, dict) else ""
            cand_rank = _extra_origin_rank(rp, extra_key=key, method=method)
            existing_rank = _extra_origin_rank(existing_path, extra_key=key, method=existing_method)
            if existing is None or cand_rank > existing_rank:
                by_extra_origin[extra_key] = {"patch_key": key, "override_diff": rp, "method": method, "origin_patch_key": origin}
            continue

        existing = by_key.get(key)
        if existing is None or score(rp) > score(str(existing.get("override_diff", "") or "")):
            by_key[key] = {"patch_key": key, "override_diff": rp, "method": method}

    for key, item in by_key.items():
        item["new_start_line"] = patch_key_new_start_line.get(key, 0)
        per_hunk.append(item)

    for (key, _origin), item in by_extra_origin.items():
        item["new_start_line"] = patch_key_new_start_line.get(key, 0)
        per_hunk.append(item)

    # Sort like script/revert_patch_test.py: newer hunks first (bottom-up application).
    per_hunk.sort(
        key=lambda item: (
            -int(item.get("new_start_line", 0) or 0),
            str(item.get("patch_key", "") or ""),
            str(item.get("origin_patch_key", "") or ""),
            str(item.get("override_diff", "") or ""),
        )
    )
    override_paths = [
        str(item.get("override_diff", "") or "").strip()
        for item in per_hunk
        if str(item.get("override_diff", "") or "").strip()
    ]

    # De-dup while preserving order.
    seen: set[str] = set()
    deduped: List[str] = []
    for p in override_paths:
        rp = str(Path(p).expanduser().resolve())
        if rp in seen:
            continue
        seen.add(rp)
        deduped.append(rp)

    return {
        "override_paths": deduped,
        "per_hunk": per_hunk,
        "missing_patch_keys": missing,
        "sort_error": sort_err,
    }


def _allowed_roots_from_env() -> Optional[List[str]]:
    raw = os.environ.get("REACT_AGENT_PATCH_ALLOWED_ROOTS", "").strip()
    if not raw:
        return None
    roots = [r.strip() for r in raw.split(os.pathsep) if r.strip()]
    return roots or None


def _load_bundle(patch_path: str) -> Tuple[Any, Any]:
    script_dir = Path(__file__).resolve().parents[1]
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))
    from migration_tools.patch_bundle import load_patch_bundle  # type: ignore
    from migration_tools.tools import _get_error_patch_from_bundle  # type: ignore

    bundle = load_patch_bundle(patch_path, allowed_roots=_allowed_roots_from_env())
    return bundle, _get_error_patch_from_bundle


def _error_type_priority(err: Dict[str, Any]) -> int:
    """Return priority for error type ordering (lower = handled first).

    Order:
      unknown type name (0)
      < undeclared function (1)
      < __revert_* undefined-internal (2)
      < linker undefined reference (3)
      < others (4)
    Rationale: fix type definitions first, then function declarations that may use those types,
    then missing internal helper definitions, then linker errors (link-time, after compile fixes).
    """
    msg = str(err.get("msg", "")).lower()
    kind = str(err.get("kind", "")).lower()

    # Priority 0: unknown type name (must define types first)
    if "unknown type name" in msg:
        return 0
    # Priority 1: undeclared function (compile-time)
    if "undeclared function" in msg or "implicit declaration of function" in msg:
        return 1
    # Priority 2: __revert_* helper with internal linkage but no definition.
    if (
        kind == "undefined_internal"
        or ("has internal linkage but is not defined" in msg and "__revert_" in msg)
    ):
        return 2
    # Priority 3: linker undefined reference (link-time, after compile fixes)
    if kind == "linker" or "undefined reference" in msg:
        return 3
    # Priority 4: everything else
    return 4


_ARG_COUNT_RE = re.compile(r"too (?:few|many) arguments to function call", re.IGNORECASE)


def _remove_rename_only_hunks_with_arg_errors(
    groups: Dict[str, List[Dict[str, Any]]],
    patch_path: str,
) -> List[str]:
    """Remove patch_keys whose errors are all argument-count mismatches on rename-only hunks.

    Returns the list of removed patch_keys (for logging).
    """
    bundle, _ = _load_bundle(patch_path)
    removed: List[str] = []
    keys_to_remove: List[str] = []

    for key, errs in groups.items():
        # All errors for this key must be "too few/many arguments"
        if not errs or not all(_ARG_COUNT_RE.search(str(e.get("msg", ""))) for e in errs):
            continue
        patch = bundle.patches.get(key)
        if patch is None:
            continue

        # Lazy import to avoid circular dependency at module level
        script_dir = Path(__file__).resolve().parents[1]
        if str(script_dir) not in sys.path:
            sys.path.insert(0, str(script_dir))
        from migration_tools.tools import is_rename_only_hunk  # type: ignore

        if is_rename_only_hunk(patch.patch_text):
            keys_to_remove.append(key)

    for key in keys_to_remove:
        del groups[key]
        removed.append(key)

    return removed


def _split_extra_patch_keys_in_bundle(patch_path: str, artifacts_root: Path) -> str:
    """Split multi-hunk ``_extra_*`` entries into per-hunk keys for parallel processing.

    For each ``_extra_*`` key with 2+ non-overlapping hunks, create N new entries
    keyed ``_extra_<filename>__h<old_start>`` (one per hunk) and remove the original.
    Writes the modified bundle as ``<base>.split_extra.patch2`` under *artifacts_root*.
    Returns the new path, or *patch_path* unchanged if no splits were made.
    """
    import pickle

    script_dir = Path(__file__).resolve().parents[1]
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))
    from migration_tools.patch_bundle import load_patch_bundle  # type: ignore
    from migration_tools.tools import _iter_hunks  # type: ignore
    from migration_tools.types import PatchInfo as _PatchInfo  # type: ignore

    bundle = load_patch_bundle(patch_path, allowed_roots=_allowed_roots_from_env())
    # Collect keys to split: only _extra_* with 2+ non-overlapping hunks.
    splits: Dict[str, List[Dict[str, Any]]] = {}  # original_key -> list of parsed hunks
    for key, patch in bundle.patches.items():
        if not key.startswith("_extra_"):
            continue
        hunks = _iter_hunks(patch.patch_text)
        if len(hunks) < 2:
            continue
        # Check pairwise overlap: [old_start, old_start + old_len)
        ranges = [(h["old_start"], h["old_start"] + h["old_len"]) for h in hunks]
        ranges.sort()
        overlapping = False
        for i in range(len(ranges) - 1):
            if ranges[i][1] > ranges[i + 1][0]:
                overlapping = True
                break
        if overlapping:
            continue
        splits[key] = hunks

    if not splits:
        return patch_path

    # Extract diff header lines (everything before the first @@) from patch_text.
    def _diff_header(patch_text: str) -> str:
        lines: List[str] = []
        for line in (patch_text or "").splitlines():
            if line.startswith("@@"):
                break
            lines.append(line)
        return "\n".join(lines) + "\n" if lines else ""

    # Build new patches dict from existing, applying splits.
    new_patches: Dict[str, Any] = {}
    for key, patch in bundle.patches.items():
        if key not in splits:
            new_patches[key] = patch
            continue
        header = _diff_header(patch.patch_text)
        for hunk in splits[key]:
            old_s = hunk["old_start"]
            old_l = hunk["old_len"]
            new_s = hunk["new_start"]
            new_l = hunk["new_len"]
            hunk_header = f"@@ -{old_s},{old_l} +{new_s},{new_l} @@\n"
            body = "\n".join(hunk["lines"])
            single_patch_text = header + hunk_header + body
            split_key = f"{key}__h{old_s}"
            new_patches[split_key] = _PatchInfo(
                file_path_old=patch.file_path_old,
                file_path_new=patch.file_path_new,
                patch_text=single_patch_text,
                file_type=patch.file_type,
                old_start_line=old_s,
                old_end_line=old_s + old_l - 1,
                new_start_line=new_s,
                new_end_line=new_s + new_l - 1,
                patch_type=set(patch.patch_type) if patch.patch_type else {"Extra"},
                old_signature=patch.old_signature,
                new_signature=patch.new_signature,
            )

    # Sort by new_start_line descending (bottom-up), matching the convention
    # in revert_patch_test.py and load_patch_bundle().keys_sorted.
    # The dict order matters: downstream code iterates the raw dict when
    # mapping errors to patch hunks.
    keys_sorted = sorted(
        new_patches.keys(),
        key=lambda k: (-int(getattr(new_patches[k], "new_start_line", 0) or 0), str(k)),
    )
    sorted_patches: Dict[str, Any] = {k: new_patches[k] for k in keys_sorted}

    # Write the modified bundle.
    base = _patch_base_name(patch_path)
    out_path = artifacts_root / f"{base}.split_extra.patch2"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        pickle.dump(sorted_patches, f, protocol=pickle.HIGHEST_PROTOCOL)

    # Also write a corresponding .diff in the same order.
    diff_path = artifacts_root / f"{base}.split_extra.diff"
    with open(diff_path, "w", encoding="utf-8") as f:
        for k in keys_sorted:
            f.write(sorted_patches[k].patch_text)
            f.write("\n\n")

    return str(out_path)


def _find_split_extra_key(bundle_patches: Dict[str, Any], base_key: str) -> str:
    """Find a split variant of *base_key* in *bundle_patches*.

    Returns the first (lowest ``__h`` anchor, numerically) split key matching
    ``<base_key>__h*``, or empty string if none found.
    """
    prefix = f"{base_key}__h"

    def _hunk_start(key: str) -> int:
        suffix = key[len(prefix):]
        try:
            return int(suffix)
        except ValueError:
            return 10**9

    matches = [k for k in bundle_patches if k.startswith(prefix)]
    if not matches:
        return ""
    matches.sort(key=_hunk_start)
    return matches[0]


def _group_errors_by_patch_key(*, build_log_text: str, patch_path: str) -> Dict[str, List[Dict[str, Any]]]:
    bundle, get_error_patch_fn = _load_bundle(patch_path)
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for err in iter_compiler_errors(build_log_text, snippet_lines=10):
        mapping = get_error_patch_fn(bundle, patch_path=patch_path, file_path=err["file"], line_number=err["line"])
        key = str(mapping.get("patch_key") or "").strip()
        if not key:
            # Fallback: compiler errors outside any patch hunk but in a file that
            # has an _extra_* hunk.  These are typically missing forward declarations
            # or conflicting types for __revert_* functions.  Route them to the
            # _extra_<file> hunk so the agent can add the missing declaration.
            base_file = Path(err["file"]).name if err.get("file") else ""
            if base_file:
                candidate = f"_extra_{base_file}"
                patches = getattr(bundle, "patches", {}) or {}
                if candidate in patches:
                    key = candidate
                else:
                    split_key = _find_split_extra_key(patches, candidate)
                    if split_key:
                        key = split_key
        if not key:
            continue
        enriched = dict(err)
        enriched["patch_key"] = key
        enriched["old_signature"] = mapping.get("old_signature")
        groups.setdefault(key, []).append(enriched)

    # Also process linker errors (undefined reference errors from the linker stage).
    for err in iter_linker_errors(build_log_text, snippet_lines=10):
        fp = str(err.get("file", "") or "").strip()
        fn = str(err.get("function", "") or "").strip()
        symbol = str(err.get("symbol", "") or "").strip()
        if not fp or not (fn or symbol):
            continue
        mapping: Dict[str, Any] = {}
        key = ""
        for cand in (fn, symbol):
            c = str(cand or "").strip()
            if not c:
                continue
            mapping = get_link_error_patch(patch_path=patch_path, file_path=fp, function_name=c)
            key = str(mapping.get("patch_key") or "").strip()
            if key:
                break
        if not key:
            # Fallback: for __revert_* undefined references, assign to _extra_<caller_file>.
            # The agent will inject the missing definition via
            # make_extra_patch_override(prefer_definition=true).
            if symbol and symbol.startswith("__revert_"):
                base_file = Path(fp).name if fp else ""
                if base_file:
                    candidate = f"_extra_{base_file}"
                    if candidate in bundle.patches:
                        key = candidate
                    else:
                        # Check for split variants (_extra_<file>__h*)
                        split_key = _find_split_extra_key(bundle.patches, candidate)
                        key = split_key or candidate
            # Broader fallback: for any unmapped linker error, derive the source
            # file from the object path ("libhts.a(hfile.o)" → "hfile.c") and
            # check if _extra_<source_file> exists in the bundle.
            if not key:
                import re as _re
                _m_obj = _re.match(r".*\(([^)]+\.o)\)$", fp)
                obj_name = _m_obj.group(1) if _m_obj else (fp if fp.endswith(".o") else "")
                if obj_name:
                    source_file = obj_name[:-2] + ".c"  # "hfile.o" → "hfile.c"
                    candidate = f"_extra_{source_file}"
                    if candidate in bundle.patches:
                        key = candidate
                    else:
                        split_key = _find_split_extra_key(bundle.patches, candidate)
                        if split_key:
                            key = split_key
            if not key:
                continue
        enriched = dict(err)
        enriched["patch_key"] = key
        enriched["old_signature"] = mapping.get("old_signature")
        groups.setdefault(key, []).append(enriched)

    # Sort errors within each group: unknown type name first, then implicit declaration, then linker, then others.
    for key in groups:
        groups[key].sort(key=_error_type_priority)

    return groups


def _rank_patch_keys(groups: Dict[str, List[Dict[str, Any]]]) -> List[str]:
    keys: List[str] = []
    for k, errs in groups.items():
        if not k or not errs:
            continue
        keys.append(k)

    first_seen: Dict[str, int] = {}
    idx = 0
    for k in keys:
        if k not in first_seen:
            first_seen[k] = idx
            idx += 1

    keys.sort(key=lambda k: (-len(groups.get(k, [])), first_seen.get(k, 10**9), k))
    return keys


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run one patch-scope ReAct agent per patch hunk (patch_key).")
    p.add_argument("build_log", nargs="?", default="-", help="Build log path, or '-' for stdin.")
    p.add_argument("--patch-path", required=True, help="Path to a tmp_patch bundle (*.patch2).")
    p.add_argument(
        "--resume-from",
        default="",
        help="Resume a prior multi-agent run from an artifacts dir (multi_<run_id>) or a summary/progress JSON file.",
    )
    p.add_argument("--max-groups", type=int, default=20, help="Max patch_key groups to run (default: 20).")
    p.add_argument(
        "--max-restarts-per-hunk",
        type=int,
        default=int(os.environ.get("REACT_AGENT_MAX_RESTARTS_PER_HUNK", "3") or 3),
        help="If a hunk is not fixed, delete its artifacts dir and rerun (default: 3).",
    )
    p.add_argument("--jobs", type=int, default=1, help="Max concurrent agents to run (default: 1).")
    p.add_argument(
        "--agent-timeout",
        type=int,
        default=int(os.environ.get("REACT_AGENT_TIMEOUT", "3600") or 3600),
        help="Timeout in seconds for each agent subprocess (default: 1800 = 30 min).",
    )
    p.add_argument("--output-format", choices=["none", "auto", "json", "json-pretty", "text"], default="none")
    p.add_argument("--model", choices=["openai", "stub"], default=os.environ.get("REACT_AGENT_MODEL", "openai"))
    p.add_argument("--tools", choices=["real", "fake"], default="real")
    p.add_argument(
        "--max-steps",
        type=int,
        default=int(os.environ.get("REACT_AGENT_MAX_STEPS", "20") or 20),
        help="Max steps per agent run (default: REACT_AGENT_MAX_STEPS or 20).",
    )
    p.add_argument(
        "--recursion-limit",
        type=int,
        default=int(os.environ.get("REACT_AGENT_RECURSION_LIMIT", "0") or 0),
        help="Forwarded to agent_langgraph.py (LangGraph recursion_limit; 0=auto).",
    )
    p.add_argument("--only-patch-keys", default="", help="Comma-separated patch_key allowlist.")
    p.add_argument(
        "--include-agent-output",
        action="store_true",
        help="Include full per-agent JSON output in the multi-agent report (default: store full output in artifacts only).",
    )
    p.add_argument(
        "--final-ossfuzz-test",
        choices=["auto", "always", "never"],
        default=str(os.environ.get("REACT_AGENT_FINAL_OSSFUZZ_TEST", "always") or "always"),
        help=(
            "After all hunks complete, run a single OSS-Fuzz build/check_build using the combined override diffs. "
            "always=run regardless of per-hunk status; auto=only when all hunks are fixed and --tools real; never=skip."
        ),
    )
    p.add_argument("--v1-json-dir", default="", help="Root directory containing V1 *_analysis.json files")
    p.add_argument("--v2-json-dir", default="", help="Root directory containing V2 *_analysis.json files")
    p.add_argument("--v1-src", default="", help="Local filesystem root for V1 source code")
    p.add_argument("--v2-src", default="", help="Local filesystem root for V2 source code")

    p.add_argument("--openai-api-key", default=os.environ.get("OPENAI_API_KEY", ""))
    p.add_argument("--openai-model", default=os.environ.get("OPENAI_MODEL", "") or "gpt-5-mini")
    p.add_argument("--openai-base-url", default=os.environ.get("OPENAI_BASE_URL", "") or "https://api.openai.com/v1")
    p.add_argument("--openai-org", default=os.environ.get("OPENAI_ORG", ""))
    p.add_argument("--openai-project", default=os.environ.get("OPENAI_PROJECT", ""))
    p.add_argument("--openai-max-tokens", type=int, default=int(os.environ.get("OPENAI_MAX_TOKENS", "0") or 0))
    p.add_argument("--no-json-mode", action="store_true", help="Disable OpenAI JSON mode.")

    p.add_argument(
        "--debug-llm",
        action="store_true",
        default=str(os.environ.get("REACT_AGENT_DEBUG_LLM", "") or "").strip().lower() in {"1", "true", "yes", "y", "on"},
        help="Forwarded to agent_langgraph.py (print full LLM request/response to stderr).",
    )
    p.add_argument(
        "--debug-llm-dir",
        default=os.environ.get("REACT_AGENT_DEBUG_LLM_DIR", ""),
        help="Forwarded to agent_langgraph.py (write request/response JSON under this directory).",
    )

    p.add_argument("--ossfuzz-project", default=os.environ.get("REACT_AGENT_OSSFUZZ_PROJECT", ""))
    p.add_argument("--ossfuzz-commit", default=os.environ.get("REACT_AGENT_OSSFUZZ_COMMIT", ""))
    p.add_argument("--ossfuzz-build-csv", default=os.environ.get("REACT_AGENT_OSSFUZZ_BUILD_CSV", ""))
    p.add_argument("--ossfuzz-sanitizer", default=os.environ.get("REACT_AGENT_OSSFUZZ_SANITIZER", "address"))
    p.add_argument("--ossfuzz-arch", default=os.environ.get("REACT_AGENT_OSSFUZZ_ARCH", "x86_64"))
    p.add_argument("--ossfuzz-engine", default=os.environ.get("REACT_AGENT_OSSFUZZ_ENGINE", "libfuzzer"))
    p.add_argument("--ossfuzz-fuzz-target", default=os.environ.get("REACT_AGENT_OSSFUZZ_FUZZ_TARGET", ""))
    p.add_argument("--ossfuzz-use-sudo", action="store_true", default=bool(os.environ.get("REACT_AGENT_OSSFUZZ_USE_SUDO", "")))
    p.add_argument(
        "--auto-ossfuzz-loop",
        action="store_true",
        default=str(os.environ.get("REACT_AGENT_AUTO_OSSFUZZ_LOOP", "") or "").strip().lower() in {"1", "true", "yes", "y", "on"},
        help="Forwarded to agent_langgraph.py (patch-scope only: re-parse OSS-Fuzz logs and iterate within the same patch_key).",
    )
    p.add_argument(
        "--ossfuzz-loop-max",
        type=int,
        default=int(os.environ.get("REACT_AGENT_OSSFUZZ_LOOP_MAX", "3") or 3),
        help="Forwarded to agent_langgraph.py (max ossfuzz_apply_patch_and_test calls when --auto-ossfuzz-loop is enabled).",
    )
    return p


def _resolve_resume_root(value: str) -> Optional[Path]:
    raw = str(value or "").strip()
    if not raw:
        return None
    p = Path(raw).expanduser().resolve()
    if p.is_dir():
        return p
    if p.is_file() and p.suffix.lower() == ".json":
        return p.parent
    return None


def _load_resume_report(artifacts_root: Path) -> Dict[str, Any]:
    for name in ("progress.json", "summary.json"):
        p = (artifacts_root / name).resolve()
        if not p.is_file():
            continue
        try:
            payload = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if isinstance(payload, dict):
            payload.setdefault("_resume_source", str(p))
            return payload
    return {}


def _write_progress_json(artifacts_root: Path, report: Dict[str, Any]) -> None:
    try:
        p = (artifacts_root / "progress.json").resolve()
        p.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass


def _agent_cmd(
    args: argparse.Namespace,
    *,
    agent_script: Path,
    build_log_path: str,
    patch_path: str,
    patch_key: str,
    patch_key_dirname: str,
) -> List[str]:
    cmd = [
        sys.executable,
        str(agent_script),
        str(build_log_path),
        "--output-format",
        "json-pretty",
        "--model",
        str(args.model),
        "--tools",
        str(args.tools),
        "--max-steps",
        str(max(int(args.max_steps or 1), 1)),
        "--recursion-limit",
        str(int(getattr(args, "recursion_limit", 0) or 0)),
        "--error-scope",
        "patch",
        "--patch-path",
        str(patch_path),
        "--focus-patch-key",
        str(patch_key),
        "--ossfuzz-project",
        str(args.ossfuzz_project),
        "--ossfuzz-commit",
        str(args.ossfuzz_commit),
        "--ossfuzz-build-csv",
        str(args.ossfuzz_build_csv),
        "--ossfuzz-sanitizer",
        str(args.ossfuzz_sanitizer),
        "--ossfuzz-arch",
        str(args.ossfuzz_arch),
        "--ossfuzz-engine",
        str(args.ossfuzz_engine),
        "--ossfuzz-fuzz-target",
        str(args.ossfuzz_fuzz_target),
    ]
    if args.ossfuzz_use_sudo:
        cmd.append("--ossfuzz-use-sudo")
    if bool(getattr(args, "auto_ossfuzz_loop", False)):
        cmd.append("--auto-ossfuzz-loop")
        cmd.extend(["--ossfuzz-loop-max", str(max(int(getattr(args, "ossfuzz_loop_max", 0) or 0), 1))])

    if str(args.v1_json_dir).strip():
        cmd.extend(["--v1-json-dir", str(args.v1_json_dir)])
    if str(args.v2_json_dir).strip():
        cmd.extend(["--v2-json-dir", str(args.v2_json_dir)])
    if str(args.v1_src).strip():
        cmd.extend(["--v1-src", str(args.v1_src)])
    if str(args.v2_src).strip():
        cmd.extend(["--v2-src", str(args.v2_src)])

    if bool(getattr(args, "debug_llm", False)):
        cmd.append("--debug-llm")
    base_debug_dir = str(getattr(args, "debug_llm_dir", "") or "").strip()
    if base_debug_dir:
        # Avoid collisions across concurrent agents by using a per-patch_key debug subdirectory.
        cmd.extend(["--debug-llm-dir", str(Path(base_debug_dir) / str(patch_key_dirname))])

    if str(getattr(args, "openai_api_key", "") or "").strip():
        cmd.extend(["--openai-api-key", str(getattr(args, "openai_api_key", "")).strip()])
    if str(getattr(args, "openai_model", "") or "").strip():
        cmd.extend(["--openai-model", str(getattr(args, "openai_model", "")).strip()])
    if str(getattr(args, "openai_base_url", "") or "").strip():
        cmd.extend(["--openai-base-url", str(getattr(args, "openai_base_url", "")).strip()])
    if str(getattr(args, "openai_org", "") or "").strip():
        cmd.extend(["--openai-org", str(getattr(args, "openai_org", "")).strip()])
    if str(getattr(args, "openai_project", "") or "").strip():
        cmd.extend(["--openai-project", str(getattr(args, "openai_project", "")).strip()])
    if int(args.openai_max_tokens or 0) > 0:
        cmd.extend(["--openai-max-tokens", str(int(args.openai_max_tokens))])
    if bool(args.no_json_mode):
        cmd.append("--no-json-mode")

    return cmd


def main(argv: List[str]) -> int:
    args = build_parser().parse_args(argv)
    patch_path = str(args.patch_path or "").strip()
    if not patch_path:
        raise ValueError("--patch-path is required")

    if not str(args.ossfuzz_project).strip() or not str(args.ossfuzz_commit).strip():
        raise ValueError("--ossfuzz-project and --ossfuzz-commit are required (patch-scope agents must test before stopping)")

    build_log_text = load_build_log(str(args.build_log))

    repo_root = Path(__file__).resolve().parents[2]
    agent_script = repo_root / "script" / "react_agent" / "agent_langgraph.py"
    if not agent_script.is_file():
        raise FileNotFoundError(str(agent_script))

    resume_root = _resolve_resume_root(str(getattr(args, "resume_from", "") or ""))
    resumed_report: Dict[str, Any] = {}
    resumed_by_key: Dict[str, Dict[str, Any]] = {}

    run_id = default_run_id()
    artifacts_root = repo_root / "data" / "react_agent_artifacts" / f"multi_{run_id}"
    if resume_root is not None:
        artifacts_root = resume_root
        resumed_report = _load_resume_report(artifacts_root)
        prev = resumed_report.get("results")
        if isinstance(prev, list):
            for item in prev:
                if not isinstance(item, dict):
                    continue
                key = str(item.get("patch_key", "") or "").strip()
                if key:
                    resumed_by_key[key] = item

    artifacts_root.mkdir(parents=True, exist_ok=True)

    # Split multi-hunk _extra_* keys into per-hunk keys for parallel processing.
    effective_patch_path = _split_extra_patch_keys_in_bundle(patch_path, artifacts_root)

    groups = _group_errors_by_patch_key(build_log_text=build_log_text, patch_path=effective_patch_path)

    # NOTE: rename-only hunks with argument-count mismatches are no longer removed.
    # The agent will attempt to fix them using the existing patch override tools.

    ranked_all = _rank_patch_keys(groups)
    patch_key_groups_found = len(ranked_all)

    allow_raw = str(args.only_patch_keys or "").strip()
    allow = {s.strip() for s in allow_raw.split(",") if s.strip()} if allow_raw else set()
    if allow:
        ranked_all = [k for k in ranked_all if k in allow]
    patch_key_groups_after_allowlist = len(ranked_all)

    max_groups_requested = max(0, int(args.max_groups or 0))
    ranked = ranked_all
    if max_groups_requested:
        ranked = ranked[:max_groups_requested]
    patch_key_groups_selected = len(ranked)

    agent_build_log_path = str(args.build_log)
    if str(args.build_log).strip() == "-":
        out_path = artifacts_root / "build.log"
        out_path.write_text(build_log_text + ("\n" if build_log_text and not build_log_text.endswith("\n") else ""), encoding="utf-8", errors="replace")
        agent_build_log_path = str(out_path)

    env = dict(os.environ)
    env["REACT_AGENT_ARTIFACT_ROOT"] = str(artifacts_root)
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    # Ensure dynamically-generated merged patch bundles under ARTIFACT_ROOT remain readable when an allowlist is used.
    raw_allowed = str(os.environ.get("REACT_AGENT_PATCH_ALLOWED_ROOTS", "") or "").strip()
    if raw_allowed:
        merged = raw_allowed + os.pathsep + str(artifacts_root)
        env["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = merged
        os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = merged

    def _report_snapshot(*, results: List[Dict[str, Any]], ongoing: Optional[List[str]] = None) -> Dict[str, Any]:
        hunks_fixed = sum(1 for r in results if r.get("hunk_fixed") is True)
        hunks_not_fixed = sum(1 for r in results if r.get("hunk_fixed") is False)
        hunks_unknown = sum(1 for r in results if r.get("hunk_fixed") is None)
        agents_failed = sum(1 for r in results if int(r.get("agent_exit_code") or 0) != 0)
        restarts_attempted_total = sum(int(r.get("restarts_attempted") or 0) for r in results)
        hunks_restarted = sum(1 for r in results if int(r.get("restarts_attempted") or 0) > 0)
        task_status_counts: Dict[str, int] = {}
        not_fixed: List[Dict[str, Any]] = []
        for r in results:
            status = str(r.get("task_status", "") or "").strip() or "unknown"
            task_status_counts[status] = task_status_counts.get(status, 0) + 1
            if status != "fixed":
                not_fixed.append(
                    {
                        "patch_key": r.get("patch_key"),
                        "task_status": status,
                        "hunk_fixed": r.get("hunk_fixed"),
                        "remaining_in_active_patch_key": r.get("remaining_in_active_patch_key"),
                        "agent_exit_code": r.get("agent_exit_code"),
                        "agent_output_parse_error": r.get("agent_output_parse_error"),
                    }
                )
        summary_path = artifacts_root / "summary.json"
        return {
            "type": "multi_agent",
            "build_log": str(args.build_log),
            "patch_path": patch_path,
            "max_groups_requested": max_groups_requested,
            "max_steps": max(1, int(getattr(args, "max_steps", 1) or 1)),
            "max_restarts_per_hunk": max(0, int(getattr(args, "max_restarts_per_hunk", 0) or 0)),
            "patch_key_groups_found": patch_key_groups_found,
            "patch_key_groups_after_allowlist": patch_key_groups_after_allowlist,
            "patch_key_groups_selected": patch_key_groups_selected,
            "patch_keys_total": len(ranked),
            "jobs": max(1, int(args.jobs or 1)),
            "artifacts_root": str(artifacts_root),
            "summary_json_path": str(summary_path),
            "hunks_fixed": hunks_fixed,
            "hunks_not_fixed": hunks_not_fixed,
            "hunks_unknown": hunks_unknown,
            "agents_failed": agents_failed,
            "hunks_restarted": hunks_restarted,
            "restarts_attempted_total": restarts_attempted_total,
            "task_status_counts": task_status_counts,
            "not_fixed": not_fixed[:50],
            "results": results,
            "resumed_from": str(resumed_report.get("_resume_source", "") or "").strip(),
            "ongoing": ongoing or [],
        }

    items: Dict[int, Dict[str, Any]] = {}
    to_run: List[tuple[int, str]] = []
    for idx, key in enumerate(ranked):
        prev = resumed_by_key.get(key)
        if isinstance(prev, dict) and str(prev.get("task_status", "") or "").strip() == "fixed":
            items[idx] = prev
        else:
            to_run.append((idx, key))
    if resumed_by_key:
        snap = _report_snapshot(results=[items[i] for i in sorted(items.keys())])
        _write_progress_json(artifacts_root, snap)

    def reset_out_dir(out_dir: Path) -> None:
        resolved = out_dir.resolve()
        root_resolved = artifacts_root.resolve()
        try:
            resolved.relative_to(root_resolved)
        except ValueError as exc:
            raise ValueError(f"Refusing to delete non-artifact directory: {resolved}") from exc
        if resolved == root_resolved:
            raise ValueError(f"Refusing to delete artifacts_root itself: {resolved}")
        if resolved.exists():
            shutil.rmtree(resolved)
        resolved.mkdir(parents=True, exist_ok=True)

    def run_one(patch_key: str, idx: int, *, patch_path_for_agent: str, build_log_path_for_agent: str) -> tuple[int, Dict[str, Any]]:
        errs = groups.get(patch_key) or []
        primary = str(errs[0].get("raw", "")).strip() if errs else ""
        out_dir = artifacts_root / _safe_patch_key_dirname(patch_key)
        out_dir.mkdir(parents=True, exist_ok=True)

        attempt_history: List[Dict[str, Any]] = []
        max_restarts = max(0, int(getattr(args, "max_restarts_per_hunk", 0) or 0))
        attempt = 0
        item: Dict[str, Any] = {}
        while True:
            attempt += 1
            if attempt > 1:
                reset_out_dir(out_dir)

            started_at = time.time()
            started_mono = time.monotonic()
            cmd = _agent_cmd(
                args,
                agent_script=agent_script,
                build_log_path=build_log_path_for_agent,
                patch_path=patch_path_for_agent,
                patch_key=patch_key,
                patch_key_dirname=out_dir.name,
            )
            agent_timeout = getattr(args, "agent_timeout", 1800) or 1800
            # Use per-hunk artifact root so merged diffs go to per-hunk subdirectory, not multi-agent root.
            agent_env = dict(env)
            agent_env["REACT_AGENT_ARTIFACT_ROOT"] = str(out_dir)
            (out_dir / "agent_cmd.txt").write_text(_redact_cmd_for_log(cmd), encoding="utf-8", errors="replace")
            proc_returncode: int = -1  # Default for timeout case
            try:
                proc = subprocess.run(cmd, text=True, capture_output=True, env=agent_env, timeout=agent_timeout)
                stdout = (proc.stdout or "").strip()
                stderr = (proc.stderr or "").strip()
                proc_returncode = proc.returncode
            except subprocess.TimeoutExpired as te:
                stdout = str(te.stdout or "") if te.stdout else ""
                stderr = str(te.stderr or "") if te.stderr else ""
                stderr += f"\n\n[multi_agent] Agent timed out after {agent_timeout} seconds."
                proc_returncode = -1  # Indicate timeout with non-zero exit code
            duration_sec = max(0.0, time.monotonic() - started_mono)
            finished_at = time.time()

            parsed, parse_error = _try_parse_agent_output(stdout)

            (out_dir / "agent_stdout.json").write_text(stdout + ("\n" if stdout else ""), encoding="utf-8", errors="replace")
            if stderr:
                (out_dir / "agent_stderr.log").write_text(stderr + "\n", encoding="utf-8", errors="replace")

            agent_summary = str(parsed.get("summary", "")).strip() if isinstance(parsed, dict) else ""
            agent_next_step = str(parsed.get("next_step", "")).strip() if isinstance(parsed, dict) else ""
            agent_error = parsed.get("error") if isinstance(parsed, dict) else None
            agent_error_line = ""
            if isinstance(agent_error, dict):
                agent_error_line = str(agent_error.get("line", "")).strip()

            ossfuzz_verdict = parsed.get("ossfuzz_verdict") if isinstance(parsed, dict) else None
            patch_key_verdict = parsed.get("patch_key_verdict") if isinstance(parsed, dict) else None

            hunk_fixed: Optional[bool] = None
            remaining_in_active_patch_key: Optional[int] = None
            active_patch_key: str = ""
            log_artifacts: List[str] = []
            if isinstance(patch_key_verdict, dict):
                active_patch_key = str(patch_key_verdict.get("active_patch_key", "") or "").strip()
                la = patch_key_verdict.get("log_artifacts")
                if isinstance(la, list):
                    log_artifacts = [str(x) for x in la if str(x).strip()]
                if patch_key_verdict.get("status") == "ok":
                    rem = patch_key_verdict.get("remaining_in_active_patch_key")
                    if isinstance(rem, int):
                        remaining_in_active_patch_key = rem
                        # Consider the hunk "fixed" if the agent resolved at least one
                        # target error.  With ossfuzz-loop-max=1 the agent only gets a
                        # single build cycle, so partial progress is still valuable --
                        # remaining errors will be picked up in subsequent rounds.
                        total = patch_key_verdict.get("target_errors_total")
                        if isinstance(total, int) and total > 0:
                            hunk_fixed = rem < total
                        else:
                            hunk_fixed = rem == 0

            target_fixed: Optional[bool] = None
            if isinstance(ossfuzz_verdict, dict) and ossfuzz_verdict.get("status") == "ok":
                fixed = ossfuzz_verdict.get("fixed")
                if isinstance(fixed, bool):
                    target_fixed = fixed

            task_status = "unknown"
            task_success: Optional[bool] = None
            if int(proc_returncode) != 0:
                task_status = "agent_failed"
                task_success = False
            elif parse_error:
                task_status = "agent_output_parse_error"
                task_success = False
            elif target_fixed is True:
                # The agent resolved its target error(s) for this patch_key.
                # Even if the overall build still fails (e.g. linker errors
                # from other patch_keys), this hunk's job is done.
                task_status = "fixed"
                task_success = True
                if hunk_fixed is None:
                    hunk_fixed = True
            elif (
                (isinstance(patch_key_verdict, dict) and patch_key_verdict.get("status") == "failed")
                or (isinstance(ossfuzz_verdict, dict) and ossfuzz_verdict.get("status") == "failed")
            ):
                task_status = "ossfuzz_failed"
                task_success = False
            elif hunk_fixed is True:
                task_status = "fixed"
                task_success = True
            elif hunk_fixed is False:
                task_status = "remaining_errors"
                task_success = False

            attempt_history.append(
                {
                    "attempt": attempt,
                    "agent_exit_code": int(proc_returncode),
                    "agent_output_parse_error": parse_error,
                    "task_status": task_status,
                    "task_success": task_success,
                    "hunk_fixed": hunk_fixed,
                    "remaining_in_active_patch_key": remaining_in_active_patch_key,
                    "duration_sec": duration_sec,
                }
            )

            item = {
                "patch_key": patch_key,
                "patch_key_dirname": out_dir.name,
                "errors": len(errs),
                "primary_error": primary,
                "agent_exit_code": int(proc_returncode),
                "agent_summary": agent_summary,
                "agent_next_step": agent_next_step,
                "agent_error_line": agent_error_line,
                "agent_output_parse_error": parse_error,
                "artifacts_dir": str(out_dir),
                "agent_stdout_path": str(out_dir / "agent_stdout.json"),
                "started_at": started_at,
                "finished_at": finished_at,
                "duration_sec": duration_sec,
                "hunk_fixed": hunk_fixed,
                "target_fixed": target_fixed,
                "task_status": task_status,
                "task_success": task_success,
                "remaining_in_active_patch_key": remaining_in_active_patch_key,
                "active_patch_key": active_patch_key,
                "log_artifacts": log_artifacts,
                "ossfuzz_verdict": ossfuzz_verdict,
                "patch_key_verdict": patch_key_verdict,
                "attempts": attempt,
                "restarts_attempted": max(0, attempt - 1),
                "attempt_history": attempt_history,
            }
            if bool(args.include_agent_output):
                item["agent_output"] = parsed

            if task_status == "fixed":
                break
            if attempt >= max_restarts + 1:
                break
            # Not fixed: restart from scratch with a clean artifact directory.
            continue

        return idx, item

    jobs = max(1, int(args.jobs or 1))
    if jobs == 1:
        for idx, key in to_run:
            # Write progress showing this key as ongoing before starting
            snap = _report_snapshot(results=[items[i] for i in sorted(items.keys())], ongoing=[key])
            _write_progress_json(artifacts_root, snap)
            _, item = run_one(key, idx, patch_path_for_agent=effective_patch_path, build_log_path_for_agent=agent_build_log_path)
            items[idx] = item
            snap = _report_snapshot(results=[items[i] for i in sorted(items.keys())], ongoing=[])
            _write_progress_json(artifacts_root, snap)
    else:
        with ThreadPoolExecutor(max_workers=jobs) as ex:
            # Track ongoing patch keys
            ongoing_keys: set[str] = set()
            fut_to_key: Dict[Any, str] = {}
            futs = []
            for idx, key in to_run:
                ongoing_keys.add(key)
                fut = ex.submit(
                    run_one, key, idx, patch_path_for_agent=effective_patch_path, build_log_path_for_agent=agent_build_log_path
                )
                futs.append(fut)
                fut_to_key[fut] = key
            # Write initial progress with all ongoing
            snap = _report_snapshot(results=[items[i] for i in sorted(items.keys())], ongoing=sorted(ongoing_keys))
            _write_progress_json(artifacts_root, snap)
            for fut in as_completed(futs):
                idx, item = fut.result()
                items[idx] = item
                # Remove completed key from ongoing
                completed_key = fut_to_key.get(fut)
                if completed_key:
                    ongoing_keys.discard(completed_key)
                snap = _report_snapshot(results=[items[i] for i in sorted(items.keys())], ongoing=sorted(ongoing_keys))
                _write_progress_json(artifacts_root, snap)
    results = [items[i] for i in sorted(items.keys())]

    hunks_fixed = sum(1 for r in results if r.get("hunk_fixed") is True)
    hunks_not_fixed = sum(1 for r in results if r.get("hunk_fixed") is False)
    hunks_unknown = sum(1 for r in results if r.get("hunk_fixed") is None)
    agents_failed = sum(1 for r in results if int(r.get("agent_exit_code") or 0) != 0)
    restarts_attempted_total = sum(int(r.get("restarts_attempted") or 0) for r in results)
    hunks_restarted = sum(1 for r in results if int(r.get("restarts_attempted") or 0) > 0)
    task_status_counts: Dict[str, int] = {}
    not_fixed: List[Dict[str, Any]] = []
    for r in results:
        status = str(r.get("task_status", "") or "").strip() or "unknown"
        task_status_counts[status] = task_status_counts.get(status, 0) + 1
        if status != "fixed":
            not_fixed.append(
                {
                    "patch_key": r.get("patch_key"),
                    "task_status": status,
                    "hunk_fixed": r.get("hunk_fixed"),
                    "remaining_in_active_patch_key": r.get("remaining_in_active_patch_key"),
                    "agent_exit_code": r.get("agent_exit_code"),
                    "agent_output_parse_error": r.get("agent_output_parse_error"),
                }
            )

    overrides = _collect_final_override_diffs(results, patch_path=effective_patch_path)
    combined_override_paths: List[str] = list(overrides.get("override_paths") or [])
    combined_override_paths_count = len(combined_override_paths)
    merged_patch_bundle_path = ""
    merged_patch_bundle_error = ""
    if combined_override_paths:
        try:
            # Ensure the bundle writer validates override paths under the multi-run artifact root.
            os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(artifacts_root)
            from tools.ossfuzz_tools import write_patch_bundle_with_overrides  # type: ignore

            base = _patch_base_name(effective_patch_path)
            out = write_patch_bundle_with_overrides(
                patch_path=str(effective_patch_path),
                patch_override_paths=combined_override_paths,
                output_name=f"{base}.merged_overrides.patch2",
            )
            merged_patch_bundle_path = str(out.get("merged_patch_bundle_path", "") or "").strip()
        except Exception as exc:  # noqa: BLE001
            merged_patch_bundle_error = f"{type(exc).__name__}: {exc}"
            merged_patch_bundle_path = ""

    final_mode = str(getattr(args, "final_ossfuzz_test", "auto") or "auto").strip().lower()
    final_ossfuzz_test: Dict[str, Any] = {
        "status": "skipped",
        "mode": final_mode,
        "reason": "",
        "override_paths_count": combined_override_paths_count,
        "override_paths": combined_override_paths,
        "override_paths_sorted_by": "PatchInfo.new_start_line(desc)",
        "combined_override_diffs_path": "",
        "combined_override_diffs_note": "Disabled: multi_agent now writes a merged patch bundle instead of concatenating override diffs.",
        "merged_patch_bundle_path": merged_patch_bundle_path,
        "merged_patch_bundle_error": merged_patch_bundle_error,
        "merged_patch_bundle_note": (
            "Patch bundle (pickle) with per-hunk override diffs applied. "
            "Use this as --patch-path for future patch-scope runs, or pass it to ossfuzz_apply_patch_and_test with patch_override_paths=[]."
        ),
        "override_diffs_per_hunk": list(overrides.get("per_hunk") or []),
        "override_diffs_missing_patch_keys": list(overrides.get("missing_patch_keys") or []),
        "override_diffs_sort_error": str(overrides.get("sort_error") or "").strip(),
    }
    if final_mode not in {"auto", "always", "never"}:
        final_mode = "auto"
        final_ossfuzz_test["mode"] = final_mode
    if final_mode == "never":
        final_ossfuzz_test["reason"] = "final-ossfuzz-test=never"
    elif str(args.tools) != "real":
        final_ossfuzz_test["reason"] = f"--tools {args.tools} (final OSS-Fuzz test requires --tools real)"
    else:
        all_fixed = all(str(r.get("task_status", "") or "").strip() == "fixed" for r in results or [])
        if final_mode == "auto" and not all_fixed:
            final_ossfuzz_test["reason"] = "Not all hunks are fixed (auto mode)."
        else:
            try:
                os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(artifacts_root)
                from tools.ossfuzz_tools import ossfuzz_apply_patch_and_test  # type: ignore

                patch_path_for_test = (
                    merged_patch_bundle_path if merged_patch_bundle_path and not merged_patch_bundle_error else str(args.patch_path)
                )
                override_paths_for_test: List[str] = [] if patch_path_for_test != str(args.patch_path) else combined_override_paths

                res = ossfuzz_apply_patch_and_test(
                    project=str(args.ossfuzz_project),
                    commit=str(args.ossfuzz_commit),
                    patch_path=str(patch_path_for_test),
                    patch_override_paths=override_paths_for_test,
                    build_csv=str(args.ossfuzz_build_csv),
                    sanitizer=str(args.ossfuzz_sanitizer),
                    architecture=str(args.ossfuzz_arch),
                    engine=str(args.ossfuzz_engine),
                    fuzz_target=str(args.ossfuzz_fuzz_target),
                    use_sudo=bool(args.ossfuzz_use_sudo),
                )

                build_log_path = (artifacts_root / "final_ossfuzz_build_output.log").resolve()
                # build_output is an artifact ref dict; read actual content from artifact_path
                build_output_ref = res.get("build_output") or {}
                build_output_artifact = build_output_ref.get("artifact_path", "") if isinstance(build_output_ref, dict) else ""
                if build_output_artifact and Path(build_output_artifact).is_file():
                    build_log_text = Path(build_output_artifact).read_text(encoding="utf-8", errors="replace")
                else:
                    build_log_text = str(build_output_ref)
                build_log_path.write_text(build_log_text, encoding="utf-8", errors="replace")

                # Remove the redundant tool artifact (content already saved as final_ossfuzz_build_output.log)
                if build_output_artifact and Path(build_output_artifact).is_file():
                    Path(build_output_artifact).unlink(missing_ok=True)

                patch_apply_ok = bool(res.get("patch_apply_ok"))
                build_ok = bool(res.get("build_ok"))
                ok = patch_apply_ok and build_ok
                final_ossfuzz_test.update(
                    {
                        "status": "ok" if ok else "failed",
                        "reason": str(res.get("patch_apply_error", "") or "").strip(),
                        "merged_patch_file_path": str(res.get("merged_patch_file_path", "") or "").strip(),
                        "patch_apply_ok": patch_apply_ok,
                        "build_ok": build_ok,
                        "build_output_path": str(build_log_path),
                    }
                )
                if not final_ossfuzz_test["reason"] and not ok:
                    final_ossfuzz_test["reason"] = "OSS-Fuzz build failed."
            except Exception as exc:
                final_ossfuzz_test.update({"status": "failed", "reason": f"{type(exc).__name__}: {exc}"})

    summary_path = artifacts_root / "summary.json"
    report = {
        "type": "multi_agent",
        "build_log": str(args.build_log),
        "patch_path": patch_path,
        "max_groups_requested": max_groups_requested,
        "max_steps": max(1, int(getattr(args, "max_steps", 1) or 1)),
        "max_restarts_per_hunk": max(0, int(getattr(args, "max_restarts_per_hunk", 0) or 0)),
        "final_ossfuzz_test": final_ossfuzz_test,
        "patch_key_groups_found": patch_key_groups_found,
        "patch_key_groups_after_allowlist": patch_key_groups_after_allowlist,
        "patch_key_groups_selected": patch_key_groups_selected,
        "patch_keys_total": len(ranked),
        "jobs": jobs,
        "artifacts_root": str(artifacts_root),
        "summary_json_path": str(summary_path),
        "hunks_fixed": hunks_fixed,
        "hunks_not_fixed": hunks_not_fixed,
        "hunks_unknown": hunks_unknown,
        "agents_failed": agents_failed,
        "hunks_restarted": hunks_restarted,
        "restarts_attempted_total": restarts_attempted_total,
        "task_status_counts": task_status_counts,
        "not_fixed": not_fixed[:50],
        "results": results,
        "resumed_from": str(resumed_report.get("_resume_source", "") or "").strip(),
    }
    summary_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _write_progress_json(artifacts_root, report)
    _emit(report, str(args.output_format))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
