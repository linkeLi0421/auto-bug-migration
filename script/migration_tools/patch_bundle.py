from __future__ import annotations

import gzip
import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from .types import FunctionLocation, PatchInfo


def _repo_root() -> Path:
    # script/migration_tools/patch_bundle.py -> script/migration_tools -> script -> repo
    return Path(__file__).resolve().parents[2]


DEFAULT_ALLOWED_ROOTS: tuple[Path, ...] = (
    _repo_root() / "data" / "tmp_patch",
    _repo_root() / "data" / "react_agent_artifacts",
)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def ensure_allowed_path(path: str | Path, allowed_roots: Optional[Iterable[str | Path]] = None) -> Path:
    """Resolve and validate a patch bundle path against an allowlist."""
    p = Path(path).expanduser().resolve()
    roots = [Path(r).expanduser().resolve() for r in (allowed_roots or DEFAULT_ALLOWED_ROOTS)]
    if not any(_is_within(p, r) for r in roots):
        roots_s = ", ".join(str(r) for r in roots)
        raise ValueError(f"Refusing to read patch bundle outside allowed roots: {p} (allowed: {roots_s})")
    if not p.is_file():
        raise FileNotFoundError(str(p))
    return p


class RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that only allows a small allowlist of globals."""

    _SAFE_BUILTINS: dict[str, Any] = {
        "dict": dict,
        "list": list,
        "set": set,
        "frozenset": frozenset,
        "tuple": tuple,
        "str": str,
        "int": int,
        "float": float,
        "bool": bool,
        "bytes": bytes,
    }

    _ALLOWED_GLOBALS: dict[tuple[str, str], Any] = {
        ("migration_tools.types", "PatchInfo"): PatchInfo,
        ("migration_tools.types", "FunctionLocation"): FunctionLocation,
        # Back-compat: old pickles created when revert_patch_test.py ran as a script.
        ("__main__", "PatchInfo"): PatchInfo,
        ("__main__", "FunctionLocation"): FunctionLocation,
        # Back-compat: possible module names when run/imported differently.
        ("revert_patch_test", "PatchInfo"): PatchInfo,
        ("revert_patch_test", "FunctionLocation"): FunctionLocation,
        ("script.revert_patch_test", "PatchInfo"): PatchInfo,
        ("script.revert_patch_test", "FunctionLocation"): FunctionLocation,
    }

    def find_class(self, module: str, name: str) -> Any:  # noqa: D401
        """Resolve global references with a strict allowlist."""
        if module == "builtins" and name in self._SAFE_BUILTINS:
            return self._SAFE_BUILTINS[name]
        key = (module, name)
        if key in self._ALLOWED_GLOBALS:
            return self._ALLOWED_GLOBALS[key]
        raise pickle.UnpicklingError(f"Forbidden global during unpickle: {module}.{name}")


@dataclass(frozen=True)
class PatchBundle:
    """Loaded patch bundle with helper indexes."""

    patches: Dict[str, PatchInfo]
    keys_sorted: list[str]
    by_file_new: Dict[str, list[str]]
    by_patch_type: Dict[str, list[str]]
    by_signature: Dict[str, list[str]]


def _peek_is_gzip(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(2) == b"\x1f\x8b"
    except OSError:
        return False


def load_patch_bundle(path: str | Path, *, allowed_roots: Optional[Iterable[str | Path]] = None) -> PatchBundle:
    """Load a patch bundle from a pickle (optionally gzip-compressed)."""
    p = ensure_allowed_path(path, allowed_roots=allowed_roots)
    is_gz = p.suffix == ".gz" or _peek_is_gzip(p)

    opener = gzip.open if is_gz else open
    with opener(p, "rb") as f:
        data = RestrictedUnpickler(f).load()

    if not isinstance(data, dict):
        raise ValueError("Patch bundle must be a dict")

    patches: Dict[str, PatchInfo] = {}
    for k, v in data.items():
        if not isinstance(k, str):
            k = str(k)
        if not isinstance(v, PatchInfo):
            raise ValueError(f"Unexpected patch value type for {k}: {type(v).__name__}")
        patches[k] = v

    keys_sorted = sorted(patches.keys(), key=lambda key: (-int(getattr(patches[key], "new_start_line", 0) or 0), key))
    by_file_new: Dict[str, list[str]] = {}
    by_patch_type: Dict[str, list[str]] = {}
    by_signature: Dict[str, list[str]] = {}

    for key in keys_sorted:
        patch = patches[key]
        file_new = str(patch.file_path_new or "")
        by_file_new.setdefault(file_new, []).append(key)
        for pt in sorted(patch.patch_type or set()):
            by_patch_type.setdefault(str(pt), []).append(key)
        for sig in (patch.old_signature, patch.new_signature):
            if sig:
                by_signature.setdefault(str(sig), []).append(key)

    return PatchBundle(
        patches=patches,
        keys_sorted=keys_sorted,
        by_file_new=by_file_new,
        by_patch_type=by_patch_type,
        by_signature=by_signature,
    )
