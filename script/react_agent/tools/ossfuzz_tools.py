from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_PATCH_APPLY_ERROR_PATTERNS = [
    re.compile(r"^error:\s+corrupt patch(?:\s+at\s+line\s+\d+)?\s*$", re.IGNORECASE),
    re.compile(r"^error:\s+patch failed:\s+.*$", re.IGNORECASE),
    re.compile(r"^error:\s+.*:\s+patch does not apply\s*$", re.IGNORECASE),
    re.compile(r"^error:\s+no valid patches in input.*$", re.IGNORECASE),
    re.compile(r"^patch:\s+\*{4}.*$", re.IGNORECASE),
    re.compile(r"^fatal:\s+patch failed.*$", re.IGNORECASE),
]
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


def _allowed_patch_roots_from_env() -> list[str] | None:
    raw = os.environ.get("REACT_AGENT_PATCH_ALLOWED_ROOTS", "").strip()
    if not raw:
        return None
    roots = [r.strip() for r in raw.split(os.pathsep) if r.strip()]
    return roots or None


def _infer_patch_key_from_path(path: Path, patch_keys: set[str]) -> str:
    for parent in [path.parent, *path.parents]:
        name = str(parent.name or "").strip()
        if name and name in patch_keys:
            return name
    raise ValueError(
        "Could not infer patch_key for override patch file. "
        "Put override artifacts under a directory named <patch_key> (e.g. data/react_agent_artifacts/<patch_key>/...)."
    )


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

    overrides: dict[str, str] = {}
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
        overrides[patch_key] = text
        override_files.append({"patch_key": patch_key, "path": str(p)})

    parts: list[str] = []
    for key in bundle.keys_sorted:
        patch_text = overrides.get(key, bundle.patches[key].patch_text or "")
        patch_text = str(patch_text or "").rstrip("\n")
        if patch_text:
            parts.append(patch_text)

    merged_text = ("\n\n".join(parts).rstrip("\n") + "\n") if parts else ""

    out_name = _safe_filename(str(output_name or "ossfuzz_merged.diff"))
    # Avoid collisions across parallel agents by writing the merged patch file under the inferred patch_key
    # directory when possible (single-hunk overrides are the common case). If the allow-root is already the
    # per-hunk patch_key directory, do not nest patch_key/patch_key.
    out_dir = allow_root
    unique_keys = {str(o.get("patch_key", "")).strip() for o in override_files if str(o.get("patch_key", "")).strip()}
    inferred_key = ""
    if len(unique_keys) == 1:
        inferred_key = next(iter(unique_keys))
    elif not unique_keys:
        # Common case: patch_override_paths may be empty when the caller uses an "effective" *.patch2 that already
        # contains the updated patch_text for the active patch_key. In that scenario, infer the patch_key from the
        # bundle path on disk so merged patch output stays under the per-hunk artifacts dir.
        try:
            inferred_key = _infer_patch_key_from_path(Path(patch_path).expanduser().resolve(), patch_keys)
        except Exception:
            inferred_key = ""
    if inferred_key and str(allow_root.name) != str(inferred_key):
        out_dir = (allow_root / inferred_key).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
    out_path = _unique_path((out_dir / out_name).resolve())
    _validate_under_root(out_path, allow_root)
    out_path.write_text(merged_text, encoding="utf-8", errors="replace")

    return {
        "patch_path": str(Path(patch_path).expanduser().resolve()),
        "merged_patch_file_path": str(out_path),
        "patch_count_total": len(bundle.patches),
        "override_count": len(override_files),
        "override_files": override_files,
        "overridden_patch_keys": sorted({o["patch_key"] for o in override_files}),
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
    run_fuzzer_seconds: int = 30,
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
        build_ok = build_res["returncode"] == 0
        build_patch_apply_error = _find_patch_apply_error(build_res.get("output", ""))

        check_build_cmd: List[str] = [
            sys.executable,
            str(helper_py),
            "check_build",
            "--sanitizer",
            str(sanitizer or "address"),
            "--engine",
            str(engine or "libfuzzer"),
            "--architecture",
            str(architecture or "x86_64"),
            "-e",
            "ASAN_OPTIONS=detect_leaks=0",
            project_name,
        ]
        check_build_cmd = _maybe_prefix_sudo(check_build_cmd, use_sudo=use_sudo)

        check_res = _run(check_build_cmd, label="check_build", cwd=str(oss_fuzz_dir), timeout_seconds=timeout_seconds)
        check_ok = check_res["returncode"] == 0
        check_patch_apply_error = _find_patch_apply_error(check_res.get("output", ""))
        patch_apply_error = build_patch_apply_error or check_patch_apply_error
        patch_apply_ok = not bool(patch_apply_error)

        run_fuzzer_output = ""
        run_fuzzer_cmd: List[str] = []
        run_fuzzer_ok: Optional[bool] = None
        if fuzz_target:
            secs = max(1, min(int(run_fuzzer_seconds or 0), 600))
            run_fuzzer_cmd = [
                sys.executable,
                str(helper_py),
                "run_fuzzer",
                "-e",
                "ASAN_OPTIONS=detect_leaks=0",
                project_name,
                str(fuzz_target),
                "--",
                f"-max_total_time={secs}",
                "-timeout=5",
            ]
            run_fuzzer_cmd = _maybe_prefix_sudo(run_fuzzer_cmd, use_sudo=use_sudo)
            run_res = _run(run_fuzzer_cmd, label="run_fuzzer", cwd=str(oss_fuzz_dir), timeout_seconds=timeout_seconds)
            run_fuzzer_output = run_res["output"]
            run_fuzzer_ok = run_res["returncode"] == 0

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
        "check_build_ok": check_ok,
        "run_fuzzer_ok": run_fuzzer_ok,
        "build_cmd": build_cmd,
        "check_build_cmd": check_build_cmd,
        "run_fuzzer_cmd": run_fuzzer_cmd,
        "build_output": build_res["output"],
        "check_build_output": check_res["output"],
        "run_fuzzer_output": run_fuzzer_output,
    }
