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
from build_log import iter_compiler_errors, load_build_log


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


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
    redacted: List[str] = []
    skip_next = False
    for token in cmd:
        if skip_next:
            redacted.append("REDACTED")
            skip_next = False
            continue
        if token == "--openai-api-key":
            redacted.append(token)
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


def _latest_make_error_patch_override_diff(artifacts_dir: Path) -> Optional[Path]:
    patterns = [
        "make_error_patch_override_patch_text_*.diff",
        "make_error_patch_override_patch_text*.diff",
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


def _collect_final_override_diffs(results: List[Dict[str, Any]], *, patch_path: str) -> Dict[str, Any]:
    override_paths: List[str] = []
    per_hunk: List[Dict[str, Any]] = []
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

        chosen = ""
        method = ""
        agent_stdout_path = artifacts_dir / "agent_stdout.json"
        if agent_stdout_path.is_file():
            chosen = _extract_override_diff_from_agent_stdout(agent_stdout_path)
            if chosen:
                method = "agent_stdout.next_step"

        if not chosen:
            latest = _latest_make_error_patch_override_diff(artifacts_dir)
            if latest is not None:
                chosen = str(latest.resolve())
                method = "glob_latest"

        if not chosen:
            missing.append(patch_key)
            continue

        override_paths.append(chosen)
        per_hunk.append(
            {
                "patch_key": patch_key,
                "override_diff": chosen,
                "method": method,
                "new_start_line": patch_key_new_start_line.get(patch_key, 0),
            }
        )

    # Sort like script/revert_patch_test.py: newer hunks first (bottom-up application).
    per_hunk.sort(key=lambda item: (-int(item.get("new_start_line", 0) or 0), str(item.get("patch_key", "") or "")))
    override_paths = [str(item.get("override_diff", "") or "").strip() for item in per_hunk if str(item.get("override_diff", "") or "").strip()]

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


def _group_errors_by_patch_key(*, build_log_text: str, patch_path: str) -> Dict[str, List[Dict[str, Any]]]:
    bundle, get_error_patch = _load_bundle(patch_path)
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for err in iter_compiler_errors(build_log_text, snippet_lines=10):
        mapping = get_error_patch(bundle, patch_path=patch_path, file_path=err["file"], line_number=err["line"])
        key = str(mapping.get("patch_key") or "").strip()
        if not key:
            continue
        enriched = dict(err)
        enriched["patch_key"] = key
        enriched["old_signature"] = mapping.get("old_signature")
        groups.setdefault(key, []).append(enriched)
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
    p.add_argument("--max-groups", type=int, default=20, help="Max patch_key groups to run (default: 20).")
    p.add_argument(
        "--max-restarts-per-hunk",
        type=int,
        default=int(os.environ.get("REACT_AGENT_MAX_RESTARTS_PER_HUNK", "0") or 0),
        help="If a hunk is not fixed, delete its artifacts dir and rerun (default: 0).",
    )
    p.add_argument("--jobs", type=int, default=1, help="Max concurrent agents to run (default: 1).")
    p.add_argument("--output-format", choices=["none", "auto", "json", "json-pretty", "text"], default="none")
    p.add_argument("--model", choices=["openai", "stub"], default=os.environ.get("REACT_AGENT_MODEL", "openai"))
    p.add_argument("--tools", choices=["real", "fake"], default="real")
    p.add_argument("--max-steps", type=int, default=10)
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
        default=str(os.environ.get("REACT_AGENT_FINAL_OSSFUZZ_TEST", "auto") or "auto"),
        help=(
            "After all hunks complete, run a single OSS-Fuzz build/check_build using the combined override diffs. "
            "auto=only when all hunks are fixed and --tools real; always=run regardless of per-hunk status; never=skip."
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


def _agent_cmd(
    args: argparse.Namespace, *, agent_script: Path, build_log_path: str, patch_key: str, patch_key_dirname: str
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
        str(args.patch_path),
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
    groups = _group_errors_by_patch_key(build_log_text=build_log_text, patch_path=patch_path)
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

    repo_root = Path(__file__).resolve().parents[2]
    agent_script = repo_root / "script" / "react_agent" / "agent_langgraph.py"
    if not agent_script.is_file():
        raise FileNotFoundError(str(agent_script))

    run_id = default_run_id()
    artifacts_root = repo_root / "data" / "react_agent_artifacts" / f"multi_{run_id}"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    agent_build_log_path = str(args.build_log)
    if str(args.build_log).strip() == "-":
        out_path = artifacts_root / "build.log"
        out_path.write_text(build_log_text + ("\n" if build_log_text and not build_log_text.endswith("\n") else ""), encoding="utf-8", errors="replace")
        agent_build_log_path = str(out_path)

    results: List[Dict[str, Any]] = []
    env = dict(os.environ)
    env["REACT_AGENT_ARTIFACT_ROOT"] = str(artifacts_root)
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")

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

    def run_one(patch_key: str, idx: int) -> tuple[int, Dict[str, Any]]:
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
                build_log_path=agent_build_log_path,
                patch_key=patch_key,
                patch_key_dirname=out_dir.name,
            )
            proc = subprocess.run(cmd, text=True, capture_output=True, env=env)
            duration_sec = max(0.0, time.monotonic() - started_mono)
            finished_at = time.time()

            stdout = (proc.stdout or "").strip()
            stderr = (proc.stderr or "").strip()
            parsed, parse_error = _try_parse_agent_output(stdout)

            (out_dir / "agent_cmd.txt").write_text(_redact_cmd_for_log(cmd), encoding="utf-8", errors="replace")
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
                        hunk_fixed = rem == 0

            target_fixed: Optional[bool] = None
            if isinstance(ossfuzz_verdict, dict) and ossfuzz_verdict.get("status") == "ok":
                fixed = ossfuzz_verdict.get("fixed")
                if isinstance(fixed, bool):
                    target_fixed = fixed

            task_status = "unknown"
            task_success: Optional[bool] = None
            if int(proc.returncode) != 0:
                task_status = "agent_failed"
                task_success = False
            elif parse_error:
                task_status = "agent_output_parse_error"
                task_success = False
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
                    "agent_exit_code": int(proc.returncode),
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
                "agent_exit_code": int(proc.returncode),
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
        for idx, key in enumerate(ranked):
            _, item = run_one(key, idx)
            results.append(item)
    else:
        items: Dict[int, Dict[str, Any]] = {}
        with ThreadPoolExecutor(max_workers=jobs) as ex:
            futs = [ex.submit(run_one, key, idx) for idx, key in enumerate(ranked)]
            for fut in as_completed(futs):
                idx, item = fut.result()
                items[idx] = item
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

    overrides = _collect_final_override_diffs(results, patch_path=patch_path)
    combined_override_paths: List[str] = list(overrides.get("override_paths") or [])
    combined_override_paths_count = len(combined_override_paths)
    merged_patch_bundle_path = ""
    merged_patch_bundle_error = ""
    if combined_override_paths:
        try:
            # Ensure the bundle writer validates override paths under the multi-run artifact root.
            os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(artifacts_root)
            from tools.ossfuzz_tools import write_patch_bundle_with_overrides  # type: ignore

            base = Path(patch_path).stem or "bundle"
            out = write_patch_bundle_with_overrides(
                patch_path=str(patch_path),
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
                check_log_path = (artifacts_root / "final_ossfuzz_check_build_output.log").resolve()
                build_log_path.write_text(str(res.get("build_output", "") or ""), encoding="utf-8", errors="replace")
                check_log_path.write_text(str(res.get("check_build_output", "") or ""), encoding="utf-8", errors="replace")

                run_fuzzer_output = str(res.get("run_fuzzer_output", "") or "")
                run_fuzzer_path = ""
                if run_fuzzer_output.strip():
                    p = (artifacts_root / "final_ossfuzz_run_fuzzer_output.log").resolve()
                    p.write_text(run_fuzzer_output, encoding="utf-8", errors="replace")
                    run_fuzzer_path = str(p)

                patch_apply_ok = bool(res.get("patch_apply_ok"))
                build_ok = bool(res.get("build_ok"))
                check_ok = bool(res.get("check_build_ok"))
                run_ok = res.get("run_fuzzer_ok")
                ok = patch_apply_ok and build_ok and check_ok and (run_ok is not False)
                final_ossfuzz_test.update(
                    {
                        "status": "ok" if ok else "failed",
                        "reason": str(res.get("patch_apply_error", "") or "").strip(),
                        "merged_patch_file_path": str(res.get("merged_patch_file_path", "") or "").strip(),
                        "patch_apply_ok": patch_apply_ok,
                        "build_ok": build_ok,
                        "check_build_ok": check_ok,
                        "run_fuzzer_ok": run_ok,
                        "build_output_path": str(build_log_path),
                        "check_build_output_path": str(check_log_path),
                        "run_fuzzer_output_path": run_fuzzer_path,
                    }
                )
                if not final_ossfuzz_test["reason"] and not ok:
                    final_ossfuzz_test["reason"] = "OSS-Fuzz build/check_build failed."
            except Exception as exc:
                final_ossfuzz_test.update({"status": "failed", "reason": f"{type(exc).__name__}: {exc}"})

    summary_path = artifacts_root / "summary.json"
    report = {
        "type": "multi_agent",
        "build_log": str(args.build_log),
        "patch_path": patch_path,
        "max_groups_requested": max_groups_requested,
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
    }
    summary_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _emit(report, str(args.output_format))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
