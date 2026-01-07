#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from artifacts import default_run_id
from build_log import iter_compiler_errors, load_build_log


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_patch_key_dirname(name: str, *, max_len: int = 160) -> str:
    raw = str(name or "").strip()
    raw = raw.replace(os.sep, "_")
    cleaned = _SAFE_NAME_RE.sub("_", raw).strip("._-")
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
    if fmt == "text":
        sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
        return
    if fmt == "json-pretty":
        sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
        return
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")


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
    for err in iter_compiler_errors(build_log_text):
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
    p.add_argument("--output-format", choices=["auto", "json", "json-pretty", "text"], default="json-pretty")
    p.add_argument("--model", choices=["openai", "stub"], default=os.environ.get("REACT_AGENT_MODEL", "openai"))
    p.add_argument("--tools", choices=["real", "fake"], default="real")
    p.add_argument("--max-steps", type=int, default=10)
    p.add_argument("--only-patch-keys", default="", help="Comma-separated patch_key allowlist.")
    p.add_argument(
        "--include-agent-output",
        action="store_true",
        help="Include full per-agent JSON output in the multi-agent report (default: store full output in artifacts only).",
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

    p.add_argument("--ossfuzz-project", default=os.environ.get("REACT_AGENT_OSSFUZZ_PROJECT", ""))
    p.add_argument("--ossfuzz-commit", default=os.environ.get("REACT_AGENT_OSSFUZZ_COMMIT", ""))
    p.add_argument("--ossfuzz-build-csv", default=os.environ.get("REACT_AGENT_OSSFUZZ_BUILD_CSV", ""))
    p.add_argument("--ossfuzz-sanitizer", default=os.environ.get("REACT_AGENT_OSSFUZZ_SANITIZER", "address"))
    p.add_argument("--ossfuzz-arch", default=os.environ.get("REACT_AGENT_OSSFUZZ_ARCH", "x86_64"))
    p.add_argument("--ossfuzz-engine", default=os.environ.get("REACT_AGENT_OSSFUZZ_ENGINE", "libfuzzer"))
    p.add_argument("--ossfuzz-fuzz-target", default=os.environ.get("REACT_AGENT_OSSFUZZ_FUZZ_TARGET", ""))
    p.add_argument("--ossfuzz-use-sudo", action="store_true", default=bool(os.environ.get("REACT_AGENT_OSSFUZZ_USE_SUDO", "")))
    return p


def _agent_cmd(args: argparse.Namespace, *, agent_script: Path, patch_key: str) -> List[str]:
    cmd = [
        sys.executable,
        str(agent_script),
        str(args.build_log),
        "--output-format",
        "json-pretty",
        "--model",
        str(args.model),
        "--tools",
        str(args.tools),
        "--max-steps",
        str(max(int(args.max_steps or 1), 1)),
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

    if str(args.v1_json_dir).strip():
        cmd.extend(["--v1-json-dir", str(args.v1_json_dir)])
    if str(args.v2_json_dir).strip():
        cmd.extend(["--v2-json-dir", str(args.v2_json_dir)])
    if str(args.v1_src).strip():
        cmd.extend(["--v1-src", str(args.v1_src)])
    if str(args.v2_src).strip():
        cmd.extend(["--v2-src", str(args.v2_src)])

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
    ranked = _rank_patch_keys(groups)

    allow_raw = str(args.only_patch_keys or "").strip()
    allow = {s.strip() for s in allow_raw.split(",") if s.strip()} if allow_raw else set()
    if allow:
        ranked = [k for k in ranked if k in allow]

    max_groups = max(0, int(args.max_groups or 0))
    if max_groups:
        ranked = ranked[:max_groups]

    repo_root = Path(__file__).resolve().parents[2]
    agent_script = repo_root / "script" / "react_agent" / "agent_langgraph.py"
    if not agent_script.is_file():
        raise FileNotFoundError(str(agent_script))

    run_id = default_run_id()
    artifacts_root = repo_root / "data" / "react_agent_artifacts" / f"multi_{run_id}"
    artifacts_root.mkdir(parents=True, exist_ok=True)

    results: List[Dict[str, Any]] = []
    env = dict(os.environ)
    env["REACT_AGENT_ARTIFACT_ROOT"] = str(artifacts_root)
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")

    for key in ranked:
        errs = groups.get(key) or []
        primary = str(errs[0].get("raw", "")).strip() if errs else ""
        cmd = _agent_cmd(args, agent_script=agent_script, patch_key=key)
        proc = subprocess.run(cmd, text=True, capture_output=True, env=env)
        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        parsed: Any = None
        parse_error: Optional[str] = None
        if stdout:
            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError as exc:
                parse_error = f"{type(exc).__name__}: {exc}"

        out_dir = artifacts_root / _safe_patch_key_dirname(key)
        out_dir.mkdir(parents=True, exist_ok=True)
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

        item: Dict[str, Any] = {
            "patch_key": key,
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
        }
        if bool(args.include_agent_output):
            item["agent_output"] = parsed
        results.append(item)

    report = {
        "type": "multi_agent",
        "build_log": str(args.build_log),
        "patch_path": patch_path,
        "patch_keys_total": len(ranked),
        "artifacts_root": str(artifacts_root),
        "results": results,
    }
    (artifacts_root / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _emit(report, str(args.output_format))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
