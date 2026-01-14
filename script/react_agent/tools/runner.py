from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional

from agent_tools import AgentTools

from .registry import ALLOWED_TOOLS

from .artifact_tools import read_artifact as read_artifact_tool

from .ossfuzz_tools import ossfuzz_apply_patch_and_test as ossfuzz_apply_patch_and_test_tool

from .migration_tools import (  # noqa: E402
    get_error_patch_context as get_error_patch_context_tool,
    get_patch as get_patch_tool,
    list_patch_bundle as list_patch_bundle_tool,
    make_error_patch_override as make_error_patch_override_tool,
    parse_build_errors as parse_build_errors_tool,
    search_patches as search_patches_tool,
)


@dataclass(frozen=True)
class ToolObservation:
    """Result of executing a tool call."""

    ok: bool
    tool: str
    args: Dict[str, Any]
    output: Any
    error: Optional[str] = None


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "y", "on"}:
            return True
        if lowered in {"0", "false", "no", "n", "off"}:
            return False
    return default


class ToolRunner:
    """Dispatch tool calls to AgentTools with best-effort validation."""

    def __init__(self, agent_tools: Optional[AgentTools], mode: Literal["real", "fake"] = "real") -> None:
        self._agent_tools = agent_tools
        self._mode = mode

    def call(self, tool: str, args: Dict[str, Any]) -> ToolObservation:
        """Execute a tool call and return a JSON-serializable observation."""
        if tool not in ALLOWED_TOOLS:
            return ToolObservation(False, tool, args, output="", error=f"Unknown tool: {tool}")
        if not isinstance(args, dict):
            return ToolObservation(False, tool, {}, output="", error="Tool args must be an object")

        if self._mode == "fake":
            return ToolObservation(True, tool, args, output=f"[FAKE TOOL OUTPUT] {tool}({args})")

        try:
            if tool == "read_artifact":
                artifact_path = str(args.get("artifact_path", "")).strip()
                start_line = _as_int(args.get("start_line"), 1)
                max_lines = _as_int(args.get("max_lines"), 200)
                query = str(args.get("query", "")).strip()
                context_lines = _as_int(args.get("context_lines"), 8)
                max_chars = _as_int(args.get("max_chars"), 20000)
                if not artifact_path:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: artifact_path")
                out = read_artifact_tool(
                    artifact_path=artifact_path,
                    start_line=start_line,
                    max_lines=max_lines,
                    query=query,
                    context_lines=context_lines,
                    max_chars=max_chars,
                )
                return ToolObservation(
                    True,
                    tool,
                    {
                        "artifact_path": artifact_path,
                        "start_line": start_line,
                        "max_lines": max_lines,
                        "query": query,
                        "context_lines": context_lines,
                        "max_chars": max_chars,
                    },
                    output=out,
                )

            if tool == "inspect_symbol":
                return ToolObservation(False, tool, args, output="", error="Removed tool: inspect_symbol (use search_definition).")

            if tool == "search_definition":
                if not self._agent_tools:
                    return ToolObservation(False, tool, args, output="", error="Tool runner not configured")
                symbol_name = str(args.get("symbol_name", "")).strip()
                version = str(args.get("version", "v1")).strip() or "v1"
                if not symbol_name:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: symbol_name")
                if version not in {"v1", "v2"}:
                    return ToolObservation(False, tool, args, output="", error="Invalid arg: version (expected v1|v2)")
                out = self._agent_tools.search_definition(symbol_name, version=version)
                return ToolObservation(True, tool, {"symbol_name": symbol_name, "version": version}, output=out)

            if tool == "kb_search_symbols":
                if not self._agent_tools:
                    return ToolObservation(False, tool, args, output="", error="Tool runner not configured")
                symbols = args.get("symbols", [])
                version = str(args.get("version", "v2")).strip() or "v2"
                kinds = args.get("kinds")
                limit_per_symbol = _as_int(args.get("limit_per_symbol"), 5)
                if not isinstance(symbols, list):
                    symbols = [symbols]
                if kinds is not None and not isinstance(kinds, list):
                    kinds = [kinds]
                if version not in {"v1", "v2"}:
                    return ToolObservation(False, tool, args, output="", error="Invalid arg: version (expected v1|v2)")
                out = self._agent_tools.kb_search_symbols(
                    [str(s) for s in symbols],
                    version=version,
                    kinds=[str(k) for k in kinds] if kinds is not None else None,
                    limit_per_symbol=limit_per_symbol,
                )
                return ToolObservation(
                    True,
                    tool,
                    {"symbols": [str(s) for s in symbols], "version": version, "kinds": kinds, "limit_per_symbol": limit_per_symbol},
                    output=out,
                )

            if tool == "read_file_context":
                if not self._agent_tools:
                    return ToolObservation(False, tool, args, output="", error="Tool runner not configured")
                file_path = str(args.get("file_path", "")).strip()
                line_number = _as_int(args.get("line_number"), 0)
                context = _as_int(args.get("context"), 5)
                version = str(args.get("version", "v2")).strip() or "v2"
                if not file_path:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: file_path")
                if line_number <= 0:
                    return ToolObservation(False, tool, args, output="", error="Invalid arg: line_number")
                out = self._agent_tools.read_file_context(
                    file_path=file_path,
                    line_number=line_number,
                    context=context,
                    version=version,
                )
                return ToolObservation(
                    True,
                    tool,
                    {"file_path": file_path, "line_number": line_number, "context": context, "version": version},
                    output=out,
                )

            if tool == "ossfuzz_apply_patch_and_test":
                project = str(args.get("project", "")).strip()
                commit = str(args.get("commit", "")).strip()
                patch_path = str(args.get("patch_path", "")).strip()
                if str(args.get("patch_text", "")).strip():
                    return ToolObservation(
                        False, tool, args, output="", error="Unsupported arg: patch_text (use patch_override_paths instead)"
                    )
                if str(args.get("patch_file_path", "")).strip():
                    return ToolObservation(
                        False,
                        tool,
                        args,
                        output="",
                        error="Unsupported arg: patch_file_path (use patch_path + patch_override_paths instead)",
                    )

                override_raw = args.get("patch_override_paths", [])
                patch_override_paths: list[str] = []
                if override_raw is None or override_raw == "":
                    patch_override_paths = []
                elif isinstance(override_raw, list):
                    patch_override_paths = [str(p).strip() for p in override_raw if str(p).strip()]
                elif isinstance(override_raw, str):
                    patch_override_paths = [override_raw.strip()] if override_raw.strip() else []
                else:
                    return ToolObservation(
                        False,
                        tool,
                        args,
                        output="",
                        error="Invalid arg: patch_override_paths (expected list[string] or string)",
                    )

                build_csv = str(args.get("build_csv", "")).strip()
                sanitizer = str(args.get("sanitizer", "")).strip() or "address"
                architecture = str(args.get("architecture", "")).strip() or "x86_64"
                engine = str(args.get("engine", "")).strip() or "libfuzzer"
                fuzz_target = str(args.get("fuzz_target", "")).strip()
                run_fuzzer_seconds = _as_int(args.get("run_fuzzer_seconds"), 30)
                timeout_seconds = _as_int(args.get("timeout_seconds"), 1800)
                use_sudo = _as_bool(args.get("use_sudo"), False)
                if not project:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: project")
                if not commit:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: commit")
                if not patch_path:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: patch_path")
                out = ossfuzz_apply_patch_and_test_tool(
                    project=project,
                    commit=commit,
                    patch_path=patch_path,
                    patch_override_paths=patch_override_paths,
                    build_csv=build_csv,
                    sanitizer=sanitizer,
                    architecture=architecture,
                    engine=engine,
                    fuzz_target=fuzz_target,
                    run_fuzzer_seconds=run_fuzzer_seconds,
                    timeout_seconds=timeout_seconds,
                    use_sudo=use_sudo,
                )
                return ToolObservation(
                    True,
                    tool,
                    {
                        "project": project,
                        "commit": commit,
                        "patch_path": patch_path,
                        "patch_override_paths": patch_override_paths[:20],
                        "build_csv": build_csv,
                        "sanitizer": sanitizer,
                        "architecture": architecture,
                        "engine": engine,
                        "fuzz_target": fuzz_target,
                        "run_fuzzer_seconds": run_fuzzer_seconds,
                        "timeout_seconds": timeout_seconds,
                        "use_sudo": use_sudo,
                    },
                    output=out,
                )

            if tool == "list_patch_bundle":
                patch_path = str(args.get("patch_path", "")).strip()
                if not patch_path:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: patch_path")
                filter_file = str(args.get("filter_file", "")).strip()
                filter_patch_type = str(args.get("filter_patch_type", "")).strip()
                limit = _as_int(args.get("limit"), 50)
                out = list_patch_bundle_tool(
                    patch_path=patch_path,
                    filter_file=filter_file,
                    filter_patch_type=filter_patch_type,
                    limit=limit,
                )
                return ToolObservation(
                    True,
                    tool,
                    {
                        "patch_path": patch_path,
                        "filter_file": filter_file,
                        "filter_patch_type": filter_patch_type,
                        "limit": limit,
                    },
                    output=out,
                )

            if tool == "get_patch":
                patch_path = str(args.get("patch_path", "")).strip()
                patch_key = str(args.get("patch_key", "")).strip()
                include_text = _as_bool(args.get("include_text"), False)
                max_lines = _as_int(args.get("max_lines"), 200)
                if not patch_path:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: patch_path")
                if not patch_key:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: patch_key")
                out = get_patch_tool(
                    patch_path=patch_path,
                    patch_key=patch_key,
                    include_text=include_text,
                    max_lines=max_lines,
                )
                return ToolObservation(
                    True,
                    tool,
                    {"patch_path": patch_path, "patch_key": patch_key, "include_text": include_text, "max_lines": max_lines},
                    output=out,
                )

            if tool == "search_patches":
                patch_path = str(args.get("patch_path", "")).strip()
                query = str(args.get("query", "")).strip()
                limit = _as_int(args.get("limit"), 50)
                if not patch_path:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: patch_path")
                if not query:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: query")
                out = search_patches_tool(patch_path=patch_path, query=query, limit=limit)
                return ToolObservation(True, tool, {"patch_path": patch_path, "query": query, "limit": limit}, output=out)

            if tool == "get_error_patch_context":
                patch_path = str(args.get("patch_path", "")).strip()
                file_path = str(args.get("file_path", "")).strip()
                line_number = _as_int(args.get("line_number"), 0)
                error_text = str(args.get("error_text", "")).strip()
                context_lines = _as_int(args.get("context_lines"), 30)
                max_total_lines = _as_int(args.get("max_total_lines"), 200)
                if not patch_path:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: patch_path")
                if not file_path:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: file_path")
                if line_number <= 0:
                    return ToolObservation(False, tool, args, output="", error="Invalid arg: line_number")
                out = get_error_patch_context_tool(
                    patch_path=patch_path,
                    file_path=file_path,
                    line_number=line_number,
                    error_text=error_text,
                    context_lines=context_lines,
                    max_total_lines=max_total_lines,
                )
                return ToolObservation(
                    True,
                    tool,
                    {
                        "patch_path": patch_path,
                        "file_path": file_path,
                        "line_number": line_number,
                        "error_text": error_text[:2000],
                        "context_lines": context_lines,
                        "max_total_lines": max_total_lines,
                    },
                    output=out,
                )

            if tool == "make_error_patch_override":
                patch_path = str(args.get("patch_path", "")).strip()
                file_path = str(args.get("file_path", "")).strip()
                line_number = _as_int(args.get("line_number"), 0)
                new_func_code = str(args.get("new_func_code", ""))
                context_lines = _as_int(args.get("context_lines"), 0)
                max_lines = _as_int(args.get("max_lines"), 2000)
                max_chars = _as_int(args.get("max_chars"), 200000)
                if not patch_path:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: patch_path")
                if not file_path:
                    return ToolObservation(False, tool, args, output="", error="Missing arg: file_path")
                if line_number <= 0:
                    return ToolObservation(False, tool, args, output="", error="Invalid arg: line_number")
                if not str(new_func_code).strip():
                    return ToolObservation(False, tool, args, output="", error="Missing arg: new_func_code")
                out = make_error_patch_override_tool(
                    patch_path=patch_path,
                    file_path=file_path,
                    line_number=line_number,
                    new_func_code=new_func_code,
                    context_lines=context_lines,
                    max_lines=max_lines,
                    max_chars=max_chars,
                )
                return ToolObservation(
                    True,
                    tool,
                    {
                        "patch_path": patch_path,
                        "file_path": file_path,
                        "line_number": line_number,
                        "context_lines": context_lines,
                        "max_lines": max_lines,
                        "max_chars": max_chars,
                        "new_func_code": str(new_func_code)[:2000],
                    },
                    output=out,
                )

            if tool == "parse_build_errors":
                build_log_path = str(args.get("build_log_path", "")).strip()
                build_log_text = str(args.get("build_log_text", "")).strip()
                if not build_log_path and not build_log_text:
                    return ToolObservation(
                        False, tool, args, output="", error="Missing arg: build_log_path or build_log_text"
                    )
                out = parse_build_errors_tool(build_log_path=build_log_path, build_log_text=build_log_text)
                return ToolObservation(
                    True,
                    tool,
                    {"build_log_path": build_log_path, "build_log_text": build_log_text[:2000]},
                    output=out,
                )

            return ToolObservation(False, tool, args, output="", error=f"Unhandled tool: {tool}")
        except Exception as exc:  # noqa: BLE001
            return ToolObservation(False, tool, args, output="", error=f"{type(exc).__name__}: {exc}")
