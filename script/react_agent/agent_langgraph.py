#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import textwrap
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, TypedDict

try:
    from langgraph.graph import END, StateGraph  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    from langgraph_shim import END, StateGraph

from build_log import find_first_fatal, iter_compiler_errors, load_build_log
from agent_tools import AgentTools, KbIndex, SourceManager
from artifacts import offload_patch_output, resolve_artifact_dir
from models import ChatModel, ModelError, OpenAIChatCompletionsModel, StubModel
from tools.registry import ALLOWED_TOOLS, TOOL_SPECS
from tools.runner import ToolObservation, ToolRunner


class Decision(TypedDict, total=False):
    type: Literal["tool", "final"]
    thought: str
    tool: str
    args: Dict[str, Any]
    summary: str
    next_step: str


@dataclass
class AgentConfig:
    max_steps: int = 4
    tools_mode: Literal["real", "fake"] = "real"
    error_scope: Literal["first", "patch"] = "first"


@dataclass
class AgentState:
    build_log_path: str
    patch_path: str
    error_scope: Literal["first", "patch"]
    error_line: str
    snippet: str
    artifacts_dir: str = ""
    patch_key: str = ""
    grouped_errors: List[Dict[str, Any]] = field(default_factory=list)
    missing_struct_members: List[Dict[str, Any]] = field(default_factory=list)
    steps: List[Dict[str, Any]] = field(default_factory=list)
    last_observation: Optional[ToolObservation] = None
    pending_patch: Optional[Decision] = None
    patch_generated: bool = False
    patch_result: Optional[Dict[str, Any]] = None
    target_errors: List[Dict[str, str]] = field(default_factory=list)

    # OSS-Fuzz testing config (required for patch-scope runs once a patch is generated)
    ossfuzz_project: str = ""
    ossfuzz_commit: str = ""
    ossfuzz_build_csv: str = ""
    ossfuzz_sanitizer: str = "address"
    ossfuzz_arch: str = "x86_64"
    ossfuzz_engine: str = "libfuzzer"
    ossfuzz_fuzz_target: str = ""
    ossfuzz_use_sudo: bool = False

    # Tracks the latest generated override diff artifact paths (for OSS-Fuzz tool)
    patch_override_paths: List[str] = field(default_factory=list)

    # Indicates we already attempted OSS-Fuzz test after generating a patch.
    ossfuzz_test_attempted: bool = False

    # Latest macro tokens reported by get_error_v1_code_slice (used for guardrails).
    macro_tokens_not_defined_in_slice: List[str] = field(default_factory=list)

    # Macro-lookup guardrail state when the model tries to invent missing macros.
    macro_lookup: Optional[Dict[str, Any]] = None


class GraphState(TypedDict, total=False):
    state: AgentState
    pending: Decision
    final: Dict[str, Any]


def _error_payload(state: AgentState) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"line": state.error_line, "snippet": state.snippet}
    if state.patch_path:
        payload["patch_path"] = state.patch_path
    if state.artifacts_dir:
        payload["artifacts_dir"] = state.artifacts_dir
    payload["scope"] = state.error_scope
    if state.patch_key:
        payload["patch_key"] = state.patch_key
    if state.grouped_errors:
        payload["grouped_errors"] = [
            {
                "raw": str(e.get("raw", "")).strip(),
                "file": e.get("file"),
                "line": e.get("line"),
                "col": e.get("col"),
                "msg": e.get("msg"),
                "old_signature": e.get("old_signature"),
            }
            for e in state.grouped_errors
        ]
    if state.target_errors:
        payload["target_errors"] = state.target_errors
    if state.missing_struct_members:
        payload["missing_struct_members"] = state.missing_struct_members
    return payload


def _extract_target_errors(
    *,
    error_line: str,
    grouped_errors: List[Dict[str, Any]],
    patch_key: str = "",
) -> List[Dict[str, str]]:
    targets: List[Dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    pk = str(patch_key or "").strip()
    for e in grouped_errors or []:
        if not isinstance(e, dict):
            continue
        fp = str(e.get("file", "") or "").strip()
        msg = str(e.get("msg", "") or "").strip()
        if not fp or not msg:
            continue
        key = (pk or fp, msg)
        if key in seen:
            continue
        seen.add(key)
        item = {"file": fp, "msg": msg}
        if pk:
            item["patch_key"] = pk
        targets.append(item)
    if targets:
        return targets

    raw = str(error_line or "").strip()
    m = _ERROR_LOC_RE.match(raw)
    if m:
        fp = str(m.group("file") or "").strip()
        msg_m = re.search(r"\berror:\s*(.*)$", raw)
        msg = str((msg_m.group(1) if msg_m else "") or "").strip()
        if fp and msg:
            targets.append({"file": fp, "msg": msg})
    return targets


def _read_text(path: str) -> str:
    p = Path(str(path or "").strip()).expanduser().resolve()
    return p.read_text(encoding="utf-8", errors="replace")


def _summarize_target_error_status(state: AgentState) -> Dict[str, Any]:
    """Return whether the original target errors still appear after OSS-Fuzz build/check_build."""
    targets = list(state.target_errors or [])
    if not targets:
        targets = _extract_target_errors(error_line=state.error_line, grouped_errors=state.grouped_errors, patch_key=state.patch_key)
    if not targets:
        return {"status": "unknown", "reason": "No target errors captured."}

    obs = state.last_observation
    out = obs.output if isinstance(obs, ToolObservation) else None
    if not isinstance(out, dict):
        return {"status": "unknown", "reason": "Missing OSS-Fuzz tool output."}

    def artifact_path(field: str) -> str:
        v = out.get(field)
        if isinstance(v, dict):
            return str(v.get("artifact_path", "") or "").strip()
        if isinstance(v, str):
            return v.strip()
        return ""

    build_path = artifact_path("build_output")
    check_path = artifact_path("check_build_output")
    if not build_path and not check_path:
        return {"status": "unknown", "reason": "No build/check_build log artifacts found."}

    combined_errors: List[Dict[str, Any]] = []
    sources: List[str] = []
    try:
        if build_path:
            sources.append(build_path)
            combined_errors.extend(iter_compiler_errors(_read_text(build_path), snippet_lines=0))
        if check_path:
            sources.append(check_path)
            combined_errors.extend(iter_compiler_errors(_read_text(check_path), snippet_lines=0))
    except Exception as exc:  # noqa: BLE001
        return {"status": "unknown", "reason": f"Failed to parse logs: {exc}", "log_artifacts": sources}

    def same_file(a: str, b: str) -> bool:
        a_s = str(a or "").strip()
        b_s = str(b or "").strip()
        if not a_s or not b_s:
            return False
        if a_s == b_s:
            return True
        return Path(a_s).name == Path(b_s).name

    def allowed_roots_from_env() -> list[str] | None:
        raw = os.environ.get("REACT_AGENT_PATCH_ALLOWED_ROOTS", "").strip()
        if not raw:
            return None
        roots = [r.strip() for r in raw.split(os.pathsep) if r.strip()]
        return roots or None

    bundle: Any = None
    bundle_err: Optional[str] = None
    load_patch_bundle: Any = None
    get_error_patch_from_bundle: Any = None

    def patch_key_for_error(file_path: str, line_number: int) -> str:
        nonlocal bundle, bundle_err, load_patch_bundle, get_error_patch_from_bundle
        fp = str(file_path or "").strip()
        ln = int(line_number or 0)
        if not (state.patch_path and fp and ln > 0):
            return ""
        if bundle_err is not None:
            return ""
        try:
            if bundle is None:
                script_dir = Path(__file__).resolve().parents[1]
                if str(script_dir) not in sys.path:
                    sys.path.insert(0, str(script_dir))
                from migration_tools.patch_bundle import load_patch_bundle as _lpb  # type: ignore
                from migration_tools.tools import _get_error_patch_from_bundle as _gepb  # type: ignore

                load_patch_bundle = _lpb
                get_error_patch_from_bundle = _gepb
                bundle = load_patch_bundle(state.patch_path, allowed_roots=allowed_roots_from_env())
            mapping = get_error_patch_from_bundle(bundle, patch_path=state.patch_path, file_path=fp, line_number=ln)
            return str(mapping.get("patch_key") or "").strip()
        except Exception as exc:  # noqa: BLE001
            bundle_err = f"{type(exc).__name__}: {exc}"
            return ""

    matched: List[Dict[str, Any]] = []
    matched_keys: set[tuple[str, str]] = set()
    for err in combined_errors:
        fp = str(err.get("file", "") or "").strip()
        ln = int(err.get("line", 0) or 0)
        msg = str(err.get("msg", "") or "").strip()
        if not fp or not msg:
            continue
        err_patch_key = patch_key_for_error(fp, ln)
        for t in targets:
            t_patch_key = str(t.get("patch_key", "") or "").strip()
            if t_patch_key:
                if err_patch_key != t_patch_key:
                    continue
                if msg != str(t.get("msg", "")).strip():
                    continue
                k = (t_patch_key, msg)
                if k in matched_keys:
                    continue
                matched_keys.add(k)
                matched.append(
                    {"raw": err.get("raw", ""), "file": fp, "line": ln, "patch_key": err_patch_key, "msg": msg}
                )
                continue
            if not same_file(fp, t.get("file", "")):
                continue
            if msg != str(t.get("msg", "")).strip():
                continue
            k = (fp, msg)
            if k in matched_keys:
                continue
            matched_keys.add(k)
            matched.append({"raw": err.get("raw", ""), "file": fp, "line": ln, "patch_key": err_patch_key, "msg": msg})

    fixed = len(matched) == 0
    other = [
        {
            "raw": str(e.get("raw", "") or "").strip(),
            "file": str(e.get("file", "") or "").strip(),
            "line": int(e.get("line", 0) or 0),
            "patch_key": patch_key_for_error(str(e.get("file", "") or ""), int(e.get("line", 0) or 0)),
            "msg": str(e.get("msg", "") or "").strip(),
        }
        for e in combined_errors
        if str(e.get("raw", "") or "").strip()
    ]
    return {
        "status": "ok",
        "fixed": fixed,
        "targets": targets,
        "matched_target_errors": matched,
        "other_errors": other[:10],
        "log_artifacts": sources,
        "mapping_error": bundle_err,
    }


def _extract_first_json_object(text: str) -> str:
    stripped = text.strip()
    start = stripped.find("{")
    if start < 0:
        return stripped
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(stripped)):
        c = stripped[i]
        if in_string:
            if escape:
                escape = False
                continue
            if c == "\\":
                escape = True
                continue
            if c == '"':
                in_string = False
            continue

        if c == '"':
            in_string = True
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return stripped[start : i + 1]
    return stripped[start:]


def _parse_decision(text: str) -> Decision:
    raw = str(text or "")
    if not raw.strip():
        raise ValueError("Empty model response (expected a JSON object).")

    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        extracted = _extract_first_json_object(raw)
        if not extracted.strip():
            raise ValueError("Model response contained no JSON object.") from None
        try:
            obj = json.loads(extracted)
        except json.JSONDecodeError as exc:
            snippet = raw.strip()
            if len(snippet) > 400:
                snippet = snippet[:400] + "\n...[truncated]"
            raise ValueError(f"Invalid JSON from model: {exc}. Raw snippet: {snippet!r}") from exc

    if not isinstance(obj, dict):
        raise ValueError("Model output must be a JSON object")
    decision: Decision = obj  # type: ignore[assignment]
    if decision.get("type") not in {"tool", "final"}:
        raise ValueError("Missing/invalid field: type")
    return decision


def _validate_tool_decision(decision: Decision) -> None:
    tool = str(decision.get("tool", "")).strip()
    if tool not in ALLOWED_TOOLS:
        raise ValueError(f"Invalid tool: {tool}")
    args = decision.get("args")
    if not isinstance(args, dict):
        raise ValueError("Tool args must be an object")


def _collect_focus_terms(state: AgentState) -> List[str]:
    terms: List[str] = []

    def keep(term: str) -> bool:
        t = str(term or "").strip()
        if not t:
            return False
        # Very short tokens are usually noise and can anchor snippets incorrectly (e.g. "c" matches "char").
        if len(t) < 3:
            return False
        low = t.lower()
        if low in {"error", "fatal", "warning", "note", "expected"}:
            return False
        if low in {"src", "include"}:
            return False
        return True

    # Macro-expansion errors: prioritize the macro name and macro-like tokens from the snippet.
    snippet = str(state.snippet or "")
    if snippet:
        for macro_name in re.findall(r"expanded from macro '([^']+)'", snippet):
            if keep(macro_name):
                terms.append(str(macro_name).strip())
        # Include ALLCAPS tokens (e.g. MAKE_HANDLER, EMPTY_ICONV) from the snippet.
        snippet_sanitized = re.sub(r'"([^"\\]|\\.)*"', '""', snippet)
        for tok in re.findall(r"\b[A-Z][A-Z0-9_]{2,}\b", snippet_sanitized):
            if keep(tok):
                terms.append(tok)
    for item in state.missing_struct_members or []:
        if not isinstance(item, dict):
            continue
        for member in item.get("members") or []:
            m = str(member or "").strip()
            if keep(m):
                terms.append(m)
        struct_name = str(item.get("struct", "") or "").strip()
        if keep(struct_name):
            terms.append(struct_name)
    # Also include a few tokens from the error line itself.
    err = str(state.error_line or "")
    for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", err):
        if keep(tok):
            terms.append(tok)
    # Dedup preserve order
    seen: set[str] = set()
    out: List[str] = []
    for t in terms:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out[:32]


def _truncate_text_around_terms(text: str, terms: List[str], *, max_chars: int) -> str:
    s = str(text or "")
    if max_chars <= 0 or len(s) <= max_chars:
        return s
    # If any focus term appears, show a window around the first match.
    for term in terms:
        if not term:
            continue
        idx = s.find(term)
        if idx < 0:
            continue
        half = max_chars // 2
        start = max(0, idx - half)
        end = min(len(s), idx + half)
        prefix = "...[truncated head]...\n" if start > 0 else ""
        suffix = "\n...[truncated tail]..." if end < len(s) else ""
        return prefix + s[start:end] + suffix
    # Fallback: head+tail
    head_n = max_chars // 2
    tail_n = max_chars - head_n
    return s[:head_n] + "\n...[truncated]...\n" + s[-tail_n:]


def _extract_defined_macros_from_code(text: str) -> List[str]:
    raw = str(text or "")
    if not raw.strip():
        return []
    names: List[str] = []
    for line in raw.splitlines():
        m = re.match(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b", line)
        if m:
            names.append(str(m.group(1)))
    # Dedup preserve order
    seen: set[str] = set()
    out: List[str] = []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _has_read_file_context_for_token(state: AgentState, token: str) -> bool:
    t = str(token or "").strip()
    if not t:
        return False
    for step in state.steps:
        if not isinstance(step, dict):
            continue
        decision = step.get("decision") or {}
        if (decision.get("tool") or "") != "read_file_context":
            continue
        obs = step.get("observation") or {}
        out = obs.get("output")
        if not isinstance(out, str):
            continue
        # Require both token presence and a define line to avoid unrelated mentions.
        if t in out and "#define" in out:
            return True
    return False


def _macro_define_guardrail_for_override(state: AgentState, decision: Decision) -> Optional[Decision]:
    """Return a forced search_text decision when the override invents missing macros without source evidence."""
    if str(decision.get("type", "")).strip() != "tool":
        return None
    if str(decision.get("tool", "")).strip() != "make_error_patch_override":
        return None
    args_obj = decision.get("args") if isinstance(decision.get("args"), dict) else {}
    new_code = str(args_obj.get("new_func_code", "") or "")
    defines = set(_extract_defined_macros_from_code(new_code))
    missing = set(str(t) for t in (state.macro_tokens_not_defined_in_slice or []) if str(t).strip())
    for tok in sorted(defines & missing):
        if _has_read_file_context_for_token(state, tok):
            continue
        state.macro_lookup = {"token": tok, "stage": "need_search_text", "version": "v2"}
        return {
            "type": "tool",
            "thought": f"Macro guardrail: locate the real #define for {tok} before adding it.",
            "tool": "search_text",
            "args": {"query": f"#define {tok}", "version": "v2", "limit": 20, "file_glob": ""},
        }
    return None


def _macro_lookup_pick_token(state: AgentState) -> str:
    """Pick the most relevant missing macro token for the current macro-expansion snippet."""
    snippet = str(state.snippet or "")
    missing = [str(t) for t in (state.macro_tokens_not_defined_in_slice or []) if str(t).strip()]
    if not missing:
        return ""
    # Prefer tokens that are explicitly mentioned in the current compiler snippet (e.g. macro expansion body line).
    for tok in missing:
        if tok and tok in snippet:
            return tok
    # Fall back to the first missing token.
    return missing[0] if missing else ""


def _rewrite_search_text_query_for_macro(state: AgentState, decision: Decision) -> Optional[Decision]:
    """Rewrite search_text(query=TOKEN) to search_text(query=\"#define TOKEN\") for missing macro tokens."""
    if str(decision.get("type", "")).strip() != "tool":
        return None
    if str(decision.get("tool", "")).strip() != "search_text":
        return None
    args_obj = decision.get("args") if isinstance(decision.get("args"), dict) else {}
    query = str(args_obj.get("query", "") or "").strip()
    if not query or query.startswith("#define "):
        return None
    missing = set(str(t) for t in (state.macro_tokens_not_defined_in_slice or []) if str(t).strip())
    if query not in missing:
        return None
    rewritten = dict(decision)
    rewritten_args = dict(args_obj)
    rewritten_args["query"] = f"#define {query}"
    rewritten_args.setdefault("version", "v2")
    rewritten["args"] = rewritten_args  # type: ignore[assignment]
    rewritten["thought"] = (str(decision.get("thought", "") or "").strip() + f" (rewrite search to find macro definition for {query})").strip()
    return rewritten  # type: ignore[return-value]


def _macro_lookup_update_from_search_text_output(state: AgentState, output: Any) -> None:
    """Advance macro_lookup state based on a search_text tool output."""
    if not isinstance(state.macro_lookup, dict):
        return
    stage = str(state.macro_lookup.get("stage", "") or "").strip()
    token = str(state.macro_lookup.get("token", "") or "").strip()
    version = str(state.macro_lookup.get("version", "v2") or "v2").strip() or "v2"
    if stage != "need_search_text" or not token:
        return
    if not isinstance(output, dict):
        return
    matches = output.get("matches") if isinstance(output.get("matches"), list) else []
    first = matches[0] if matches else None
    if isinstance(first, dict) and first.get("file") and first.get("line"):
        state.macro_lookup = {
            "token": token,
            "stage": "need_read_file_context",
            "version": version,
            "file_path": str(first.get("file")),
            "line_number": int(first.get("line") or 0),
        }
        return
    # No matches: try the other version, then give up.
    if version == "v2":
        state.macro_lookup = {"token": token, "stage": "need_search_text", "version": "v1"}
    else:
        state.macro_lookup = {"token": token, "stage": "done", "version": version, "not_found": True}


def _compact_observation_for_prompt(state: AgentState, observation: Any) -> Any:
    """Reduce tool observation size before sending it back to the model.

    This keeps the prompt small enough to avoid empty/invalid responses on long patches.
    """
    terms = _collect_focus_terms(state)
    tool_name = ""
    if isinstance(observation, dict):
        tool_name = str(observation.get("tool", "") or "").strip()

    def compact(value: Any, *, depth: int = 0, key_path: tuple[str, ...] = ()) -> Any:
        if depth > 4:
            return "[truncated]"
        if isinstance(value, str):
            # read_artifact output text must remain intact; truncating it can silently
            # drop tail lines from a slice that will later be used to rewrite a patch.
            if tool_name == "read_artifact" and key_path == ("output", "text"):
                return value
            return _truncate_text_around_terms(value, terms, max_chars=12000)
        if isinstance(value, dict):
            out: Dict[str, Any] = {}
            for i, (k, v) in enumerate(value.items()):
                if i >= 60:
                    out["...[truncated_keys]"] = f"{len(value) - i} more keys"
                    break
                key = str(k)
                if tool_name == "read_artifact" and key_path == ("output",) and key == "text" and isinstance(v, str):
                    out[key] = v
                    continue
                if key in {"excerpt", "func_code", "patch_text"} and isinstance(v, str):
                    out[key] = _truncate_text_around_terms(v, terms, max_chars=12000)
                else:
                    out[key] = compact(v, depth=depth + 1, key_path=key_path + (key,))
            return out
        if isinstance(value, list):
            if len(value) > 50:
                return [compact(v, depth=depth + 1, key_path=key_path) for v in value[:50]] + [
                    f"...[{len(value)-50} more items]"
                ]
            return [compact(v, depth=depth + 1, key_path=key_path) for v in value]
        return value

    compacted = compact(observation)
    if isinstance(compacted, dict):
        compacted.setdefault(
            "_note",
            "Tool output in this prompt may be truncated or offloaded to artifacts; use read_artifact(artifact_path, ...) when you see an artifact_path reference.",
        )
    return compacted


_TYPE_EDIT_RE = re.compile(r"\b(struct|typedef|enum|union)\b", re.IGNORECASE)
_TYPE_EDIT_VERBS_RE = re.compile(
    r"\b(add|insert|restore|reintroduce|introduce|modify|edit|change|update)\b", re.IGNORECASE
)
_TYPE_EDIT_HINT_RE = re.compile(r"\b(field|member|definition|layout|ABI)\b", re.IGNORECASE)


def _suggests_v2_type_edit(text: str) -> bool:
    """Best-effort detector for suggestions to modify V2 type definitions."""
    t = str(text or "").strip()
    if not t:
        return False
    lowered = t.lower()
    headerish = ("include/" in lowered) or (".h" in lowered) or ("header" in lowered)
    if headerish and _TYPE_EDIT_RE.search(t) and _TYPE_EDIT_VERBS_RE.search(t):
        return True
    if "struct" in lowered and "add" in lowered and _TYPE_EDIT_HINT_RE.search(t):
        return True
    return False


def _decision_suggests_v2_type_edit(decision: Decision) -> bool:
    summary = str(decision.get("summary", "") or "")
    next_step = str(decision.get("next_step", "") or "")
    thought = str(decision.get("thought", "") or "")
    return _suggests_v2_type_edit(summary) or _suggests_v2_type_edit(next_step) or _suggests_v2_type_edit(thought)


_MISSING_MEMBER_RE = re.compile(r"no member named '[^']+' in '([^']+)'")
_ERROR_LOC_RE = re.compile(r"^(?P<file>[^:\n]+):(?P<line>\d+):(?P<col>\d+):")


def _first_error_location(state: AgentState) -> tuple[str, int]:
    if state.grouped_errors:
        fp = str(state.grouped_errors[0].get("file", "") or "").strip()
        ln = int(state.grouped_errors[0].get("line", 0) or 0)
        if fp and ln > 0:
            return fp, ln

    m = _ERROR_LOC_RE.match(str(state.error_line or "").strip())
    if m:
        fp = m.group("file")
        ln = int(m.group("line"))
        return fp, ln
    return "", 0


def _normalize_struct_queries(struct_name: str) -> List[str]:
    raw = str(struct_name or "").strip()
    if not raw:
        return []
    names = [raw]
    parts = raw.split()
    if len(parts) >= 2 and parts[0] in {"struct", "union", "enum"}:
        names.append(parts[-1])
    uniq: List[str] = []
    seen: set[str] = set()
    for n in names:
        if n and n not in seen:
            seen.add(n)
            uniq.append(n)
    return uniq


def _should_force_struct_diff_tools(state: AgentState) -> Optional[str]:
    if not state.patch_path or state.error_scope != "patch":
        return None

    struct_name = ""
    if state.missing_struct_members:
        struct_name = str(state.missing_struct_members[0].get("struct", "") or "").strip()
    if not struct_name:
        m = _MISSING_MEMBER_RE.search(str(state.error_line or ""))
        if m:
            struct_name = str(m.group(1) or "").strip()
    if not struct_name:
        return None

    queries = _normalize_struct_queries(struct_name)
    if not queries:
        return None

    def called(tool_name: str, *, version: str = "", symbol_any: Optional[List[str]] = None) -> bool:
        for step in state.steps:
            if not isinstance(step, dict):
                continue
            decision = step.get("decision")
            if not isinstance(decision, dict):
                continue
            if str(decision.get("tool", "")).strip() != tool_name:
                continue
            args = decision.get("args") if isinstance(decision.get("args"), dict) else {}
            if version and str(args.get("version", "")).strip() != version:
                continue
            if symbol_any is not None:
                sym = str(args.get("symbol_name", "")).strip()
                if sym not in symbol_any:
                    continue
            return True
        return False

    if not called("get_error_v1_code_slice"):
        return "get_error_v1_code_slice"
    if not called("search_definition", version="v1", symbol_any=queries):
        return f"search_definition:v1:{queries[0]}"
    if not called("search_definition", version="v2", symbol_any=queries):
        return f"search_definition:v2:{queries[0]}"
    return None


def _has_tool_call(state: AgentState, tool_name: str) -> bool:
    for step in state.steps:
        if not isinstance(step, dict):
            continue
        decision = step.get("decision")
        if not isinstance(decision, dict):
            continue
        if str(decision.get("tool", "")).strip() == tool_name:
            return True
    return False


def _should_require_make_error_patch_override(state: AgentState) -> bool:
    """Return True if we should force patch generation before allowing a final decision."""
    if not state.patch_path or state.error_scope != "patch":
        return False
    # Only require this in the patch-slice rewrite workflow (we've extracted a V1-origin slice).
    if not _has_tool_call(state, "get_error_v1_code_slice"):
        return False
    # Do not accept final until we've attempted patch generation at least once.
    return not _has_tool_call(state, "make_error_patch_override")


def _last_tool_call_name(state: AgentState) -> str:
    if not state.steps:
        return ""
    last = state.steps[-1] if isinstance(state.steps[-1], dict) else {}
    decision = last.get("decision") if isinstance(last, dict) else {}
    if not isinstance(decision, dict):
        return ""
    return str(decision.get("tool", "")).strip()


def _structs_to_compare(state: AgentState) -> List[str]:
    structs: List[str] = []
    for item in state.missing_struct_members or []:
        if not isinstance(item, dict):
            continue
        s = str(item.get("struct", "") or "").strip()
        if s:
            structs.append(s)
    if not structs:
        m = _MISSING_MEMBER_RE.search(str(state.error_line or ""))
        if m:
            structs.append(str(m.group(1) or "").strip())
    # Dedup preserve order.
    seen: set[str] = set()
    out: List[str] = []
    for s in structs:
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out[:8]


def _has_struct_definition(state: AgentState, struct_name: str, version: str) -> bool:
    queries = set(_normalize_struct_queries(struct_name))
    if not queries:
        return False
    for step in state.steps:
        if not isinstance(step, dict):
            continue
        decision = step.get("decision")
        if not isinstance(decision, dict):
            continue
        if str(decision.get("tool", "")).strip() != "search_definition":
            continue
        args = decision.get("args") if isinstance(decision.get("args"), dict) else {}
        if str(args.get("version", "")).strip() != version:
            continue
        sym = str(args.get("symbol_name", "")).strip()
        if sym in queries:
            return True
    return False


def _last_artifact_path(state: AgentState, tool_name: str, field: str) -> str:
    for step in reversed(state.steps):
        if not isinstance(step, dict):
            continue
        obs = step.get("observation")
        if not isinstance(obs, dict):
            continue
        if obs.get("ok") is not True:
            continue
        if str(obs.get("tool", "")).strip() != tool_name:
            continue
        out = obs.get("output")
        if not isinstance(out, dict):
            return ""
        val = out.get(field)
        if isinstance(val, dict):
            ap = str(val.get("artifact_path", "") or "").strip()
            return ap
        return ""
    return ""


def _next_patch_prereq_tool(state: AgentState) -> Optional[Decision]:
    if not state.patch_path:
        return None

    file_path, line_number = _first_error_location(state)
    if not file_path or line_number <= 0:
        return None

    if not _has_tool_call(state, "get_error_patch_context"):
        return {
            "type": "tool",
            "thought": "First map the migrated error location to its patch context.",
            "tool": "get_error_patch_context",
            "args": {
                "patch_path": state.patch_path,
                "file_path": file_path,
                "line_number": line_number,
                "error_text": str(state.error_line or "")[:400],
                "context_lines": 80,
                "max_total_lines": 800,
            },
        }

    if not _has_tool_call(state, "get_error_v1_code_slice"):
        return {
            "type": "tool",
            "thought": "Extract the V1-origin code slice from the patch before proposing a replacement.",
            "tool": "get_error_v1_code_slice",
            "args": {
                "patch_path": state.patch_path,
                "file_path": file_path,
                "line_number": line_number,
                "max_lines": 400,
                "max_chars": 20000,
            },
        }

    structs = _structs_to_compare(state)
    if structs:
        for struct_name in structs:
            if not _has_struct_definition(state, struct_name, "v1"):
                return {
                    "type": "tool",
                    "thought": "Fetch the V1 definition of the struct (the failing code is V1-origin).",
                    "tool": "search_definition",
                    "args": {"symbol_name": _normalize_struct_queries(struct_name)[0], "version": "v1"},
                }
        for struct_name in structs:
            if not _has_struct_definition(state, struct_name, "v2"):
                return {
                    "type": "tool",
                    "thought": "Fetch the V2 definition of the struct to compare and infer the correct adaptation.",
                    "tool": "search_definition",
                    "args": {"symbol_name": _normalize_struct_queries(struct_name)[0], "version": "v2"},
                }

    return None


def _resolve_output_format(value: str) -> str:
    if value == "auto":
        return "text" if sys.stdout.isatty() else "json"
    return value


def _render_tools_text() -> str:
    lines = ["Tools:"]
    for spec in TOOL_SPECS:
        name = str(spec.get("name", "")).strip()
        args = spec.get("args") if isinstance(spec.get("args"), dict) else {}
        desc = str(spec.get("description", "")).strip()
        if args:
            args_s = ", ".join(f"{k}: {v}" for k, v in args.items())
            sig = f"{name}({args_s})"
        else:
            sig = f"{name}()"
        lines.append(f"- {sig}")
        if desc:
            lines.append(textwrap.indent(desc, "  "))
    return "\n".join(lines) + "\n"


def _render_final_text(final: Dict[str, Any]) -> str:
    lines: List[str] = []
    error = final.get("error") if isinstance(final.get("error"), dict) else {}
    error_line = str(error.get("line", "")).strip()
    snippet = str(error.get("snippet", "")).rstrip("\n")
    patch_path = str(error.get("patch_path", "")).strip()
    artifacts_dir = str(error.get("artifacts_dir", "")).strip()
    patch_key = str(error.get("patch_key", "")).strip()
    scope = str(error.get("scope", "")).strip()
    grouped = error.get("grouped_errors") if isinstance(error.get("grouped_errors"), list) else []
    if patch_path:
        lines.append(f"Patch bundle: {patch_path}")
    if artifacts_dir:
        lines.append(f"Artifacts: {artifacts_dir}")
    if patch_key:
        lines.append(f"Patch key: {patch_key}")
    if scope:
        lines.append(f"Scope: {scope}")
    if error_line:
        if lines:
            lines.append("")
        lines.append("Build error:")
        lines.append(textwrap.indent(error_line, "  "))
    if snippet:
        if lines:
            lines.append("")
        lines.append("Log context:")
        lines.append(textwrap.indent(snippet, "  "))
    if grouped:
        lines.append("")
        lines.append(f"Grouped errors ({len(grouped)}):")
        for item in grouped:
            if not isinstance(item, dict):
                continue
            raw = str(item.get("raw", "")).strip()
            if raw:
                lines.append(textwrap.indent(raw, "  "))

    steps = final.get("steps")
    if isinstance(steps, list) and steps:
        lines.append("")
        lines.append(f"Steps ({len(steps)}):")
        for idx, step in enumerate(steps, start=1):
            decision = step.get("decision") if isinstance(step, dict) else {}
            observation = step.get("observation") if isinstance(step, dict) else {}
            if not isinstance(decision, dict) or not isinstance(observation, dict):
                lines.append(f"{idx}. (malformed step)")
                continue
            tool = str(decision.get("tool", "")).strip()
            args = decision.get("args") if isinstance(decision.get("args"), dict) else {}
            thought = str(decision.get("thought", "")).strip()
            args_s = json.dumps(args, ensure_ascii=False)
            lines.append(f"{idx}. tool: {tool} args: {args_s}")
            if thought:
                lines.append(textwrap.indent(f"thought: {thought}", "  "))
            ok = observation.get("ok")
            if ok is not None:
                lines.append(textwrap.indent(f"ok: {ok}", "  "))
            err = str(observation.get("error", "") or "").strip()
            if err:
                lines.append(textwrap.indent(f"error: {err}", "  "))
            out_val = observation.get("output", "")
            if isinstance(out_val, (dict, list)):
                out = json.dumps(out_val, ensure_ascii=False, indent=2)
            else:
                out = str(out_val or "").rstrip("\n")
            if out:
                lines.append(textwrap.indent("output:", "  "))
                lines.append(textwrap.indent(out, "    "))

    summary = str(final.get("summary", "") or "").strip()
    next_step = str(final.get("next_step", "") or "").strip()
    thought = str(final.get("thought", "") or "").strip()

    lines.append("")
    lines.append("Result:")
    if summary:
        lines.append(textwrap.indent(f"summary: {summary}", "  "))
    if next_step:
        lines.append(textwrap.indent(f"next_step: {next_step}", "  "))
    if thought:
        lines.append(textwrap.indent(f"thought: {thought}", "  "))

    return "\n".join(lines).rstrip("\n") + "\n"


def _emit(obj: Dict[str, Any], output_format: str) -> None:
    fmt = _resolve_output_format(output_format)
    if fmt == "json":
        sys.stdout.write(json.dumps(obj, ensure_ascii=False))
        sys.stdout.write("\n")
        return
    if fmt == "json-pretty":
        sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=2))
        sys.stdout.write("\n")
        return

    if obj.get("type") == "tools":
        sys.stdout.write(_render_tools_text())
        return

    sys.stdout.write(_render_final_text(obj))


def _argv_has_output_format(argv: List[str]) -> bool:
    return any(a == "--output-format" or a.startswith("--output-format=") for a in argv)


def _system_prompt() -> str:
    tool_lines: List[str] = []
    for spec in TOOL_SPECS:
        name = str(spec.get("name", "")).strip()
        args = spec.get("args") if isinstance(spec.get("args"), dict) else {}
        desc = str(spec.get("description", "")).strip()
        args_obj = "{" + ", ".join(str(k) for k in args.keys()) + "}"
        if desc:
            tool_lines.append(f"- {name}({args_obj}): {desc}")
        else:
            tool_lines.append(f"- {name}({args_obj})")
    tools = "\n".join(tool_lines)
    return (
        "You are a C/C++ build triage agent.\n"
        "You MUST output exactly one JSON object with no extra text.\n"
        "You can either request one tool call, or return a final decision.\n\n"
        "Important:\n"
        "- Patch-related tools persist diff excerpts / V1-origin code slices / generated patches as artifact files.\n"
        "  When that happens, the observation contains an object like {artifact_path, sha256, bytes, lines}.\n"
        "  Use read_artifact(artifact_path, ...) to fetch only the lines you need.\n"
        "- Patch bundles are applied via `git apply --reverse`: in these diffs, `-` lines become additions.\n"
        "- Tool ordering (two-phase workflow):\n"
        "  1) Analysis phase: map error -> patch context, extract V1-origin code, fetch V1+V2 definitions.\n"
        "     Do NOT call read_artifact in this phase.\n"
        "  2) Patching phase (last): call read_artifact only to pull the minimum code context you need,\n"
        "     then call make_error_patch_override to generate an override diff,\n"
        "     then call ossfuzz_apply_patch_and_test to validate it in OSS-Fuzz,\n"
        "     then return final.\n"
        "- Policy: do NOT suggest modifying V2 type definitions (struct/typedef/enum/union),\n"
        "  especially in shared/public headers. Prefer adapting V1-origin usage to V2 semantics.\n"
        "- If the user provides a patch bundle path (patch_path), treat build-log file:line as patched/migrated code.\n"
        "- read_file_context reads from the raw V1/V2 source checkouts; it must use pre-patch line numbers.\n"
        "- Never call read_file_context with the raw build-log /src/...:line values.\n"
        "- Only call read_file_context using (a) KB-derived locations from search_definition, or\n"
        "  (b) get_error_patch_context pre_patch_file_path + pre_patch_line_number (when available).\n"
        "- Prefer patch-first triage: parse_build_errors -> get_error_patch_context -> search_definition.\n"
        "- For \"no member named 'X' in 'struct Y'\" errors, treat the failing code as V1-origin and compare definitions:\n"
        "  search_definition(symbol_name='struct Y', version='v1') and search_definition(..., version='v2') before search_text.\n"
        "  If multiple members are missing for the same struct, reuse the same fetched struct definitions.\n"
        "- When you have a concrete fix for the V1-origin code slice (functions/macros/consts/decls; often inside __revert_*), update the patch bundle slice:\n"
        "  call make_error_patch_override(patch_path, file_path, line_number, new_func_code) to generate an override diff,\n"
        "  then call ossfuzz_apply_patch_and_test(project, commit, patch_path, patch_override_paths=[patch_text.artifact_path]).\n"
        "  This tool rewrites the patch bundle diff (it does not edit source files directly); do NOT modify V2 type definitions.\n"
        "- After generating a patch (make_error_patch_override), you MUST run ossfuzz_apply_patch_and_test before returning final.\n"
        "- If a missing token is likely a macro and search_definition returns nothing, use search_text as a fallback.\n\n"
        "- Macro/decl hunks: syntax errors like \"expected '}'\" can be caused by a macro body referencing undefined\n"
        "  placeholder macros (e.g. a slice defines `MAKE_HANDLER(... out EMPTY_ICONV EMPTY_UCONV ...)` but does not\n"
        "  also add `EMPTY_ICONV` / `EMPTY_UCONV`). Use get_error_v1_code_slice.macro_tokens_not_defined_in_slice as a\n"
        "  hint, search for the missing macro definitions (search_text + read_file_context; v2 first, then v1), and include\n"
        "  the required `#define ...` lines (or a V2-equivalent adaptation) in the override `new_func_code`.\n"
        "  Example: add `#define EMPTY_ICONV` and `#define EMPTY_UCONV` above `#define MAKE_HANDLER(...)` if that matches\n"
        "  the intended V1 semantics, or copy the correct definitions from V2/V1 and adapt call sites as needed.\n\n"
        "- Guardrail (macros): do NOT invent placeholder macro definitions.\n"
        "  If you plan to add `#define TOKEN ...` for any missing macro token (from get_error_v1_code_slice.macro_tokens_not_defined_in_slice),\n"
        "  you MUST first locate its real definition using tools:\n"
        "    - search_text(query=\"#define TOKEN\", version=\"v2\") then search_text(query=\"#define TOKEN\", version=\"v1\")\n"
        "    - read_file_context(version, file_path, line_number, context=80) on the best match to capture the full guarded block.\n"
        "  If neither V1 nor V2 defines TOKEN, do NOT add a dummy `#define`; instead remove/replace TOKEN in the macro body or adapt to V2 semantics.\n\n"
        "- Macro dependency resolution recipe (general):\n"
        "  1) From the build snippet, identify the expanded macro name (`expanded from macro 'X'`).\n"
        "  2) From get_error_v1_code_slice.macro_tokens_not_defined_in_slice, pick the 1–3 missing tokens most relevant to X.\n"
        "  3) For each token, locate `#define` with search_text (v2 then v1) and confirm via read_file_context (include full #if/#endif block).\n"
        "  4) Only then rewrite the patch slice: include dependency macro blocks first, then the macro being added/modified, then call make_error_patch_override.\n\n"
        "Available tools:\n"
        f"{tools}\n\n"
        "Tool output format:\n"
        '{"type":"tool","tool":"<name>","args":{...},"thought":"<one sentence>"}\n\n'
        "Final output format:\n"
        '{"type":"final","summary":"<short>","next_step":"<short>","thought":"<one sentence>"}'
    )


def _build_messages(state: AgentState) -> List[Dict[str, str]]:
    header_lines: List[str] = []
    if state.build_log_path:
        header_lines.append(f"Build log path: {state.build_log_path}")
    if state.patch_path:
        header_lines.append(f"Patch bundle path: {state.patch_path}")
        header_lines.append(
            "NOTE: file:line locations below refer to migrated code; use patch tools to map locations to patches."
        )
    if state.artifacts_dir:
        header_lines.append(f"Artifacts dir: {state.artifacts_dir}")
    if state.ossfuzz_project and state.ossfuzz_commit:
        header_lines.append("OSS-Fuzz test config:")
        header_lines.append(f"  project: {state.ossfuzz_project}")
        header_lines.append(f"  commit: {state.ossfuzz_commit}")
        if state.ossfuzz_build_csv:
            header_lines.append(f"  build_csv: {state.ossfuzz_build_csv}")
        if state.ossfuzz_sanitizer:
            header_lines.append(f"  sanitizer: {state.ossfuzz_sanitizer}")
        if state.ossfuzz_arch:
            header_lines.append(f"  arch: {state.ossfuzz_arch}")
        if state.ossfuzz_engine:
            header_lines.append(f"  engine: {state.ossfuzz_engine}")
        if state.ossfuzz_fuzz_target:
            header_lines.append(f"  fuzz_target: {state.ossfuzz_fuzz_target}")
        header_lines.append(f"  use_sudo: {state.ossfuzz_use_sudo}")
    if state.missing_struct_members:
        header_lines.append("Missing struct members (JSON):")
        header_lines.append(json.dumps(state.missing_struct_members, ensure_ascii=False))
    header = "\n".join(header_lines).strip()

    messages: List[Dict[str, str]] = [
        {"role": "system", "content": _system_prompt()},
        {
            "role": "user",
            "content": (header + "\n\n" if header else "")
            + (
                "Patch-scope errors (all map to the same patch key):\n"
                + (("\n".join(str(e.get("raw", "")).strip() for e in state.grouped_errors if e.get("raw"))) + "\n\n")
                + "Details (JSON):\n"
                + json.dumps({"patch_key": state.patch_key, "errors": state.grouped_errors}, ensure_ascii=False, indent=2)
                if state.error_scope == "patch" and state.grouped_errors
                else "Build error:\n" + state.error_line + "\n\nContext:\n" + state.snippet
            )
            + "\n\nChoose the next best tool call or return a final decision.",
        },
    ]

    for step in state.steps:
        messages.append({"role": "assistant", "content": json.dumps(step["decision"])})
        compacted = _compact_observation_for_prompt(state, step.get("observation"))
        messages.append({"role": "user", "content": "Observation:\n" + json.dumps(compacted, ensure_ascii=False)})

    return messages


def _run_langgraph(
    model: ChatModel,
    runner: ToolRunner,
    state: AgentState,
    cfg: AgentConfig,
    *,
    artifact_store: Any = None,
) -> Dict[str, Any]:
    # Build a small two-node graph: LLM -> TOOL -> LLM (until final).
    def llm_node(gs: GraphState) -> GraphState:
        st = gs["state"]
        if st.patch_generated and not st.ossfuzz_test_attempted:
            # Mandatory: test the generated override patch in OSS-Fuzz before allowing final.
            if not st.patch_path:
                return {
                    "state": st,
                    "final": {
                        "type": "final",
                        "thought": "Cannot run OSS-Fuzz test: missing patch_path.",
                        "summary": "Stopped after patch generation (missing patch bundle path).",
                        "next_step": "Re-run with --patch-path so the agent can merge bundle + override(s) and test in OSS-Fuzz.",
                        "steps": st.steps,
                        "error": _error_payload(st),
                    },
                }
            if not (st.ossfuzz_project and st.ossfuzz_commit):
                return {
                    "state": st,
                    "final": {
                        "type": "final",
                        "thought": "Cannot run OSS-Fuzz test: missing required OSS-Fuzz CLI args.",
                        "summary": "Stopped after patch generation (OSS-Fuzz config missing).",
                        "next_step": "Re-run with --ossfuzz-project and --ossfuzz-commit.",
                        "steps": st.steps,
                        "error": _error_payload(st),
                    },
                }

            decision = {
                "type": "tool",
                "thought": "Test the generated patch in OSS-Fuzz using the patch bundle + override diff artifacts.",
                "tool": "ossfuzz_apply_patch_and_test",
                "args": {
                    "project": st.ossfuzz_project,
                    "commit": st.ossfuzz_commit,
                    "patch_path": st.patch_path,
                    "patch_override_paths": list(st.patch_override_paths or []),
                    "build_csv": st.ossfuzz_build_csv,
                    "sanitizer": st.ossfuzz_sanitizer,
                    "architecture": st.ossfuzz_arch,
                    "engine": st.ossfuzz_engine,
                    "fuzz_target": st.ossfuzz_fuzz_target,
                    "use_sudo": bool(st.ossfuzz_use_sudo),
                },
            }
            _validate_tool_decision(decision)
            return {"state": st, "pending": decision}

        if st.patch_generated and st.ossfuzz_test_attempted:
            patch_text_path = ""
            merged_patch_file_path = ""
            if isinstance(st.patch_result, dict):
                pt = st.patch_result.get("patch_text")
                if isinstance(pt, dict):
                    patch_text_path = str(pt.get("artifact_path", "") or "").strip()
            if isinstance(st.last_observation, ToolObservation) and st.last_observation.tool == "ossfuzz_apply_patch_and_test":
                out = st.last_observation.output
                if isinstance(out, dict):
                    merged_patch_file_path = str(out.get("merged_patch_file_path", "") or "").strip()
            verdict = _summarize_target_error_status(st)
            fixed_str = "unknown"
            if verdict.get("status") == "ok":
                fixed_str = "yes" if verdict.get("fixed") else "no"
            next_step_lines = [f"Target error fixed: {fixed_str}."]
            if verdict.get("status") == "ok":
                matched = verdict.get("matched_target_errors") or []
                if matched:
                    next_step_lines.append("Remaining target errors:")
                    for m in matched[:5]:
                        raw = str((m or {}).get("raw", "")).strip()
                        if raw:
                            next_step_lines.append(f"- {raw}")
                elif verdict.get("other_errors"):
                    next_step_lines.append("Next top errors:")
                    for e in (verdict.get("other_errors") or [])[:5]:
                        raw = str((e or {}).get("raw", "")).strip()
                        if raw:
                            next_step_lines.append(f"- {raw}")
            next_step_lines.append("Review OSS-Fuzz logs in artifacts and apply the merged patch file.")
            if merged_patch_file_path:
                next_step_lines.append(f"Merged patch: {merged_patch_file_path}")
            if patch_text_path:
                next_step_lines.append(f"Override diff: {patch_text_path}")
            next_step = "\n".join(next_step_lines).strip()
            return {
                "state": st,
                "final": {
                    "type": "final",
                    "thought": "Generated a patch and attempted OSS-Fuzz testing; stopping.",
                    "summary": "Generated a function-body replacement patch, tested it in OSS-Fuzz, and checked whether the target error is fixed.",
                    "next_step": next_step.strip(),
                    "steps": st.steps,
                    "error": _error_payload(st),
                },
            }

        if st.pending_patch and st.last_observation and st.last_observation.tool == "read_artifact":
            if len(st.steps) >= cfg.max_steps:
                return {
                    "state": st,
                    "final": {
                        "type": "final",
                        "thought": "Reached max tool steps before generating the patch.",
                        "summary": "Stopped due to max_steps.",
                        "next_step": "Increase --max-steps to allow make_error_patch_override to run after read_artifact.",
                        "steps": st.steps,
                        "error": _error_payload(st),
                    },
                }
            decision = st.pending_patch
            st.pending_patch = None
            _validate_tool_decision(decision)
            return {"state": st, "pending": decision}

        if len(st.steps) >= cfg.max_steps:
            return {
                "state": st,
                "final": {
                    "type": "final",
                    "thought": "Reached max tool steps without a final decision.",
                    "summary": "Stopped after max_steps.",
                    "next_step": "Increase --max-steps or review the last observation and proceed manually.",
                    "steps": st.steps,
                    "error": _error_payload(st),
                },
            }

        # Macro-expansion preflight: if we have missing macro tokens for a macro-expansion error,
        # force an evidence-gathering lookup (v2 then v1) before the model decides to define/remove tokens.
        if (
            not st.macro_lookup
            and st.macro_tokens_not_defined_in_slice
            and "expanded from macro" in str(st.snippet or "")
        ):
            token = _macro_lookup_pick_token(st)
            if token:
                st.macro_lookup = {"token": token, "stage": "need_search_text", "version": "v2"}
                forced: Decision = {
                    "type": "tool",
                    "thought": f"Macro preflight: locate the real #define for {token} (v2 then v1) before rewriting the patch.",
                    "tool": "search_text",
                    "args": {"query": f"#define {token}", "version": "v2", "limit": 20, "file_glob": ""},
                }
                _validate_tool_decision(forced)
                return {"state": st, "pending": forced}

        if isinstance(st.macro_lookup, dict):
            stage = str(st.macro_lookup.get("stage", "") or "").strip()
            token = str(st.macro_lookup.get("token", "") or "").strip()
            version = str(st.macro_lookup.get("version", "v2") or "v2").strip() or "v2"
            if stage == "need_search_text" and token:
                forced: Decision = {
                    "type": "tool",
                    "thought": f"Macro guardrail: locate the real #define for {token} before adding it.",
                    "tool": "search_text",
                    "args": {"query": f"#define {token}", "version": version, "limit": 20, "file_glob": ""},
                }
                _validate_tool_decision(forced)
                return {"state": st, "pending": forced}
            if stage == "need_read_file_context":
                file_path = str(st.macro_lookup.get("file_path", "") or "").strip()
                line_number = int(st.macro_lookup.get("line_number") or 0)
                if file_path and line_number > 0:
                    forced = {
                        "type": "tool",
                        "thought": f"Macro guardrail: read the real definition context for {token} before rewriting the patch.",
                        "tool": "read_file_context",
                        "args": {"file_path": file_path, "line_number": line_number, "context": 80, "version": version},
                    }
                    _validate_tool_decision(forced)
                    st.macro_lookup = {"token": token, "stage": "done", "version": version}
                    return {"state": st, "pending": forced}
        messages = _build_messages(st)
        raw = model.complete(messages)
        try:
            decision = _parse_decision(raw)
        except Exception:  # noqa: BLE001
            # Best-effort repair: some models may ignore JSON-only instructions.
            raw_snippet = str(raw or "").strip()
            if len(raw_snippet) > 2000:
                raw_snippet = raw_snippet[:2000] + "\n...[truncated]"
            repair_messages = list(messages)
            if raw_snippet:
                repair_messages.append({"role": "assistant", "content": raw_snippet})
            repair_messages.append(
                {
                    "role": "user",
                    "content": (
                        "Your previous response was invalid (not a single JSON object).\n"
                        "Return exactly one JSON object now, with no extra text, no markdown, no code fences.\n"
                        'It must match one of:\n'
                        '{"type":"tool","tool":"<name>","args":{...},"thought":"<one sentence>"}\n'
                        '{"type":"final","summary":"<short>","next_step":"<short>","thought":"<one sentence>"}'
                    ),
                }
            )
            repair_model: ChatModel = model
            if isinstance(model, OpenAIChatCompletionsModel) and model.json_mode and not raw_snippet:
                # gpt-5 style models can sometimes return empty content under strict JSON mode when the
                # completion token budget is too low (reasoning consumes it). Retry with a larger budget
                # and without response_format enforcement.
                repair_model = replace(
                    model,
                    json_mode=False,
                    max_tokens=max(int(model.max_tokens or 0), 8000),
                )
            repaired_raw = repair_model.complete(repair_messages)
            try:
                decision = _parse_decision(repaired_raw)
            except Exception as exc:  # noqa: BLE001
                repaired_snippet = str(repaired_raw or "").strip()
                if len(repaired_snippet) > 800:
                    repaired_snippet = repaired_snippet[:800] + "\n...[truncated]"
                return {
                    "state": st,
                    "final": {
                        "type": "final",
                        "thought": "Model did not return valid JSON.",
                        "summary": "Agent stopped due to invalid model output.",
                        "next_step": (
                            f"{exc}\n\n"
                            "Try again, or run with --no-json-mode, or set OPENAI_MODEL/OPENAI_BASE_URL to a JSON-capable endpoint.\n"
                            + (f"Repaired raw snippet: {repaired_snippet!r}" if repaired_snippet else "")
                        ).strip(),
                        "steps": st.steps,
                        "error": _error_payload(st),
                    },
                }
        if decision["type"] == "final":
            remaining = cfg.max_steps - len(st.steps)
            required = _should_force_struct_diff_tools(st)
            if required and remaining >= 2:
                if required == "get_error_v1_code_slice":
                    file_path, line_number = _first_error_location(st)
                    if file_path and line_number > 0:
                        forced: Decision = {
                            "type": "tool",
                            "thought": "Missing-member error in patch-scope: extract V1-origin function body from the patch before finalizing.",
                            "tool": "get_error_v1_code_slice",
                            "args": {
                                "patch_path": st.patch_path,
                                "file_path": file_path,
                                "line_number": line_number,
                                "max_lines": 400,
                                "max_chars": 20000,
                            },
                        }
                        _validate_tool_decision(forced)
                        return {"state": st, "pending": forced}
                elif required.startswith("search_definition:"):
                    _, version, symbol = required.split(":", 2)
                    forced = {
                        "type": "tool",
                        "thought": f"Missing-member error in patch-scope: fetch {version} definition of the struct before finalizing.",
                        "tool": "search_definition",
                        "args": {"symbol_name": symbol, "version": version},
                    }
                    _validate_tool_decision(forced)
                    return {"state": st, "pending": forced}

            # Guardrail: in patch-scope patch-slice rewrite flows, do not accept final until
            # make_error_patch_override has been called (the primary goal is to emit a patch bundle rewrite).
            if _should_require_make_error_patch_override(st):
                prereq = _next_patch_prereq_tool(st)
                if prereq and remaining >= 1:
                    _validate_tool_decision(prereq)
                    return {"state": st, "pending": prereq}

                last_tool = _last_tool_call_name(st)
                file_path, line_number = _first_error_location(st)
                if not file_path or line_number <= 0:
                    return {
                        "state": st,
                        "final": {
                            "type": "final",
                            "thought": "Cannot force patch generation: missing error file/line location.",
                            "summary": "Stopped before patch generation.",
                            "next_step": "Ensure the build log contains a file:line:col error location, or run with --error-scope patch on a log with mapped errors.",
                            "steps": st.steps,
                            "error": _error_payload(st),
                        },
                    }

                # Ensure we have an artifact-backed view of the full V1-origin function before asking for a patch.
                if last_tool != "read_artifact":
                    if remaining < 3:
                        return {
                            "state": st,
                            "final": {
                                "type": "final",
                                "thought": "Not enough remaining tool steps to read artifacts and generate a patch.",
                                "summary": "Stopped before patch generation.",
                                "next_step": "Increase --max-steps (need at least 3 remaining steps: read_artifact -> make_error_patch_override -> ossfuzz_apply_patch_and_test).",
                                "steps": st.steps,
                                "error": _error_payload(st),
                            },
                        }

                    artifact_path = _last_artifact_path(st, "get_error_v1_code_slice", "func_code") or _last_artifact_path(
                        st, "get_error_patch_context", "excerpt"
                    )
                    forced_read: Decision = {
                        "type": "tool",
                        "thought": "Before generating the patch, read the full V1-origin function artifact so we can rewrite it safely.",
                        "tool": "read_artifact",
                        "args": {
                            "artifact_path": artifact_path,
                            "start_line": 1,
                            "max_lines": 800,
                            "max_chars": 200000,
                        },
                    }
                    _validate_tool_decision(forced_read)
                    return {"state": st, "pending": forced_read}

                # We just read the function code; require the model to emit a patch-generation tool call next.
                base_rewrite_messages = list(messages)
                base_rewrite_messages.append({"role": "assistant", "content": json.dumps(decision, ensure_ascii=False)})
                base_rewrite_messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Do NOT return a final decision yet.\n"
                            "You MUST generate a patch now by calling make_error_patch_override.\n"
                            "Return exactly one JSON object of type tool with:\n"
                            f'- tool="make_error_patch_override"\n'
                            f'- args.patch_path="{st.patch_path}"\n'
                            f'- args.file_path="{file_path}"\n'
                            f"- args.line_number={line_number}\n"
                            "- args.new_func_code=<the full replacement function body as a JSON string with \\\\n escapes>\n"
                            "Do not include any extra text."
                        ),
                    }
                )
                try:
                    coerced = _parse_decision(model.complete(base_rewrite_messages))
                except Exception:
                    coerced = {}
                if isinstance(coerced, dict) and coerced.get("type") == "tool" and str(coerced.get("tool", "")).strip() == "make_error_patch_override":
                    _validate_tool_decision(coerced)  # type: ignore[arg-type]
                    return {"state": st, "pending": coerced}  # type: ignore[typeddict-item]

                return {
                    "state": st,
                    "final": {
                        "type": "final",
                        "thought": "Patch generation required, but the model did not produce a make_error_patch_override tool call.",
                        "summary": "Stopped before patch generation.",
                        "next_step": (
                            "Re-run with a larger model / higher OPENAI_MAX_TOKENS, or manually call make_error_patch_override.\n"
                            "Required: generate a full replacement function body and pass it as new_func_code."
                        ),
                        "steps": st.steps,
                        "error": _error_payload(st),
                    },
                }

            if _decision_suggests_v2_type_edit(decision):
                base_rewrite_messages = list(messages)
                base_rewrite_messages.append({"role": "assistant", "content": json.dumps(decision, ensure_ascii=False)})

                def attempt_rewrite(extra_user: str) -> Optional[Decision]:
                    rewrite_messages = list(base_rewrite_messages)
                    rewrite_messages.append({"role": "user", "content": extra_user})
                    raw_out = model.complete(rewrite_messages)
                    try:
                        return _parse_decision(raw_out)
                    except Exception:
                        raw_snippet = str(raw_out or "").strip()
                        if len(raw_snippet) > 1200:
                            raw_snippet = raw_snippet[:1200] + "\n...[truncated]"
                        repair_messages = list(rewrite_messages)
                        if raw_snippet:
                            repair_messages.append({"role": "assistant", "content": raw_snippet})
                        repair_messages.append(
                            {
                                "role": "user",
                                "content": (
                                    "Return exactly one JSON object of type final now, with no extra text.\n"
                                    '{"type":"final","summary":"<short>","next_step":"<short>","thought":"<one sentence>"}'
                                ),
                            }
                        )
                        try:
                            return _parse_decision(model.complete(repair_messages))
                        except Exception:
                            return None

                rewrite_prompt = (
                    "Your previous final decision suggests modifying V2 type definitions, which is not allowed.\n"
                    "Rewrite it into a V2-usage-adaptation plan (do not edit V2 struct/typedef/enum/union definitions).\n"
                    "Base your suggestion on the tool observations already shown (patch excerpt, V1 function code, struct defs).\n"
                    "If you believe V2 type edits are required, explicitly say they are out-of-policy and stop.\n"
                    "Return exactly one JSON object of type final with summary/next_step/thought."
                )
                rewritten = attempt_rewrite(rewrite_prompt)
                if not (isinstance(rewritten, dict) and rewritten.get("type") == "final") or _decision_suggests_v2_type_edit(rewritten or {}):  # type: ignore[arg-type]
                    rewritten = attempt_rewrite(
                        rewrite_prompt
                        + "\nDo NOT mention adding fields/members to structs or editing headers; only propose call-site / API adaptations."
                    )

                if isinstance(rewritten, dict) and rewritten.get("type") == "final" and not _decision_suggests_v2_type_edit(rewritten or {}):  # type: ignore[arg-type]
                    decision = rewritten  # type: ignore[assignment]
                else:
                    decision = {
                        "type": "final",
                        "thought": "Policy forbids suggesting V2 type definition edits.",
                        "summary": "Agent blocked a suggestion to modify V2 type definitions.",
                        "next_step": (
                            "Adapt the V1-origin code to V2 semantics instead (change call sites / field usage / APIs).\n"
                            "V2 type definition edits are out-of-policy and require human review."
                        ),
                    }
            return {
                "state": st,
                "final": {
                    "type": "final",
                    "thought": str(decision.get("thought", "")).strip(),
                    "summary": str(decision.get("summary", "")).strip(),
                    "next_step": str(decision.get("next_step", "")).strip(),
                    "steps": st.steps,
                    "error": _error_payload(st),
                },
            }
        _validate_tool_decision(decision)

        rewritten_search = _rewrite_search_text_query_for_macro(st, decision)
        if rewritten_search:
            decision = rewritten_search  # type: ignore[assignment]
            _validate_tool_decision(decision)

        forced_macro = _macro_define_guardrail_for_override(st, decision)
        if forced_macro:
            _validate_tool_decision(forced_macro)
            return {"state": st, "pending": forced_macro}

        # Enforce tool ordering: analysis first, patching last.
        remaining = cfg.max_steps - len(st.steps)
        tool = str(decision.get("tool", "")).strip()
        if tool in {"read_artifact", "make_error_patch_override"}:
            prereq = _next_patch_prereq_tool(st)
            if prereq:
                _validate_tool_decision(prereq)
                return {"state": st, "pending": prereq}

        if tool == "read_artifact" and remaining < 3:
            return {
                "state": st,
                "final": {
                    "type": "final",
                    "thought": "Not enough remaining tool steps to read artifacts and generate a patch.",
                    "summary": "Stopped before patch generation.",
                    "next_step": "Increase --max-steps (need at least 3 remaining steps: read_artifact -> make_error_patch_override -> ossfuzz_apply_patch_and_test).",
                    "steps": st.steps,
                    "error": _error_payload(st),
                },
            }

        if tool == "make_error_patch_override" and st.artifacts_dir and _last_tool_call_name(st) != "read_artifact":
            if remaining >= 3:
                st.pending_patch = decision
                artifact_path = _last_artifact_path(st, "get_error_v1_code_slice", "func_code") or _last_artifact_path(
                    st, "get_error_patch_context", "excerpt"
                )
                forced: Decision = {
                    "type": "tool",
                    "thought": "Before generating the patch, read the full artifact slice so the replacement does not accidentally drop tail lines.",
                    "tool": "read_artifact",
                    "args": {
                        "artifact_path": artifact_path,
                        "start_line": 1,
                        "query": "",
                        "context_lines": 0,
                        "max_lines": 0,
                        "max_chars": 0,
                    },
                }
                _validate_tool_decision(forced)
                return {"state": st, "pending": forced}
            return {
                "state": st,
                "final": {
                    "type": "final",
                    "thought": "Not enough remaining tool steps to read artifacts and generate a patch in-order.",
                    "summary": "Stopped before patch generation.",
                    "next_step": "Increase --max-steps (need at least 3 remaining steps: read_artifact -> make_error_patch_override -> ossfuzz_apply_patch_and_test).",
                    "steps": st.steps,
                    "error": _error_payload(st),
                },
            }

        return {"state": st, "pending": decision}

    def tool_node(gs: GraphState) -> GraphState:
        st = gs["state"]
        decision = gs["pending"]
        tool = str(decision["tool"])
        args = dict(decision.get("args", {}))
        obs = runner.call(tool, args)
        if artifact_store and obs.ok and obs.tool != "read_artifact":
            offloaded = offload_patch_output(
                store=artifact_store, tool=obs.tool, args=obs.args, output=obs.output, focus_terms=_collect_focus_terms(st)
            )
            if offloaded is not obs.output:
                obs = ToolObservation(ok=obs.ok, tool=obs.tool, args=obs.args, output=offloaded, error=obs.error)
        st.steps.append({"decision": decision, "observation": obs.__dict__})
        st.last_observation = obs
        if obs.ok and obs.tool == "get_error_v1_code_slice" and isinstance(obs.output, dict):
            missing = obs.output.get("macro_tokens_not_defined_in_slice")
            if isinstance(missing, list):
                st.macro_tokens_not_defined_in_slice = [str(x) for x in missing if str(x).strip()][:200]
        if obs.ok and obs.tool == "search_text" and isinstance(st.macro_lookup, dict):
            _macro_lookup_update_from_search_text_output(st, obs.output)
        if obs.ok and obs.tool == "make_error_patch_override":
            st.patch_generated = True
            st.patch_result = obs.output if isinstance(obs.output, dict) else None
            st.pending_patch = None
            patch_text_path = ""
            if isinstance(st.patch_result, dict):
                pt = st.patch_result.get("patch_text")
                if isinstance(pt, dict):
                    patch_text_path = str(pt.get("artifact_path", "") or "").strip()
            if patch_text_path:
                st.patch_override_paths = [patch_text_path]
        if obs.tool == "ossfuzz_apply_patch_and_test":
            st.ossfuzz_test_attempted = True
        return {"state": st}

    def route(gs: GraphState) -> str:
        if "final" in gs:
            return "final"
        return "tool"

    graph = StateGraph(GraphState)
    graph.add_node("llm", llm_node)
    graph.add_node("tool", tool_node)
    graph.set_entry_point("llm")
    graph.add_conditional_edges("llm", route, {"tool": "tool", "final": END})
    graph.add_edge("tool", "llm")
    compiled = graph.compile()
    result = compiled.invoke({"state": state})
    final = result.get("final")
    if final:
        return final
    return {
        "type": "final",
        "thought": "Reached max tool steps without a final decision.",
        "summary": "Stopped after max_steps.",
        "next_step": "Increase --max-steps or review the last observation and proceed manually.",
        "steps": state.steps,
        "error": _error_payload(state),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LLM-driven build triage agent (OpenAI + LangGraph).")
    parser.add_argument("build_log", nargs="?", default="-", help="Build log path, or '-' for stdin.")

    parser.add_argument("--list-tools", action="store_true", help="Print available tools and exit.")
    parser.add_argument(
        "--output-format",
        choices=["auto", "json", "json-pretty", "text"],
        default=os.environ.get("REACT_AGENT_OUTPUT_FORMAT", "auto"),
        help="Output format (default: auto=text when stdout is a TTY, else json).",
    )
    parser.add_argument("--model", choices=["openai", "stub"], default=os.environ.get("REACT_AGENT_MODEL", "openai"))
    parser.add_argument("--max-steps", type=int, default=4)
    parser.add_argument(
        "--error-scope",
        choices=["first", "patch"],
        default=os.environ.get("REACT_AGENT_ERROR_SCOPE", "first"),
        help="Triage scope: only the first error, or all errors mapping to the same patch.",
    )
    parser.add_argument(
        "--tools", choices=["real", "fake"], default="real")
    parser.add_argument("--v1-json-dir", help="Root directory containing V1 *_analysis.json files")
    parser.add_argument("--v2-json-dir", help="Root directory containing V2 *_analysis.json files")
    parser.add_argument("--v1-src", help="Local filesystem root for V1 source code")
    parser.add_argument("--v2-src", help="Local filesystem root for V2 source code")
    parser.add_argument(
        "--patch-path",
        default=os.environ.get("REACT_AGENT_PATCH_PATH", ""),
        help="Path to a tmp_patch bundle (*.patch2) for patch-aware triage.",
    )
    parser.add_argument(
        "--focus-patch-key",
        default=os.environ.get("REACT_AGENT_FOCUS_PATCH_KEY", ""),
        help="In --error-scope patch mode, select this patch_key group (hunk) instead of the default heuristic.",
    )
    parser.add_argument(
        "--artifact-dir",
        default=os.environ.get("REACT_AGENT_ARTIFACT_DIR", ""),
        help="Directory for saving large tool outputs (artifacts). Default: data/react_agent_artifacts/<run_id>/",
    )
    parser.add_argument("--no-artifacts", action="store_true", help="Disable artifact-backed tool outputs.")

    parser.add_argument("--openai-api-key", default=os.environ.get("OPENAI_API_KEY", ""))
    parser.add_argument("--openai-model", default=os.environ.get("OPENAI_MODEL", "") or "gpt-5-mini")
    parser.add_argument("--openai-base-url", default=os.environ.get("OPENAI_BASE_URL", "") or "https://api.openai.com/v1")
    parser.add_argument("--openai-org", default=os.environ.get("OPENAI_ORG", ""))
    parser.add_argument("--openai-project", default=os.environ.get("OPENAI_PROJECT", ""))
    parser.add_argument(
        "--openai-max-tokens",
        type=int,
        default=int(os.environ.get("OPENAI_MAX_TOKENS", "0") or 0),
        help="Max completion tokens for the OpenAI call (0=auto; recommended >=2000 for gpt-5-*).",
    )
    parser.add_argument("--no-json-mode", action="store_true", help="Disable OpenAI JSON mode.")

    # OSS-Fuzz testing (mandatory after patch generation in patch-scope runs)
    parser.add_argument("--ossfuzz-project", default=os.environ.get("REACT_AGENT_OSSFUZZ_PROJECT", ""))
    parser.add_argument("--ossfuzz-commit", default=os.environ.get("REACT_AGENT_OSSFUZZ_COMMIT", ""))
    parser.add_argument("--ossfuzz-build-csv", default=os.environ.get("REACT_AGENT_OSSFUZZ_BUILD_CSV", ""))
    parser.add_argument("--ossfuzz-sanitizer", default=os.environ.get("REACT_AGENT_OSSFUZZ_SANITIZER", "address"))
    parser.add_argument("--ossfuzz-arch", default=os.environ.get("REACT_AGENT_OSSFUZZ_ARCH", "x86_64"))
    parser.add_argument("--ossfuzz-engine", default=os.environ.get("REACT_AGENT_OSSFUZZ_ENGINE", "libfuzzer"))
    parser.add_argument("--ossfuzz-fuzz-target", default=os.environ.get("REACT_AGENT_OSSFUZZ_FUZZ_TARGET", ""))
    parser.add_argument("--ossfuzz-use-sudo", action="store_true", default=bool(os.environ.get("REACT_AGENT_OSSFUZZ_USE_SUDO", "")))
    return parser


def main(argv: List[str]) -> int:
    args = build_parser().parse_args(argv)
    if args.list_tools:
        output_format = args.output_format
        if not _argv_has_output_format(argv):
            output_format = "text" if sys.stdout.isatty() else "json-pretty"
        _emit({"type": "tools", "tools": TOOL_SPECS}, output_format)
        return 0
    cfg = AgentConfig(
        max_steps=max(args.max_steps, 1),
        tools_mode=args.tools,
        error_scope=args.error_scope,
    )

    # Fail fast: in patch-scope runs we will generate a patch and must be able to test it.
    ossfuzz_project = str(getattr(args, "ossfuzz_project", "") or "").strip()
    ossfuzz_commit = str(getattr(args, "ossfuzz_commit", "") or "").strip()
    if cfg.error_scope == "patch":
        missing_ossfuzz: List[str] = []
        if not ossfuzz_project:
            missing_ossfuzz.append("--ossfuzz-project")
        if not ossfuzz_commit:
            missing_ossfuzz.append("--ossfuzz-commit")
        if missing_ossfuzz:
            raise ValueError(
                "Patch-scope runs require OSS-Fuzz test config (agent tests the patch before stopping). Missing: "
                + ", ".join(missing_ossfuzz)
            )

    build_log = load_build_log(args.build_log)

    patch_path = str(getattr(args, "patch_path", "") or "").strip()
    if not patch_path and getattr(args, "v2_src", None):
        repo_root = Path(__file__).resolve().parents[2]
        inferred = repo_root / "data" / "tmp_patch" / f"{Path(args.v2_src).resolve().name}.patch2"
        if inferred.is_file():
            patch_path = str(inferred)

    grouped_errors: List[Dict[str, Any]] = []
    patch_key = ""
    missing_struct_members: List[Dict[str, Any]] = []

    error_line, snippet = find_first_fatal(build_log)
    if not error_line:
        _emit({"type": "final", "thought": "No compiler error found.", "summary": "", "next_step": ""}, args.output_format)
        return 0

    if patch_path and cfg.error_scope == "first":
        try:
            from tools.migration_tools import get_error_patch as map_error_patch  # noqa: PLC0415

            m = _ERROR_LOC_RE.match(str(error_line or "").strip())
            if m:
                mapping = map_error_patch(patch_path=patch_path, file_path=m.group("file"), line_number=int(m.group("line")))
                patch_key = str(mapping.get("patch_key") or "").strip()
        except Exception:
            patch_key = ""

    if cfg.error_scope == "patch" and not patch_path:
        raise ValueError("--error-scope patch requires --patch-path (or REACT_AGENT_PATCH_PATH)")
    if cfg.error_scope == "patch" and patch_path:
        try:
            from tools.migration_tools import get_error_patch as map_error_patch  # noqa: PLC0415
            from tools.migration_tools import parse_build_errors as parse_build_errors_tool  # noqa: PLC0415

            errs = iter_compiler_errors(build_log, snippet_lines=10)
            groups: Dict[str, List[Dict[str, Any]]] = {}
            first_mapped_key = ""
            for err in errs:
                mapping = map_error_patch(patch_path=patch_path, file_path=err["file"], line_number=err["line"])
                key = str(mapping.get("patch_key") or "").strip()
                enriched = dict(err)
                enriched["patch_key"] = mapping.get("patch_key")
                enriched["old_signature"] = mapping.get("old_signature")
                if key:
                    if not first_mapped_key:
                        first_mapped_key = key
                    groups.setdefault(key, []).append(enriched)
            if groups:
                focus = str(getattr(args, "focus_patch_key", "") or "").strip()
                if focus and focus in groups:
                    patch_key = focus
                else:
                    patch_key = first_mapped_key if first_mapped_key in groups else max(groups.items(), key=lambda kv: len(kv[1]))[0]
                grouped_errors = groups[patch_key]
                if grouped_errors:
                    error_line = str(grouped_errors[0].get("raw", error_line))
                    snippet = str(grouped_errors[0].get("snippet", snippet))
                raw_block = "\n".join(str(e.get("raw", "")).strip() for e in grouped_errors if e.get("raw"))
                if raw_block:
                    parsed = parse_build_errors_tool(build_log_text=raw_block)
                    msm = parsed.get("missing_struct_members") if isinstance(parsed, dict) else None
                    if isinstance(msm, list) and msm:
                        by_struct: Dict[str, set[str]] = {}
                        for item in msm:
                            if not isinstance(item, dict):
                                continue
                            struct_raw = str(item.get("struct", "")).strip()
                            member = str(item.get("member", "")).strip()
                            if struct_raw and member:
                                by_struct.setdefault(struct_raw, set()).add(member)
                        # Bound output size for prompt readability.
                        max_structs = 8
                        max_members = 12
                        missing_struct_members = []
                        for struct_name in sorted(by_struct.keys())[:max_structs]:
                            members = sorted(by_struct[struct_name])[:max_members]
                            missing_struct_members.append({"struct": struct_name, "members": members})
        except Exception:
            grouped_errors = []
            patch_key = ""
            missing_struct_members = []

    target_errors = _extract_target_errors(error_line=error_line, grouped_errors=grouped_errors, patch_key=patch_key)

    artifact_store, artifacts_dir = resolve_artifact_dir(
        cli_dir=str(getattr(args, "artifact_dir", "") or ""),
        disabled=bool(args.no_artifacts),
        patch_key=patch_key,
    )
    if artifact_store and artifacts_dir:
        os.environ["REACT_AGENT_ARTIFACT_DIR"] = artifacts_dir
    # Patch-related tool outputs are persisted as artifacts without size thresholds.

    try:
        if args.model == "stub":
            model: ChatModel = StubModel()
        else:
            api_key = str(args.openai_api_key).strip()
            if not api_key:
                raise ModelError("OPENAI_API_KEY (or --openai-api-key) is required")
            openai_model_name = str(args.openai_model).strip()
            max_tokens = int(getattr(args, "openai_max_tokens", 0) or 0)
            if max_tokens <= 0:
                max_tokens = 4000 if openai_model_name.startswith(("gpt-5", "o")) else 800
            model = OpenAIChatCompletionsModel(
                api_key=api_key,
                model=openai_model_name,
                base_url=str(args.openai_base_url).strip(),
                org=str(args.openai_org).strip(),
                project=str(args.openai_project).strip(),
                max_tokens=max_tokens,
                json_mode=not bool(args.no_json_mode),
            )

        agent_tools: Optional[AgentTools] = None
        if cfg.tools_mode == "real":
            missing = [k for k in ("v1_json_dir", "v2_json_dir", "v1_src", "v2_src") if getattr(args, k) is None]
            if missing:
                raise ValueError(
                    "Missing required args for --tools real: "
                    + ", ".join("--" + m.replace("_", "-") for m in missing)
                )
            kb = KbIndex(args.v1_json_dir, args.v2_json_dir)
            sm = SourceManager(args.v1_src, args.v2_src)
            agent_tools = AgentTools(kb, sm)

        runner = ToolRunner(agent_tools, mode=cfg.tools_mode)
        state = AgentState(
            build_log_path=str(args.build_log),
            patch_path=patch_path,
            error_scope=cfg.error_scope,
            error_line=error_line,
            snippet=snippet,
            artifacts_dir=artifacts_dir,
            patch_key=patch_key,
            grouped_errors=grouped_errors,
            missing_struct_members=missing_struct_members,
            target_errors=target_errors,
            ossfuzz_project=ossfuzz_project,
            ossfuzz_commit=ossfuzz_commit,
            ossfuzz_build_csv=str(getattr(args, "ossfuzz_build_csv", "") or "").strip(),
            ossfuzz_sanitizer=str(getattr(args, "ossfuzz_sanitizer", "") or "address").strip() or "address",
            ossfuzz_arch=str(getattr(args, "ossfuzz_arch", "") or "x86_64").strip() or "x86_64",
            ossfuzz_engine=str(getattr(args, "ossfuzz_engine", "") or "libfuzzer").strip() or "libfuzzer",
            ossfuzz_fuzz_target=str(getattr(args, "ossfuzz_fuzz_target", "") or "").strip(),
            ossfuzz_use_sudo=bool(getattr(args, "ossfuzz_use_sudo", False)),
        )

        final = _run_langgraph(
            model,
            runner,
            state,
            cfg,
            artifact_store=artifact_store,
        )
    except Exception as exc:  # noqa: BLE001
        _emit({"type": "final", "thought": "Agent error.", "summary": "", "next_step": str(exc)}, args.output_format)
        return 1

    _emit(final, args.output_format)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
