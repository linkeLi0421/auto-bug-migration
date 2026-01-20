#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import textwrap
import inspect
from dataclasses import asdict, dataclass, field, replace
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
from prompting import build_system_prompt
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
    recursion_limit: int = 0
    debug_llm: bool = False
    debug_llm_dir: str = ""
    auto_ossfuzz_loop: bool = False
    ossfuzz_loop_max: int = 1


@dataclass
class AgentState:
    build_log_path: str
    patch_path: str
    error_scope: Literal["first", "patch"]
    error_line: str
    snippet: str
    artifacts_dir: str = ""
    patch_key: str = ""

    # Active patch-slice focus (used for patch-scope iteration across OSS-Fuzz runs).
    active_patch_key: str = ""
    active_file_path: str = ""
    active_line_number: int = 0
    active_func_start_index: Optional[int] = None
    active_func_end_index: Optional[int] = None
    active_old_signature: str = ""
    active_excerpt_artifact_path: str = ""
    active_patch_minus_code_artifact_path: str = ""
    active_error_func_code_artifact_path: str = ""
    pre_patch_file_path: str = ""
    pre_patch_line_number: int = 0
    grouped_errors: List[Dict[str, Any]] = field(default_factory=list)
    # High-level grouping summary of all errors in the active patch_key (grouped by old_signature).
    function_groups: List[Dict[str, Any]] = field(default_factory=list)
    function_groups_total: int = 0
    function_groups_truncated: bool = False
    # Union of unique error lines seen across this agent run, keyed by old_signature.
    # Used to explain why "current" function groups may differ from earlier iterations.
    function_error_history: Dict[str, List[str]] = field(default_factory=dict)
    function_error_history_truncated: bool = False
    missing_struct_members: List[Dict[str, Any]] = field(default_factory=list)
    # Compact record of previously targeted errors (survives state.steps trimming in auto-loop).
    error_history: List[Dict[str, Any]] = field(default_factory=list)
    # Full tool-call history across the whole run (survives state.steps trimming in auto-loop).
    step_history: List[Dict[str, Any]] = field(default_factory=list)
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
    # Total number of ossfuzz_apply_patch_and_test tool calls in this run.
    ossfuzz_runs_attempted: int = 0

    # When set, points to the current BASE slice artifact to read before generating the next override.
    loop_base_func_code_artifact_path: str = ""

    # Latest macro tokens inferred from the active V1-origin patch slice (used for guardrails).
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
    if str(getattr(state, "active_old_signature", "") or "").strip():
        payload["active_old_signature"] = str(state.active_old_signature).strip()
    if isinstance(getattr(state, "function_groups", None), list) and state.function_groups:
        payload["function_groups"] = state.function_groups
        payload["function_groups_total"] = int(getattr(state, "function_groups_total", 0) or 0)
        payload["function_groups_truncated"] = bool(getattr(state, "function_groups_truncated", False))
    hist = getattr(state, "function_error_history", None)
    if isinstance(hist, dict) and hist:
        hist_groups, hist_total, hist_trunc = _summarize_function_error_history(hist)
        payload["function_groups_history"] = hist_groups
        payload["function_groups_history_total"] = hist_total
        payload["function_groups_history_truncated"] = bool(getattr(state, "function_error_history_truncated", False)) or hist_trunc
    if state.error_history:
        payload["error_history"] = state.error_history
    if state.target_errors:
        payload["target_errors"] = state.target_errors
    if state.missing_struct_members:
        payload["missing_struct_members"] = state.missing_struct_members
    return payload


def _steps_for_output(state: AgentState) -> List[Dict[str, Any]]:
    hist = state.step_history if isinstance(getattr(state, "step_history", None), list) else []
    if hist:
        return hist
    steps = state.steps if isinstance(getattr(state, "steps", None), list) else []
    return steps


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


_ERROR_HISTORY_MAX_ENTRIES = 20
_ERROR_HISTORY_MAX_GROUP_LINES = 12


def _make_error_history_entry(
    *,
    patch_key: str,
    error_line: str,
    grouped_errors: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    pk = str(patch_key or "").strip()
    line = str(error_line or "").strip()
    raw_group: List[str] = []
    for e in grouped_errors or []:
        if not isinstance(e, dict):
            continue
        raw = str(e.get("raw", "") or "").strip()
        if not raw:
            continue
        raw_group.append(raw)
        if len(raw_group) >= _ERROR_HISTORY_MAX_GROUP_LINES:
            break
    if not raw_group and line:
        raw_group = [line]
    if not line and raw_group:
        line = raw_group[0]
    if not line and not raw_group:
        return None
    return {"patch_key": pk, "error_line": line, "grouped_errors": raw_group}


def _append_error_history(state: AgentState, entry: Optional[Dict[str, Any]]) -> None:
    if not entry:
        return
    pk = str(entry.get("patch_key", "") or "").strip()
    line = str(entry.get("error_line", "") or "").strip()
    if not line:
        return
    for existing in state.error_history:
        if not isinstance(existing, dict):
            continue
        if str(existing.get("patch_key", "") or "").strip() == pk and str(existing.get("error_line", "") or "").strip() == line:
            return
    state.error_history.append(entry)
    if len(state.error_history) > _ERROR_HISTORY_MAX_ENTRIES:
        state.error_history = state.error_history[-_ERROR_HISTORY_MAX_ENTRIES:]


def _record_current_error_group(state: AgentState) -> None:
    pk = str(state.active_patch_key or state.patch_key or "").strip()
    entry = _make_error_history_entry(patch_key=pk, error_line=state.error_line, grouped_errors=state.grouped_errors)
    _append_error_history(state, entry)


def _select_function_group_errors(
    errors: List[Dict[str, Any]], *, preferred_old_signature: str = ""
) -> tuple[List[Dict[str, Any]], str]:
    """Select a single function's errors within a patch_key when the patch hunk is merged/tail.

    We treat "merged hunk" heuristically as: multiple distinct non-empty `old_signature` values
    appear among errors for the same patch_key. In that case, return only the errors for the
    preferred signature if present, otherwise the first signature group in original order.
    """
    preferred = str(preferred_old_signature or "").strip()

    sig_order: List[str] = []
    by_sig: Dict[str, List[Dict[str, Any]]] = {}
    for err in errors or []:
        if not isinstance(err, dict):
            continue
        sig = str(err.get("old_signature", "") or "").strip()
        if not sig:
            continue
        if sig not in by_sig:
            by_sig[sig] = []
            sig_order.append(sig)
        by_sig[sig].append(err)

    if len(by_sig) <= 1:
        chosen = preferred or (sig_order[0] if sig_order else "")
        return list(errors or []), chosen

    chosen = preferred if preferred and preferred in by_sig else sig_order[0]
    return by_sig[chosen], chosen


def _prioritize_warnings_within_hunk(errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stable ordering helper: warnings first, then errors.

    Within warnings, prioritize missing-prototype warnings first (they are deterministic to fix via _extra_* prototypes).
    """
    ranked: List[tuple[int, int, int, Dict[str, Any]]] = []
    for idx, err in enumerate(errors or []):
        if not isinstance(err, dict):
            continue
        level = str(err.get("level", "error") or "error").strip().lower()
        msg = str(err.get("msg", "") or "")
        is_warning = level == "warning"
        is_missing_proto = is_warning and ("no previous prototype for function" in msg)
        ranked.append((0 if is_warning else 1, 0 if is_missing_proto else 1, idx, err))
    ranked.sort(key=lambda t: (t[0], t[1], t[2]))
    return [e for _, _, _, e in ranked]


def _summarize_function_groups(
    errors: List[Dict[str, Any]], *, max_groups: int = 12, max_examples_per_group: int = 3
) -> tuple[List[Dict[str, Any]], int, bool]:
    """Summarize errors by old_signature for display/debugging (human-facing)."""
    order: List[str] = []
    counts: Dict[str, int] = {}
    examples: Dict[str, List[str]] = {}
    for err in errors or []:
        if not isinstance(err, dict):
            continue
        sig = str(err.get("old_signature", "") or "").strip() or "<unknown>"
        if sig not in counts:
            counts[sig] = 0
            examples[sig] = []
            order.append(sig)
        counts[sig] += 1
        raw = str(err.get("raw", "") or "").strip()
        if raw and len(examples[sig]) < max(1, int(max_examples_per_group or 0)):
            examples[sig].append(raw)

    total = len(order)
    shown = order[: max(0, int(max_groups or 0))]
    truncated = total > len(shown)
    out: List[Dict[str, Any]] = []
    for sig in shown:
        out.append(
            {
                "old_signature": "" if sig == "<unknown>" else sig,
                "count": int(counts.get(sig, 0) or 0),
                "examples": list(examples.get(sig) or []),
            }
        )
    return out, total, truncated


def _update_function_error_history(state: AgentState, errors: List[Dict[str, Any]]) -> None:
    """Accumulate a union of unique error lines by old_signature across the run."""
    hist = getattr(state, "function_error_history", None)
    if not isinstance(hist, dict):
        hist = {}
    truncated = bool(getattr(state, "function_error_history_truncated", False))

    max_groups = 120
    max_total_unique = 8000
    max_per_group = 2000

    total_unique = 0
    for v in hist.values():
        if isinstance(v, list):
            total_unique += len(v)

    for err in errors or []:
        if not isinstance(err, dict):
            continue
        sig = str(err.get("old_signature", "") or "").strip() or "<unknown>"
        raw = str(err.get("raw", "") or "").strip()
        if not raw:
            continue
        if sig not in hist:
            if len(hist) >= max_groups:
                truncated = True
                continue
            hist[sig] = []
        lst = hist.get(sig)
        if not isinstance(lst, list):
            lst = []
            hist[sig] = lst
        if raw in lst:
            continue
        if total_unique >= max_total_unique or len(lst) >= max_per_group:
            truncated = True
            continue
        lst.append(raw)
        total_unique += 1

    state.function_error_history = hist
    state.function_error_history_truncated = truncated


def _summarize_function_error_history(
    hist: Dict[str, List[str]], *, max_groups: int = 12, max_examples_per_group: int = 3
) -> tuple[List[Dict[str, Any]], int, bool]:
    """Summarize the union of unique error lines by old_signature."""
    order = [str(k) for k in hist.keys()]
    total = len(order)
    shown = order[: max(0, int(max_groups or 0))]
    truncated = total > len(shown)

    out: List[Dict[str, Any]] = []
    max_examples = max(0, int(max_examples_per_group or 0))
    for sig in shown:
        raws = hist.get(sig) if isinstance(hist.get(sig), list) else []
        out.append(
            {
                "old_signature": "" if sig == "<unknown>" else sig,
                "count": len(raws),
                "examples": list(raws[:max_examples]) if max_examples else [],
            }
        )
    return out, total, truncated


def _read_text(path: str) -> str:
    p = Path(str(path or "").strip()).expanduser().resolve()
    return p.read_text(encoding="utf-8", errors="replace")


def _allowed_patch_roots_from_env() -> list[str] | None:
    raw = os.environ.get("REACT_AGENT_PATCH_ALLOWED_ROOTS", "").strip()
    if not raw:
        return None
    roots = [r.strip() for r in raw.split(os.pathsep) if r.strip()]
    return roots or None


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

    build_text, check_text, sources, read_err = _read_ossfuzz_logs(out)
    if not build_text and not check_text:
        return {"status": "unknown", "reason": read_err or "Empty OSS-Fuzz logs.", "log_artifacts": sources}

    infra = _ossfuzz_infra_failure(build_text, check_text)
    if infra:
        payload: Dict[str, Any] = {
            "status": "failed",
            "reason": str(infra.get("reason") or "").strip(),
            "targets": targets,
            "log_artifacts": sources,
        }
        hint = str(infra.get("hint") or "").strip()
        if hint:
            payload["hint"] = hint
        return payload

    patch_apply = _ossfuzz_patch_apply_failure(build_text, check_text)
    if patch_apply:
        payload = {
            "status": "failed",
            "reason": str(patch_apply.get("reason") or "").strip(),
            "targets": targets,
            "log_artifacts": sources,
        }
        hint = str(patch_apply.get("hint") or "").strip()
        if hint:
            payload["hint"] = hint
        return payload

    combined_errors: List[Dict[str, Any]] = []
    try:
        if build_text:
            combined_errors.extend(iter_compiler_errors(build_text, snippet_lines=0))
        if check_text:
            combined_errors.extend(iter_compiler_errors(check_text, snippet_lines=0))
    except Exception as exc:  # noqa: BLE001
        return {"status": "unknown", "reason": f"Failed to parse logs: {exc}", "log_artifacts": sources}

    if not combined_errors:
        noncompiler = _ossfuzz_non_compiler_failure_from_output(out, build_text=build_text, check_text=check_text)
        if noncompiler:
            kind = str(noncompiler.get("kind", "") or "").strip()
            reason = str(noncompiler.get("reason", "") or "").strip()
            if not reason:
                reason = "OSS-Fuzz reported failure without compiler errors."
            payload: Dict[str, Any] = {
                "status": "failed",
                "reason": reason,
                "targets": targets,
                "log_artifacts": sources,
            }
            if kind == "build":
                payload["hint"] = "OSS-Fuzz failed without emitting compiler diagnostics; inspect build/check_build logs and ensure the build environment is healthy."
            elif kind == "patch_apply":
                payload["hint"] = "OSS-Fuzz reported a patch-apply failure; regenerate a complete unified diff override and retry."
            return payload

    def same_file(a: str, b: str) -> bool:
        a_s = str(a or "").strip()
        b_s = str(b or "").strip()
        if not a_s or not b_s:
            return False
        if a_s == b_s:
            return True
        return Path(a_s).name == Path(b_s).name

    bundle: Any = None
    bundle_err: Optional[str] = None
    get_error_patch_from_bundle: Any = None
    mapping_cache: Dict[tuple[str, int], Dict[str, Any]] = {}

    def mapping_for_error(file_path: str, line_number: int) -> Dict[str, Any]:
        nonlocal bundle, bundle_err, get_error_patch_from_bundle
        fp = str(file_path or "").strip()
        ln = int(line_number or 0)
        if not (state.patch_path and fp and ln > 0):
            return {}
        cache_key = (fp, ln)
        cached = mapping_cache.get(cache_key)
        if isinstance(cached, dict):
            return cached
        if bundle_err is not None:
            mapping_cache[cache_key] = {}
            return {}
        try:
            if bundle is None:
                bundle, bundle_err2 = _load_effective_patch_bundle_for_mapping(state)
                if bundle_err2 or bundle is None:
                    bundle_err = str(bundle_err2 or "Failed to load patch bundle.")
                    mapping_cache[cache_key] = {}
                    return {}
                script_dir = Path(__file__).resolve().parents[1]
                if str(script_dir) not in sys.path:
                    sys.path.insert(0, str(script_dir))
                from migration_tools.tools import _get_error_patch_from_bundle as _gepb  # type: ignore

                get_error_patch_from_bundle = _gepb
            mapping = get_error_patch_from_bundle(bundle, patch_path=state.patch_path, file_path=fp, line_number=ln)
            mapping_cache[cache_key] = mapping if isinstance(mapping, dict) else {}
            return mapping_cache[cache_key]
        except Exception as exc:  # noqa: BLE001
            bundle_err = f"{type(exc).__name__}: {exc}"
            mapping_cache[cache_key] = {}
            return {}

    def patch_key_for_error(file_path: str, line_number: int) -> str:
        mapping = mapping_for_error(file_path, line_number)
        if not isinstance(mapping, dict):
            return ""
        return str(mapping.get("patch_key") or "").strip()

    active_patch_key = str(getattr(state, "active_patch_key", "") or state.patch_key or "").strip()
    active_old_sig = str(getattr(state, "active_old_signature", "") or "").strip()
    if (
        state.error_scope == "patch"
        and state.patch_path
        and active_patch_key
        and active_old_sig
        and combined_errors
    ):
        remaining_in_active_func: List[Dict[str, Any]] = []
        for err in combined_errors:
            fp = str(err.get("file", "") or "").strip()
            ln = int(err.get("line", 0) or 0)
            msg = str(err.get("msg", "") or "").strip()
            if not fp or ln <= 0 or not msg:
                continue
            mapping = mapping_for_error(fp, ln)
            if not isinstance(mapping, dict):
                continue
            err_patch_key = str(mapping.get("patch_key") or "").strip()
            err_sig = str(mapping.get("old_signature") or "").strip()
            if err_patch_key != active_patch_key or err_sig != active_old_sig:
                continue
            remaining_in_active_func.append(
                {
                    "raw": err.get("raw", ""),
                    "file": fp,
                    "line": ln,
                    "patch_key": err_patch_key,
                    "old_signature": err_sig,
                    "msg": msg,
                }
            )

        fixed = len(remaining_in_active_func) == 0
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
            "matched_target_errors": remaining_in_active_func,
            "other_errors": other[:10],
            "log_artifacts": sources,
            "mapping_error": bundle_err,
            "target_mode": "active_old_signature",
            "active_patch_key": active_patch_key,
            "active_old_signature": active_old_sig,
        }

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


def _format_other_errors_for_next_step(other_errors: Any, *, limit: int = 5) -> List[str]:
    """Format compiler errors for inclusion in final.next_step (human-facing)."""
    out: List[str] = []
    lim = max(0, int(limit or 0))
    for item in other_errors or []:
        if lim and len(out) >= lim:
            break
        if not isinstance(item, dict):
            continue
        raw = str(item.get("raw", "") or "").strip()
        if not raw:
            continue
        patch_key = str(item.get("patch_key", "") or "").strip()
        suffix = f" (patch_key={patch_key})" if patch_key else ""
        out.append(f"- {raw}{suffix}")
    return out


def _ossfuzz_artifact_path(output: Any, field: str) -> str:
    if not isinstance(output, dict):
        return ""
    v = output.get(field)
    if isinstance(v, dict):
        return str(v.get("artifact_path", "") or "").strip()
    if isinstance(v, str):
        return v.strip()
    return ""


_OSSFUZZ_INFRA_ERR_PREFIX = "OSS-Fuzz infra error:"
_OSSFUZZ_PATCH_APPLY_ERR_PREFIX = "OSS-Fuzz patch apply error:"
_OSSFUZZ_BUILD_ERR_PREFIX = "OSS-Fuzz build failed:"


_OSSFUZZ_PATCH_APPLY_ERROR_PATTERNS = [
    re.compile(r"^error:\s+corrupt patch(?:\s+at\s+line\s+\d+)?\s*$", re.IGNORECASE),
    re.compile(r"^error:\s+patch failed:\s+.*$", re.IGNORECASE),
    re.compile(r"^error:\s+.*:\s+patch does not apply\s*$", re.IGNORECASE),
    re.compile(r"^error:\s+no valid patches in input.*$", re.IGNORECASE),
    re.compile(r"^patch:\s+\*{4}.*$", re.IGNORECASE),
    re.compile(r"^fatal:\s+patch failed.*$", re.IGNORECASE),
]


def _ossfuzz_patch_apply_failure_reason(text: str) -> Optional[Dict[str, str]]:
    raw = str(text or "")
    if not raw.strip():
        return None

    hit: Optional[str] = None
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        for pat in _OSSFUZZ_PATCH_APPLY_ERROR_PATTERNS:
            if pat.search(stripped):
                hit = stripped
                break
        if hit:
            break

    if not hit:
        return None

    return {
        "reason": f"Patch failed to apply: {hit}",
        "hint": (
            "The override diff is malformed or truncated (e.g. missing lines in a large hunk). "
            "Regenerate the override diff and ensure it is a complete unified diff (diff --git/---/+++ plus full @@ hunks)."
        ),
    }


def _ossfuzz_infra_failure_reason(text: str) -> Optional[Dict[str, str]]:
    raw = str(text or "")
    if not raw.strip():
        return None
    lowered = raw.lower()
    if "/var/run/docker.sock" in raw and "permission denied" in lowered:
        return {
            "reason": "Docker permission denied (cannot connect to /var/run/docker.sock).",
            "hint": "Run with --ossfuzz-use-sudo or fix Docker permissions (e.g., add your user to the docker group).",
        }
    if "cannot connect to the docker daemon" in lowered:
        return {
            "reason": "Cannot connect to the Docker daemon.",
            "hint": "Ensure Docker is running and accessible (or run with --ossfuzz-use-sudo).",
        }
    if "docker: command not found" in lowered:
        return {
            "reason": "Docker command not found.",
            "hint": "Install Docker or ensure the docker CLI is available in PATH.",
        }
    return None


_OSSFUZZ_NONCOMPILER_FAILURE_LINE_RE = re.compile(
    r"(?:\berror\b|fatal\b|failed\b|cannot\b|no such file\b|permission denied\b|traceback\b|exception\b)",
    re.IGNORECASE,
)


def _pick_ossfuzz_failure_line(blob: str) -> str:
    """Best-effort pick a single non-empty line that explains a failure (non-compiler errors included)."""
    lines = [str(l).strip() for l in str(blob or "").splitlines() if str(l).strip()]
    if not lines:
        return ""
    for line in reversed(lines):
        if _OSSFUZZ_NONCOMPILER_FAILURE_LINE_RE.search(line):
            return line
    return lines[-1]


def _ossfuzz_non_compiler_failure_from_output(
    output: Dict[str, Any], *, build_text: str, check_text: str
) -> Optional[Dict[str, str]]:
    """Return failure reason when OSS-Fuzz indicates failure but logs have no compiler diagnostics."""
    patch_apply_ok = output.get("patch_apply_ok")
    if isinstance(patch_apply_ok, bool) and patch_apply_ok is False:
        reason = str(output.get("patch_apply_error", "") or "").strip()
        if not reason:
            reason = _pick_ossfuzz_failure_line(build_text) or _pick_ossfuzz_failure_line(check_text) or "patch_apply_ok=false"
        return {"kind": "patch_apply", "reason": reason}

    build_ok = output.get("build_ok")
    check_ok = output.get("check_build_ok")
    failed_steps: List[str] = []
    if isinstance(build_ok, bool) and build_ok is False:
        failed_steps.append("build_version")
    if isinstance(check_ok, bool) and check_ok is False:
        failed_steps.append("check_build")
    if not failed_steps:
        return None

    hint = ""
    if "build_version" in failed_steps:
        hint = _pick_ossfuzz_failure_line(build_text)
    if not hint and "check_build" in failed_steps:
        hint = _pick_ossfuzz_failure_line(check_text)
    if not hint:
        hint = _pick_ossfuzz_failure_line(build_text) or _pick_ossfuzz_failure_line(check_text)

    reason = f"{', '.join(failed_steps)} failed"
    if hint:
        reason += f": {hint}"
    return {"kind": "build", "reason": reason}


def _ossfuzz_infra_failure(build_text: str, check_text: str) -> Optional[Dict[str, str]]:
    for blob in (build_text, check_text):
        hit = _ossfuzz_infra_failure_reason(blob)
        if hit:
            return hit
    return None


def _ossfuzz_patch_apply_failure(build_text: str, check_text: str) -> Optional[Dict[str, str]]:
    for blob in (build_text, check_text):
        hit = _ossfuzz_patch_apply_failure_reason(blob)
        if hit:
            return hit
    return None


def _read_ossfuzz_logs(output: Dict[str, Any]) -> tuple[str, str, List[str], Optional[str]]:
    build_path = _ossfuzz_artifact_path(output, "build_output")
    check_path = _ossfuzz_artifact_path(output, "check_build_output")
    if not build_path and not check_path:
        return "", "", [], "No build/check_build log artifacts found."

    sources: List[str] = []
    build_text = ""
    check_text = ""
    read_errors: List[str] = []
    if build_path:
        sources.append(build_path)
        try:
            build_text = _read_text(build_path)
        except Exception as exc:  # noqa: BLE001
            read_errors.append(f"Failed to read build log: {type(exc).__name__}: {exc}")
    if check_path:
        sources.append(check_path)
        try:
            check_text = _read_text(check_path)
        except Exception as exc:  # noqa: BLE001
            read_errors.append(f"Failed to read check_build log: {type(exc).__name__}: {exc}")

    if read_errors and not (build_text or check_text):
        return "", "", sources, "; ".join(read_errors)
    return build_text, check_text, sources, ("; ".join(read_errors) if read_errors else None)


def _reindex_patch_bundle(bundle: Any) -> Any:
    patches = getattr(bundle, "patches", None)
    if not isinstance(patches, dict):
        return bundle

    hunk_re = re.compile(r"^@@ -(?P<old_start>\\d+)(?:,(?P<old_len>\\d+))? \\+(?P<new_start>\\d+)(?:,(?P<new_len>\\d+))? @@")

    def new_start_for(key: str) -> int:
        p = patches.get(key)
        if p is None:
            return 0
        text = str(getattr(p, "patch_text", "") or "")
        for line in text.splitlines():
            if not line.startswith("@@"):
                continue
            m = hunk_re.match(line.strip())
            if not m:
                continue
            try:
                return int(m.group("new_start"))
            except Exception:
                return 0
        try:
            return int(getattr(p, "new_start_line", 0) or 0)
        except Exception:
            return 0

    keys_sorted = sorted(patches.keys(), key=lambda k: (-new_start_for(k), str(k)))
    by_file_new: Dict[str, list[str]] = {}
    by_patch_type: Dict[str, list[str]] = {}
    by_signature: Dict[str, list[str]] = {}

    for key in keys_sorted:
        patch = patches[key]
        file_new = str(getattr(patch, "file_path_new", "") or "")
        by_file_new.setdefault(file_new, []).append(key)
        for pt in sorted(getattr(patch, "patch_type", None) or set()):
            by_patch_type.setdefault(str(pt), []).append(key)
        for sig in (getattr(patch, "old_signature", None), getattr(patch, "new_signature", None)):
            if sig:
                by_signature.setdefault(str(sig), []).append(key)

    try:
        return replace(bundle, keys_sorted=keys_sorted, by_file_new=by_file_new, by_patch_type=by_patch_type, by_signature=by_signature)
    except Exception:
        return bundle


_SAFE_BUNDLE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_DIFF_HUNK_HDR_RE = re.compile(r"^@@ -(?P<old_start>\d+)(?:,(?P<old_len>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_len>\d+))? @@")
_COMMITISH_RE = re.compile(r"[0-9a-fA-F]{5,40}")


def _infer_commitish_from_path(path: str) -> str:
    """Best-effort infer a git commit-ish from a directory name like `project-<sha>`."""
    name = str(Path(str(path or "")).name or "").strip()
    if not name:
        return ""
    matches = _COMMITISH_RE.findall(name)
    if not matches:
        return ""
    return str(matches[-1]).strip()


def _safe_bundle_name(name: str, *, max_len: int = 160) -> str:
    raw = str(name or "").strip().replace(os.sep, "_")
    cleaned = _SAFE_BUNDLE_NAME_RE.sub("_", raw).strip("._-")
    if not cleaned:
        cleaned = "artifact"
    return cleaned[:max_len]


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
    raise RuntimeError(f"Could not allocate unique path for: {path}")


def _enforce_patch_key_scope(state: AgentState, obs: ToolObservation) -> ToolObservation:
    """Prevent patch-scope runs from drifting across patch_keys.

    In patch-aware mode, multi-agent runs execute one agent per patch_key and store artifacts under
    `.../<patch_key>/`. If the model calls get_error_patch_context/make_error_patch_override for a
    different patch_key mid-run, the resulting override diff is written under the wrong directory
    and later applied to the wrong patch entry during the final merge.

    This helper converts such cross-patch_key tool outputs into errors so the model can recover
    without mutating state.
    """
    pinned = str(getattr(state, "patch_key", "") or "").strip()
    if state.error_scope != "patch" or not pinned:
        return obs
    if not obs.ok:
        return obs
    if obs.tool not in {"get_error_patch_context", "make_error_patch_override"}:
        return obs
    if not isinstance(obs.output, dict):
        return obs

    observed = str(obs.output.get("patch_key", "") or "").strip()
    if not observed or observed == pinned:
        return obs

    fp = str(obs.output.get("file_path", "") or obs.args.get("file_path", "") or "").strip()
    ln = obs.output.get("line_number") if isinstance(obs.output.get("line_number"), int) else obs.args.get("line_number")
    loc = f"{fp}:{ln}" if fp and ln else fp or ""
    msg = (
        f"Out of scope for this run: requested location {loc or '<unknown>'} maps to patch_key={observed!r}, "
        f"but this agent run is pinned to patch_key={pinned!r}. "
        "Do not switch patch_keys mid-run; pick an error location within the pinned patch_key "
        f"or rerun with --focus-patch-key {observed}."
    )
    slim_output: Dict[str, Any] = {"patch_key": observed}
    if fp:
        slim_output["file_path"] = fp
    if ln:
        slim_output["line_number"] = ln
    sig = str(obs.output.get("old_signature", "") or "").strip()
    if sig:
        slim_output["old_signature"] = sig
    return ToolObservation(False, obs.tool, obs.args, output=slim_output, error=msg)


_PATCH_TOOLS_WITH_PATCH_PATH: set[str] = {
    "list_patch_bundle",
    "get_patch",
    "search_patches",
    "get_error_patch",
    "get_error_patch_context",
    "make_extra_patch_override",
    "make_error_patch_override",
}


def _update_patchinfo_ranges_from_diff(patch: Any, patch_text: str) -> None:
    old_starts: List[int] = []
    old_ends: List[int] = []
    new_starts: List[int] = []
    new_ends: List[int] = []
    for line in str(patch_text or "").splitlines():
        if not line.startswith("@@"):
            continue
        m = _DIFF_HUNK_HDR_RE.match(line.strip())
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


def _write_effective_patch_bundle(
    state: AgentState,
    *,
    patch_key: str,
    patch_text: str,
    hiden_func_dict_updated: Any = None,
) -> tuple[str, Optional[str]]:
    """Persist an updated *.patch2 bundle with a single patch_key entry replaced.

    This keeps merged/tail metadata (notably hiden_func_dict + hunk line ranges) in sync with the
    rewritten patch_text so subsequent error→function mapping remains correct after line shifts.
    """
    src_patch_path = str(state.patch_path or "").strip()
    key = str(patch_key or "").strip()
    text = str(patch_text or "")
    if not src_patch_path:
        return "", "missing patch_path"
    if not key:
        return "", "missing patch_key"
    if not text.strip():
        return "", "missing patch_text"

    script_dir = Path(__file__).resolve().parents[1]
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))

    try:
        from migration_tools.patch_bundle import load_patch_bundle as _lpb  # type: ignore
    except Exception as exc:  # noqa: BLE001
        return "", f"failed to import patch_bundle: {type(exc).__name__}: {exc}"

    try:
        bundle = _lpb(src_patch_path, allowed_roots=_allowed_patch_roots_from_env())
    except Exception as exc:  # noqa: BLE001
        return "", f"failed to load patch bundle: {type(exc).__name__}: {exc}"

    patches = getattr(bundle, "patches", None)
    if not isinstance(patches, dict):
        return "", "patch bundle has invalid patches map"
    if key not in patches:
        if not key.startswith("_extra_"):
            return "", f"unknown patch_key in bundle: {key}"

        def parse_diff_paths(text: str) -> tuple[str, str]:
            old_fp = ""
            new_fp = ""
            for line in str(text or "").splitlines():
                if line.startswith("diff --git "):
                    m = re.match(r"^diff --git a/(?P<old>\\S+) b/(?P<new>\\S+)$", line.strip())
                    if m:
                        old_fp = str(m.group("old") or "")
                        new_fp = str(m.group("new") or "")
                        break
            if old_fp and new_fp:
                return old_fp, new_fp
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
            return old_fp, new_fp

        old_fp, new_fp = parse_diff_paths(text)
        new_fp = str(new_fp or "").strip()
        old_fp = str(old_fp or "").strip() or new_fp
        if not new_fp or new_fp == "/dev/null":
            return "", f"cannot create new patch_key without file paths: {key}"

        try:
            from migration_tools.types import PatchInfo  # type: ignore
        except Exception as exc:  # noqa: BLE001
            return "", f"failed to import PatchInfo: {type(exc).__name__}: {exc}"

        suffix = Path(new_fp).suffix.lower()
        file_type = suffix.lstrip(".") if suffix else "unknown"
        patches[key] = PatchInfo(
            file_path_old=old_fp,
            file_path_new=new_fp,
            patch_text="",
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

    patch_obj = patches[key]
    patch_obj.patch_text = text.rstrip("\n") + "\n"

    if isinstance(hiden_func_dict_updated, dict):
        try:
            patch_obj.hiden_func_dict = {str(k): int(v) for k, v in hiden_func_dict_updated.items()}
        except Exception:
            pass

    _update_patchinfo_ranges_from_diff(patch_obj, patch_obj.patch_text)

    src_path = Path(src_patch_path).expanduser().resolve()
    safe_key = _safe_bundle_name(key, max_len=160)

    artifacts_dir_raw = str(getattr(state, "artifacts_dir", "") or "").strip()
    if artifacts_dir_raw:
        out_dir = Path(artifacts_dir_raw).expanduser().resolve()
        if safe_key not in out_dir.parts and out_dir.name != safe_key:
            out_dir = (out_dir / safe_key).resolve()
    else:
        repo_root = Path(__file__).resolve().parents[2]
        out_dir = (repo_root / "data" / "react_agent_artifacts" / safe_key).resolve()

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception as exc:  # noqa: BLE001
        return "", f"failed to create effective bundle dir: {type(exc).__name__}: {exc}"

    stem = src_path.stem or "bundle"
    # Normalize repeated ".effective" suffix chains from earlier iterations:
    # e.g. "libxml2.effective.1.effective.1" -> "libxml2".
    while True:
        m = re.match(r"^(?P<base>.*)\.effective(?:\.\d+)?$", stem)
        if not m:
            break
        stem = str(m.group("base") or "")
    base_name = f"{stem}.effective.patch2"
    out_path = _unique_path((out_dir / base_name).resolve())

    try:
        import pickle  # noqa: PLC0415

        out_path.write_bytes(pickle.dumps(dict(bundle.patches), protocol=pickle.HIGHEST_PROTOCOL))
    except Exception as exc:  # noqa: BLE001
        return "", f"failed to write effective patch bundle: {type(exc).__name__}: {exc}"

    return str(out_path), None


def _load_effective_patch_bundle_for_mapping(state: AgentState) -> tuple[Any | None, Optional[str]]:
    """Load the patch bundle, optionally overlaying the latest override patch_text for active_patch_key."""
    if not state.patch_path:
        return None, "missing patch_path"

    script_dir = Path(__file__).resolve().parents[1]
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))

    try:
        from migration_tools.patch_bundle import load_patch_bundle as _lpb  # type: ignore
    except Exception as exc:  # noqa: BLE001
        return None, f"failed to import patch_bundle: {type(exc).__name__}: {exc}"

    try:
        bundle = _lpb(state.patch_path, allowed_roots=_allowed_patch_roots_from_env())
    except Exception as exc:  # noqa: BLE001
        return None, f"failed to load patch bundle: {type(exc).__name__}: {exc}"

    active_key = str(state.active_patch_key or state.patch_key or "").strip()
    override_path = str((state.patch_override_paths[-1] if state.patch_override_paths else "") or "").strip()
    if active_key and override_path and isinstance(getattr(bundle, "patches", None), dict) and active_key in bundle.patches:
        try:
            override_text = _read_text(override_path)
            if override_text.strip():
                bundle.patches[active_key].patch_text = override_text
        except Exception:
            pass

    # If make_error_patch_override returned an updated merged/tail offset map, overlay it as well so
    # error→function mapping stays correct even when the bundle on disk hasn't been rewritten yet.
    if active_key and isinstance(getattr(bundle, "patches", None), dict) and active_key in bundle.patches:
        updated = state.patch_result.get("hiden_func_dict_updated") if isinstance(state.patch_result, dict) else None
        if isinstance(updated, dict):
            try:
                bundle.patches[active_key].hiden_func_dict = {str(k): int(v) for k, v in updated.items()}
            except Exception:
                pass

    bundle = _reindex_patch_bundle(bundle)
    return bundle, None


def _iter_ossfuzz_compiler_errors(state: AgentState) -> tuple[List[Dict[str, Any]], List[str], Optional[str]]:
    obs = state.last_observation
    out = obs.output if isinstance(obs, ToolObservation) else None
    if not isinstance(out, dict):
        return [], [], "Missing OSS-Fuzz tool output."

    build_text, check_text, sources, read_err = _read_ossfuzz_logs(out)
    if not build_text and not check_text:
        return [], sources, read_err or "Empty OSS-Fuzz logs."

    infra = _ossfuzz_infra_failure(build_text, check_text)
    if infra:
        reason = str(infra.get("reason") or "").strip()
        hint = str(infra.get("hint") or "").strip()
        msg = f"{_OSSFUZZ_INFRA_ERR_PREFIX} {reason}".strip()
        if hint:
            msg += f" Hint: {hint}"
        return [], sources, msg

    patch_apply = _ossfuzz_patch_apply_failure(build_text, check_text)
    if patch_apply:
        reason = str(patch_apply.get("reason") or "").strip()
        hint = str(patch_apply.get("hint") or "").strip()
        msg = f"{_OSSFUZZ_PATCH_APPLY_ERR_PREFIX} {reason}".strip()
        if hint:
            msg += f" Hint: {hint}"
        return [], sources, msg

    combined_errors: List[Dict[str, Any]] = []
    try:
        if build_text:
            combined_errors.extend(iter_compiler_errors(build_text, snippet_lines=2))
        if check_text:
            combined_errors.extend(iter_compiler_errors(check_text, snippet_lines=2))
    except Exception as exc:  # noqa: BLE001
        return [], sources, f"Failed to parse OSS-Fuzz logs: {type(exc).__name__}: {exc}"

    # De-dup across build/check_build while preserving order.
    seen: set[tuple[str, int, int, str]] = set()
    deduped: List[Dict[str, Any]] = []
    for err in combined_errors:
        fp = str(err.get("file", "") or "").strip()
        ln = int(err.get("line", 0) or 0)
        col = int(err.get("col", 0) or 0)
        msg = str(err.get("msg", "") or "").strip()
        if not fp or ln <= 0 or not msg:
            continue
        key = (fp, ln, col, msg)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(err)

    # OSS-Fuzz can fail without emitting compiler diagnostics (e.g. build script errors).
    # Do not treat an empty compiler-error set as "clean" when OSS-Fuzz indicates failure.
    if not deduped:
        noncompiler = _ossfuzz_non_compiler_failure_from_output(out, build_text=build_text, check_text=check_text)
        if noncompiler:
            kind = str(noncompiler.get("kind", "") or "").strip()
            reason = str(noncompiler.get("reason", "") or "").strip()
            if not reason:
                reason = "OSS-Fuzz reported failure without compiler errors."
            prefix = _OSSFUZZ_PATCH_APPLY_ERR_PREFIX if kind == "patch_apply" else _OSSFUZZ_BUILD_ERR_PREFIX
            return [], sources, f"{prefix} {reason}".strip()

    return deduped, sources, None


def _summarize_active_patch_key_status(state: AgentState) -> Dict[str, Any]:
    """Summarize whether compiler errors remain for the active patch_key after the last OSS-Fuzz run."""
    active_key = str(state.active_patch_key or state.patch_key or "").strip()
    errors, sources, err_msg = _iter_ossfuzz_compiler_errors(state)
    if err_msg:
        msg = str(err_msg).strip()
        status = (
            "failed"
            if msg.startswith(_OSSFUZZ_INFRA_ERR_PREFIX)
            or msg.startswith(_OSSFUZZ_PATCH_APPLY_ERR_PREFIX)
            or msg.startswith(_OSSFUZZ_BUILD_ERR_PREFIX)
            else "unknown"
        )
        return {
            "status": status,
            "reason": err_msg,
            "active_patch_key": active_key,
            "log_artifacts": sources,
            "ossfuzz_runs_attempted": int(state.ossfuzz_runs_attempted or 0),
        }
    if not errors:
        return {
            "status": "ok",
            "active_patch_key": active_key,
            "remaining_in_active_patch_key": 0,
            "errors": [],
            "log_artifacts": sources,
            "ossfuzz_runs_attempted": int(state.ossfuzz_runs_attempted or 0),
        }

    bundle, bundle_err = _load_effective_patch_bundle_for_mapping(state)
    if bundle_err or bundle is None:
        return {
            "status": "unknown",
            "reason": bundle_err or "Failed to load patch bundle.",
            "active_patch_key": active_key,
            "log_artifacts": sources,
            "ossfuzz_runs_attempted": int(state.ossfuzz_runs_attempted or 0),
        }

    try:
        from migration_tools.tools import _get_error_patch_from_bundle as _gepb  # type: ignore
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "unknown",
            "reason": f"Failed to import mapping helper: {type(exc).__name__}: {exc}",
            "active_patch_key": active_key,
            "log_artifacts": sources,
            "ossfuzz_runs_attempted": int(state.ossfuzz_runs_attempted or 0),
        }

    mapping_error: Optional[str] = None
    enriched: List[Dict[str, Any]] = []
    for e in errors:
        fp = str(e.get("file", "") or "").strip()
        ln = int(e.get("line", 0) or 0)
        if not fp or ln <= 0:
            continue
        patch_key = ""
        try:
            mapping = _gepb(bundle, patch_path=state.patch_path, file_path=fp, line_number=ln)
            patch_key = str((mapping or {}).get("patch_key") or "").strip()
        except Exception as exc:  # noqa: BLE001
            if mapping_error is None:
                mapping_error = f"{type(exc).__name__}: {exc}"
        item = {
            "raw": str(e.get("raw", "") or "").strip(),
            "file": fp,
            "line": ln,
            "col": int(e.get("col", 0) or 0),
            "msg": str(e.get("msg", "") or "").strip(),
            "patch_key": patch_key,
        }
        if item["raw"]:
            enriched.append(item)

    in_active = [e for e in enriched if str(e.get("patch_key", "") or "").strip() == active_key] if active_key else []
    func_groups, func_total, func_trunc = _summarize_function_groups(in_active)
    return {
        "status": "ok",
        "active_patch_key": active_key,
        "remaining_in_active_patch_key": len(in_active),
        "errors": in_active[:10],
        "function_groups": func_groups,
        "function_groups_total": func_total,
        "function_groups_truncated": func_trunc,
        "log_artifacts": sources,
        "mapping_error": mapping_error,
        "ossfuzz_runs_attempted": int(state.ossfuzz_runs_attempted or 0),
    }


def _extract_minus_slice_from_patch_text(*, patch_text: str, func_start_index: int, func_end_index: int) -> str:
    patch_lines = str(patch_text or "").splitlines()
    if not patch_lines:
        return ""
    first_hunk_idx = next((i for i, l in enumerate(patch_lines) if l.startswith("@@")), -1)
    body_start = first_hunk_idx + 1 if first_hunk_idx >= 0 else 4
    body_len = max(len(patch_lines) - body_start, 0)
    fs = max(0, min(int(func_start_index), body_len))
    fe = max(0, min(int(func_end_index), body_len))
    if fe <= fs:
        return ""
    slice_lines = patch_lines[body_start + fs : body_start + fe]
    minus_lines = [line[1:] for line in slice_lines if line.startswith("-")]
    return "\n".join(minus_lines).rstrip("\n")


def _prepare_next_patch_scope_iteration_after_ossfuzz(
    state: AgentState,
    cfg: AgentConfig,
    *,
    artifact_store: Any = None,
) -> Optional[Decision]:
    """If auto-loop is enabled and errors remain in the active patch_key, restart patch-scope triage for the next error.

    Strategy: treat each loop iteration like a fresh patch-scope run using:
      - patch_path = latest effective *.patch2 bundle
      - build error = next compiler error from the latest OSS-Fuzz logs

    Then force get_error_patch_context as the first tool call to refresh mapping + BASE slice artifacts.
    """
    if not cfg.auto_ossfuzz_loop:
        return None
    if state.error_scope != "patch":
        return None
    if state.ossfuzz_runs_attempted >= max(int(cfg.ossfuzz_loop_max or 0), 1):
        return None
    if not state.patch_path:
        return None

    active_key = str(state.active_patch_key or state.patch_key or "").strip()
    if not active_key:
        return None

    errors, sources, err_msg = _iter_ossfuzz_compiler_errors(state)
    if err_msg:
        return None
    if not errors:
        return None

    bundle, bundle_err = _load_effective_patch_bundle_for_mapping(state)
    if bundle_err or bundle is None:
        return None

    try:
        from migration_tools.tools import _get_error_patch_from_bundle as _gepb  # type: ignore
    except Exception:
        return None

    enriched: List[Dict[str, Any]] = []
    for e in errors:
        fp = str(e.get("file", "") or "").strip()
        ln = int(e.get("line", 0) or 0)
        if not fp or ln <= 0:
            continue
        try:
            mapping = _gepb(bundle, patch_path=state.patch_path, file_path=fp, line_number=ln)
        except Exception:
            mapping = {}
        patch_key = str((mapping or {}).get("patch_key") or "").strip()
        item = dict(e)
        if patch_key:
            item["patch_key"] = patch_key
        if isinstance(mapping, dict):
            for k in ("old_signature", "func_start_index", "func_end_index"):
                if k in mapping:
                    item[k] = mapping.get(k)
        enriched.append(item)

    in_active = _prioritize_warnings_within_hunk(
        [e for e in enriched if str(e.get("patch_key", "") or "").strip() == active_key]
    )
    if not in_active:
        return None

    func_groups, func_total, func_trunc = _summarize_function_groups(in_active)
    state.function_groups = func_groups
    state.function_groups_total = func_total
    state.function_groups_truncated = func_trunc
    _update_function_error_history(state, in_active)

    _record_current_error_group(state)

    preferred_sig = str(getattr(state, "active_old_signature", "") or "").strip()
    if not preferred_sig and state.grouped_errors:
        preferred_sig = str(state.grouped_errors[0].get("old_signature", "") or "").strip()

    selected, chosen_sig = _select_function_group_errors(in_active, preferred_old_signature=preferred_sig)
    if chosen_sig:
        state.active_old_signature = chosen_sig
    if not selected:
        return None

    next_err = selected[0]
    state.grouped_errors = selected[:10]
    state.error_line = str(next_err.get("raw", "") or "").strip() or state.error_line
    state.snippet = str(next_err.get("snippet", "") or "").rstrip("\n") or state.snippet
    state.target_errors = _extract_target_errors(
        error_line=state.error_line, grouped_errors=state.grouped_errors, patch_key=active_key
    )
    _record_current_error_group(state)

    # Refresh missing-member summary for this iteration (bounded output).
    state.missing_struct_members = []
    try:
        from tools.migration_tools import parse_build_errors as parse_build_errors_tool  # noqa: PLC0415

        raw_block = "\n".join(str(e.get("raw", "")).strip() for e in state.grouped_errors if e.get("raw"))
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
                max_structs = 8
                max_members = 12
                out: List[Dict[str, Any]] = []
                for struct_name in sorted(by_struct.keys())[:max_structs]:
                    members = sorted(by_struct[struct_name])[:max_members]
                    out.append({"struct": struct_name, "members": members})
                state.missing_struct_members = out
    except Exception:
        state.missing_struct_members = []

    # Clear macro guardrail state across iterations to avoid drift.
    state.macro_tokens_not_defined_in_slice = []
    state.macro_lookup = None

    # Update the active build-error location for guardrails and for the forced get_error_patch_context.
    fp = str(next_err.get("file", "") or "").strip()
    ln = int(next_err.get("line", 0) or 0)
    if fp and ln > 0:
        state.active_file_path = fp
        state.active_line_number = ln

    # Ensure active_old_signature matches the selected error, even when only one signature remains.
    sig = str(next_err.get("old_signature", "") or "").strip()
    if sig:
        state.active_old_signature = sig

    # Treat the latest OSS-Fuzz build output as the new "build log" for this round (for display/debugging).
    build_log_path = sources[0] if sources else ""
    try:
        obs_out = state.last_observation.output if isinstance(state.last_observation, ToolObservation) else None
        if isinstance(obs_out, dict):
            build_log_path = _ossfuzz_artifact_path(obs_out, "build_output") or build_log_path
    except Exception:
        build_log_path = build_log_path
    if build_log_path:
        state.build_log_path = build_log_path

    # Clear per-round patch context artifacts so we re-run patch-context tools like the first round.
    state.active_func_start_index = None
    state.active_func_end_index = None
    state.active_excerpt_artifact_path = ""
    state.active_patch_minus_code_artifact_path = ""
    state.active_error_func_code_artifact_path = ""
    state.loop_base_func_code_artifact_path = ""
    state.pending_patch = None

    # Drop most prior context before restarting the triage loop.
    state.steps = []

    # Reset patch/test state for the next iteration.
    state.patch_generated = False
    state.patch_result = None
    state.patch_override_paths = []
    state.ossfuzz_test_attempted = False
    state.last_observation = None

    if not fp or ln <= 0:
        return None

    err_text = str(next_err.get("msg", "") or "").strip() or str(state.error_line or "")[:400]
    forced: Decision = {
        "type": "tool",
        "thought": (
            f"Auto-loop restart: start next round from latest OSS-Fuzz logs and the updated patch bundle; refresh patch context for {fp}:{ln}."
        ),
        "tool": "get_error_patch_context",
        "args": {
            "patch_path": state.patch_path,
            "file_path": fp,
            "line_number": ln,
            "error_text": err_text,
            "context_lines": 200,
            "max_total_lines": 8000,
        },
    }
    return forced


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


_CODE_FENCE_RE = re.compile(r"```(?:[A-Za-z0-9_+-]+)?\n(.*?)```", re.DOTALL)


def _extract_first_code_fence(text: str) -> str:
    """Return the first fenced code block if present, otherwise return the raw text."""
    raw = str(text or "")
    if "```" not in raw:
        return raw
    m = _CODE_FENCE_RE.search(raw)
    if not m:
        return raw
    return str(m.group(1) or "")


def _extract_function_name_from_signature(signature: str) -> str:
    s = str(signature or "").strip()
    if not s:
        return ""
    open_paren = s.find("(")
    if open_paren <= 0:
        return ""
    j = open_paren - 1
    while j >= 0 and s[j].isspace():
        j -= 1
    end = j
    while j >= 0 and (s[j].isalnum() or s[j] == "_"):
        j -= 1
    return s[j + 1 : end + 1]


def _count_top_level_bodies(code: str) -> tuple[int, bool]:
    """Count top-level bodies that look like `) {` and detect extra decls before the first body.

    This is a heuristic to catch "new_func_code contains the entire hunk" in function-by-function mode.

    Returns:
      (body_count, semicolon_before_first_body)
    """
    text = str(code or "").replace("\r\n", "\n").replace("\r", "\n")
    brace_depth = 0
    bodies = 0
    saw_semicolon_before_first = False

    in_sl_comment = False
    in_ml_comment = False
    in_str = False
    in_char = False
    escape = False
    at_line_start = True
    last_sig_char: Optional[str] = None

    i = 0
    while i < len(text):
        c = text[i]
        n = text[i + 1] if i + 1 < len(text) else ""

        if in_sl_comment:
            if c == "\n":
                in_sl_comment = False
                at_line_start = True
            i += 1
            continue
        if in_ml_comment:
            if c == "*" and n == "/":
                in_ml_comment = False
                i += 2
                continue
            if c == "\n":
                at_line_start = True
            i += 1
            continue
        if in_str:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_str = False
            if c == "\n":
                at_line_start = True
            i += 1
            continue
        if in_char:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == "'":
                in_char = False
            if c == "\n":
                at_line_start = True
            i += 1
            continue

        # Skip preprocessor directive lines at top level to avoid counting macro bodies.
        if at_line_start and brace_depth == 0:
            j = i
            while j < len(text) and text[j] in " \t":
                j += 1
            if j < len(text) and text[j] == "#":
                nl = text.find("\n", j)
                if nl < 0:
                    break
                i = nl + 1
                at_line_start = True
                last_sig_char = None
                continue

        if c == "/" and n == "/":
            in_sl_comment = True
            i += 2
            continue
        if c == "/" and n == "*":
            in_ml_comment = True
            i += 2
            continue
        if c == '"':
            in_str = True
            escape = False
            i += 1
            continue
        if c == "'":
            in_char = True
            escape = False
            i += 1
            continue

        if c == "\n":
            at_line_start = True
            i += 1
            continue
        if c not in " \t\r":
            at_line_start = False

        if c == "{":
            if brace_depth == 0 and last_sig_char == ")":
                bodies += 1
            brace_depth += 1
            last_sig_char = "{"
            i += 1
            continue
        if c == "}":
            if brace_depth > 0:
                brace_depth -= 1
            last_sig_char = "}"
            i += 1
            continue

        if brace_depth == 0 and c == ";":
            if bodies == 0:
                saw_semicolon_before_first = True
            last_sig_char = ";"
            i += 1
            continue

        if brace_depth == 0 and not c.isspace():
            last_sig_char = c
        i += 1

    return bodies, saw_semicolon_before_first


def _last_read_artifact_text(state: AgentState) -> str:
    for step in reversed(state.steps):
        if not isinstance(step, dict):
            continue
        obs = step.get("observation")
        if not isinstance(obs, dict) or obs.get("ok") is not True:
            continue
        if str(obs.get("tool", "")).strip() != "read_artifact":
            continue
        out = obs.get("output")
        if isinstance(out, dict):
            text = out.get("text")
            if isinstance(text, str) and text:
                return text
    return ""


def _override_preserve_base_guardrail_error(state: AgentState, decision: Decision) -> Optional[str]:
    """Return an error message if new_func_code drops too much of the mapped '-' slice baseline.

    For merged/tail hunks, the "BASE slice" must be the mapped function slice (error_func_code / loop_base slice),
    not the entire hunk/patch text, otherwise a correct per-function rewrite would be flagged as "too short".
    """
    if str(decision.get("type", "")).strip() != "tool":
        return None
    if str(decision.get("tool", "")).strip() != "make_error_patch_override":
        return None

    base_text = ""
    base_source = ""

    loop_base_path = str(getattr(state, "loop_base_func_code_artifact_path", "") or "").strip()
    if loop_base_path:
        try:
            base_text = _read_text(loop_base_path)
            base_source = "loop_base_func_code_artifact_path"
        except Exception:
            base_text = ""

    if not base_text.strip():
        err_func_path = str(getattr(state, "active_error_func_code_artifact_path", "") or "").strip()
        if err_func_path:
            try:
                base_text = _read_text(err_func_path)
                base_source = "get_error_patch_context.error_func_code"
            except Exception:
                base_text = ""

    if not base_text.strip():
        base_text = _last_read_artifact_text(state)
        base_source = "read_artifact"

    if not base_text.strip():
        return None

    args_obj = decision.get("args") if isinstance(decision.get("args"), dict) else {}
    new_raw = str(args_obj.get("new_func_code", "") or "")
    new_text = _extract_first_code_fence(new_raw).replace("\r\n", "\n").replace("\r", "\n")
    if not new_text.strip():
        return "new_func_code is empty."

    base_lines = [ln.rstrip() for ln in base_text.replace("\r\n", "\n").replace("\r", "\n").splitlines()]
    new_lines = [ln.rstrip() for ln in new_text.splitlines()]
    base_n = len(base_lines)
    new_n = len(new_lines)
    if base_n <= 0 or new_n <= 0:
        return None

    base_tail = [ln for ln in base_lines if ln.strip()]
    base_tail = base_tail[-6:] if len(base_tail) >= 6 else base_tail
    if base_tail:
        hits = sum(1 for ln in base_tail if ln and ln in new_text)
        if hits < min(2, len(base_tail)):
            return (
                f"new_func_code does not appear to include the tail of the mapped '-' slice baseline ({base_source}). "
                "If you intend a minimal edit, start from the baseline slice and apply minimal edits."
            )

    return None


def _override_single_function_guardrail_error(state: AgentState, decision: Decision) -> Optional[str]:
    """Return an error message if new_func_code looks like it rewrites more than the active slice.

    For merged/tail hunks, the BASE slice may be a full function body or just a small mapped fragment. The goal is
    to prevent the model from pasting the entire patch/hunk (multiple functions) into new_func_code.
    """
    if str(decision.get("type", "")).strip() != "tool":
        return None
    if str(decision.get("tool", "")).strip() != "make_error_patch_override":
        return None

    active_sig = str(getattr(state, "active_old_signature", "") or "").strip()
    if not active_sig:
        return None

    func_name = _extract_function_name_from_signature(active_sig)

    base_text = ""
    loop_base_path = str(getattr(state, "loop_base_func_code_artifact_path", "") or "").strip()
    if loop_base_path:
        try:
            base_text = _read_text(loop_base_path)
        except Exception:
            base_text = ""

    if not base_text.strip():
        err_func_path = str(getattr(state, "active_error_func_code_artifact_path", "") or "").strip()
        if err_func_path:
            try:
                base_text = _read_text(err_func_path)
            except Exception:
                base_text = ""

    if not base_text.strip():
        base_text = _last_read_artifact_text(state)

    args_obj = decision.get("args") if isinstance(decision.get("args"), dict) else {}
    new_raw = str(args_obj.get("new_func_code", "") or "")
    new_text = _extract_first_code_fence(new_raw).replace("\r\n", "\n").replace("\r", "\n")
    if not new_text.strip():
        return "new_func_code is empty."

    # Reject unified-diff content: make_error_patch_override expects raw code, not a diff.
    if (
        "diff --git " in new_text
        or "\n@@ " in new_text
        or "\n--- " in new_text
        or "\n+++ " in new_text
        or new_text.lstrip().startswith("--- ")
        or new_text.lstrip().startswith("+++ ")
    ):
        return "new_func_code appears to be a unified diff; provide only the raw mapped code slice (no diff headers)."

    new_bodies, new_semicolon_before_first = _count_top_level_bodies(new_text)

    base_bodies: Optional[int] = None
    if base_text.strip():
        base_bodies, _ = _count_top_level_bodies(base_text)

    # If we cannot infer the BASE slice (e.g. fake-tool tests), fall back to a generic guard:
    # do not allow multi-body overrides (common sign of pasting the whole hunk).
    if base_bodies is None:
        if new_bodies > 1:
            return (
                f"new_func_code appears to contain multiple top-level bodies ({new_bodies}). "
                "Do not paste the entire patch/hunk; rewrite only the mapped slice for this round."
            )
        return None

    # If the BASE slice has no top-level body (fragment rewrite), reject attempts that paste full function bodies / hunks.
    if base_bodies == 0:
        if new_bodies > 0:
            return (
                "The BASE slice for this override appears to be a small fragment (no top-level `) {` body). "
                "Do not paste whole functions or full hunks into new_func_code; rewrite only the mapped fragment."
            )
        return None

    # BASE slice has a top-level body (likely function-scoped rewrite); require the override to remain single-body.
    if new_bodies != 1:
        return (
            f"new_func_code appears to contain {new_bodies} top-level bodies, but the BASE slice contains {base_bodies}. "
            "Rewrite only the single mapped body for this round (do not include other functions or the entire hunk)."
        )

    # Note: allow __revert_* prefixed names like "__revert_e11519_xmlParserNsPush" to match active old_signature
    # function names like "xmlParserNsPush". Use a boundary that treats '_' as a separator (not alnum).
    if func_name and re.search(rf"(?<![A-Za-z0-9]){re.escape(func_name)}\s*\(", new_text) is None:
        return f"new_func_code does not appear to contain the active function name {func_name}(...) from active_old_signature."

    if new_semicolon_before_first:
        return (
            f"new_func_code appears to include top-level declarations before {func_name or 'the active body'}."
            " In function-scoped mode, avoid adding extra top-level decls/macros; keep the rewrite inside the mapped body."
        )

    return None


def _brace_balance(code: str) -> tuple[int, bool]:
    """Return (final_brace_depth, saw_underflow) while ignoring braces in strings/comments."""
    text = str(code or "").replace("\r\n", "\n").replace("\r", "\n")
    brace_depth = 0
    saw_underflow = False

    in_sl_comment = False
    in_ml_comment = False
    in_str = False
    in_char = False
    escape = False
    at_line_start = True

    i = 0
    while i < len(text):
        c = text[i]
        n = text[i + 1] if i + 1 < len(text) else ""

        if in_sl_comment:
            if c == "\n":
                in_sl_comment = False
                at_line_start = True
            i += 1
            continue
        if in_ml_comment:
            if c == "*" and n == "/":
                in_ml_comment = False
                i += 2
                continue
            if c == "\n":
                at_line_start = True
            i += 1
            continue
        if in_str:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_str = False
            if c == "\n":
                at_line_start = True
            i += 1
            continue
        if in_char:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == "'":
                in_char = False
            if c == "\n":
                at_line_start = True
            i += 1
            continue

        # Skip preprocessor directive lines at top level to avoid counting macro bodies.
        if at_line_start and brace_depth == 0:
            j = i
            while j < len(text) and text[j] in " \t":
                j += 1
            if j < len(text) and text[j] == "#":
                nl = text.find("\n", j)
                if nl < 0:
                    break
                i = nl + 1
                at_line_start = True
                continue

        if c == "/" and n == "/":
            in_sl_comment = True
            i += 2
            continue
        if c == "/" and n == "*":
            in_ml_comment = True
            i += 2
            continue
        if c == '"':
            in_str = True
            escape = False
            i += 1
            continue
        if c == "'":
            in_char = True
            escape = False
            i += 1
            continue

        if c == "\n":
            at_line_start = True
            i += 1
            continue
        if c not in " \t\r":
            at_line_start = False

        if c == "{":
            brace_depth += 1
            i += 1
            continue
        if c == "}":
            if brace_depth == 0:
                saw_underflow = True
            else:
                brace_depth -= 1
            i += 1
            continue

        i += 1

    return brace_depth, saw_underflow


def _override_complete_function_guardrail_error(state: AgentState, decision: Decision) -> Optional[str]:
    """Return an error if new_func_code looks like an incomplete/truncated function body.

    Only applies when the BASE slice is function-scoped (has a top-level `) {` body). For small fragment rewrites,
    the override may legitimately be unbalanced.
    """
    if str(decision.get("type", "")).strip() != "tool":
        return None
    if str(decision.get("tool", "")).strip() != "make_error_patch_override":
        return None

    base_text = ""
    base_source = ""

    loop_base_path = str(getattr(state, "loop_base_func_code_artifact_path", "") or "").strip()
    if loop_base_path:
        try:
            base_text = _read_text(loop_base_path)
            base_source = "loop_base_func_code_artifact_path"
        except Exception:
            base_text = ""

    if not base_text.strip():
        err_func_path = str(getattr(state, "active_error_func_code_artifact_path", "") or "").strip()
        if err_func_path:
            try:
                base_text = _read_text(err_func_path)
                base_source = "get_error_patch_context.error_func_code"
            except Exception:
                base_text = ""

    if not base_text.strip():
        base_text = _last_read_artifact_text(state)
        base_source = "read_artifact"

    if not base_text.strip():
        return None

    base_bodies, _ = _count_top_level_bodies(base_text)
    if base_bodies <= 0:
        return None

    args_obj = decision.get("args") if isinstance(decision.get("args"), dict) else {}
    new_raw = str(args_obj.get("new_func_code", "") or "")
    new_text = _extract_first_code_fence(new_raw).replace("\r\n", "\n").replace("\r", "\n")
    if not new_text.strip():
        return "new_func_code is empty."

    new_bodies, _ = _count_top_level_bodies(new_text)
    if new_bodies <= 0:
        return f"new_func_code does not appear to contain a full function body (BASE slice source: {base_source})."

    depth, underflow = _brace_balance(new_text)
    if underflow or depth != 0:
        return (
            f"new_func_code appears to be an incomplete function body (unbalanced braces: depth={depth}, underflow={underflow}). "
            f"BASE slice source: {base_source}."
        )

    return None


def _override_location_guardrail_for_override(state: AgentState, decision: Decision) -> Optional[Decision]:
    """Rewrite make_error_patch_override args when the model mistakenly uses pre_patch_*.

    make_error_patch_override must be called with the build-log /src/... error location. pre_patch_* is only for
    read_file_context. If the model supplies (file_path,line_number) matching pre_patch_*, rewrite them back to the
    build-log location captured as active_file_path/active_line_number.
    """
    if str(decision.get("type", "")).strip() != "tool":
        return None
    if str(decision.get("tool", "")).strip() != "make_error_patch_override":
        return None

    active_fp = str(getattr(state, "active_file_path", "") or "").strip()
    active_ln = int(getattr(state, "active_line_number", 0) or 0)
    pre_fp = str(getattr(state, "pre_patch_file_path", "") or "").strip()
    pre_ln = int(getattr(state, "pre_patch_line_number", 0) or 0)
    if not (active_fp and active_ln > 0 and pre_fp and pre_ln > 0):
        return None

    args_obj = decision.get("args") if isinstance(decision.get("args"), dict) else {}
    arg_fp = str(args_obj.get("file_path", "") or "").strip()
    arg_ln_raw = args_obj.get("line_number", 0)
    try:
        arg_ln = int(arg_ln_raw or 0)
    except (TypeError, ValueError):
        arg_ln = 0
    if not (arg_fp and arg_ln > 0):
        return None

    def norm(p: str) -> str:
        return str(p or "").replace("\\", "/").strip().lstrip("./").strip()

    arg_fp_n = norm(arg_fp).lstrip("/")
    pre_fp_n = norm(pre_fp).lstrip("/")

    file_matches = False
    if arg_fp_n == pre_fp_n:
        file_matches = True
    elif arg_fp_n.endswith("/" + pre_fp_n) or pre_fp_n.endswith("/" + arg_fp_n):
        file_matches = True

    if not file_matches or arg_ln != pre_ln:
        return None

    new_decision: Decision = dict(decision)
    new_args = dict(args_obj)
    new_args["file_path"] = active_fp
    new_args["line_number"] = active_ln
    new_decision["args"] = new_args
    return new_decision


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
    """Block invented #defines by forcing deterministic `_extra_*` insertion."""
    if str(decision.get("type", "")).strip() != "tool":
        return None
    if str(decision.get("tool", "")).strip() != "make_error_patch_override":
        return None

    args_obj = decision.get("args") if isinstance(decision.get("args"), dict) else {}
    new_code = str(args_obj.get("new_func_code", "") or "")
    defines = set(_extract_defined_macros_from_code(new_code))
    missing = set(str(t) for t in (state.macro_tokens_not_defined_in_slice or []) if str(t).strip())
    tokens = [t for t in sorted(defines & missing) if t and (not _has_read_file_context_for_token(state, t))]
    if not tokens:
        return None

    file_path, _ = _first_error_location(state)
    if not file_path:
        return None

    token = tokens[0]
    if _has_make_extra_patch_override_for_symbol(state, token):
        return None

    return {
        "type": "tool",
        "thought": f"Macro guardrail: add the real definition for {token} via the file's _extra_* hunk (do not invent #define values in the function body).",
        "tool": "make_extra_patch_override",
        "args": {"patch_path": state.patch_path, "file_path": file_path, "symbol_name": token, "version": "v1"},
    }


def _has_make_extra_patch_override_for_symbol(state: AgentState, symbol: str) -> bool:
    want = str(symbol or "").strip()
    if not want:
        return False
    for step in (state.step_history or []):
        if not isinstance(step, dict):
            continue
        decision = step.get("decision")
        if not isinstance(decision, dict):
            continue
        if str(decision.get("tool", "")).strip() != "make_extra_patch_override":
            continue
        args = decision.get("args") if isinstance(decision.get("args"), dict) else {}
        if str(args.get("symbol_name", "")).strip() == want:
            return True
    return False


def _count_make_extra_patch_override_for_symbol(state: AgentState, symbol: str) -> int:
    want = str(symbol or "").strip()
    if not want:
        return 0
    count = 0
    for step in (state.step_history or []):
        if not isinstance(step, dict):
            continue
        decision = step.get("decision")
        if not isinstance(decision, dict):
            continue
        if str(decision.get("tool", "")).strip() != "make_extra_patch_override":
            continue
        args = decision.get("args") if isinstance(decision.get("args"), dict) else {}
        if str(args.get("symbol_name", "")).strip() == want:
            count += 1
    return count


def _undeclared_symbol_extra_patch_guardrail_for_override(state: AgentState, decision: Decision) -> Optional[Decision]:
    """Prefer deterministic `_extra_*` insertions over function rewrites that delete missing symbols.

    If the current diagnostic is an undeclared symbol/type/macro, try make_extra_patch_override once per
    symbol before allowing make_error_patch_override to "fix" the compile by removing references.
    """
    if str(decision.get("type", "")).strip() != "tool":
        return None
    if str(decision.get("tool", "")).strip() != "make_error_patch_override":
        return None
    if state.error_scope != "patch" or not state.patch_path:
        return None
    # Only run after patch prereqs (mapping) are satisfied, otherwise let tool ordering drive.
    if _next_patch_prereq_tool(state) is not None:
        return None

    undeclared = _extract_undeclared_symbol_name(state)
    if not undeclared:
        return None
    if _has_make_extra_patch_override_for_symbol(state, undeclared):
        return None

    file_path, _ = _first_error_location(state)
    if not file_path:
        return None

    # Prefer trying make_extra_patch_override once (deterministic KB-backed insertion) before allowing a
    # function rewrite that "fixes" the build by deleting/replacing the symbol (e.g. turning globals into locals).
    return {
        "type": "tool",
        "thought": "Undeclared symbol guardrail: try a deterministic file-scope insertion via the file's _extra_* hunk before rewriting the function.",
        "tool": "make_extra_patch_override",
        "args": {
            "patch_path": state.patch_path,
            "file_path": file_path,
            "symbol_name": undeclared,
            "version": "v1",
        },
    }


def _incomplete_type_extra_patch_guardrail_for_override(state: AgentState, decision: Decision) -> Optional[Decision]:
    """Prefer deterministic `_extra_*` type definitions over semantic no-op function rewrites.

    If the current diagnostic indicates an incomplete type, force make_extra_patch_override before allowing
    make_error_patch_override to "fix" the compile by deleting field accesses/sizeof usage.

    We allow up to 2 attempts per type symbol to support the common sequence:
      1) insert forward typedef (unknown type) then
      2) insert tag body definition (incomplete type).
    """
    if str(decision.get("type", "")).strip() != "tool":
        return None
    if str(decision.get("tool", "")).strip() != "make_error_patch_override":
        return None
    if state.error_scope != "patch" or not state.patch_path:
        return None
    # Only run after patch prereqs (mapping) are satisfied, otherwise let tool ordering drive.
    if _next_patch_prereq_tool(state) is not None:
        return None

    candidates = _extract_incomplete_type_symbol_candidates(state)
    if not candidates:
        return None

    file_path, _ = _first_error_location(state)
    if not file_path:
        return None

    for sym in candidates:
        if _count_make_extra_patch_override_for_symbol(state, sym) >= 2:
            continue
        return {
            "type": "tool",
            "thought": (
                f"Incomplete-type guardrail: add the real definition for {sym} via the file's _extra_* hunk "
                "(do not rewrite the function to remove field access/sizeof usage)."
            ),
            "tool": "make_extra_patch_override",
            "args": {
                "patch_path": state.patch_path,
                "file_path": file_path,
                "symbol_name": sym,
                "version": "v1",
            },
        }

    return None


def _missing_prototype_extra_patch_guardrail(state: AgentState, decision: Decision) -> Optional[Decision]:
    """Handle -Wmissing-prototypes warnings by inserting a prototype via `_extra_*`.

    In patch-scope mode, prefer make_extra_patch_override to add a file-scope prototype for the reported
    function (often a generated `__revert_*`), rather than rewriting the function body.
    """
    if state.error_scope != "patch" or not state.patch_path:
        return None
    # Only run after patch prereqs (mapping) are satisfied, otherwise let tool ordering drive.
    if _next_patch_prereq_tool(state) is not None:
        return None

    sym = _extract_missing_prototype_symbol_name(state)
    if not sym:
        return None
    if _has_make_extra_patch_override_for_symbol(state, sym):
        return None
    if (
        str(decision.get("type", "")).strip() == "tool"
        and str(decision.get("tool", "")).strip() == "make_extra_patch_override"
        and isinstance(decision.get("args"), dict)
        and str((decision.get("args") or {}).get("symbol_name", "")).strip() == sym
    ):
        return None

    file_path, _ = _first_error_location(state)
    if not file_path:
        return None

    return {
        "type": "tool",
        "thought": (
            f"Missing-prototype warning: add a file-scope prototype for {sym} via the file's _extra_* hunk "
            "(deterministic extra patch strategy)."
        ),
        "tool": "make_extra_patch_override",
        "args": {"patch_path": state.patch_path, "file_path": file_path, "symbol_name": sym, "version": "v1"},
    }


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


def _macro_lookup_pick_tokens(state: AgentState, *, max_tokens: int = 3) -> List[str]:
    """Pick up to max_tokens missing macro tokens, prioritized by appearance in the compiler snippet."""
    snippet = str(state.snippet or "")
    missing = [str(t) for t in (state.macro_tokens_not_defined_in_slice or []) if str(t).strip()]
    if not missing:
        return []
    ordered: List[str] = []
    for tok in missing:
        if tok and tok in snippet and tok not in ordered:
            ordered.append(tok)
    for tok in missing:
        if tok and tok not in ordered:
            ordered.append(tok)
    return ordered[: max(0, int(max_tokens or 0))]


def _maybe_rewrite_deprecated_kb_search(decision: Decision) -> Optional[Decision]:
    """Compatibility: rewrite deprecated kb_search_symbols calls into search_definition.

    We no longer expose kb_search_symbols as a tool. If a model still emits it, rewrite the request
    into a single search_definition call (first symbol) so runs don't crash.
    """
    if str(decision.get("type", "")).strip() != "tool":
        return None
    if str(decision.get("tool", "")).strip() != "kb_search_symbols":
        return None
    args_obj = decision.get("args") if isinstance(decision.get("args"), dict) else {}
    syms = args_obj.get("symbols")
    symbols = [str(s) for s in (syms if isinstance(syms, list) else [syms]) if str(s).strip()]
    if not symbols:
        return {
            "type": "final",
            "thought": "Deprecated tool call had no symbols.",
            "summary": "kb_search_symbols is removed; no symbols provided to rewrite.",
            "next_step": "Call search_definition(symbol_name=...) or make_extra_patch_override(symbol_name=...) instead.",
        }
    ver = str(args_obj.get("version", "v2") or "v2").strip().lower()
    if ver not in {"v1", "v2"}:
        ver = "v2"
    return {
        "type": "tool",
        "thought": "Rewrite deprecated kb_search_symbols into a single search_definition call.",
        "tool": "search_definition",
        "args": {"symbol_name": symbols[0], "version": ver},
    }


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
                if key in {"excerpt", "func_code", "patch_text", "patch_minus_code", "error_func_code"} and isinstance(v, str):
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
_MISSING_MEMBER_FIELD_RE = re.compile(r"no member named '([^']+)' in '([^']+)'")
_ERROR_LOC_RE = re.compile(r"^(?P<file>[^:\n]+):(?P<line>\d+):(?P<col>\d+):")
_UNDECLARED_SYMBOL_RE = re.compile(
    r"(?:use of undeclared identifier|call to undeclared function|implicit declaration of function|unknown type name|undeclared function)\s*'(?P<symbol>[^']+)'"
)
_CONFLICTING_TYPES_RE = re.compile(r"conflicting types for\s*'(?P<symbol>[^']+)'")
_INCOMPLETE_TYPE_RE = re.compile(
    r"(?:incomplete definition of type|incomplete type|dereferencing pointer to incomplete type|invalid application of 'sizeof' to an incomplete type)\s*'(?P<type>[^']+)'",
    re.IGNORECASE,
)
_MISSING_PROTOTYPE_RE = re.compile(r"no previous prototype for function\s*'(?P<symbol>[^']+)'", re.IGNORECASE)
_C_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _extract_undeclared_symbol_name(state: AgentState) -> str:
    """Best-effort extraction of an undeclared symbol/type/macro name from current error context."""
    candidates: List[str] = []
    for e in state.grouped_errors or []:
        if not isinstance(e, dict):
            continue
        raw = str(e.get("raw", "") or "").strip()
        if raw:
            candidates.append(raw)
    if str(state.error_line or "").strip():
        candidates.append(str(state.error_line))
    if str(state.snippet or "").strip():
        candidates.append(str(state.snippet))

    for text in candidates:
        for pat in (_UNDECLARED_SYMBOL_RE, _CONFLICTING_TYPES_RE):
            m = pat.search(text)
            if m:
                sym = str(m.group("symbol") or "").strip()
                if sym:
                    return sym
    return ""


def _extract_incomplete_type_symbol_candidates(state: AgentState) -> List[str]:
    """Best-effort extraction of incomplete type names from current error context.

    Returns a prioritized list of candidate symbol names to try with make_extra_patch_override.
    """
    texts: List[str] = []
    for e in state.grouped_errors or []:
        if not isinstance(e, dict):
            continue
        raw = str(e.get("raw", "") or "").strip()
        if raw:
            texts.append(raw)
    if str(state.error_line or "").strip():
        texts.append(str(state.error_line))
    if str(state.snippet or "").strip():
        texts.append(str(state.snippet))

    out: List[str] = []
    seen: set[str] = set()

    def add(sym: str) -> None:
        s = str(sym or "").strip()
        if not s or s in seen:
            return
        seen.add(s)
        out.append(s)

    for text in texts:
        m = _INCOMPLETE_TYPE_RE.search(text)
        if not m:
            continue
        raw_type = str(m.group("type") or "").strip()
        if not raw_type:
            continue

        parts = raw_type.split()
        # Normalize "struct TAG" -> "TAG"
        if len(parts) >= 2 and parts[0] in {"struct", "union", "enum"}:
            tag = parts[-1].strip()
            if _C_IDENT_RE.match(tag):
                # Common C style: `struct _Foo` is typedef'd as `Foo`. Prefer the alias first.
                if tag.startswith("_") and _C_IDENT_RE.match(tag[1:]):
                    add(tag[1:])
                add(tag)
            continue

        if _C_IDENT_RE.match(raw_type):
            add(raw_type)

    return out


def _extract_missing_prototype_symbol_name(state: AgentState) -> str:
    """Best-effort extraction of a function name from -Wmissing-prototypes warnings."""
    candidates: List[str] = []
    for e in state.grouped_errors or []:
        if not isinstance(e, dict):
            continue
        raw = str(e.get("raw", "") or "").strip()
        if raw:
            candidates.append(raw)
    if str(state.error_line or "").strip():
        candidates.append(str(state.error_line))
    if str(state.snippet or "").strip():
        candidates.append(str(state.snippet))

    for text in candidates:
        m = _MISSING_PROTOTYPE_RE.search(str(text or ""))
        if not m:
            continue
        sym = str(m.group("symbol") or "").strip()
        if sym:
            return sym
    return ""

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


def _active_override_location(state: AgentState) -> tuple[str, int]:
    fp = str(getattr(state, "active_file_path", "") or "").strip()
    ln = int(getattr(state, "active_line_number", 0) or 0)
    if fp and ln > 0:
        return fp, ln
    return _first_error_location(state)


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

    if not called("get_error_patch_context"):
        return "get_error_patch_context"
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
    if state.patch_generated:
        return False
    # Require patch generation once we have enough context to rewrite a mapped '-' slice.
    has_base = bool(str(getattr(state, "loop_base_func_code_artifact_path", "") or "").strip()) or _has_tool_call(
        state, "get_error_patch_context"
    )
    if not has_base:
        return False
    return True


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


def _struct_member_search_guardrail_for_search_definition(state: AgentState, decision: Decision) -> Optional[Decision]:
    """Rewrite search_definition(member) into search_definition(struct) for missing-member errors.

    search_definition is a symbol-definition lookup and isn't a reliable way to locate struct fields directly; when
    the model asks for a member name like `nsdb`, fetch the parent struct definition instead so the model can
    compare the V1 vs V2 field lists and adapt call sites.
    """
    if str(decision.get("type", "")).strip() != "tool":
        return None
    if str(decision.get("tool", "")).strip() != "search_definition":
        return None

    args_obj = decision.get("args") if isinstance(decision.get("args"), dict) else {}
    raw_name = str(args_obj.get("symbol_name", "") or "").strip()
    if not raw_name:
        return None

    missing: set[str] = set()
    for item in state.missing_struct_members or []:
        if not isinstance(item, dict):
            continue
        for member in item.get("members") or []:
            m = str(member or "").strip()
            if m:
                missing.add(m)
    if not missing:
        m = _MISSING_MEMBER_FIELD_RE.search(str(state.error_line or ""))
        if m:
            member = str(m.group(1) or "").strip()
            if member:
                missing.add(member)
    if not missing:
        return None

    # If the model passes expressions like "ctxt->nsdb" or "ctxt.nsdb", extract the last identifier.
    toks = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", raw_name)
    if not toks:
        return None
    candidate = str(toks[-1] or "").strip()
    if not candidate or candidate not in missing:
        return None

    structs = _structs_to_compare(state)
    if not structs:
        return None
    struct_name = structs[0]

    ver = str(args_obj.get("version", "v2") or "v2").strip().lower()
    if ver not in {"v1", "v2"}:
        ver = "v2"

    return {
        "type": "tool",
        "thought": "search_definition is not a struct-field lookup; fetch the parent struct definition instead.",
        "tool": "search_definition",
        "args": {"symbol_name": _normalize_struct_queries(struct_name)[0], "version": ver},
    }


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

    # Auto-loop iteration: the next override is driven from the latest override patch_text and a BASE slice
    # extracted from it (loop_base_func_code_artifact_path). Do not force re-mapping tools.
    if str(getattr(state, "loop_base_func_code_artifact_path", "") or "").strip():
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
    active_sig = str(error.get("active_old_signature", "")).strip()
    current_groups = error.get("function_groups") if isinstance(error.get("function_groups"), list) else []
    try:
        current_groups_total = int(error.get("function_groups_total", 0) or 0)
    except (TypeError, ValueError):
        current_groups_total = 0
    current_groups_truncated = bool(error.get("function_groups_truncated", False))

    history_groups = error.get("function_groups_history") if isinstance(error.get("function_groups_history"), list) else []
    try:
        history_groups_total = int(error.get("function_groups_history_total", 0) or 0)
    except (TypeError, ValueError):
        history_groups_total = 0
    history_groups_truncated = bool(error.get("function_groups_history_truncated", False))
    history = error.get("error_history") if isinstance(error.get("error_history"), list) else []
    if patch_path:
        lines.append(f"Patch bundle: {patch_path}")
    if artifacts_dir:
        lines.append(f"Artifacts: {artifacts_dir}")
    if patch_key:
        lines.append(f"Patch key: {patch_key}")
    if scope:
        lines.append(f"Scope: {scope}")

    show_grouping = bool(current_groups or history_groups)
    if show_grouping:
        lines.append("")
        lines.append("Function grouping note:")
        lines.append(textwrap.indent("Current = remaining compiler errors from the latest build logs.", "  "))
        lines.append(textwrap.indent("History = union of unique error lines seen earlier in this agent run (may include fixed errors).", "  "))

    if current_groups or (show_grouping and scope == "patch" and patch_key):
        lines.append("")
        total = current_groups_total or len(current_groups)
        lines.append(f"Current function groups ({total}):")
        if not current_groups:
            lines.append(textwrap.indent("(none)", "  "))
        for idx, grp in enumerate(current_groups, start=1):
            if not isinstance(grp, dict):
                continue
            sig = str(grp.get("old_signature", "") or "").strip()
            count = grp.get("count", 0)
            try:
                count_i = int(count or 0)
            except (TypeError, ValueError):
                count_i = 0
            label = sig or "<unknown>"
            suffix = " [active]" if active_sig and sig and sig == active_sig else ""
            lines.append(textwrap.indent(f"{idx}. {label} (errors={count_i}){suffix}", "  "))
            examples = grp.get("examples") if isinstance(grp.get("examples"), list) else []
            for raw in examples[:3]:
                r = str(raw or "").strip()
                if r:
                    lines.append(textwrap.indent(f"- {r}", "    "))
        if current_groups_truncated:
            lines.append(textwrap.indent("...(truncated)", "  "))

    if history_groups:
        lines.append("")
        total = history_groups_total or len(history_groups)
        lines.append(f"History function groups ({total}):")
        for idx, grp in enumerate(history_groups, start=1):
            if not isinstance(grp, dict):
                continue
            sig = str(grp.get("old_signature", "") or "").strip()
            count = grp.get("count", 0)
            try:
                count_i = int(count or 0)
            except (TypeError, ValueError):
                count_i = 0
            label = sig or "<unknown>"
            suffix = " [active]" if active_sig and sig and sig == active_sig else ""
            lines.append(textwrap.indent(f"{idx}. {label} (unique_errors={count_i}){suffix}", "  "))
            examples = grp.get("examples") if isinstance(grp.get("examples"), list) else []
            for raw in examples[:3]:
                r = str(raw or "").strip()
                if r:
                    lines.append(textwrap.indent(f"- {r}", "    "))
        if history_groups_truncated:
            lines.append(textwrap.indent("...(truncated)", "  "))
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

    if history:
        lines.append("")
        lines.append(f"Error history ({len(history)}):")
        for idx, entry in enumerate(history, start=1):
            if not isinstance(entry, dict):
                continue
            pk = str(entry.get("patch_key", "")).strip()
            el = str(entry.get("error_line", "")).strip()
            raw_group = entry.get("grouped_errors") if isinstance(entry.get("grouped_errors"), list) else []
            header = f"{idx}. {el}" if el else f"{idx}."
            if pk:
                header += f" (patch_key={pk})"
            lines.append(textwrap.indent(header, "  "))
            for raw in raw_group[:6]:
                r = str(raw or "").strip()
                if not r or r == el:
                    continue
                lines.append(textwrap.indent(f"- {r}", "    "))

    steps = final.get("steps")
    if isinstance(steps, list) and steps:
        lines.append("")
        lines.append(f"Steps (full run, {len(steps)}):")
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


def _system_prompt(state: AgentState) -> str:
    return build_system_prompt(state, tool_specs=TOOL_SPECS)


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
    if state.error_scope == "patch" and str(getattr(state, "active_old_signature", "") or "").strip():
        header_lines.append(f"Active function (old_signature): {str(state.active_old_signature).strip()}")
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
        {"role": "system", "content": _system_prompt(state)},
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
    llm_call_seq = 0
    if not state.step_history and state.steps:
        # Preserve any pre-populated steps (tests/resumed runs) before auto-loop trimming kicks in.
        state.step_history = list(state.steps)

    def _debug_dump_llm(
        *,
        call_id: int,
        label: str,
        messages: List[Dict[str, str]],
        response: Optional[str] = None,
        response_debug: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not cfg.debug_llm:
            return
        payload = {"call_id": call_id, "label": str(label or ""), "messages": messages}
        if response is not None:
            payload["response"] = str(response)
        if response_debug is not None:
            payload["response_debug"] = response_debug

        if cfg.debug_llm_dir:
            out_dir = Path(str(cfg.debug_llm_dir)).expanduser()
            out_dir.mkdir(parents=True, exist_ok=True)
            kind = "response" if response is not None else "request"
            (out_dir / f"llm_call_{call_id:04d}_{kind}.json").write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
                errors="replace",
            )

        sys.stderr.write(f"\n=== LLM {call_id:04d} {label} ({'response' if response is not None else 'request'}) ===\n")
        sys.stderr.write(json.dumps(payload, ensure_ascii=False, indent=2))
        sys.stderr.write("\n")

    def _complete(model_obj: ChatModel, messages: List[Dict[str, str]], *, label: str) -> str:
        nonlocal llm_call_seq
        llm_call_seq += 1
        call_id = llm_call_seq
        _debug_dump_llm(call_id=call_id, label=label, messages=messages)
        response_debug: Optional[Dict[str, Any]] = None
        if cfg.debug_llm and hasattr(model_obj, "complete_with_raw"):
            content, debug_info = getattr(model_obj, "complete_with_raw")(messages)
            out = str(content)
            if not out.strip():
                try:
                    response_debug = asdict(debug_info)
                except Exception:
                    response_debug = {"debug_info_type": str(type(debug_info))}
        else:
            out = model_obj.complete(messages)
        _debug_dump_llm(call_id=call_id, label=label, messages=messages, response=out, response_debug=response_debug)
        return out

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
                        "steps": _steps_for_output(st),
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
                        "steps": _steps_for_output(st),
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
            forced_loop = _prepare_next_patch_scope_iteration_after_ossfuzz(st, cfg, artifact_store=artifact_store)
            if forced_loop:
                _validate_tool_decision(forced_loop)
                return {"state": st, "pending": forced_loop}

            patch_text_path = ""
            merged_patch_file_path = ""
            if isinstance(st.patch_result, dict):
                pt = st.patch_result.get("patch_text")
                if isinstance(pt, dict):
                    patch_text_path = str(pt.get("artifact_path", "") or "").strip()

            if (
                isinstance(st.last_observation, ToolObservation)
                and st.last_observation.tool == "ossfuzz_apply_patch_and_test"
            ):
                out = st.last_observation.output
                if isinstance(out, dict):
                    merged_patch_file_path = str(out.get("merged_patch_file_path", "") or "").strip()

            verdict = _summarize_target_error_status(st)
            patch_key_verdict: Dict[str, Any] = {}
            if st.error_scope == "patch" and st.patch_path:
                patch_key_verdict = _summarize_active_patch_key_status(st)
                if isinstance(patch_key_verdict, dict) and patch_key_verdict.get("status") == "ok":
                    fg = patch_key_verdict.get("function_groups")
                    st.function_groups = fg if isinstance(fg, list) else []
                    st.function_groups_total = int(patch_key_verdict.get("function_groups_total", 0) or 0)
                    st.function_groups_truncated = bool(patch_key_verdict.get("function_groups_truncated", False))
            fixed_str = "unknown"
            if verdict.get("status") == "ok":
                fixed_str = "yes" if verdict.get("fixed") else "no"

            next_step_lines = [f"Target error fixed: {fixed_str}."]
            if verdict.get("status") == "failed":
                reason = str(verdict.get("reason", "") or "").strip()
                if reason:
                    next_step_lines.append(f"OSS-Fuzz run failed: {reason}")
                hint = str(verdict.get("hint", "") or "").strip()
                if hint:
                    next_step_lines.append(f"Hint: {hint}")
            elif verdict.get("status") == "unknown":
                reason = str(verdict.get("reason", "") or "").strip()
                if reason:
                    next_step_lines.append(f"OSS-Fuzz status unknown: {reason}")
            elif verdict.get("status") == "ok":
                matched = verdict.get("matched_target_errors") or []
                if matched:
                    next_step_lines.append("Remaining target errors:")
                    for m in matched[:5]:
                        raw = str((m or {}).get("raw", "")).strip()
                        if raw:
                            next_step_lines.append(f"- {raw}")
                elif verdict.get("other_errors"):
                    next_step_lines.append("Next top errors:")
                    next_step_lines.extend(_format_other_errors_for_next_step(verdict.get("other_errors") or [], limit=5))
            if verdict.get("status") == "ok":
                next_step_lines.append("Review OSS-Fuzz logs in artifacts and apply the merged patch file.")
            else:
                next_step_lines.append("Review OSS-Fuzz logs in artifacts and re-run once OSS-Fuzz tooling works.")
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
                    "summary": "Generated an override patch, tested it in OSS-Fuzz, and checked whether the target error is fixed.",
                    "next_step": next_step.strip(),
                    "steps": _steps_for_output(st),
                    "error": _error_payload(st),
                    "ossfuzz_verdict": verdict,
                    "patch_key_verdict": patch_key_verdict,
                    "ossfuzz_runs_attempted": int(st.ossfuzz_runs_attempted or 0),
                    "auto_ossfuzz_loop": bool(cfg.auto_ossfuzz_loop),
                    "ossfuzz_loop_max": int(cfg.ossfuzz_loop_max or 0),
                },
            }

        force_patch_after_read = False
        if st.pending_patch and st.last_observation and st.last_observation.tool == "read_artifact":
            # A prior make_error_patch_override attempt was deferred until we had the BASE slice.
            # Do not execute the stale tool call: ask the model to regenerate new_func_code from
            # the just-read BASE slice with minimal edits.
            if len(st.steps) >= cfg.max_steps:
                return {
                    "state": st,
                    "final": {
                        "type": "final",
                        "thought": "Reached max tool steps before generating the patch.",
                        "summary": "Stopped due to max_steps.",
                        "next_step": "Increase --max-steps to allow make_error_patch_override to run after read_artifact.",
                        "steps": _steps_for_output(st),
                        "error": _error_payload(st),
                    },
                }
            st.pending_patch = None
            force_patch_after_read = True

        if len(st.steps) >= cfg.max_steps:
            return {
                "state": st,
                "final": {
                    "type": "final",
                    "thought": "Reached max tool steps without a final decision.",
                    "summary": "Stopped after max_steps.",
                    "next_step": "Increase --max-steps or review the last observation and proceed manually.",
                    "steps": _steps_for_output(st),
                    "error": _error_payload(st),
                },
            }

        # Macro-expansion preflight: do not invent #defines inside the function body. Prefer adding
        # the missing macro at file scope via the file's `_extra_*` hunk.
        if st.macro_tokens_not_defined_in_slice and "expanded from macro" in str(st.snippet or ""):
            file_path, _ = _first_error_location(st)
            if file_path:
                tokens = _macro_lookup_pick_tokens(st, max_tokens=3)
                token = tokens[0] if tokens else ""
                if token and not _has_make_extra_patch_override_for_symbol(st, token):
                    forced: Decision = {
                        "type": "tool",
                        "thought": f"Macro preflight: add the real definition for {token} via the file's _extra_* hunk (do not invent #define values).",
                        "tool": "make_extra_patch_override",
                        "args": {"patch_path": st.patch_path, "file_path": file_path, "symbol_name": token, "version": "v1"},
                    }
                    _validate_tool_decision(forced)
                    return {"state": st, "pending": forced}
        messages = _build_messages(st)
        if force_patch_after_read and st.patch_path and st.error_scope == "patch":
            file_path, line_number = _active_override_location(st)
            base_text = _last_read_artifact_text(st)
            base_lines = len(base_text.splitlines()) if base_text else 0
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Do NOT return a final decision yet.\n"
                        "You just read the BASE slice via read_artifact.\n"
                        f"BASE slice lines (approx): {base_lines}\n"
                        "You MUST generate a patch now by calling make_error_patch_override with:\n"
                        f'- args.patch_path="{st.patch_path}"\n'
                        f'- args.file_path="{file_path}"\n'
                        f"- args.line_number={line_number}\n"
                        "- args.new_func_code=<the BASE slice with minimal edits only; do NOT drop unrelated lines or omit the tail>\n"
                        "Return exactly one JSON tool object."
                    ),
                }
            )
        raw = _complete(model, messages, label="main")
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
            repaired_raw = _complete(repair_model, repair_messages, label="json_repair")
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
                        "steps": _steps_for_output(st),
                        "error": _error_payload(st),
                    },
                }

        if force_patch_after_read and st.patch_path and st.error_scope == "patch":
            file_path, line_number = _active_override_location(st)
            must_patch = (
                isinstance(decision, dict)
                and decision.get("type") == "tool"
                and str(decision.get("tool", "")).strip() == "make_error_patch_override"
            )
            args_ok = False
            if must_patch:
                args = decision.get("args") or {}
                args_ok = (
                    isinstance(args, dict)
                    and str(args.get("patch_path", "")).strip() == str(st.patch_path).strip()
                    and str(args.get("file_path", "")).strip() == str(file_path).strip()
                    and int(args.get("line_number", 0) or 0) == int(line_number or 0)
                    and str(args.get("new_func_code", "") or "").strip()
                )

            if not args_ok:
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
                            "- args.new_func_code=<the BASE slice with minimal edits only; do NOT drop unrelated lines or omit the tail>\n"
                            "Do not include any extra text."
                        ),
                    }
                )
                try:
                    coerced = _parse_decision(_complete(model, base_rewrite_messages, label="force_patch_after_read"))
                except Exception:
                    coerced = {}
                if (
                    isinstance(coerced, dict)
                    and coerced.get("type") == "tool"
                    and str(coerced.get("tool", "")).strip() == "make_error_patch_override"
                ):
                    _validate_tool_decision(coerced)  # type: ignore[arg-type]
                    decision = coerced  # type: ignore[assignment]
                else:
                    return {
                        "state": st,
                        "final": {
                            "type": "final",
                            "thought": "Patch generation required after reading the BASE slice, but the model did not produce a make_error_patch_override tool call.",
                            "summary": "Stopped before patch generation.",
                            "next_step": (
                                "Re-run with a larger model / higher OPENAI_MAX_TOKENS, or manually call make_error_patch_override.\n"
                                "Required: start from the latest read_artifact BASE slice and pass it as new_func_code with minimal edits."
                            ),
                            "steps": _steps_for_output(st),
                            "error": _error_payload(st),
                        },
                    }
        deprecated = _maybe_rewrite_deprecated_kb_search(decision)
        if deprecated is not None:
            decision = deprecated  # type: ignore[assignment]
        if decision["type"] == "final":
            remaining = cfg.max_steps - len(st.steps)
            required = _should_force_struct_diff_tools(st)
            if required and remaining >= 2:
                if required == "get_error_patch_context":
                    prereq = _next_patch_prereq_tool(st)
                    if prereq:
                        forced: Decision = dict(prereq)
                        forced["thought"] = (
                            "Missing-member error in patch-scope: fetch get_error_patch_context (includes V1-origin patch_minus_code + error_func_code) "
                            "before finalizing."
                        )
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
                            "steps": _steps_for_output(st),
                            "error": _error_payload(st),
                        },
                    }

                undeclared_symbol = _extract_undeclared_symbol_name(st)
                if (
                    undeclared_symbol
                    and undeclared_symbol.startswith("__revert_")
                    and not _has_tool_call(st, "make_extra_patch_override")
                ):
                    if remaining < 2:
                        return {
                            "state": st,
                            "final": {
                                "type": "final",
                                "thought": "Not enough remaining tool steps to generate and test an extra patch override.",
                                "summary": "Stopped before patch generation.",
                                "next_step": (
                                    "Increase --max-steps (need at least 2 remaining steps: make_extra_patch_override -> ossfuzz_apply_patch_and_test)."
                                ),
                                "steps": _steps_for_output(st),
                                "error": _error_payload(st),
                            },
                        }
                    forced_extra: Decision = {
                        "type": "tool",
                        "thought": "Undeclared symbol/type detected: add a forward declaration/define in the file's _extra_* hunk (deterministic extra patch strategy).",
                        "tool": "make_extra_patch_override",
                        "args": {
                            "patch_path": st.patch_path,
                            "file_path": file_path,
                            "symbol_name": undeclared_symbol,
                            "version": "v1",
                        },
                    }
                    _validate_tool_decision(forced_extra)
                    return {"state": st, "pending": forced_extra}

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
                                "steps": _steps_for_output(st),
                                "error": _error_payload(st),
                            },
                        }

                    artifact_path = (
                        str(getattr(st, "loop_base_func_code_artifact_path", "") or "").strip()
                        or _last_artifact_path(st, "get_error_patch_context", "error_func_code")
                        or _last_artifact_path(st, "get_error_patch_context", "patch_minus_code")
                        or _last_artifact_path(st, "get_error_patch_context", "excerpt")
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
                    coerced = _parse_decision(_complete(model, base_rewrite_messages, label="force_patch"))
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
                        "steps": _steps_for_output(st),
                        "error": _error_payload(st),
                    },
                }

            if _decision_suggests_v2_type_edit(decision):
                base_rewrite_messages = list(messages)
                base_rewrite_messages.append({"role": "assistant", "content": json.dumps(decision, ensure_ascii=False)})

                def attempt_rewrite(extra_user: str) -> Optional[Decision]:
                    rewrite_messages = list(base_rewrite_messages)
                    rewrite_messages.append({"role": "user", "content": extra_user})
                    raw_out = _complete(model, rewrite_messages, label="rewrite_v2_type_edit")
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
                            return _parse_decision(_complete(model, repair_messages, label="rewrite_v2_type_edit_repair"))
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
                    "steps": _steps_for_output(st),
                    "error": _error_payload(st),
                },
            }
        _validate_tool_decision(decision)

        field_rewrite = _struct_member_search_guardrail_for_search_definition(st, decision)
        if field_rewrite:
            _validate_tool_decision(field_rewrite)
            decision = field_rewrite  # type: ignore[assignment]

        # Guardrail: make_error_patch_override must use the build-log /src/... error location, not pre_patch_*.
        fixed_loc = _override_location_guardrail_for_override(st, decision)
        if fixed_loc:
            decision = fixed_loc  # type: ignore[assignment]

        # Guardrail: if we have a BASE slice from read_artifact, do not accept an override that
        # drops large portions of it (common failure mode: model emits only a short snippet).
        if str(decision.get("tool", "")).strip() == "make_error_patch_override":
            shrink_err = _override_preserve_base_guardrail_error(st, decision)
            if shrink_err:
                repair_messages = list(messages)
                repair_messages.append({"role": "assistant", "content": json.dumps(decision, ensure_ascii=False)})
                repair_messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Your make_error_patch_override.new_func_code appears to drop too much of the mapped '-' slice baseline.\n"
                            f"{shrink_err}\n\n"
                            "Fix: start from the mapped function slice (get_error_patch_context.error_func_code or the auto-loop BASE slice) and apply the smallest possible edits.\n"
                            "If your change is meant to be minimal, do NOT omit the tail; keep unrelated lines.\n"
                            "Return exactly one JSON object of type tool calling make_error_patch_override."
                        ),
                    }
                )
                raw2 = _complete(model, repair_messages, label="override_shrink_repair")
                try:
                    repaired = _parse_decision(raw2)
                except Exception:
                    repaired = {}
                if (
                    isinstance(repaired, dict)
                    and repaired.get("type") == "tool"
                    and str(repaired.get("tool", "")).strip() == "make_error_patch_override"
                ):
                    _validate_tool_decision(repaired)  # type: ignore[arg-type]
                    shrink_err2 = _override_preserve_base_guardrail_error(st, repaired)  # type: ignore[arg-type]
                    if not shrink_err2:
                        decision = repaired  # type: ignore[assignment]
                    else:
                        return {
                            "state": st,
                            "final": {
                                "type": "final",
                                "thought": "Model repeatedly produced a truncated override body.",
                                "summary": "Stopped before patch generation due to an incomplete override body.",
                                "next_step": (
                                    f"{shrink_err2}\n\n"
                                    "Increase the model output token budget and try again (e.g. set OPENAI_MAX_TOKENS higher),\n"
                                    "or manually construct new_func_code by editing the read_artifact BASE slice."
                                ).strip(),
                                "steps": _steps_for_output(st),
                                "error": _error_payload(st),
                            },
                        }

        # Guardrail (function-by-function): in merged/tail mode, the override should only rewrite the active function,
        # not the entire patch hunk.
        if str(decision.get("tool", "")).strip() == "make_error_patch_override":
            func_scope_err = _override_single_function_guardrail_error(st, decision)
            if func_scope_err:
                repair_messages = list(messages)
                repair_messages.append({"role": "assistant", "content": json.dumps(decision, ensure_ascii=False)})
                repair_messages.append(
                    {
                        "role": "user",
                        "content": (
                            "In function-by-function mode (Active function (old_signature) is set), make_error_patch_override.new_func_code must rewrite ONLY the mapped slice "
                            "for the active function from this round.\n"
                            f"active_old_signature: {str(getattr(st, 'active_old_signature', '') or '').strip()}\n"
                            f"{func_scope_err}\n\n"
                            "Fix: start from the BASE slice (read_artifact output) and apply minimal edits to ONLY that active slice. "
                            "Do NOT include other functions or unified-diff headers.\n"
                            "Return exactly one JSON object of type tool calling make_error_patch_override."
                        ),
                    }
                )
                raw2 = _complete(model, repair_messages, label="override_function_scope_repair")
                try:
                    repaired = _parse_decision(raw2)
                except Exception:
                    repaired = {}
                if (
                    isinstance(repaired, dict)
                    and repaired.get("type") == "tool"
                    and str(repaired.get("tool", "")).strip() == "make_error_patch_override"
                ):
                    _validate_tool_decision(repaired)  # type: ignore[arg-type]
                    func_scope_err2 = _override_single_function_guardrail_error(st, repaired)  # type: ignore[arg-type]
                    if not func_scope_err2:
                        decision = repaired  # type: ignore[assignment]
                    else:
                        return {
                            "state": st,
                            "final": {
                                "type": "final",
                                "thought": "Model repeatedly produced a multi-function override body.",
                                "summary": "Stopped before patch generation due to an override that is not function-scoped.",
                                "next_step": (
                                    f"{func_scope_err2}\n\n"
                                    "Edit the BASE slice (read_artifact output) manually to include only the active function, then rerun the agent."
                                ).strip(),
                                "steps": _steps_for_output(st),
                                "error": _error_payload(st),
                            },
                        }

        # Guardrail: when the BASE slice is function-scoped, new_func_code must be a complete function body.
        if str(decision.get("tool", "")).strip() == "make_error_patch_override":
            complete_err = _override_complete_function_guardrail_error(st, decision)
            if complete_err:
                repair_messages = list(messages)
                repair_messages.append({"role": "assistant", "content": json.dumps(decision, ensure_ascii=False)})
                repair_messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Your make_error_patch_override.new_func_code appears to be an incomplete/truncated function body.\n"
                            f"{complete_err}\n\n"
                            "Fix: output the FULL function body as raw C code (balanced braces; include the final return/closing `}`), "
                            "still scoped to the mapped '-' slice for this round. Do NOT include unified-diff headers.\n"
                            "Return exactly one JSON object of type tool calling make_error_patch_override."
                        ),
                    }
                )
                raw2 = _complete(model, repair_messages, label="override_complete_body_repair")
                try:
                    repaired = _parse_decision(raw2)
                except Exception:
                    repaired = {}
                if (
                    isinstance(repaired, dict)
                    and repaired.get("type") == "tool"
                    and str(repaired.get("tool", "")).strip() == "make_error_patch_override"
                ):
                    _validate_tool_decision(repaired)  # type: ignore[arg-type]
                    complete_err2 = _override_complete_function_guardrail_error(st, repaired)  # type: ignore[arg-type]
                    if not complete_err2:
                        decision = repaired  # type: ignore[assignment]
                    else:
                        return {
                            "state": st,
                            "final": {
                                "type": "final",
                                "thought": "Model repeatedly produced an incomplete function body for the override.",
                                "summary": "Stopped before patch generation due to an incomplete override function body.",
                                "next_step": (
                                    f"{complete_err2}\n\n"
                                    "Increase the model output token budget and try again, or manually edit the BASE slice (read_artifact output) to produce a complete function body."
                                ).strip(),
                                "steps": _steps_for_output(st),
                                "error": _error_payload(st),
                            },
                        }

        forced_missing_proto = _missing_prototype_extra_patch_guardrail(st, decision)
        if forced_missing_proto:
            _validate_tool_decision(forced_missing_proto)
            return {"state": st, "pending": forced_missing_proto}

        forced_undeclared = _undeclared_symbol_extra_patch_guardrail_for_override(st, decision)
        if forced_undeclared:
            _validate_tool_decision(forced_undeclared)
            return {"state": st, "pending": forced_undeclared}

        forced_incomplete = _incomplete_type_extra_patch_guardrail_for_override(st, decision)
        if forced_incomplete:
            _validate_tool_decision(forced_incomplete)
            return {"state": st, "pending": forced_incomplete}

        forced_macro = _macro_define_guardrail_for_override(st, decision)
        if forced_macro:
            _validate_tool_decision(forced_macro)
            return {"state": st, "pending": forced_macro}

        # Enforce tool ordering: analysis first, patching last.
        remaining = cfg.max_steps - len(st.steps)
        tool = str(decision.get("tool", "")).strip()
        if tool in {"read_artifact", "make_error_patch_override", "make_extra_patch_override"}:
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
                    "steps": _steps_for_output(st),
                    "error": _error_payload(st),
                },
            }

        if tool == "make_error_patch_override" and st.artifacts_dir and _last_tool_call_name(st) != "read_artifact":
            if remaining >= 3:
                st.pending_patch = decision
                artifact_path = (
                    str(getattr(st, "loop_base_func_code_artifact_path", "") or "").strip()
                    or _last_artifact_path(st, "get_error_patch_context", "error_func_code")
                    or _last_artifact_path(st, "get_error_patch_context", "patch_minus_code")
                    or _last_artifact_path(st, "get_error_patch_context", "excerpt")
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
                    "steps": _steps_for_output(st),
                    "error": _error_payload(st),
                },
            }

        return {"state": st, "pending": decision}

    def tool_node(gs: GraphState) -> GraphState:
        st = gs["state"]
        decision = gs["pending"]
        tool = str(decision["tool"])
        # Patch-scope: always run patch tools against the current effective patch bundle.
        if st.error_scope == "patch" and st.patch_path and tool in _PATCH_TOOLS_WITH_PATCH_PATH:
            args_obj = decision.get("args")
            if not isinstance(args_obj, dict):
                args_obj = {}
                decision["args"] = args_obj
            args_obj["patch_path"] = str(st.patch_path)

        args = dict(decision.get("args", {}))
        obs = runner.call(tool, args)
        obs = _enforce_patch_key_scope(st, obs)
        if artifact_store and obs.ok and obs.tool != "read_artifact":
            offloaded = offload_patch_output(
                store=artifact_store, tool=obs.tool, args=obs.args, output=obs.output, focus_terms=_collect_focus_terms(st)
            )
            if offloaded is not obs.output:
                obs = ToolObservation(ok=obs.ok, tool=obs.tool, args=obs.args, output=offloaded, error=obs.error)
        step_rec = {"decision": decision, "observation": obs.__dict__}
        st.steps.append(step_rec)
        st.step_history.append(step_rec)
        st.last_observation = obs

        if obs.ok and obs.tool == "get_error_patch_context" and isinstance(obs.output, dict):
            st.active_patch_key = str(obs.output.get("patch_key") or st.active_patch_key or st.patch_key or "").strip()
            st.active_file_path = str(obs.output.get("file_path") or st.active_file_path or "").strip()
            st.active_line_number = int(obs.output.get("line_number", 0) or st.active_line_number or 0)
            st.active_old_signature = str(obs.output.get("old_signature") or st.active_old_signature or "").strip()
            st.pre_patch_file_path = str(obs.output.get("pre_patch_file_path") or st.pre_patch_file_path or "").strip()
            st.pre_patch_line_number = int(obs.output.get("pre_patch_line_number", 0) or st.pre_patch_line_number or 0)
            fs = obs.output.get("func_start_index")
            fe = obs.output.get("func_end_index")
            if isinstance(fs, int):
                st.active_func_start_index = fs
            if isinstance(fe, int):
                st.active_func_end_index = fe
            excerpt = obs.output.get("excerpt")
            if isinstance(excerpt, dict):
                st.active_excerpt_artifact_path = str(excerpt.get("artifact_path", "") or "").strip()
            patch_minus = obs.output.get("patch_minus_code")
            if isinstance(patch_minus, dict):
                st.active_patch_minus_code_artifact_path = str(patch_minus.get("artifact_path", "") or "").strip()
            err_func = obs.output.get("error_func_code")
            if isinstance(err_func, dict):
                st.active_error_func_code_artifact_path = str(err_func.get("artifact_path", "") or "").strip()
            missing = obs.output.get("macro_tokens_not_defined_in_slice")
            if isinstance(missing, list):
                st.macro_tokens_not_defined_in_slice = [str(x) for x in missing if str(x).strip()][:200]
        if obs.ok and obs.tool == "make_error_patch_override":
            st.patch_generated = True
            st.patch_result = obs.output if isinstance(obs.output, dict) else None
            st.pending_patch = None
            if isinstance(obs.output, dict):
                st.active_patch_key = str(obs.output.get("patch_key") or st.active_patch_key or st.patch_key or "").strip()
                st.active_file_path = str(obs.output.get("file_path") or st.active_file_path or "").strip()
                st.active_line_number = int(obs.output.get("line_number", 0) or st.active_line_number or 0)
                st.active_old_signature = str(obs.output.get("old_signature") or st.active_old_signature or "").strip()
                fs = obs.output.get("func_start_index")
                fe = obs.output.get("func_end_index")
                if isinstance(fs, int):
                    st.active_func_start_index = fs
                if isinstance(fe, int):
                    st.active_func_end_index = fe

            patch_text = ""
            patch_text_path = ""
            hiden_func_dict_updated = None
            if isinstance(st.patch_result, dict):
                hiden_func_dict_updated = st.patch_result.get("hiden_func_dict_updated")
                pt = st.patch_result.get("patch_text")
                if isinstance(pt, dict):
                    patch_text_path = str(pt.get("artifact_path", "") or "").strip()
                    if patch_text_path:
                        try:
                            patch_text = _read_text(patch_text_path)
                        except Exception:
                            patch_text = ""
                elif isinstance(pt, str):
                    patch_text = pt

            if patch_text.strip():
                effective_path, effective_err = _write_effective_patch_bundle(
                    st,
                    patch_key=str(st.active_patch_key or st.patch_key or "").strip(),
                    patch_text=patch_text,
                    hiden_func_dict_updated=hiden_func_dict_updated,
                )
                if effective_path and not effective_err:
                    st.patch_path = effective_path
                    # The bundle now contains the rewritten patch_text; no separate override diff is required.
                    st.patch_override_paths = []
                elif patch_text_path:
                    st.patch_override_paths = [patch_text_path]
            elif patch_text_path:
                st.patch_override_paths = [patch_text_path]
        if obs.ok and obs.tool == "make_extra_patch_override":
            st.patch_result = obs.output if isinstance(obs.output, dict) else None
            st.pending_patch = None

            patch_text = ""
            patch_text_path = ""
            extra_patch_key = ""
            if isinstance(st.patch_result, dict):
                extra_patch_key = str(st.patch_result.get("patch_key", "") or "").strip()
                pt = st.patch_result.get("patch_text")
                if isinstance(pt, dict):
                    patch_text_path = str(pt.get("artifact_path", "") or "").strip()
                    if patch_text_path:
                        try:
                            patch_text = _read_text(patch_text_path)
                        except Exception:
                            patch_text = ""
                elif isinstance(pt, str):
                    patch_text = pt

            has_patch = bool(patch_text.strip()) or bool(patch_text_path)
            if not has_patch:
                # Tool ran but did not emit an override diff (e.g. symbol not found); do not trigger OSS-Fuzz test.
                st.patch_generated = False
            else:
                st.patch_generated = True

            if patch_text.strip() and extra_patch_key:
                effective_path, effective_err = _write_effective_patch_bundle(
                    st,
                    patch_key=extra_patch_key,
                    patch_text=patch_text,
                )
                if effective_path and not effective_err:
                    st.patch_path = effective_path
                    st.patch_override_paths = []
                elif patch_text_path and patch_text_path not in st.patch_override_paths:
                    st.patch_override_paths.append(patch_text_path)
            elif patch_text_path and patch_text_path not in st.patch_override_paths:
                st.patch_override_paths.append(patch_text_path)
        if obs.tool == "ossfuzz_apply_patch_and_test":
            st.ossfuzz_test_attempted = True
            if obs.ok:
                st.ossfuzz_runs_attempted += 1
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
    # LangGraph has a default recursion limit of 25, which can be too low for patch-scope
    # workflows where we may loop llm<->tool multiple times (e.g. iterative OSS-Fuzz runs).
    # Keep this configurable and default it based on max_steps.
    recursion_limit = int(cfg.recursion_limit or 0)
    if recursion_limit <= 0:
        recursion_limit = max(25, int(cfg.max_steps or 0) * 8 + 25)
    # LangGraph/shim compatibility:
    # - real langgraph compiled graphs accept `invoke(input, config=...)` (RunnableConfig)
    # - our langgraph_shim `_CompiledGraph.invoke(initial)` accepts no config at all
    invoke_sig = None
    try:
        invoke_sig = inspect.signature(compiled.invoke)  # type: ignore[arg-type]
    except Exception:
        invoke_sig = None

    if invoke_sig and ("config" in invoke_sig.parameters or any(p.kind == p.VAR_KEYWORD for p in invoke_sig.parameters.values())):
        result = compiled.invoke({"state": state}, config={"recursion_limit": recursion_limit})
    else:
        result = compiled.invoke({"state": state})
    final = result.get("final")
    if final:
        return final
    return {
        "type": "final",
        "thought": "Reached max tool steps without a final decision.",
        "summary": "Stopped after max_steps.",
        "next_step": "Increase --max-steps or review the last observation and proceed manually.",
        "steps": _steps_for_output(state),
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
        "--recursion-limit",
        type=int,
        default=int(os.environ.get("REACT_AGENT_RECURSION_LIMIT", "0") or 0),
        help="LangGraph recursion_limit (0=auto based on --max-steps; increase if you hit the default limit of 25).",
    )
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

    parser.add_argument(
        "--debug-llm",
        action="store_true",
        default=str(os.environ.get("REACT_AGENT_DEBUG_LLM", "") or "").strip().lower() in {"1", "true", "yes", "y", "on"},
        help="Print full LLM request/response messages to stderr (for debugging).",
    )
    parser.add_argument(
        "--debug-llm-dir",
        default=os.environ.get("REACT_AGENT_DEBUG_LLM_DIR", ""),
        help="If set, also write each LLM request/response as JSON under this directory.",
    )

    # OSS-Fuzz testing (mandatory after patch generation in patch-scope runs)
    parser.add_argument("--ossfuzz-project", default=os.environ.get("REACT_AGENT_OSSFUZZ_PROJECT", ""))
    parser.add_argument("--ossfuzz-commit", default=os.environ.get("REACT_AGENT_OSSFUZZ_COMMIT", ""))
    parser.add_argument("--ossfuzz-build-csv", default=os.environ.get("REACT_AGENT_OSSFUZZ_BUILD_CSV", ""))
    parser.add_argument("--ossfuzz-sanitizer", default=os.environ.get("REACT_AGENT_OSSFUZZ_SANITIZER", "address"))
    parser.add_argument("--ossfuzz-arch", default=os.environ.get("REACT_AGENT_OSSFUZZ_ARCH", "x86_64"))
    parser.add_argument("--ossfuzz-engine", default=os.environ.get("REACT_AGENT_OSSFUZZ_ENGINE", "libfuzzer"))
    parser.add_argument("--ossfuzz-fuzz-target", default=os.environ.get("REACT_AGENT_OSSFUZZ_FUZZ_TARGET", ""))
    parser.add_argument("--ossfuzz-use-sudo", action="store_true", default=bool(os.environ.get("REACT_AGENT_OSSFUZZ_USE_SUDO", "")))
    parser.add_argument(
        "--auto-ossfuzz-loop",
        action="store_true",
        default=str(os.environ.get("REACT_AGENT_AUTO_OSSFUZZ_LOOP", "") or "").strip().lower() in {"1", "true", "yes", "y", "on"},
        help="After each OSS-Fuzz run, re-parse logs and keep iterating within the same patch_key until clean (patch-scope only).",
    )
    parser.add_argument(
        "--ossfuzz-loop-max",
        type=int,
        default=int(os.environ.get("REACT_AGENT_OSSFUZZ_LOOP_MAX", "3") or 3),
        help="Max ossfuzz_apply_patch_and_test tool calls when --auto-ossfuzz-loop is enabled (includes the first run).",
    )
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
        recursion_limit=int(getattr(args, "recursion_limit", 0) or 0),
        debug_llm=bool(getattr(args, "debug_llm", False)),
        debug_llm_dir=str(getattr(args, "debug_llm_dir", "") or "").strip(),
        auto_ossfuzz_loop=bool(getattr(args, "auto_ossfuzz_loop", False)),
        ossfuzz_loop_max=max(int(getattr(args, "ossfuzz_loop_max", 0) or 0), 1),
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
    active_old_signature = ""
    function_groups: List[Dict[str, Any]] = []
    function_groups_total: int = 0
    function_groups_truncated: bool = False
    # Full unfiltered list of compiler errors mapped to the selected patch_key (used for history union).
    full_grouped_for_history: List[Dict[str, Any]] = []

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
                enriched["func_start_index"] = mapping.get("func_start_index")
                enriched["func_end_index"] = mapping.get("func_end_index")
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
                full_grouped = _prioritize_warnings_within_hunk(groups[patch_key])
                full_grouped_for_history = list(full_grouped)
                function_groups, function_groups_total, function_groups_truncated = _summarize_function_groups(full_grouped)
                grouped_errors = full_grouped
                # If this patch_key is a merged/tail hunk (multiple old_signature values), further
                # scope to a single function at a time to keep the agent focused.
                grouped_errors, active_old_signature = _select_function_group_errors(grouped_errors)
                if grouped_errors:
                    error_line = str(grouped_errors[0].get("raw", error_line))
                    snippet = str(grouped_errors[0].get("snippet", snippet))
                    if not active_old_signature:
                        active_old_signature = str(grouped_errors[0].get("old_signature", "") or "").strip()
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

    active_patch_key = str(patch_key or "").strip()
    active_file_path = ""
    active_line_number = 0
    active_func_start_index: Optional[int] = None
    active_func_end_index: Optional[int] = None
    if grouped_errors:
        active_file_path = str(grouped_errors[0].get("file", "") or "").strip()
        active_line_number = int(grouped_errors[0].get("line", 0) or 0)
    else:
        m = _ERROR_LOC_RE.match(str(error_line or "").strip())
        if m:
            active_file_path = str(m.group("file") or "").strip()
            active_line_number = int(m.group("line") or 0)

    if cfg.error_scope == "patch" and patch_path and active_file_path and active_line_number > 0:
        try:
            from tools.migration_tools import get_error_patch as map_error_patch  # noqa: PLC0415

            mapping = map_error_patch(patch_path=patch_path, file_path=active_file_path, line_number=active_line_number)
            if isinstance(mapping, dict):
                if not active_patch_key:
                    active_patch_key = str(mapping.get("patch_key") or "").strip()
                fs = mapping.get("func_start_index")
                fe = mapping.get("func_end_index")
                if isinstance(fs, int):
                    active_func_start_index = fs
                if isinstance(fe, int):
                    active_func_end_index = fe
        except Exception:
            pass

    artifact_store, artifacts_dir = resolve_artifact_dir(
        disabled=bool(args.no_artifacts),
        patch_key=patch_key,
        patch_key_overwrite=not bool(cfg.auto_ossfuzz_loop),
    )
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
            # When users point both --v1-src/--v2-src at the same worktree (or use a checkout at a different
            # revision than the KB JSON), SourceManager may not be able to read KB-referenced files. Provide
            # best-effort git commit hints so SourceManager can fall back to `git show <commit>:<path>`.
            if not str(os.environ.get("REACT_AGENT_V1_SRC_COMMIT", "") or "").strip():
                inferred = _infer_commitish_from_path(str(args.v1_json_dir))
                if inferred:
                    os.environ["REACT_AGENT_V1_SRC_COMMIT"] = inferred
            if not str(os.environ.get("REACT_AGENT_V2_SRC_COMMIT", "") or "").strip():
                inferred = _infer_commitish_from_path(str(args.v2_json_dir)) or str(ossfuzz_commit or "").strip()
                if inferred:
                    os.environ["REACT_AGENT_V2_SRC_COMMIT"] = inferred
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
            active_patch_key=active_patch_key,
            active_file_path=active_file_path,
            active_line_number=active_line_number,
            active_func_start_index=active_func_start_index,
            active_func_end_index=active_func_end_index,
            active_old_signature=active_old_signature,
            grouped_errors=grouped_errors,
            function_groups=function_groups,
            function_groups_total=function_groups_total,
            function_groups_truncated=function_groups_truncated,
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
        if full_grouped_for_history:
            _update_function_error_history(state, full_grouped_for_history)
        _record_current_error_group(state)

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
