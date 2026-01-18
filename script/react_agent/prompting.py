from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List


@dataclass(frozen=True)
class PromptContext:
    error_scope: str
    snippet: str
    error_line: str
    active_old_signature: str
    missing_struct_members: bool
    macro_tokens_not_defined_in_slice: bool


_FRAGMENT_CACHE: Dict[str, str] = {}


def _prompt_dir() -> Path:
    return Path(__file__).resolve().parent / "prompts"


def _load_fragment(filename: str) -> str:
    key = str(filename or "").strip()
    if not key:
        return ""
    cached = _FRAGMENT_CACHE.get(key)
    if cached is not None:
        return cached
    path = _prompt_dir() / key
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        text = ""
    out = str(text or "").strip()
    _FRAGMENT_CACHE[key] = out
    return out


def _tools_block(tool_specs: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for spec in tool_specs or []:
        if not isinstance(spec, dict):
            continue
        name = str(spec.get("name", "") or "").strip()
        if not name:
            continue
        args = spec.get("args") if isinstance(spec.get("args"), dict) else {}
        arg_keys = [str(k) for k in args.keys() if str(k).strip()]
        sig = f"{name}({', '.join(arg_keys)})" if arg_keys else f"{name}()"
        lines.append(f"- {sig}")
    return "\n".join(lines).rstrip("\n")


def _context_from_state(state: Any) -> PromptContext:
    error_scope = str(getattr(state, "error_scope", "") or "").strip()
    snippet = str(getattr(state, "snippet", "") or "")
    error_line = str(getattr(state, "error_line", "") or "")
    active_old_signature = str(getattr(state, "active_old_signature", "") or "").strip()
    missing_struct_members = bool(getattr(state, "missing_struct_members", None) or []) or ("no member named" in error_line)
    macro_tokens_not_defined_in_slice = bool(getattr(state, "macro_tokens_not_defined_in_slice", None) or [])
    return PromptContext(
        error_scope=error_scope,
        snippet=snippet,
        error_line=error_line,
        active_old_signature=active_old_signature,
        missing_struct_members=missing_struct_members,
        macro_tokens_not_defined_in_slice=macro_tokens_not_defined_in_slice,
    )


def _needs_macro_guidance(ctx: PromptContext) -> bool:
    if ctx.macro_tokens_not_defined_in_slice:
        return True
    snip = ctx.snippet or ""
    if "expanded from macro" in snip:
        return True
    err = ctx.error_line or ""
    if "expanded from macro" in err:
        return True
    # Heuristic: common macro-driven syntax errors.
    if "expected '}'" in err or "expected ')'" in err:
        return True
    return False


def build_system_prompt(state: Any, *, tool_specs: List[Dict[str, Any]]) -> str:
    ctx = _context_from_state(state)

    parts: List[str] = []
    base = _load_fragment("system_base.txt")
    if base:
        parts.append(base)

    tools_tmpl = _load_fragment("system_tools.txt") or "Available tools:\n{tools}"
    parts.append(tools_tmpl.format(tools=_tools_block(tool_specs)).strip())

    if ctx.error_scope == "patch":
        patch_scope = _load_fragment("system_patch_scope.txt")
        if patch_scope:
            parts.append(patch_scope)

    if ctx.active_old_signature:
        merged_tail = _load_fragment("system_merged_tail.txt")
        if merged_tail:
            parts.append(merged_tail)

    if _needs_macro_guidance(ctx):
        macro = _load_fragment("system_macro.txt")
        if macro:
            parts.append(macro)

    if ctx.missing_struct_members:
        struct_members = _load_fragment("system_struct_members.txt")
        if struct_members:
            parts.append(struct_members)

    prompt = "\n\n".join(p for p in parts if str(p or "").strip()).strip()

    # Optional debugging: include the assembled prompt section names.
    if str(os.environ.get("REACT_AGENT_PROMPT_DEBUG", "") or "").strip().lower() in {"1", "true", "yes", "y", "on"}:
        names = ["system_base.txt", "system_tools.txt"]
        if ctx.error_scope == "patch":
            names.append("system_patch_scope.txt")
        if ctx.active_old_signature:
            names.append("system_merged_tail.txt")
        if _needs_macro_guidance(ctx):
            names.append("system_macro.txt")
        if ctx.missing_struct_members:
            names.append("system_struct_members.txt")
        prompt = f"[prompt_sections={','.join(names)}]\n\n{prompt}".strip()

    return prompt + "\n"

