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
    active_patch_types: List[str]
    active_patch_is_merged: bool
    missing_struct_members: bool
    undeclared_symbol: bool
    macro_tokens_not_defined_in_slice: bool
    incomplete_type: bool
    missing_prototypes: bool
    linker_error: bool
    func_sig_change: bool  # "too few/many arguments to function call"
    conflicting_types: bool  # "conflicting types for 'func'"


_FRAGMENT_CACHE: Dict[str, str] = {}
_UNDECLARED_SYMBOL_SNIPPETS = (
    "use of undeclared identifier",
    "call to undeclared function",
    "unknown type name",
    "implicit declaration of function",
)


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
    active_patch_types = getattr(state, "active_patch_types", None)
    if not isinstance(active_patch_types, list):
        active_patch_types = []
    patch_is_merged = any("merged" in str(pt).lower() for pt in active_patch_types)
    err_lower = error_line.lower()
    snip_lower = snippet.lower()
    missing_struct_members = bool(getattr(state, "missing_struct_members", None) or []) or ("no member named" in error_line)
    undeclared_symbol = any(s in err_lower for s in _UNDECLARED_SYMBOL_SNIPPETS)
    macro_tokens_not_defined_in_slice = bool(getattr(state, "macro_tokens_not_defined_in_slice", None) or [])
    incomplete_type = ("incomplete" in err_lower and "type" in err_lower) or ("incomplete" in snip_lower and "type" in snip_lower)
    missing_prototypes = ("no previous prototype" in err_lower) or ("missing-prototypes" in err_lower)
    linker_error = "undefined reference to" in err_lower or "undefined reference to" in snip_lower
    func_sig_change = ("too few arguments" in err_lower) or ("too many arguments" in err_lower)
    # Only handle conflicting_types when there are NO undeclared symbol errors.
    # Undeclared function errors are the root cause; fixing them properly resolves the conflict.
    conflicting_types = ("conflicting types for" in err_lower or "conflicting types for" in snip_lower) and not undeclared_symbol
    return PromptContext(
        error_scope=error_scope,
        snippet=snippet,
        error_line=error_line,
        active_old_signature=active_old_signature,
        active_patch_types=active_patch_types,
        active_patch_is_merged=patch_is_merged,
        missing_struct_members=missing_struct_members,
        undeclared_symbol=undeclared_symbol,
        macro_tokens_not_defined_in_slice=macro_tokens_not_defined_in_slice,
        incomplete_type=incomplete_type,
        missing_prototypes=missing_prototypes,
        linker_error=linker_error,
        func_sig_change=func_sig_change,
        conflicting_types=conflicting_types,
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

    if ctx.error_scope == "patch" and ctx.active_old_signature:
        mapped_slice = _load_fragment("system_mapped_slice_rewrite.txt")
        if mapped_slice:
            parts.append(mapped_slice)
        if ctx.active_patch_is_merged:
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

    if ctx.undeclared_symbol:
        undeclared = _load_fragment("system_undeclared_symbol.txt")
        if undeclared:
            parts.append(undeclared)

    if ctx.incomplete_type:
        incomplete_type = _load_fragment("system_incomplete_type.txt")
        if incomplete_type:
            parts.append(incomplete_type)

    if ctx.missing_prototypes:
        missing_prototypes = _load_fragment("system_missing_prototypes.txt")
        if missing_prototypes:
            parts.append(missing_prototypes)

    if ctx.linker_error:
        linker_error = _load_fragment("system_linker_error.txt")
        if linker_error:
            parts.append(linker_error)

    if ctx.func_sig_change:
        func_sig_change = _load_fragment("system_func_sig_change.txt")
        if func_sig_change:
            parts.append(func_sig_change)

    if ctx.conflicting_types:
        conflicting_types = _load_fragment("system_conflicting_types.txt")
        if conflicting_types:
            parts.append(conflicting_types)

    prompt = "\n\n".join(p for p in parts if str(p or "").strip()).strip()

    # Optional debugging: include the assembled prompt section names.
    if str(os.environ.get("REACT_AGENT_PROMPT_DEBUG", "") or "").strip().lower() in {"1", "true", "yes", "y", "on"}:
        names = ["system_base.txt", "system_tools.txt"]
        if ctx.error_scope == "patch":
            names.append("system_patch_scope.txt")
        if ctx.error_scope == "patch" and ctx.active_old_signature:
            names.append("system_mapped_slice_rewrite.txt")
            if ctx.active_patch_is_merged:
                names.append("system_merged_tail.txt")
        if _needs_macro_guidance(ctx):
            names.append("system_macro.txt")
        if ctx.missing_struct_members:
            names.append("system_struct_members.txt")
        if ctx.undeclared_symbol:
            names.append("system_undeclared_symbol.txt")
        if ctx.incomplete_type:
            names.append("system_incomplete_type.txt")
        if ctx.missing_prototypes:
            names.append("system_missing_prototypes.txt")
        if ctx.linker_error:
            names.append("system_linker_error.txt")
        if ctx.func_sig_change:
            names.append("system_func_sig_change.txt")
        if ctx.conflicting_types:
            names.append("system_conflicting_types.txt")
        prompt = f"[prompt_sections={','.join(names)}]\n\n{prompt}".strip()

    return prompt + "\n"
