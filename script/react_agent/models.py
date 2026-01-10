from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


Message = Dict[str, str]


class ModelError(RuntimeError):
    """Raised when a model invocation fails."""


class ChatModel:
    """Minimal chat-model interface."""

    def complete(self, messages: List[Message]) -> str:  # noqa: D401
        """Return the assistant message content."""
        raise NotImplementedError


_COMPILER_ERROR_RE = re.compile(r"^(?P<file>[^:\n]+):(?P<line>\d+):(?P<col>\d+):\s*(?:fatal\s+)?error:\s*(?P<msg>.*)$")

@dataclass(frozen=True)
class ModelResponseDebug:
    status_code: Optional[int]
    content_type: str
    raw_body: str
    raw_body_truncated: bool
    parsed_finish_reason: str


@dataclass
class StubModel(ChatModel):
    """Offline model that emits deterministic tool calls for tests."""

    _turn: int = 0

    def complete(self, messages: List[Message]) -> str:
        self._turn += 1

        user_text = "\n".join(m.get("content", "") for m in messages if m.get("role") == "user")
        if "You MUST generate a patch now by calling make_error_patch_override" in user_text:
            # Runtime guardrail prompt: force a patch-generation tool call.
            match = None
            error_line = ""
            for m in messages:
                if m.get("role") != "user":
                    continue
                for line in m.get("content", "").splitlines():
                    if _COMPILER_ERROR_RE.match(line.strip()):
                        error_line = line.strip()
                        break
                if error_line:
                    break
            match = _COMPILER_ERROR_RE.match(error_line)
            msg = match.group("msg") if match else ""
            file_path = match.group("file") if match else ""
            line_number = int(match.group("line")) if match else 0

            patch_path = ""
            for line in user_text.splitlines():
                if line.startswith("Patch bundle path:"):
                    patch_path = line.split(":", 1)[1].strip()
                    break

            # Provide a small deterministic replacement. Real runs should use the artifact content.
            new_func_code = (
                "int __revert_stub(void) {\n"
                "  /* Stub replacement used by offline tests.\n"
                "   * Real runs should adapt V1-origin usage to V2 semantics.\n"
                "   */\n"
                "  return 0;\n"
                "}\n"
            )
            if patch_path and file_path and line_number > 0 and ("no member named" in msg or "unknown type name" in msg or msg):
                return json.dumps(
                    {
                        "type": "tool",
                        "thought": "Forced by runtime guardrail: generate a patch now.",
                        "tool": "make_error_patch_override",
                        "args": {
                            "patch_path": patch_path,
                            "file_path": file_path,
                            "line_number": line_number,
                            "new_func_code": new_func_code,
                            "context_lines": 8,
                            "max_lines": 2000,
                            "max_chars": 200000,
                        },
                    }
                )

        if "suggests modifying V2 type definitions" in user_text and "Rewrite it into a V2-usage-adaptation plan" in user_text:
            return json.dumps(
                {
                    "type": "final",
                    "thought": "Avoid changing shared V2 type layouts; adapt call sites.",
                    "summary": "Rewrite: do not modify V2 type definitions.",
                    "next_step": (
                        "Adapt the migrated (V1-origin) code to V2 semantics: remove/replace the missing field usage using V2 APIs/fields.\n"
                        "V2 type definition edits are out-of-policy and require human review."
                    ),
                }
            )
        observation_count = sum(
            1 for m in messages if m.get("role") == "user" and "Observation:" in m.get("content", "")
        )

        patch_path = ""
        for line in user_text.splitlines():
            if line.startswith("Patch bundle path:"):
                patch_path = line.split(":", 1)[1].strip()
                break

        build_log_path = ""
        for line in user_text.splitlines():
            if line.startswith("Build log path:"):
                build_log_path = line.split(":", 1)[1].strip()
                break

        # Find the first error line in the conversation.
        error_line = ""
        for m in messages:
            if m.get("role") != "user":
                continue
            for line in m.get("content", "").splitlines():
                if _COMPILER_ERROR_RE.match(line.strip()):
                    error_line = line.strip()
                    break
            if error_line:
                break

        match = _COMPILER_ERROR_RE.match(error_line)
        msg = match.group("msg") if match else ""
        file_path = match.group("file") if match else ""
        line_number = int(match.group("line")) if match else 0

        # Patch-aware triage: migrated logs -> map to patch first.
        if patch_path and "unknown type name" in msg:
            if observation_count == 0:
                args: Dict[str, str] = {"build_log_text": error_line}
                if build_log_path and build_log_path != "-":
                    args = {"build_log_path": build_log_path}
                return json.dumps(
                    {
                        "type": "tool",
                        "thought": "Parse the build log into structured errors first.",
                        "tool": "parse_build_errors",
                        "args": args,
                    }
                )
            if observation_count == 1:
                return json.dumps(
                    {
                        "type": "tool",
                        "thought": "Map the migrated error location to a patch and inspect a bounded diff excerpt.",
                        "tool": "get_error_patch_context",
                        "args": {
                            "patch_path": patch_path,
                            "file_path": file_path,
                            "line_number": line_number,
                            "error_text": error_line,
                            "context_lines": 30,
                            "max_total_lines": 200,
                        },
                    }
                )
            return json.dumps(
                {
                    "type": "final",
                    "thought": "Sufficient evidence collected; propose next investigation step.",
                    "summary": "Stub model completed patch-aware triage steps.",
                    "next_step": "Use the excerpt to identify missing typedef/include/macro and locate its definition in V1.",
                }
            )

        # Patch-aware triage for missing struct members: compare struct definitions in V1 vs V2.
        if patch_path and "no member named" in msg and "struct" in msg:
            st = re.search(r"no member named '[^']+' in '([^']+)'", msg)
            struct_symbol = st.group(1).strip() if st else ""
            if observation_count == 0:
                return json.dumps(
                    {
                        "type": "tool",
                        "thought": "Map the migrated error location to a patch and inspect a bounded diff excerpt.",
                        "tool": "get_error_patch_context",
                        "args": {
                            "patch_path": patch_path,
                            "file_path": file_path,
                            "line_number": line_number,
                            "error_text": error_line,
                            "context_lines": 30,
                            "max_total_lines": 200,
                        },
                    }
                )
            if observation_count == 1:
                return json.dumps(
                    {
                        "type": "tool",
                        "thought": "Extract the V1-origin function body from the patch to understand the V1 usage.",
                        "tool": "get_error_v1_code_slice",
                        "args": {
                            "patch_path": patch_path,
                            "file_path": file_path,
                            "line_number": line_number,
                            "max_lines": 200,
                            "max_chars": 12000,
                        },
                    }
                )
            if observation_count == 2:
                return json.dumps(
                    {
                        "type": "tool",
                        "thought": "Fetch the struct definition in V1 (the migrated code is V1-origin).",
                        "tool": "search_definition",
                        "args": {"symbol_name": struct_symbol, "version": "v1"},
                    }
                )
            if observation_count == 3:
                return json.dumps(
                    {
                        "type": "tool",
                        "thought": "Fetch the struct definition in V2 to compare and infer member drift.",
                        "tool": "search_definition",
                        "args": {"symbol_name": struct_symbol, "version": "v2"},
                    }
                )
            if observation_count == 4:
                if os.environ.get("REACT_AGENT_STUB_SUGGEST_V2_TYPE_EDIT", "").strip():
                    return json.dumps(
                        {
                            "type": "final",
                            "thought": "A fast fix is to add the missing fields back, but this may be unsafe.",
                            "summary": "Option A: add missing members to the struct definition in V2 headers.",
                            "next_step": "Add the missing fields to the struct definition in the V2 header so the migrated code compiles.",
                        }
                    )
                # In the real agent flow, read_artifact should happen immediately before
                # make_error_patch_override (enforced by runtime guardrails).
                new_func_code = (
                    "int __revert_stub(void) {\n"
                    "  /* Stub replacement used by offline tests.\n"
                    "   * Real runs should adapt V1-origin usage to V2 semantics.\n"
                    "   */\n"
                    "  return 0;\n"
                    "}\n"
                )
                return json.dumps(
                    {
                        "type": "tool",
                        "thought": "Generate a patch that replaces the migrated (V1-origin) function body with an adapted version.",
                        "tool": "make_error_patch_override",
                        "args": {
                            "patch_path": patch_path,
                            "file_path": file_path,
                            "line_number": line_number,
                            "new_func_code": new_func_code,
                            "context_lines": 8,
                            "max_lines": 2000,
                            "max_chars": 200000,
                        },
                    }
                )
            return json.dumps(
                {
                    "type": "final",
                    "thought": "Collected patch context and both struct definitions; ready to propose a migration hint.",
                    "summary": "Stub model completed cross-version struct-member triage steps.",
                    "next_step": "Compare the V1 vs V2 struct fields and decide whether the member was renamed/removed; update the migrated code accordingly.",
                }
            )

        # Patch-aware fallback: never use read_file_context with raw build-log line numbers.
        if patch_path:
            if observation_count == 0:
                return json.dumps(
                    {
                        "type": "tool",
                        "thought": "Patch-aware run: map the build error to a patch excerpt first.",
                        "tool": "get_error_patch_context",
                        "args": {
                            "patch_path": patch_path,
                            "file_path": file_path,
                            "line_number": line_number,
                            "error_text": error_line,
                            "context_lines": 30,
                            "max_total_lines": 200,
                        },
                    }
                )
            if observation_count == 1:
                pre_file = file_path
                pre_line = None
                try:
                    from tools.migration_tools import get_error_patch_context as map_ctx  # noqa: PLC0415

                    ctx = map_ctx(
                        patch_path=patch_path,
                        file_path=file_path,
                        line_number=line_number,
                        error_text=error_line,
                        context_lines=5,
                        max_total_lines=80,
                    )
                    pre_file_raw = ctx.get("pre_patch_file_path")
                    pre_line_raw = ctx.get("pre_patch_line_number")
                    if isinstance(pre_file_raw, str) and pre_file_raw.strip():
                        pre_file = pre_file_raw.strip()
                    if isinstance(pre_line_raw, int) and pre_line_raw > 0:
                        pre_line = pre_line_raw
                except Exception:
                    pre_line = None

                if pre_line is None:
                    return json.dumps(
                        {
                            "type": "final",
                            "thought": "Pre-patch line mapping unavailable; rely on patch excerpt and KB locations instead of reading by build-log line numbers.",
                            "summary": "Stopped after patch mapping.",
                            "next_step": "Use search_definition to get source-checkout locations, or inspect the patch excerpt directly.",
                        }
                    )
                return json.dumps(
                    {
                        "type": "tool",
                        "thought": "Read source context using the pre-patch mapped line number (not the raw build-log line).",
                        "tool": "read_file_context",
                        "args": {"file_path": pre_file, "line_number": pre_line, "context": 5, "version": "v2"},
                    }
                )
            return json.dumps(
                {
                    "type": "final",
                    "thought": "Sufficient evidence collected; propose next investigation step.",
                    "summary": "Stub model completed patch-aware triage steps.",
                    "next_step": "Review the patch excerpt + pre-patch source context and decide the minimal fix.",
                }
            )

        # After at least one observation, return a final response.
        if observation_count >= 1 and self._turn > 1:
            return json.dumps(
                {
                    "type": "final",
                    "thought": "Sufficient evidence collected; propose next investigation step.",
                    "summary": "Stub model completed one tool step.",
                    "next_step": "Run the suggested tool call output through a human review or a patch generator.",
                }
            )

        # Heuristics aligned with TASKS.md.
        if "implicit declaration of function" in msg:
            fn = re.search(r"implicit declaration of function\s+'([^']+)'", msg)
            symbol = fn.group(1) if fn else ""
            return json.dumps(
                {
                    "type": "tool",
                    "thought": "Implicit function declaration; inspect the function symbol across versions.",
                    "tool": "search_definition",
                    "args": {"symbol_name": symbol, "version": "v2"},
                }
            )
        if "no member named" in msg and "struct" in msg:
            st = re.search(r"in 'struct\s+([^']+)'", msg)
            struct_name = st.group(1) if st else ""
            return json.dumps(
                {
                    "type": "tool",
                    "thought": "Struct member missing; inspect the struct symbol across versions.",
                    "tool": "search_definition",
                    "args": {"symbol_name": f"struct {struct_name}" if struct_name else "", "version": "v2"},
                }
            )
        if "unknown type name" in msg:
            ty = re.search(r"unknown type name\s+'([^']+)'", msg)
            type_name = ty.group(1) if ty else ""
            return json.dumps(
                {
                    "type": "tool",
                    "thought": "Unknown type; search its definition in V1.",
                    "tool": "search_definition",
                    "args": {"symbol_name": type_name, "version": "v1"},
                }
            )

        return json.dumps(
            {
                "type": "tool",
                "thought": "Need more context; read source around the error line.",
                "tool": "read_file_context",
                "args": {"file_path": file_path, "line_number": line_number, "context": 5, "version": "v2"},
            }
        )


@dataclass
class OpenAIChatCompletionsModel(ChatModel):
    """Direct OpenAI Chat Completions client implemented with stdlib HTTP."""

    api_key: str
    model: str
    base_url: str = "https://api.openai.com/v1"
    org: str = ""
    project: str = ""
    temperature: float = 0.0
    max_tokens: int = 800
    json_mode: bool = True
    reasoning_effort: str = "low"
    timeout_s: int = 120
    max_debug_body_chars: int = 200_000

    @classmethod
    def from_env(cls) -> "OpenAIChatCompletionsModel":
        api_key = os.environ.get("OPENAI_API_KEY", "").strip()
        model = os.environ.get("OPENAI_MODEL", "").strip() or "gpt-4o-mini"
        base_url = os.environ.get("OPENAI_BASE_URL", "").strip() or "https://api.openai.com/v1"
        org = os.environ.get("OPENAI_ORG", "").strip()
        project = os.environ.get("OPENAI_PROJECT", "").strip()
        if not api_key:
            raise ModelError("OPENAI_API_KEY is required")
        return cls(api_key=api_key, model=model, base_url=base_url, org=org, project=project)

    def complete_with_raw(self, messages: List[Message]) -> tuple[str, ModelResponseDebug]:
        url = self.base_url.rstrip("/") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if self.org:
            headers["OpenAI-Organization"] = self.org
        if self.project:
            headers["OpenAI-Project"] = self.project
        base_payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
        }
        if not self.model.startswith(("gpt-5", "o")):
            base_payload["temperature"] = self.temperature
        if self.model.startswith(("gpt-5", "o")) and str(self.reasoning_effort).strip():
            base_payload["reasoning_effort"] = str(self.reasoning_effort).strip()
        if self.json_mode:
            base_payload["response_format"] = {"type": "json_object"}

        token_fields = ["max_tokens", "max_completion_tokens"]
        if self.model.startswith(("gpt-5", "o")):
            token_fields = ["max_completion_tokens", "max_tokens"]

        raw = ""
        raw_for_debug = ""
        status_code: Optional[int] = None
        content_type: str = ""
        last_http_error: Optional[urllib.error.HTTPError] = None
        last_http_detail = ""
        raw_body_truncated = False

        for idx, token_field in enumerate(token_fields):
            payload = dict(base_payload)
            payload[token_field] = self.max_tokens
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    status_code = int(getattr(resp, "status", 0) or 0) or int(resp.getcode() or 0)
                    content_type = str(resp.headers.get("Content-Type", "") or "")
                    raw = resp.read().decode("utf-8", errors="replace")
                raw_for_debug = raw
                if self.max_debug_body_chars and len(raw_for_debug) > int(self.max_debug_body_chars):
                    raw_for_debug = raw_for_debug[: int(self.max_debug_body_chars)]
                    raw_body_truncated = True
                last_http_error = None
                break
            except urllib.error.HTTPError as e:
                last_http_error = e
                last_http_detail = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else str(e)
                unsupported_param = None
                unsupported_code = None
                try:
                    err_data = json.loads(last_http_detail)
                    err_obj = err_data.get("error", {}) if isinstance(err_data, dict) else {}
                    if isinstance(err_obj, dict):
                        unsupported_param = err_obj.get("param")
                        unsupported_code = err_obj.get("code")
                except Exception:  # noqa: BLE001
                    pass

                can_retry = (
                    e.code == 400
                    and (unsupported_code == "unsupported_parameter" or "Unsupported parameter" in last_http_detail)
                    and (unsupported_param == token_field or f"'{token_field}'" in last_http_detail)
                    and idx < len(token_fields) - 1
                )
                if can_retry:
                    continue
                raise ModelError(f"OpenAI HTTPError: {e.code} {e.reason} {last_http_detail}") from e
            except urllib.error.URLError as e:
                raise ModelError(f"OpenAI URLError: {e}") from e

        if last_http_error is not None:
            raise ModelError(
                f"OpenAI HTTPError: {last_http_error.code} {last_http_error.reason} {last_http_detail}"
            ) from last_http_error

        try:
            if not raw.strip():
                raise ModelError(
                    "Bad OpenAI response: empty body (possible network/proxy block or invalid OPENAI_BASE_URL)."
                )
            if content_type and "json" not in content_type.lower():
                snippet = raw.strip()
                if len(snippet) > 400:
                    snippet = snippet[:400] + "\n...[truncated]"
                raise ModelError(
                    "Bad OpenAI response: expected JSON but got "
                    f"Content-Type={content_type!r} status={status_code}. Body snippet: {snippet!r}"
                )
            data = json.loads(raw)
            choice0 = data.get("choices", [{}])[0] if isinstance(data, dict) else {}
            msg0 = choice0.get("message", {}) if isinstance(choice0, dict) else {}
            content = str(msg0.get("content", "") or "")
            finish_reason = str(choice0.get("finish_reason", "") or "")
            return content, ModelResponseDebug(
                status_code=status_code,
                content_type=content_type,
                raw_body=raw_for_debug,
                raw_body_truncated=raw_body_truncated,
                parsed_finish_reason=finish_reason,
            )
        except ModelError:
            raise
        except json.JSONDecodeError as exc:
            snippet = raw.strip()
            if len(snippet) > 400:
                snippet = snippet[:400] + "\n...[truncated]"
            hint = ""
            if snippet.startswith("<"):
                hint = " (looks like HTML; check network/proxy and OPENAI_BASE_URL)"
            raise ModelError(
                "Bad OpenAI response: invalid JSON"
                f"{hint}. status={status_code} Content-Type={content_type!r} error={exc}. Body snippet: {snippet!r}"
            ) from exc
        except Exception as exc:  # noqa: BLE001
            raise ModelError(
                f"Bad OpenAI response: {type(exc).__name__}: {exc}. status={status_code} Content-Type={content_type!r}"
            ) from exc

    def complete(self, messages: List[Message]) -> str:
        content, _debug = self.complete_with_raw(messages)
        return content
