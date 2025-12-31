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


@dataclass
class StubModel(ChatModel):
    """Offline model that emits deterministic tool calls for tests."""

    _turn: int = 0

    def complete(self, messages: List[Message]) -> str:
        self._turn += 1

        # After at least one observation, return a final response.
        if any(m.get("role") == "user" and "Observation:" in m.get("content", "") for m in messages) and self._turn > 1:
            return json.dumps(
                {
                    "type": "final",
                    "thought": "Sufficient evidence collected; propose next investigation step.",
                    "summary": "Stub model completed one tool step.",
                    "next_step": "Run the suggested tool call output through a human review or a patch generator.",
                }
            )

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

        # Heuristics aligned with TASKS.md.
        if "implicit declaration of function" in msg:
            fn = re.search(r"implicit declaration of function\s+'([^']+)'", msg)
            symbol = fn.group(1) if fn else ""
            return json.dumps(
                {
                    "type": "tool",
                    "thought": "Implicit function declaration; inspect the function symbol across versions.",
                    "tool": "inspect_symbol",
                    "args": {"symbol_name": symbol},
                }
            )
        if "no member named" in msg and "struct" in msg:
            st = re.search(r"in 'struct\s+([^']+)'", msg)
            struct_name = st.group(1) if st else ""
            return json.dumps(
                {
                    "type": "tool",
                    "thought": "Struct member missing; inspect the struct symbol across versions.",
                    "tool": "inspect_symbol",
                    "args": {"symbol_name": struct_name},
                }
            )
        if "unknown type name" in msg:
            ty = re.search(r"unknown type name\s+'([^']+)'", msg)
            type_name = ty.group(1) if ty else ""
            return json.dumps(
                {
                    "type": "tool",
                    "thought": "Unknown type; search its definition in V1.",
                    "tool": "search_definition_in_v1",
                    "args": {"symbol_name": type_name},
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
    timeout_s: int = 60

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

    def complete(self, messages: List[Message]) -> str:
        url = self.base_url.rstrip("/") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if self.org:
            headers["OpenAI-Organization"] = self.org
        if self.project:
            headers["OpenAI-Project"] = self.project
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if self.json_mode:
            payload["response_format"] = {"type": "json_object"}

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else str(e)
            raise ModelError(f"OpenAI HTTPError: {e.code} {e.reason} {detail}") from e
        except urllib.error.URLError as e:
            raise ModelError(f"OpenAI URLError: {e}") from e

        try:
            data = json.loads(raw)
            return str(data["choices"][0]["message"]["content"])
        except Exception as exc:  # noqa: BLE001
            raise ModelError(f"Bad OpenAI response: {type(exc).__name__}: {exc}") from exc
