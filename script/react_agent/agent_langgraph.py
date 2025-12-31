#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, TypedDict

from langgraph.graph import END, StateGraph  # type: ignore

from build_log import find_first_fatal, load_build_log
from agent_tools import AgentTools, KbIndex, SourceManager
from models import ChatModel, ModelError, OpenAIChatCompletionsModel, StubModel
from tools_wrapper import ALLOWED_TOOLS, TOOL_SPECS, ToolObservation, ToolRunner


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


@dataclass
class AgentState:
    error_line: str
    snippet: str
    steps: List[Dict[str, Any]] = field(default_factory=list)
    last_observation: Optional[ToolObservation] = None


class GraphState(TypedDict, total=False):
    state: AgentState
    pending: Decision
    final: Dict[str, Any]


def _extract_first_json_object(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped
    start = stripped.find("{")
    if start < 0:
        return stripped
    depth = 0
    for i in range(start, len(stripped)):
        c = stripped[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return stripped[start : i + 1]
    return stripped[start:]


def _parse_decision(text: str) -> Decision:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        obj = json.loads(_extract_first_json_object(text))

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


def _system_prompt() -> str:
    tools = "\n".join(
        [
            "- inspect_symbol({symbol_name})",
            "- read_file_context({file_path, line_number, context, version})",
            "- search_definition_in_v1({symbol_name})",
        ]
    )
    return (
        "You are a C/C++ build triage agent.\n"
        "You MUST output exactly one JSON object with no extra text.\n"
        "You can either request one tool call, or return a final decision.\n\n"
        "Available tools:\n"
        f"{tools}\n\n"
        "Tool output format:\n"
        '{"type":"tool","tool":"<name>","args":{...},"thought":"<one sentence>"}\n\n'
        "Final output format:\n"
        '{"type":"final","summary":"<short>","next_step":"<short>","thought":"<one sentence>"}'
    )


def _build_messages(state: AgentState) -> List[Dict[str, str]]:
    messages: List[Dict[str, str]] = [
        {"role": "system", "content": _system_prompt()},
        {
            "role": "user",
            "content": "Build error:\n"
            + state.error_line
            + "\n\nContext:\n"
            + state.snippet
            + "\n\nChoose the next best tool call or return a final decision.",
        },
    ]

    for step in state.steps:
        messages.append({"role": "assistant", "content": json.dumps(step["decision"])})
        messages.append({"role": "user", "content": "Observation:\n" + json.dumps(step["observation"])})

    return messages


def _run_langgraph(model: ChatModel, runner: ToolRunner, state: AgentState, cfg: AgentConfig) -> Dict[str, Any]:
    # Build a small two-node graph: LLM -> TOOL -> LLM (until final).
    def llm_node(gs: GraphState) -> GraphState:
        st = gs["state"]
        if len(st.steps) >= cfg.max_steps:
            return {
                "state": st,
                "final": {
                    "type": "final",
                    "thought": "Reached max tool steps without a final decision.",
                    "summary": "Stopped after max_steps.",
                    "next_step": "Increase --max-steps or review the last observation and proceed manually.",
                    "steps": st.steps,
                    "error": {"line": st.error_line, "snippet": st.snippet},
                },
            }
        raw = model.complete(_build_messages(st))
        decision = _parse_decision(raw)
        if decision["type"] == "final":
            return {
                "state": st,
                "final": {
                    "type": "final",
                    "thought": str(decision.get("thought", "")).strip(),
                    "summary": str(decision.get("summary", "")).strip(),
                    "next_step": str(decision.get("next_step", "")).strip(),
                    "steps": st.steps,
                    "error": {"line": st.error_line, "snippet": st.snippet},
                },
            }
        _validate_tool_decision(decision)
        return {"state": st, "pending": decision}

    def tool_node(gs: GraphState) -> GraphState:
        st = gs["state"]
        decision = gs["pending"]
        tool = str(decision["tool"])
        args = dict(decision.get("args", {}))
        obs = runner.call(tool, args)
        st.steps.append({"decision": decision, "observation": obs.__dict__})
        st.last_observation = obs
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
        "error": {"line": state.error_line, "snippet": state.snippet},
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LLM-driven build triage agent (OpenAI + LangGraph).")
    parser.add_argument("build_log", nargs="?", default="-", help="Build log path, or '-' for stdin.")

    parser.add_argument("--list-tools", action="store_true", help="Print available tools and exit.")
    parser.add_argument("--model", choices=["openai", "stub"], default=os.environ.get("REACT_AGENT_MODEL", "openai"))
    parser.add_argument("--max-steps", type=int, default=4)

    parser.add_argument("--tools", choices=["real", "fake"], default="real")
    parser.add_argument("--v1-json-dir", help="Root directory containing V1 *_analysis.json files")
    parser.add_argument("--v2-json-dir", help="Root directory containing V2 *_analysis.json files")
    parser.add_argument("--v1-src", help="Local filesystem root for V1 source code")
    parser.add_argument("--v2-src", help="Local filesystem root for V2 source code")

    parser.add_argument("--openai-api-key", default=os.environ.get("OPENAI_API_KEY", ""))
    parser.add_argument("--openai-model", default=os.environ.get("OPENAI_MODEL", "") or "gpt-5-mini")
    parser.add_argument("--openai-base-url", default=os.environ.get("OPENAI_BASE_URL", "") or "https://api.openai.com/v1")
    parser.add_argument("--openai-org", default=os.environ.get("OPENAI_ORG", ""))
    parser.add_argument("--openai-project", default=os.environ.get("OPENAI_PROJECT", ""))
    parser.add_argument("--no-json-mode", action="store_true", help="Disable OpenAI JSON mode.")
    return parser


def main(argv: List[str]) -> int:
    args = build_parser().parse_args(argv)
    if args.list_tools:
        sys.stdout.write(json.dumps({"type": "tools", "tools": TOOL_SPECS}, ensure_ascii=False, indent=2))
        sys.stdout.write("\n")
        return 0
    cfg = AgentConfig(
        max_steps=max(args.max_steps, 1),
        tools_mode=args.tools,
    )

    build_log = load_build_log(args.build_log)
    error_line, snippet = find_first_fatal(build_log)
    if not error_line:
        sys.stdout.write(json.dumps({"type": "final", "thought": "No compiler error found.", "summary": "", "next_step": ""}))
        sys.stdout.write("\n")
        return 0

    try:
        if args.model == "stub":
            model: ChatModel = StubModel()
        else:
            api_key = str(args.openai_api_key).strip()
            if not api_key:
                raise ModelError("OPENAI_API_KEY (or --openai-api-key) is required")
            model = OpenAIChatCompletionsModel(
                api_key=api_key,
                model=str(args.openai_model).strip(),
                base_url=str(args.openai_base_url).strip(),
                org=str(args.openai_org).strip(),
                project=str(args.openai_project).strip(),
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
        state = AgentState(error_line=error_line, snippet=snippet)

        final = _run_langgraph(model, runner, state, cfg)
    except Exception as exc:  # noqa: BLE001
        sys.stdout.write(json.dumps({"type": "final", "thought": "Agent error.", "summary": "", "next_step": str(exc)}))
        sys.stdout.write("\n")
        return 1

    sys.stdout.write(json.dumps(final, ensure_ascii=False))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
