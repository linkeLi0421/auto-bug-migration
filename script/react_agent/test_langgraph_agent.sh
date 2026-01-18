#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

fixtures=(
  "$SCRIPT_DIR/fixtures/implicit_function.log"
  "$SCRIPT_DIR/fixtures/struct_missing_member.log"
  "$SCRIPT_DIR/fixtures/syntax_error.log"
)

# Tool registry sanity.
tools_json="$("$PYTHON" "$SCRIPT_DIR/agent_langgraph.py" --list-tools --output-format json)"
"$PYTHON" - "$tools_json" <<'PY'
import json
import sys

obj = json.loads(sys.argv[1])
tools = obj.get("tools") or []
names = {t.get("name") for t in tools if isinstance(t, dict)}
assert "ossfuzz_apply_patch_and_test" in names, sorted(n for n in names if n)
assert "make_extra_patch_override" in names, sorted(n for n in names if n)
assert "kb_search_symbols" not in names, sorted(n for n in names if n)
PY

# Backward compatibility: if a model still emits tool=kb_search_symbols, rewrite to search_definition instead of crashing.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import json
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentConfig, AgentState, _run_langgraph  # noqa: E402
from models import ChatModel  # noqa: E402
from tools.runner import ToolObservation  # noqa: E402


class OneKbSearchModel(ChatModel):
    def __init__(self) -> None:
        self.turn = 0

    def complete(self, messages):
        self.turn += 1
        if self.turn == 1:
            return json.dumps(
                {
                    "type": "tool",
                    "thought": "Legacy tool call (should be rewritten).",
                    "tool": "kb_search_symbols",
                    "args": {"symbols": ["xmlRngMutex"], "version": "v1"},
                }
            )
        return json.dumps({"type": "final", "thought": "Done.", "summary": "ok", "next_step": ""})


class Runner:
    def __init__(self) -> None:
        self.calls = []

    def call(self, tool, args):
        self.calls.append(tool)
        assert tool == "search_definition", tool
        return ToolObservation(True, tool, args, output="ok", error=None)


st = AgentState(build_log_path="-", patch_path="", error_scope="first", error_line="/src/x.c:1:1: error: x", snippet="")
cfg = AgentConfig(max_steps=3, tools_mode="fake", error_scope="first")
model = OneKbSearchModel()
runner = Runner()

final = _run_langgraph(model, runner, st, cfg, artifact_store=None)
assert final.get("type") == "final", final
assert runner.calls == ["search_definition"], runner.calls
print("OK")
PY

# System prompt composition: keep the default prompt small by only including relevant sections.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState  # noqa: E402
from prompting import build_system_prompt  # noqa: E402
from tools.registry import TOOL_SPECS  # noqa: E402

st_first = AgentState(build_log_path="-", patch_path="", error_scope="first", error_line="x", snippet="")
p_first = build_system_prompt(st_first, tool_specs=TOOL_SPECS)
assert "Patch-scope mode:" not in p_first, p_first
assert "Merged/tail hunks" not in p_first, p_first

st_patch = AgentState(build_log_path="-", patch_path="bundle.patch2", error_scope="patch", error_line="x", snippet="")
p_patch = build_system_prompt(st_patch, tool_specs=TOOL_SPECS)
assert "Patch-scope mode:" in p_patch, p_patch

st_macro = AgentState(build_log_path="-", patch_path="", error_scope="first", error_line="x", snippet="note: expanded from macro 'X'")
p_macro = build_system_prompt(st_macro, tool_specs=TOOL_SPECS)
assert "Macro-related syntax errors:" in p_macro, p_macro

st_tail = AgentState(build_log_path="-", patch_path="bundle.patch2", error_scope="patch", error_line="x", snippet="")
st_tail.active_old_signature = "int f(int x)"
p_tail = build_system_prompt(st_tail, tool_specs=TOOL_SPECS)
assert "Merged/tail hunks" in p_tail, p_tail

print("OK")
PY

# Build-log parsing: include a small subset of warning diagnostics (undeclared function) so
# patch-scope workflows can deterministically fix them.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from build_log import iter_compiler_errors  # noqa: E402

log = "/src/libxml2/dict.c:1519:21: warning: call to undeclared function '__revert_e11519_xmlDictHashName'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]\\n"
errs = iter_compiler_errors(log, snippet_lines=0)
assert errs and errs[0].get("level") == "warning", errs
assert errs[0].get("file") == "/src/libxml2/dict.c", errs
assert "__revert_e11519_xmlDictHashName" in str(errs[0].get("msg") or ""), errs
print("OK")
PY

# Artifact directories must preserve patch_key (including leading/trailing "_"),
# otherwise override diff files cannot be mapped back to bundle patch keys.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
repo_root = script_dir.parents[1]
sys.path.insert(0, str(repo_root))

from script.react_agent.artifacts import resolve_artifact_dir  # noqa: E402

with tempfile.TemporaryDirectory() as td:
    os.environ["REACT_AGENT_ARTIFACT_ROOT"] = td
    store, out_dir = resolve_artifact_dir(disabled=False, patch_key="_extra_encoding.c")
    assert Path(out_dir).name == "_extra_encoding.c", out_dir

print("OK")
PY

# Extra patch override tool: insert a forward declaration into an `_extra_*` hunk
# by extracting a prototype from an existing `__revert_*` definition in the bundle.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from migration_tools.types import PatchInfo  # noqa: E402
from tools.extra_patch_tools import make_extra_patch_override  # noqa: E402

import pickle

with tempfile.TemporaryDirectory() as td:
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = td
    os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(Path(td) / "artifacts")
    bundle_path = Path(td) / "bundle.patch2"

    extra_key = "_extra_dict.c"
    main_key = "tail-dict.c-f1_"

    extra_patch_text = (
        "diff --git a/dict.c b/dict.c\n"
        "--- a/dict.c\n"
        "+++ b/dict.c\n"
        "@@ -1,1 +1,0 @@\n"
        "-/* extra decls */\n"
    )
    main_patch_text = (
        "diff --git a/dict.c b/dict.c\n"
        "--- a/dict.c\n"
        "+++ b/dict.c\n"
        "@@ -10,10 +10,0 @@\n"
        "-static int caller(int prefix) {\n"
        "-\n"
        "-  if (prefix == 0) {\n"
        "-    return __revert_deadbeef_myfunc(123);\n"
        "-  }\n"
        "-  return 0;\n"
        "-}\n"
        "-int __revert_deadbeef_myfunc(int x) {\n"
        "-  return x;\n"
        "-}\n"
    )

    extra_patch = PatchInfo(
        file_path_old="dict.c",
        file_path_new="dict.c",
        patch_text=extra_patch_text,
        file_type="c",
        old_start_line=1,
        old_end_line=2,
        new_start_line=1,
        new_end_line=1,
        patch_type={"Extra"},
        old_signature="",
        dependent_func=set(),
        hiden_func_dict={},
    )
    main_patch = PatchInfo(
        file_path_old="dict.c",
        file_path_new="dict.c",
        patch_text=main_patch_text,
        file_type="c",
        old_start_line=10,
        old_end_line=13,
        new_start_line=10,
        new_end_line=10,
        patch_type={"Recreated function"},
        old_signature="int myfunc(int x)",
        dependent_func=set(),
        hiden_func_dict={},
    )

    bundle_path.write_bytes(
        pickle.dumps(
            {
                extra_key: extra_patch,
                main_key: main_patch,
            },
            protocol=pickle.HIGHEST_PROTOCOL,
        )
    )

    out = make_extra_patch_override(
        None,
        patch_path=str(bundle_path),
        file_path="/src/libxml2/dict.c",
        symbol_name="__revert_deadbeef_myfunc",
        version="v1",
    )
    assert out.get("patch_key") == extra_key, out
    ref = out.get("patch_text") or {}
    assert isinstance(ref, dict) and ref.get("artifact_path"), out
    p = Path(str(ref.get("artifact_path"))).resolve()
    assert p.is_file(), p
    assert p.parent.name == extra_key, p
    text = p.read_text(encoding="utf-8", errors="replace")
    assert "int __revert_deadbeef_myfunc(int x);" in text, text

print("OK")
PY

# Extra patch override tool: for non-generated symbols that only appear as DECL_REF_EXPR,
# use type_ref.typedef_extent to insert a VAR_DECL (not a statement) into the `_extra_*` hunk.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import json
import os
import pickle
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from core.kb_index import KbIndex  # noqa: E402
from core.source_manager import SourceManager  # noqa: E402
from migration_tools.types import PatchInfo  # noqa: E402
from tools.extra_patch_tools import make_extra_patch_override  # noqa: E402
from tools.symbol_tools import AgentTools  # noqa: E402

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(td)
    os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(td / "artifacts")

    # Minimal KB: only a reference node with a type_ref.typedef_extent pointing at the real VAR_DECL.
    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()
    node = {
        "kind": "DECL_REF_EXPR",
        "spelling": "xmlRngMutex",
        "location": {"file": "dict.c", "line": 921, "column": 19},
        "type_ref": {
            "target_kind": "VAR_DECL",
            "target_name": "xmlRngMutex",
            "usr": "c:dict.c@xmlRngMutex",
            "canonical_type": "struct _xmlMutex",
            "decl_location": None,
            "typedef_extent": {
                "start": {"file": "dict.c", "line": 907, "column": 1},
                "end": {"file": "dict.c", "line": 907, "column": 28},
            },
        },
        "extent": {
            "start": {"file": "dict.c", "line": 921, "column": 19},
            "end": {"file": "dict.c", "line": 921, "column": 30},
        },
    }
    (kb_v1 / "dict.c_analysis.json").write_text(json.dumps([node]), encoding="utf-8")

    # Minimal sources: provide the VAR_DECL at line 907.
    src_v1 = td / "src_v1"
    src_v2 = td / "src_v2"
    src_v1.mkdir()
    src_v2.mkdir()
    lines = ["/* filler */"] * 950
    lines[906] = "static xmlMutex xmlRngMutex;"
    lines[920] = "    xmlInitMutex(&xmlRngMutex);"
    text = "\n".join(lines) + "\n"
    (src_v1 / "dict.c").write_text(text, encoding="utf-8")
    (src_v2 / "dict.c").write_text(text, encoding="utf-8")

    tools = AgentTools(KbIndex(str(kb_v1), str(kb_v2)), SourceManager(str(src_v1), str(src_v2)))

    defs = tools.search_definition("xmlRngMutex", version="v1")
    assert "static xmlMutex xmlRngMutex;" in defs, defs

    bundle_path = td / "bundle.patch2"
    extra_key = "_extra_dict.c"
    extra_patch_text = (
        "diff --git a/dict.c b/dict.c\n"
        "--- a/dict.c\n"
        "+++ b/dict.c\n"
        "@@ -1,1 +1,0 @@\n"
        "-/* extra decls */\n"
    )
    extra_patch = PatchInfo(
        file_path_old="dict.c",
        file_path_new="dict.c",
        patch_text=extra_patch_text,
        file_type="c",
        old_start_line=1,
        old_end_line=2,
        new_start_line=1,
        new_end_line=1,
        patch_type={"Extra"},
        old_signature="",
        dependent_func=set(),
        hiden_func_dict={},
    )
    bundle_path.write_bytes(pickle.dumps({extra_key: extra_patch}, protocol=pickle.HIGHEST_PROTOCOL))

    out = make_extra_patch_override(
        tools,
        patch_path=str(bundle_path),
        file_path="/src/libxml2/dict.c",
        symbol_name="xmlRngMutex",
        version="v1",
    )
    assert out.get("patch_key") == extra_key, out
    inserted = str(out.get("inserted_code") or "")
    assert "static xmlMutex xmlRngMutex;" in inserted, inserted
    assert "xmlInitMutex" not in inserted, inserted
    ref = out.get("patch_text") or {}
    p = Path(str(ref.get("artifact_path") or "")).resolve()
    assert p.is_file(), p
    text_out = p.read_text(encoding="utf-8", errors="replace")
    assert "static xmlMutex xmlRngMutex;" in text_out, text_out
    assert "xmlInitMutex" not in text_out, text_out

print("OK")
PY

# Focus-term extraction: macro-expansion snippets should surface macro tokens and avoid tiny noise tokens.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _collect_focus_terms  # noqa: E402

state = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line="/src/libxml2/encoding.c:104:5: error: expected '}'",
    snippet=(
        "/src/libxml2/encoding.c:104:5: error: expected '}'\n"
        "  104 |     MAKE_HANDLER(\"UTF-8\", __revert_e11519_UTF8ToUTF8, __revert_e11519_UTF8ToUTF8)\n"
        "      |     ^\n"
        "/src/libxml2/encoding.c:102:30: note: expanded from macro 'MAKE_HANDLER'\n"
        "  102 |     { (char *) name, in, out EMPTY_ICONV EMPTY_UCONV }\n"
        "      |                              ^\n"
    ),
)

terms = _collect_focus_terms(state)
assert "MAKE_HANDLER" in terms, terms
assert "EMPTY_ICONV" in terms, terms
assert "EMPTY_UCONV" in terms, terms
assert "c" not in terms, terms

print("OK")
PY

# Macro guardrail: if the override tries to add a #define for a missing macro token without source evidence,
# agent_langgraph should force make_extra_patch_override(symbol_name=<TOKEN>) instead.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _macro_define_guardrail_for_override  # noqa: E402

state = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line="/src/libxml2/encoding.c:104:5: error: expected '}'",
    snippet="",
)
state.macro_tokens_not_defined_in_slice = ["EMPTY_ICONV", "EMPTY_UCONV"]

decision = {
    "type": "tool",
    "tool": "make_error_patch_override",
    "thought": "try defining missing macros",
    "args": {"patch_path": "x", "file_path": "y", "line_number": 1, "new_func_code": "#define EMPTY_ICONV\n#define EMPTY_UCONV\n"},
}

forced = _macro_define_guardrail_for_override(state, decision)
assert forced and forced.get("tool") == "make_extra_patch_override", forced
args = forced.get("args") or {}
assert args.get("symbol_name") == "EMPTY_ICONV", forced
assert args.get("file_path") == "/src/libxml2/encoding.c", forced
print("OK")
PY

# Undeclared-symbol guardrail: try make_extra_patch_override once per symbol before allowing a
# function rewrite that removes/replaces the missing symbol.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _undeclared_symbol_extra_patch_guardrail_for_override  # noqa: E402

err = "/src/libxml2/dict.c:1519:21: error: use of undeclared identifier 'xmlRngMutex'"
state = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line=err,
    snippet="",
)
state.grouped_errors = [{"raw": err, "file": "/src/libxml2/dict.c", "line": 1519, "col": 21}]
state.steps = [
    {
        "decision": {"type": "tool", "tool": "get_error_patch_context", "args": {}},
        "observation": {"ok": True, "tool": "get_error_patch_context", "args": {}, "output": {"patch_key": "p"}, "error": None},
    },
]
state.step_history = list(state.steps)

decision = {"type": "tool", "tool": "make_error_patch_override", "thought": "remove missing global", "args": {}}
forced = _undeclared_symbol_extra_patch_guardrail_for_override(state, decision)
assert forced and forced.get("tool") == "make_extra_patch_override", forced
assert forced.get("args", {}).get("symbol_name") == "xmlRngMutex", forced
assert forced.get("args", {}).get("file_path") == "/src/libxml2/dict.c", forced
print("OK")
PY

# Function grouping helper: for merged/tail hunks, split patch_key errors by old_signature and
# focus the agent on one function at a time.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import _select_function_group_errors  # noqa: E402

errors = [
    {"raw": "E1", "old_signature": "f1"},
    {"raw": "E2", "old_signature": "f2"},
    {"raw": "E3", "old_signature": "f1"},
]

sel, sig = _select_function_group_errors(errors)
assert sig == "f1", (sig, sel)
assert [e.get("raw") for e in sel] == ["E1", "E3"], sel

sel2, sig2 = _select_function_group_errors(errors, preferred_old_signature="f2")
assert sig2 == "f2", (sig2, sel2)
assert [e.get("raw") for e in sel2] == ["E2"], sel2

single = [{"raw": "E1", "old_signature": "f1"}, {"raw": "E2", "old_signature": "f1"}]
sel3, sig3 = _select_function_group_errors(single)
assert sel3 == single, sel3
assert sig3 == "f1", sig3

print("OK")
PY

# Patch-scope pinning: in patch-aware runs, do not allow get_error_patch_context/make_error_patch_override
# to drift to another patch_key mid-run (multi-agent stores artifacts under a fixed per-patch_key directory).
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import json
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentConfig, AgentState, ToolObservation, _run_langgraph  # noqa: E402
from models import ChatModel  # noqa: E402


class TwoTurnModel(ChatModel):
    def __init__(self) -> None:
        self.turn = 0

    def complete(self, messages):
        self.turn += 1
        if self.turn == 1:
            return json.dumps(
                {
                    "type": "tool",
                    "thought": "Probe patch context at the reported location.",
                    "tool": "get_error_patch_context",
                    "args": {"patch_path": "bundle.patch2", "file_path": "/src/libxml2/hash.c", "line_number": 555},
                }
            )
        return json.dumps({"type": "final", "thought": "Stop.", "summary": "done", "next_step": ""})


class FakeRunner:
    def call(self, tool, args):
        assert tool == "get_error_patch_context", tool
        # Simulate a mapping to a *different* patch_key than the pinned one.
        return ToolObservation(
            ok=True,
            tool=tool,
            args=args,
            output={"patch_key": "p_other", "file_path": "/src/libxml2/hash.c", "line_number": 555, "old_signature": "f"},
            error=None,
        )


cfg = AgentConfig(max_steps=2, tools_mode="fake", error_scope="patch")
st = AgentState(
    build_log_path="-",
    patch_path="",
    error_scope="patch",
    error_line="/src/libxml2/hash.c:295:11: error: expected ';' after top level declarator",
    snippet="",
    artifacts_dir="artifacts",
    patch_key="p_target",
    active_patch_key="p_target",
    active_file_path="/src/libxml2/hash.c",
    active_line_number=295,
)

final = _run_langgraph(TwoTurnModel(), FakeRunner(), st, cfg, artifact_store=None)
steps = [s for s in (final.get("steps") or []) if isinstance(s, dict)]
assert steps, final
obs = steps[0].get("observation") if isinstance(steps[0].get("observation"), dict) else {}
assert obs.get("ok") is False, obs
assert "Out of scope" in str(obs.get("error") or ""), obs
assert st.active_patch_key == "p_target", st.active_patch_key

print("OK")
PY

# Text output should include the function-group summary (for debugging merged hunks via logs).
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import _render_final_text  # noqa: E402

final = {
    "type": "final",
    "thought": "t",
    "summary": "s",
    "next_step": "n",
    "steps": [],
    "error": {
        "line": "err",
        "snippet": "",
        "patch_path": "bundle.patch2",
        "artifacts_dir": "artifacts",
        "scope": "patch",
        "patch_key": "p1",
        "active_old_signature": "f1",
        "function_groups": [
            {"old_signature": "f1", "count": 2, "examples": ["E1", "E2"]},
            {"old_signature": "f2", "count": 1, "examples": ["E3"]},
        ],
        "function_groups_total": 2,
        "function_groups_truncated": False,
        "function_groups_history": [
            {"old_signature": "f1", "count": 3, "examples": ["E0", "E1", "E2"]},
            {"old_signature": "f2", "count": 1, "examples": ["E3"]},
        ],
        "function_groups_history_total": 2,
        "function_groups_history_truncated": False,
        "grouped_errors": [{"raw": "E1"}],
    },
}

text = _render_final_text(final)
assert "Function grouping note:" in text, text
assert "Current function groups (2):" in text, text
assert "History function groups (2):" in text, text
assert "f1 (errors=2) [active]" in text, text
assert "f1 (unique_errors=3) [active]" in text, text
assert "- E1" in text, text
print("OK")
PY

# Text output should show "Current function groups (0)" when the active patch_key is clean after OSS-Fuzz.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import _render_final_text  # noqa: E402

final = {
    "type": "final",
    "thought": "t",
    "summary": "s",
    "next_step": "n",
    "steps": [],
    "error": {
        "line": "err",
        "snippet": "",
        "patch_path": "bundle.patch2",
        "artifacts_dir": "artifacts",
        "scope": "patch",
        "patch_key": "p1",
        "active_old_signature": "f1",
        "function_groups": [],
        "function_groups_total": 0,
        "function_groups_truncated": False,
        "function_groups_history": [
            {"old_signature": "f1", "count": 3, "examples": ["E0", "E1", "E2"]},
        ],
        "function_groups_history_total": 1,
        "function_groups_history_truncated": False,
        "grouped_errors": [{"raw": "E1"}],
    },
}

text = _render_final_text(final)
assert "Current function groups (0):" in text, text
assert "(none)" in text, text
print("OK")
PY

# Next-top-errors formatting should include patch_key when available.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import _format_other_errors_for_next_step  # noqa: E402

errs = [
    {"raw": "/src/a.c:1:1: error: boom", "patch_key": "p1"},
    {"raw": "/src/b.c:2:2: error: kaboom", "patch_key": ""},
]
lines = _format_other_errors_for_next_step(errs, limit=5)
assert lines[0].endswith("(patch_key=p1)"), lines
assert lines[1] == "- /src/b.c:2:2: error: kaboom", lines
print("OK")
PY

# search_definition guardrail: don't try to "look up" struct fields via search_definition;
# rewrite to search_definition(struct) so the model can inspect the field list.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _struct_member_search_guardrail_for_search_definition  # noqa: E402

state = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line="/src/p.c:1:1: error: no member named 'nsdb' in 'struct _xmlParserCtxt'",
    snippet="",
)
state.missing_struct_members = [{"struct": "struct _xmlParserCtxt", "members": ["nsdb"]}]

decision = {"type": "tool", "tool": "search_definition", "thought": "look for field", "args": {"symbol_name": "ctxt->nsdb", "version": "v2"}}
rewritten = _struct_member_search_guardrail_for_search_definition(state, decision)
assert rewritten and rewritten.get("tool") == "search_definition", rewritten
args = rewritten.get("args") or {}
assert args.get("symbol_name") == "struct _xmlParserCtxt", rewritten
assert args.get("version") == "v2", rewritten
print("OK")
PY

# Override guardrail: compare new_func_code against the mapped '-' slice baseline (error_func_code / loop_base),
# not the entire patch/hunk text (important for merged/tail hunks).
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _override_preserve_base_guardrail_error  # noqa: E402

base_lines = [f"LINE{i:04d} " + ("X" * 40) for i in range(120)]
base_text = "\n".join(base_lines) + "\n"
patch_text = "\n".join([f"PATCH{i:04d}" for i in range(500)]) + "\n"

state = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line="x:1:1: error: y",
    snippet="",
)
state.steps.append(
    {
        "decision": {"type": "tool", "tool": "read_artifact", "args": {"artifact_path": "x"}, "thought": "read patch"},
        "observation": {
            "ok": True,
            "tool": "read_artifact",
            "args": {"artifact_path": "x"},
            "output": {"text": patch_text},
            "error": None,
        },
    }
)

with tempfile.TemporaryDirectory() as td:
    baseline_path = Path(td) / "error_func_code.c"
    baseline_path.write_text(base_text, encoding="utf-8")
    state.active_error_func_code_artifact_path = str(baseline_path)

    short = "\n".join(base_lines[:30]) + "\n"
    decision = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "thought": "oops, too short",
        "args": {"patch_path": "x", "file_path": "y", "line_number": 1, "new_func_code": short},
    }
    err = _override_preserve_base_guardrail_error(state, decision)
    assert err, "expected shrink guardrail to trigger"
    assert "get_error_patch_context.error_func_code" in err, err

    ok_decision = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "thought": "keep base",
        "args": {"patch_path": "x", "file_path": "y", "line_number": 1, "new_func_code": base_text},
    }
    assert _override_preserve_base_guardrail_error(state, ok_decision) is None, "expected guardrail to allow full base"

    # Merged/tail hunk scenario: patch/hunk is large, but the mapped function slice is smaller.
    small_lines = [f"FUNC{i:04d}" for i in range(30)]
    small_text = "\n".join(small_lines) + "\n"
    baseline_path.write_text(small_text, encoding="utf-8")
    ok_small = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "thought": "rewrite mapped slice only",
        "args": {"patch_path": "x", "file_path": "y", "line_number": 1, "new_func_code": small_text},
    }
    assert _override_preserve_base_guardrail_error(state, ok_small) is None, "expected guardrail to use mapped slice baseline"

print("OK")
PY

# Override guardrail (function-by-function): new_func_code should only contain the active function definition.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _override_single_function_guardrail_error  # noqa: E402

state = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line="x:1:1: error: y",
    snippet="",
)
state.active_old_signature = "int foo(int x)"

import tempfile

with tempfile.TemporaryDirectory() as td:
    base_path = Path(td) / "base.c"
    base_path.write_text("int foo(int x) { return x; }\\n", encoding="utf-8")
    state.loop_base_func_code_artifact_path = str(base_path)

    multi = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "thought": "rewrite too much",
        "args": {"patch_path": "x", "file_path": "y", "line_number": 1, "new_func_code": "int foo(int x) { return x; }\\nint bar(void) { return 0; }\\n"},
    }
    assert _override_single_function_guardrail_error(state, multi), "expected multi-function guardrail to trigger"

    diffy = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "thought": "oops, diff",
        "args": {"patch_path": "x", "file_path": "y", "line_number": 1, "new_func_code": "diff --git a/a b/b\\n@@ -1 +1 @@\\n-foo\\n+bar\\n"},
    }
    assert _override_single_function_guardrail_error(state, diffy), "expected unified-diff guardrail to trigger"

    decls = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "thought": "added globals",
        "args": {"patch_path": "x", "file_path": "y", "line_number": 1, "new_func_code": "static int g = 0;\\nint foo(int x) { return x; }\\n"},
    }
    assert _override_single_function_guardrail_error(state, decls), "expected top-level decl guardrail to trigger"

    ok = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "thought": "single function",
        "args": {"patch_path": "x", "file_path": "y", "line_number": 1, "new_func_code": "int foo(int x) { return x + 1; }\\n"},
    }
    assert _override_single_function_guardrail_error(state, ok) is None, "expected function-scoped override to pass"

    prefixed = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "thought": "single function with __revert_ prefix",
        "args": {
            "patch_path": "x",
            "file_path": "y",
            "line_number": 1,
            "new_func_code": "int __revert_e11519_foo(int x) { return x + 1; }\\n",
        },
    }
    assert _override_single_function_guardrail_error(state, prefixed) is None, "expected __revert_*_foo to satisfy name check"

state.active_old_signature = ""
assert _override_single_function_guardrail_error(state, multi) is None, "guardrail should be inactive without active_old_signature"

print("OK")
PY

# Override guardrail: when the BASE slice is function-scoped, new_func_code must be a complete function body.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _override_complete_function_guardrail_error  # noqa: E402

state = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line="x:1:1: error: y",
    snippet="",
)

base_text = "int foo(int x) {\\n  if (x) { x++; }\\n  return x;\\n}\\n"
bad_text = "int foo(int x) {\\n  if (x) { x++; }\\n  return x;\\n"  # missing final '}'

with tempfile.TemporaryDirectory() as td:
    baseline_path = Path(td) / "error_func_code.c"
    baseline_path.write_text(base_text, encoding="utf-8")
    state.active_error_func_code_artifact_path = str(baseline_path)

    bad = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "thought": "missing closing brace",
        "args": {"patch_path": "x", "file_path": "y", "line_number": 1, "new_func_code": bad_text},
    }
    assert _override_complete_function_guardrail_error(state, bad), "expected incomplete-body guardrail to trigger"

    ok = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "thought": "complete body",
        "args": {"patch_path": "x", "file_path": "y", "line_number": 1, "new_func_code": base_text},
    }
    assert _override_complete_function_guardrail_error(state, ok) is None, "expected complete-body guardrail to pass"

print("OK")
PY

# Override location guardrail: make_error_patch_override must use build-log /src/... line numbers,
# not pre_patch_* line numbers from get_error_patch_context.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _override_location_guardrail_for_override  # noqa: E402

state = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line="/src/libxml2/parser.c:17188:26: error: no member named 'nsdb' in 'struct _xmlParserCtxt'",
    snippet="",
)
state.active_file_path = "/src/libxml2/parser.c"
state.active_line_number = 17188
state.pre_patch_file_path = "parser.c"
state.pre_patch_line_number = 15802

bad = {
    "type": "tool",
    "tool": "make_error_patch_override",
    "thought": "accidentally using pre_patch line numbers",
    "args": {"patch_path": "x", "file_path": "parser.c", "line_number": 15802, "new_func_code": "int x;\\n"},
}
fixed = _override_location_guardrail_for_override(state, bad)
assert fixed and (fixed.get("args") or {}).get("file_path") == "/src/libxml2/parser.c", fixed
assert (fixed.get("args") or {}).get("line_number") == 17188, fixed

good = {
    "type": "tool",
    "tool": "make_error_patch_override",
    "thought": "using build error location",
    "args": {"patch_path": "x", "file_path": "/src/libxml2/parser.c", "line_number": 17188, "new_func_code": "int x;\\n"},
}
assert _override_location_guardrail_for_override(state, good) is None

print("OK")
PY

# Effective bundle persistence: after make_error_patch_override changes function length in a merged/tail hunk,
# the next iteration must use updated hiden_func_dict offsets so later function errors don't get mis-attributed.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from agent_langgraph import AgentState, _write_effective_patch_bundle  # noqa: E402
from migration_tools.patch_bundle import load_patch_bundle  # noqa: E402
from migration_tools.tools import _get_error_patch_from_bundle, make_error_patch_override  # noqa: E402
from migration_tools.types import PatchInfo  # noqa: E402

import pickle

with tempfile.TemporaryDirectory() as td:
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = td
    bundle_path = Path(td) / "bundle.patch2"
    patch_key = "tail-file.c-f1_f2_"

    # Two functions in one recreated/merged hunk: f1 is 5 lines, f2 starts at offset 5.
    patch_text = (
        "diff --git a/file.c b/file.c\n"
        "--- a/file.c\n"
        "+++ b/file.c\n"
        "@@ -10,8 +10,0 @@\n"
        "-int f1(void) {\n"
        "-  int x = 1;\n"
        "-  int y = 2;\n"
        "-  return x + y;\n"
        "-}\n"
        "-int f2(void) {\n"
        "-  return 2;\n"
        "-}\n"
    )
    patch = PatchInfo(
        file_path_old="file.c",
        file_path_new="file.c",
        patch_text=patch_text,
        file_type="c",
        old_start_line=10,
        old_end_line=18,
        new_start_line=10,
        new_end_line=10,
        patch_type={"Recreated function", "Merged functions"},
        old_signature="int f1(void)",
        dependent_func=set(),
        hiden_func_dict={"int f1(void)": 0, "int f2(void)": 5},
    )
    bundle_path.write_bytes(pickle.dumps({patch_key: patch}, protocol=pickle.HIGHEST_PROTOCOL))

    # Rewrite f1 to be shorter (delta=-2), so f2's offset must shift from 5 -> 3.
    out = make_error_patch_override(
        patch_path=str(bundle_path),
        file_path="/src/file.c",
        line_number=12,
        new_func_code="int f1(void) {\n  return 42;\n}\n",
        allowed_roots=[td],
    )
    assert out.get("patch_key") == patch_key, out
    updated_patch_text = out.get("patch_text") or ""
    updated_hiden = out.get("hiden_func_dict_updated")
    assert isinstance(updated_hiden, dict) and updated_hiden.get("int f2(void)") == 3, updated_hiden

    # Persist an effective bundle and verify that line 14 (now inside f2) maps to f2, not f1.
    artifacts_dir = Path(td) / "react_agent_artifacts" / patch_key
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    state = AgentState(
        build_log_path="build.log",
        patch_path=str(bundle_path),
        error_scope="patch",
        error_line="x",
        snippet="",
        artifacts_dir=str(artifacts_dir),
    )
    effective_path, err = _write_effective_patch_bundle(
        state,
        patch_key=patch_key,
        patch_text=str(updated_patch_text),
        hiden_func_dict_updated=updated_hiden,
    )
    assert not err and effective_path, (effective_path, err)

    bundle2 = load_patch_bundle(effective_path, allowed_roots=[td])
    mapping = _get_error_patch_from_bundle(bundle2, patch_path=effective_path, file_path="/src/file.c", line_number=14)
    assert mapping.get("old_signature") == "int f2(void)", mapping

print("OK")
PY

for fixture in "${fixtures[@]}"; do
  output="$("$PYTHON" "$SCRIPT_DIR/agent_langgraph.py" --model stub --tools fake --max-steps 3 "$fixture")"
  "$PYTHON" - "$fixture" "$output" <<'PY'
import json
import sys

fixture = sys.argv[1]
output = sys.argv[2]
obj = json.loads(output)

assert obj["type"] == "final", obj
assert isinstance(obj.get("steps"), list), obj
assert len(obj["steps"]) <= 3, obj

allowed = {
    "read_artifact",
    "read_file_context",
    "search_definition",
    "list_patch_bundle",
    "get_patch",
    "search_patches",
    "get_error_patch_context",
    "make_extra_patch_override",
    "make_error_patch_override",
    "parse_build_errors",
}

for step in obj["steps"]:
    decision = step.get("decision") or {}
    tool = decision.get("tool")
    if tool is None:
        continue
    assert tool in allowed, (tool, step)

if fixture.endswith("implicit_function.log"):
    assert any((s.get("decision") or {}).get("tool") == "search_definition" for s in obj["steps"]), obj
elif fixture.endswith("struct_missing_member.log"):
    assert any((s.get("decision") or {}).get("tool") == "search_definition" for s in obj["steps"]), obj
elif fixture.endswith("syntax_error.log"):
    assert any((s.get("decision") or {}).get("tool") == "read_file_context" for s in obj["steps"]), obj
PY
done

# Patch-scope mode: group errors by patch and prefer patch-first workflow.
tmp_dir="$(mktemp -d "$SCRIPT_DIR/fixtures/.tmp_patch_scope.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

bundle_b64="$SCRIPT_DIR/../migration_tools/fixtures/sample.patch2.b64"
bundle_path="$tmp_dir/sample.patch2"

"$PYTHON" - "$bundle_b64" "$bundle_path" <<'PY'
import base64
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
dst.write_bytes(base64.b64decode(src.read_text(encoding="utf-8").strip()))
PY

output="$(REACT_AGENT_PATCH_ALLOWED_ROOTS="$tmp_dir" "$PYTHON" "$SCRIPT_DIR/agent_langgraph.py" \
  --model stub --tools fake --max-steps 4 --error-scope patch --patch-path "$bundle_path" \
  --ossfuzz-project example --ossfuzz-commit deadbeef \
  "$SCRIPT_DIR/fixtures/patch_scope_unknown_type.log")"

"$PYTHON" - "$output" <<'PY'
import json
import sys

obj = json.loads(sys.argv[1])
assert obj["type"] == "final", obj
steps = obj.get("steps") or []
assert len(steps) >= 2, steps

err = obj.get("error") or {}
assert err.get("scope") == "patch", err
assert err.get("patch_key") == "p2", err
grouped = err.get("grouped_errors") or []
assert isinstance(grouped, list) and len(grouped) >= 2, grouped

tools = [((s.get("decision") or {}).get("tool")) for s in steps]
assert tools[0] == "parse_build_errors", tools
assert tools[1] == "get_error_patch_context", tools
assert "read_file_context" not in tools, tools
PY

# Patch-scope mode: missing struct member should compare V1 vs V2 before grep.
output="$(REACT_AGENT_PATCH_ALLOWED_ROOTS="$tmp_dir" "$PYTHON" "$SCRIPT_DIR/agent_langgraph.py" \
  --model stub --tools fake --max-steps 8 --error-scope patch --patch-path "$bundle_path" \
  --ossfuzz-project example --ossfuzz-commit deadbeef \
  "$SCRIPT_DIR/fixtures/patch_scope_missing_member.log")"

"$PYTHON" - "$output" <<'PY'
import json
import sys

obj = json.loads(sys.argv[1])
assert obj["type"] == "final", obj
steps = obj.get("steps") or []
assert len(steps) >= 5, steps

err = obj.get("error") or {}
assert err.get("scope") == "patch", err
assert err.get("patch_key") == "p2", err

tools = []
versions = []
for s in steps:
    decision = (s.get("decision") or {})
    tool = decision.get("tool")
    if not tool:
        continue
    tools.append(tool)
    if tool == "search_definition":
        versions.append(((decision.get("args") or {}).get("version")))

assert tools[0] == "get_error_patch_context", tools
assert "get_error_v1_code_slice" not in tools, tools
assert "v1" in versions and "v2" in versions, versions

# Patch generation is followed by mandatory OSS-Fuzz test; artifact reads only happen right before patch generation.
assert "make_error_patch_override" in tools, tools
idx_patch = tools.index("make_error_patch_override")
assert idx_patch > 0 and tools[idx_patch - 1] == "read_artifact", tools
assert "ossfuzz_apply_patch_and_test" in tools[idx_patch + 1 :], tools

# Macro-expansion flows use make_extra_patch_override; this patch-scope missing-member fixture doesn't
# exercise macro handling.
PY

# Guardrail: block suggestions to edit V2 type definitions by default.
output="$(REACT_AGENT_PATCH_ALLOWED_ROOTS="$tmp_dir" REACT_AGENT_STUB_SUGGEST_V2_TYPE_EDIT=1 "$PYTHON" "$SCRIPT_DIR/agent_langgraph.py" \
  --model stub --tools fake --max-steps 8 --error-scope patch --patch-path "$bundle_path" \
  --ossfuzz-project example --ossfuzz-commit deadbeef \
  "$SCRIPT_DIR/fixtures/patch_scope_missing_member.log")"

"$PYTHON" - "$output" <<'PY'
import json
import sys

obj = json.loads(sys.argv[1])
assert obj["type"] == "final", obj

summary = (obj.get("summary") or "").lower()
next_step = (obj.get("next_step") or "").lower()
combined = summary + "\n" + next_step

assert "struct definition" not in combined, combined
assert "add the missing fields" not in combined, combined

tools = [((s.get("decision") or {}).get("tool")) for s in (obj.get("steps") or []) if isinstance(s, dict)]
assert "make_error_patch_override" in tools, tools
PY

# Patch-aware runs: if read_file_context is used, it must use pre-patch line numbers.
output="$(REACT_AGENT_PATCH_ALLOWED_ROOTS="$tmp_dir" "$PYTHON" "$SCRIPT_DIR/agent_langgraph.py" \
  --model stub --tools fake --max-steps 4 --error-scope patch --patch-path "$bundle_path" \
  --ossfuzz-project example --ossfuzz-commit deadbeef \
  "$SCRIPT_DIR/fixtures/patch_safe_read_context.log")"

"$PYTHON" - "$output" "$bundle_path" "$SCRIPT_DIR" <<'PY'
import json
import sys
from pathlib import Path

obj = json.loads(sys.argv[1])
bundle_path = Path(sys.argv[2]).resolve()
script_dir = Path(sys.argv[3]).resolve()
repo_root = script_dir.parents[1]
sys.path.insert(0, str(repo_root))

from script.migration_tools.tools import get_error_patch_context  # noqa: E402

expected = get_error_patch_context(
    patch_path=str(bundle_path),
    file_path="/src/libxml2/error.c",
    line_number=54,
    error_text="/src/libxml2/error.c:54:7: error: expected ';' after expression",
    allowed_roots=[str(bundle_path.parent)],
)
expected_pre = expected.get("pre_patch_line_number")
assert isinstance(expected_pre, int) and expected_pre > 0, expected
assert expected_pre != 54, expected_pre

tools = [((s.get("decision") or {}).get("tool")) for s in (obj.get("steps") or [])]
assert "read_file_context" in tools, tools

for s in (obj.get("steps") or []):
    decision = s.get("decision") or {}
    if decision.get("tool") != "read_file_context":
        continue
    args = decision.get("args") or {}
    assert args.get("line_number") == expected_pre, (args, expected_pre)
PY

# Artifact-backed outputs: large tool outputs should be persisted and referenced.
artifact_dir="$tmp_dir/artifacts"
mkdir -p "$artifact_dir"

bundle_fixture="$SCRIPT_DIR/fixtures/definition_bundle"
v_json="$bundle_fixture/json"
v_src="$bundle_fixture/src"

output="$(REACT_AGENT_PATCH_ALLOWED_ROOTS="$tmp_dir" REACT_AGENT_ARTIFACT_ROOT="$artifact_dir" "$PYTHON" "$SCRIPT_DIR/agent_langgraph.py" \
  --model stub --tools real --max-steps 4 --error-scope patch --patch-path "$bundle_path" \
  --ossfuzz-project example --ossfuzz-commit deadbeef \
  --v1-json-dir "$v_json" --v2-json-dir "$v_json" --v1-src "$v_src" --v2-src "$v_src" \
  "$SCRIPT_DIR/fixtures/patch_scope_unknown_type.log")"

"$PYTHON" - "$output" "$SCRIPT_DIR" "$artifact_dir" <<'PY'
import json
import os
import sys
from pathlib import Path

obj = json.loads(sys.argv[1])
script_dir = Path(sys.argv[2]).resolve()
artifact_dir = Path(sys.argv[3]).resolve()

sys.path.insert(0, str(script_dir))
os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(artifact_dir)

from tools.artifact_tools import read_artifact  # noqa: E402

steps = obj.get("steps") or []
assert len(steps) >= 2, steps

tool = (steps[1].get("decision") or {}).get("tool")
assert tool == "get_error_patch_context", tool

obs = (steps[1].get("observation") or {}).get("output") or {}
for field in ("excerpt", "patch_minus_code", "error_func_code"):
    val = obs.get(field)
    assert isinstance(val, dict) and val.get("artifact_path"), (field, val)
    ap = Path(val["artifact_path"]).resolve()
    assert ap.is_file(), ap
    assert artifact_dir in ap.parents, (artifact_dir, ap)

    snippet = read_artifact(artifact_path=str(ap), start_line=1, max_lines=20)
    assert snippet.get("text"), (field, snippet)

pm = obs.get("patch_minus_code") or {}
ef = obs.get("error_func_code") or {}
pm_text = read_artifact(artifact_path=str(pm.get("artifact_path")), start_line=1, max_lines=0, max_chars=0).get("text") or ""
ef_text = read_artifact(artifact_path=str(ef.get("artifact_path")), start_line=1, max_lines=0, max_chars=0).get("text") or ""
assert ef_text.strip(), ef_text
assert ef_text.strip() in pm_text, (ef_text[:200], pm_text[:200])

try:
    read_artifact(artifact_path=str(Path("/etc/hosts")), max_lines=5)
    raise AssertionError("expected allowlist failure")
except ValueError:
    pass
PY

# read_artifact: max_lines=0/max_chars=0 should return full text, and prompt compaction must not truncate it.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _compact_observation_for_prompt  # noqa: E402
from tools.artifact_tools import read_artifact  # noqa: E402

state = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line="x:1:1: error: y",
    snippet="",
)

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(root)

    big = root / "big.txt"
    lines = ["HEADER"] + [f"LINE{i:05d} " + ("X" * 80) for i in range(300)] + ["TAIL"]
    big.write_text("\n".join(lines) + "\n", encoding="utf-8", errors="replace")

    out = read_artifact(artifact_path=str(big), start_line=1, max_lines=0, max_chars=0)
    text = out.get("text") or ""
    assert "HEADER\n" in text, out
    assert "TAIL\n" in text, out
    assert len(text) > 12000, len(text)
    assert out.get("truncated") is False, out

    obs = {"ok": True, "tool": "read_artifact", "args": {"max_lines": 0, "max_chars": 0}, "output": out, "error": None}
    compacted = _compact_observation_for_prompt(state, obs)
    compacted_text = (((compacted or {}).get("output") or {}).get("text") or "")
    assert compacted_text == text, (len(compacted_text), len(text))

print("OK")
PY

# Patch-key artifact dirs: when only ARTIFACT_ROOT is set, store under <patch_key>/ and overwrite filenames.
artifact_root="$tmp_dir/artifact_root"
mkdir -p "$artifact_root"

output="$(REACT_AGENT_PATCH_ALLOWED_ROOTS="$tmp_dir" REACT_AGENT_ARTIFACT_ROOT="$artifact_root" "$PYTHON" "$SCRIPT_DIR/agent_langgraph.py" \
  --model stub --tools real --max-steps 4 --error-scope patch --patch-path "$bundle_path" \
  --ossfuzz-project example --ossfuzz-commit deadbeef \
  --v1-json-dir "$v_json" --v2-json-dir "$v_json" --v1-src "$v_src" --v2-src "$v_src" \
  "$SCRIPT_DIR/fixtures/patch_scope_unknown_type.log")"

output2="$(REACT_AGENT_PATCH_ALLOWED_ROOTS="$tmp_dir" REACT_AGENT_ARTIFACT_ROOT="$artifact_root" "$PYTHON" "$SCRIPT_DIR/agent_langgraph.py" \
  --model stub --tools real --max-steps 4 --error-scope patch --patch-path "$bundle_path" \
  --ossfuzz-project example --ossfuzz-commit deadbeef \
  --v1-json-dir "$v_json" --v2-json-dir "$v_json" --v1-src "$v_src" --v2-src "$v_src" \
  "$SCRIPT_DIR/fixtures/patch_scope_unknown_type.log")"

"$PYTHON" - "$output2" "$artifact_root" <<'PY'
import json
import sys
from pathlib import Path

obj = json.loads(sys.argv[1])
artifact_root = Path(sys.argv[2]).resolve()

err = obj.get("error") or {}
assert err.get("patch_key") == "p2", err

artifact_dir = (artifact_root / "p2").resolve()
assert artifact_dir.is_dir(), artifact_dir

expected = artifact_dir / "get_error_patch_context_excerpt_error.c.diff"
assert expected.is_file(), list(artifact_dir.iterdir())

unexpected = list(artifact_dir.glob("*.1.*"))
assert not unexpected, unexpected
PY

# Merge tmp_patch bundle with override diff files (no Docker).
"$PYTHON" - "$SCRIPT_DIR" "$bundle_path" "$artifact_root" <<'PY'
import os
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
bundle_path = Path(sys.argv[2]).resolve()
artifact_root = Path(sys.argv[3]).resolve()

sys.path.insert(0, str(script_dir))

os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(bundle_path.parent)
os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(artifact_root)

artifact_dir = (artifact_root / "p2").resolve()
artifact_dir.mkdir(parents=True, exist_ok=True)

from tools.ossfuzz_tools import merge_patch_bundle_with_overrides, write_patch_bundle_with_overrides  # noqa: E402
from migration_tools.patch_bundle import load_patch_bundle  # noqa: E402

override_path = artifact_dir / "override_p2.diff"
override_text = (
    "diff --git a/error.c b/error.c\n"
    "--- a/error.c\n"
    "+++ b/error.c\n"
    "@@ -10,1 +10,1 @@\n"
    "-line2\n"
    "+OVERRIDE_LINE\n"
)
override_path.write_text(override_text, encoding="utf-8", errors="replace")

out = merge_patch_bundle_with_overrides(
    patch_path=str(bundle_path),
    patch_override_paths=[str(override_path)],
    output_name="merged_test.diff",
)
merged_path = Path(out.get("merged_patch_file_path", "")).resolve()
assert merged_path.is_file(), out
merged_text = merged_path.read_text(encoding="utf-8", errors="replace")
assert "OVERRIDE_LINE" in merged_text, merged_path
assert "p2" in (out.get("overridden_patch_keys") or []), out

bundle_out = write_patch_bundle_with_overrides(
    patch_path=str(bundle_path),
    patch_override_paths=[str(override_path)],
    output_name="merged_test.patch2",
)
merged_bundle_path = Path(bundle_out.get("merged_patch_bundle_path", "")).resolve()
assert merged_bundle_path.is_file(), bundle_out
merged_bundle = load_patch_bundle(str(merged_bundle_path), allowed_roots=[str(bundle_path.parent)])
assert "p2" in merged_bundle.patches, merged_bundle_path
assert "OVERRIDE_LINE" in (merged_bundle.patches["p2"].patch_text or ""), merged_bundle_path
PY

# Target-error verdict helper (non-Docker): verify we can detect whether the original error remains in OSS-Fuzz logs.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import pickle
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, ToolObservation, _summarize_active_patch_key_status, _summarize_target_error_status  # noqa: E402
from migration_tools.types import PatchInfo  # noqa: E402

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(root)

    bundle_path = root / "bundle.pkl"
    patches = {
        "p_target": PatchInfo(
            file_path_old="libxml2/hash.c",
            file_path_new="libxml2/hash.c",
            patch_text=(
                "diff --git a/libxml2/hash.c b/libxml2/hash.c\n"
                "--- a/libxml2/hash.c\n"
                "+++ b/libxml2/hash.c\n"
                "@@ -290,10 +290,10 @@\n"
                "-old\n"
                "+new\n"
            ),
            file_type="source",
            old_start_line=290,
            old_end_line=299,
            new_start_line=290,
            new_end_line=299,
        ),
        "p_other": PatchInfo(
            file_path_old="libxml2/hash.c",
            file_path_new="libxml2/hash.c",
            patch_text=(
                "diff --git a/libxml2/hash.c b/libxml2/hash.c\n"
                "--- a/libxml2/hash.c\n"
                "+++ b/libxml2/hash.c\n"
                "@@ -550,10 +550,10 @@\n"
                "-old2\n"
                "+new2\n"
            ),
            file_type="source",
            old_start_line=550,
            old_end_line=559,
            new_start_line=550,
            new_end_line=559,
        ),
    }
    bundle_path.write_bytes(pickle.dumps(patches))

    build_log = root / "build.log"
    msg = "no member named 'randomSeed' in 'struct _xmlHashTable'"
    build_log.write_text(f"/src/libxml2/hash.c:295:11: error: {msg}\n", encoding="utf-8")

    st = AgentState(
        build_log_path="-",
        patch_path=str(bundle_path),
        error_scope="patch",
        error_line="/src/libxml2/hash.c:295:11: error: no member named 'randomSeed' in 'struct _xmlHashTable'",
        snippet="",
        artifacts_dir=str(root),
        patch_key="p_target",
        grouped_errors=[],
        missing_struct_members=[],
        target_errors=[{"patch_key": "p_target", "msg": msg}],
    )
    st.last_observation = ToolObservation(
        ok=True,
        tool="ossfuzz_apply_patch_and_test",
        args={},
        output={"build_output": {"artifact_path": str(build_log)}},
        error=None,
    )
    verdict = _summarize_target_error_status(st)
    assert verdict.get("status") == "ok", verdict
    assert verdict.get("fixed") is False, verdict

    build_log.write_text("error: corrupt patch at line 402\n", encoding="utf-8")
    verdict_bad = _summarize_target_error_status(st)
    assert verdict_bad.get("status") == "failed", verdict_bad
    assert "corrupt patch" in str(verdict_bad.get("reason") or ""), verdict_bad

    # Non-compiler OSS-Fuzz failure (e.g. build script error): if build_ok/check_build_ok is false but
    # there are no compiler diagnostics, do not treat this as "fixed".
    build_log.write_text("cp: cannot create regular file '/out/llvm-symbolizer': No such file or directory\n", encoding="utf-8")
    st.last_observation = ToolObservation(
        ok=True,
        tool="ossfuzz_apply_patch_and_test",
        args={},
        output={
            "build_output": {"artifact_path": str(build_log)},
            "build_ok": False,
            "check_build_ok": True,
            "patch_apply_ok": True,
        },
        error=None,
    )
    verdict_fail = _summarize_target_error_status(st)
    assert verdict_fail.get("status") == "failed", verdict_fail
    assert "llvm-symbolizer" in str(verdict_fail.get("reason") or ""), verdict_fail
    pkv_fail = _summarize_active_patch_key_status(st)
    assert pkv_fail.get("status") == "failed", pkv_fail

    build_log.write_text(f"/src/libxml2/hash.c:554:52: error: {msg}\n", encoding="utf-8")
    verdict2 = _summarize_target_error_status(st)
    assert verdict2.get("status") == "ok", verdict2
    assert verdict2.get("fixed") is True, verdict2
PY

# Target-error verdict (merged hunks): when focusing one old_signature at a time, treat "fixed" as
# "no remaining errors mapped to (patch_key, active_old_signature)", not "(patch_key,msg)".
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import pickle
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, ToolObservation, _summarize_target_error_status  # noqa: E402
from migration_tools.types import PatchInfo  # noqa: E402

sig1 = "int f1(void)"
sig2 = "int f2(void)"
msg = "no member named 'x' in 'struct S'"

patch_text = (
    "diff --git a/libxml2/merge.c b/libxml2/merge.c\n"
    "--- a/libxml2/merge.c\n"
    "+++ b/libxml2/merge.c\n"
    "@@ -100,25 +100,25 @@\n"
    + "".join(f"-LINE{i:02d}\n" for i in range(1, 21))
)

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(root)

    bundle_path = root / "bundle.pkl"
    patches = {
        "p_merge": PatchInfo(
            file_path_old="libxml2/merge.c",
            file_path_new="libxml2/merge.c",
            patch_text=patch_text,
            file_type="source",
            old_start_line=100,
            old_end_line=124,
            new_start_line=100,
            new_end_line=124,
            patch_type={"Recreated function", "Merged functions"},
            old_signature=sig1,
            hiden_func_dict={sig1: 0, sig2: 11},
        )
    }
    bundle_path.write_bytes(pickle.dumps(patches))

    build_log = root / "build.log"
    st = AgentState(
        build_log_path="-",
        patch_path=str(bundle_path),
        error_scope="patch",
        error_line=f"/src/libxml2/merge.c:105:1: error: {msg}",
        snippet="",
        artifacts_dir=str(root),
        patch_key="p_merge",
        active_patch_key="p_merge",
        active_old_signature=sig1,
        target_errors=[{"patch_key": "p_merge", "msg": msg}],
    )
    st.last_observation = ToolObservation(
        ok=True,
        tool="ossfuzz_apply_patch_and_test",
        args={},
        output={"build_output": {"artifact_path": str(build_log)}},
        error=None,
    )

    # Error remains, but only for sig2 -> should count as fixed for active sig1.
    build_log.write_text(f"/src/libxml2/merge.c:111:1: error: {msg}\n", encoding="utf-8")
    verdict = _summarize_target_error_status(st)
    assert verdict.get("status") == "ok", verdict
    assert verdict.get("fixed") is True, verdict
    assert verdict.get("target_mode") == "active_old_signature", verdict

    # Error for sig1 -> not fixed.
    build_log.write_text(f"/src/libxml2/merge.c:105:1: error: {msg}\n", encoding="utf-8")
    verdict2 = _summarize_target_error_status(st)
    assert verdict2.get("status") == "ok", verdict2
    assert verdict2.get("fixed") is False, verdict2
PY

# Auto-loop regression: after ossfuzz_apply_patch_and_test, restart patch-scope triage for the next error by
# forcing get_error_patch_context again (using the latest OSS-Fuzz logs + effective bundle), while trimming
# state.steps for prompt hygiene but preserving full step_history for output/debugging.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import base64
import json
import os
import re
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
repo_root = script_dir.parents[1]
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(repo_root))

from agent_langgraph import AgentConfig, AgentState, _run_langgraph  # noqa: E402
from artifacts import ArtifactStore  # noqa: E402
from tools.artifact_tools import read_artifact as read_artifact_tool  # noqa: E402
from tools.migration_tools import get_error_patch_context as get_error_patch_context_tool  # noqa: E402
from tools.migration_tools import make_error_patch_override as make_error_patch_override_tool  # noqa: E402
from tools.runner import ToolObservation  # noqa: E402

from script.migration_tools.patch_bundle import load_patch_bundle  # noqa: E402


class FakeRunner:
    def __init__(self, *, ossfuzz_outputs):
        self._ossfuzz_outputs = list(ossfuzz_outputs)
        self.calls = []

    def call(self, tool, args):
        self.calls.append(tool)
        if tool == "read_artifact":
            out = read_artifact_tool(**args)
            return ToolObservation(True, tool, args, output=out, error=None)
        if tool == "get_error_patch_context":
            out = get_error_patch_context_tool(**args)
            return ToolObservation(True, tool, args, output=out, error=None)
        if tool == "make_error_patch_override":
            out = make_error_patch_override_tool(**args)
            return ToolObservation(True, tool, args, output=out, error=None)
        if tool == "ossfuzz_apply_patch_and_test":
            if not self._ossfuzz_outputs:
                raise RuntimeError("Missing fake ossfuzz output")
            out = self._ossfuzz_outputs.pop(0)
            return ToolObservation(True, tool, args, output=out, error=None)
        return ToolObservation(True, tool, args, output={}, error=None)


_ERROR_RE = re.compile(r"^(?P<file>[^:\n]+):(?P<line>\d+):(?P<col>\d+):\s*(?:fatal\s+)?error:\s*(?P<msg>.*)$")


class BasePreservingModel:
    def complete(self, messages):
        patch_path = ""
        for m in messages:
            if m.get("role") != "user":
                continue
            for line in str(m.get("content") or "").splitlines():
                if line.startswith("Patch bundle path:"):
                    patch_path = line.split(":", 1)[1].strip()
                    break
            if patch_path:
                break

        file_path = ""
        line_number = 0
        for m in messages:
            if m.get("role") != "user":
                continue
            for line in str(m.get("content") or "").splitlines():
                mm = _ERROR_RE.match(line.strip())
                if not mm:
                    continue
                file_path = mm.group("file")
                line_number = int(mm.group("line"))
                break
            if file_path and line_number > 0:
                break

        base = ""
        for m in reversed(messages):
            if m.get("role") != "user":
                continue
            content = str(m.get("content") or "")
            if not content.startswith("Observation:\n"):
                continue
            try:
                obs = json.loads(content.split("Observation:\n", 1)[1])
            except Exception:
                continue
            if str(obs.get("tool") or "").strip() != "read_artifact":
                continue
            if obs.get("ok") is not True:
                continue
            out = obs.get("output") if isinstance(obs.get("output"), dict) else {}
            text = out.get("text") if isinstance(out, dict) else ""
            if isinstance(text, str) and text.strip():
                base = text
                break

        new_code = base.rstrip("\n")
        if new_code:
            new_code += "\n/* react_agent auto-loop test edit */\n"

        if not (patch_path and file_path and line_number > 0 and new_code.strip()):
            return json.dumps({"type": "final", "thought": "missing inputs", "summary": "", "next_step": ""})

        return json.dumps(
            {
                "type": "tool",
                "thought": "Generate a minimal edit from the BASE slice.",
                "tool": "make_error_patch_override",
                "args": {
                    "patch_path": patch_path,
                    "file_path": file_path,
                    "line_number": line_number,
                    "new_func_code": new_code,
                    "context_lines": 0,
                    "max_lines": 2000,
                    "max_chars": 200000,
                },
            }
        )

with tempfile.TemporaryDirectory() as td:
    root = Path(td).resolve()
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(root)
    os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(root)

    # Use the existing patch2 fixture bundle (decoded into an allowed root).
    bundle_b64 = (script_dir / "../migration_tools/fixtures/sample.patch2.b64").resolve()
    bundle_path = root / "sample.patch2"
    bundle_path.write_bytes(base64.b64decode(bundle_b64.read_text(encoding="utf-8").strip()))

    bundle = load_patch_bundle(str(bundle_path), allowed_roots=[str(root)])
    assert "p2" in bundle.patches, sorted(bundle.patches.keys())
    patch_text = str(bundle.patches["p2"].patch_text or "")
    assert patch_text.strip()

    override_path = root / "override_p2.diff"
    override_path.write_text(patch_text + ("\n" if not patch_text.endswith("\n") else ""), encoding="utf-8")

    # Fake OSS-Fuzz logs after the first patch attempt: a new error remains in the same patch_key (p2).
    build_1 = (
        "/src/libxml2/error.c:52:1: error: unknown type name 'foo_t'\n"
        "/src/libxml2/error.c:52:5: error: use of undeclared identifier 'bar'\n"
    )
    build_1_path = root / "ossfuzz_build_1.log"
    check_1_path = root / "ossfuzz_check_1.log"
    build_1_path.write_text(build_1, encoding="utf-8")
    check_1_path.write_text("", encoding="utf-8")

    # Second OSS-Fuzz run: still has a compiler error in the same patch_key, so the auto-loop iterates again.
    ossfuzz_2 = {
        "build_output": "/src/libxml2/error.c:52:1: error: unknown type name 'foo2_t'\n",
        "check_build_output": "",
    }

    # Third OSS-Fuzz run: clean (no compiler errors), so the auto-loop stops.
    ossfuzz_3 = {"build_output": "build ok\n", "check_build_output": "check ok\n"}

    cfg = AgentConfig(
        max_steps=20,
        tools_mode="fake",
        error_scope="patch",
        auto_ossfuzz_loop=True,
        ossfuzz_loop_max=3,
    )
    initial_error = "/src/libxml2/error.c:51:1: error: expected ';' after top level declarator"
    st = AgentState(
        build_log_path="-",
        patch_path=str(bundle_path),
        error_scope="patch",
        error_line=initial_error,
        snippet="",
        artifacts_dir=str(root),
        patch_key="p2",
        active_patch_key="p2",
        active_file_path="/src/libxml2/error.c",
        active_line_number=51,
        ossfuzz_project="example",
        ossfuzz_commit="deadbeef",
        patch_override_paths=[str(override_path)],
        patch_generated=True,
        ossfuzz_test_attempted=True,
        ossfuzz_runs_attempted=1,
        steps=[
            {"decision": {"type": "tool", "tool": "get_error_patch_context", "args": {}}, "observation": {"ok": True, "tool": "get_error_patch_context", "output": {}}},
            {"decision": {"type": "tool", "tool": "ossfuzz_apply_patch_and_test", "args": {}}, "observation": {"ok": True, "tool": "ossfuzz_apply_patch_and_test", "output": {"build_output": {"artifact_path": str(build_1_path)}, "check_build_output": {"artifact_path": str(check_1_path)}}}},
        ],
    )
    st.last_observation = ToolObservation(
        ok=True,
        tool="ossfuzz_apply_patch_and_test",
        args={},
        output={"build_output": {"artifact_path": str(build_1_path)}, "check_build_output": {"artifact_path": str(check_1_path)}},
        error=None,
    )

    model = BasePreservingModel()
    runner = FakeRunner(ossfuzz_outputs=[ossfuzz_2, ossfuzz_3])
    store = ArtifactStore(root, overwrite=False)

    final = _run_langgraph(model, runner, st, cfg, artifact_store=store)
    assert final.get("type") == "final", final

    steps = [s for s in (final.get("steps") or []) if isinstance(s, dict)]
    tools = [((s.get("decision") or {}).get("tool")) for s in steps]

    # After the transition from the first OSS-Fuzz run, we must restart patch mapping via get_error_patch_context.
    # Verify this via actual tool calls in this run, not by scanning final["steps"] (which includes pre-populated steps).
    assert "get_error_patch_context" in runner.calls, runner.calls
    assert "read_artifact" in runner.calls, runner.calls
    assert runner.calls.count("make_error_patch_override") >= 2, runner.calls
    assert runner.calls.count("ossfuzz_apply_patch_and_test") >= 2, runner.calls
    assert "get_error_v1_code_slice" not in runner.calls, runner.calls

    # Final output should include the full step history across iterations, including steps that were trimmed
    # from state.steps for prompt hygiene.
    assert "get_error_patch_context" in tools, tools
    assert len(steps) > 3, len(steps)
    assert len(st.steps) < len(st.step_history), (len(st.steps), len(st.step_history))

    # Ensure we retain and render the previously handled errors even though state.steps is trimmed in auto-loop.
    from agent_langgraph import _render_final_text  # noqa: E402

    rendered = _render_final_text(final)
    assert initial_error in rendered, rendered
    assert "unknown type name 'foo_t'" in rendered, rendered
    assert "tool: get_error_patch_context" in rendered, rendered

    # Ensure the first forced get_error_patch_context call uses the build-log /src/... location (line 52),
    # not the previous active_line_number (51).
    forced = None
    for s in steps:
        d = s.get("decision") if isinstance(s, dict) else {}
        if not isinstance(d, dict):
            continue
        if str(d.get("tool") or "") != "get_error_patch_context":
            continue
        args = d.get("args") if isinstance(d.get("args"), dict) else {}
        if args.get("line_number"):
            forced = d
            break
    assert forced, steps
    forced_args = forced.get("args") or {}
    assert forced_args.get("file_path") == "/src/libxml2/error.c", forced_args
    assert forced_args.get("line_number") == 52, forced_args

    # Artifact preservation: repeated patch/log artifacts must not overwrite prior iterations.
    patch_text_versions = sorted(root.glob("make_error_patch_override_patch_text_error.c*.diff"))
    assert len(patch_text_versions) >= 2, patch_text_versions
    build_log_versions = sorted(root.glob("ossfuzz_apply_patch_and_test_build_output*.log"))
    assert len(build_log_versions) >= 2, build_log_versions

    def artifact_path(val):
        if isinstance(val, dict):
            return str(val.get("artifact_path") or "").strip()
        if isinstance(val, str):
            return val.strip()
        return ""

    patch_text_artifacts = []
    build_output_artifacts = []
    for s in steps:
        obs = s.get("observation") if isinstance(s.get("observation"), dict) else {}
        if str(obs.get("tool") or "") == "make_error_patch_override":
            out = obs.get("output") if isinstance(obs.get("output"), dict) else {}
            ap = artifact_path(out.get("patch_text"))
            if ap:
                patch_text_artifacts.append(Path(ap))
        if str(obs.get("tool") or "") == "ossfuzz_apply_patch_and_test":
            out = obs.get("output") if isinstance(obs.get("output"), dict) else {}
            ap = artifact_path(out.get("build_output"))
            if ap and "ossfuzz_apply_patch_and_test_build_output" in Path(ap).name:
                build_output_artifacts.append(Path(ap))

    assert len(set(patch_text_artifacts)) >= 2, patch_text_artifacts
    assert all(p.is_file() for p in patch_text_artifacts), patch_text_artifacts
    assert len(set(build_output_artifacts)) >= 2, build_output_artifacts
    assert all(p.is_file() for p in build_output_artifacts), build_output_artifacts

print("OK")
PY

echo "OK"
