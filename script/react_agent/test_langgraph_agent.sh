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

# Retry transient model/network timeouts instead of exiting with "Agent error."
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import json
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentConfig, AgentState, _run_langgraph_with_retries  # noqa: E402
from models import ChatModel, ModelError  # noqa: E402


class FlakyTimeoutModel(ChatModel):
    def __init__(self) -> None:
        self.turn = 0

    def complete(self, messages):
        self.turn += 1
        if self.turn == 1:
            raise ModelError("OpenAI URLError: <urlopen error timed out>")
        return json.dumps({"type": "final", "thought": "ok", "summary": "ok", "next_step": ""})


class Runner:
    def call(self, tool, args):  # pragma: no cover
        raise AssertionError(f"unexpected tool call: {tool}")


st = AgentState(build_log_path="-", patch_path="", error_scope="first", error_line="/src/x.c:1:1: error: x", snippet="")
cfg = AgentConfig(max_steps=1, tools_mode="fake", error_scope="first")
final = _run_langgraph_with_retries(FlakyTimeoutModel(), Runner(), st, cfg, artifact_store=None, max_retries=2, backoff_sec=0)
assert final.get("type") == "final", final
assert final.get("summary") == "ok", final
print("OK")
PY

# Guardrail: do not introduce new __revert_* call targets in overrides (keep function names stable).
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import json
import tempfile
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _override_no_new_revert_symbols_guardrail_error  # noqa: E402

base = (
    "static const xmlChar *\\n"
    "__revert_e11519_xmlParseStartTag(xmlParserCtxtPtr ctxt) {\\n"
    "  const xmlChar *x = xmlParseAttribute2(ctxt, NULL, NULL, NULL, NULL, NULL, NULL);\\n"
    "  return x;\\n"
    "}\\n"
)
new = (
    "static const xmlChar *\\n"
    "__revert_e11519_xmlParseStartTag(xmlParserCtxtPtr ctxt) {\\n"
    "  const xmlChar *x = __revert_e11519_xmlParseAttribute2(ctxt, NULL, NULL, NULL, NULL, NULL, NULL);\\n"
    "  return x;\\n"
    "}\\n"
)

with tempfile.TemporaryDirectory() as td:
    base_path = Path(td) / "base.c"
    base_path.write_text(base, encoding="utf-8")
    st = AgentState(build_log_path="-", patch_path="bundle.patch2", error_scope="patch", error_line="x", snippet="")
    st.loop_base_func_code_artifact_path = str(base_path)
    decision = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "args": {"new_func_code": new, "patch_path": "bundle.patch2", "file_path": "/src/x.c", "line_number": 1},
    }
    err = _override_no_new_revert_symbols_guardrail_error(st, decision)
    assert err and "introduces" in err, err
print("OK")
PY

# read_file_context: avoid empty output when working tree path is missing but
# content is available via git-object fallback (REACT_AGENT_V2_SRC_COMMIT).
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import subprocess
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from agent_tools import AgentTools, KbIndex, SourceManager  # noqa: E402

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()

    src_v1 = td / "src_v1"
    src_v2 = td / "src_v2"
    src_v1.mkdir()
    src_v2.mkdir()

    subprocess.run(["git", "init"], cwd=src_v2, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    header_rel = Path("src/include/ndpi_typedefs.h")
    header_path = src_v2 / header_rel
    header_path.parent.mkdir(parents=True, exist_ok=True)
    header_path.write_text(
        "typedef struct ndpi_detection_module_struct {\\n"
        "  int ptree;\\n"
        "  int protocols;\\n"
        "} ndpi_detection_module_struct;\\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=src_v2, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "init"],
        cwd=src_v2,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    commit = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=src_v2, text=True)
        .strip()
    )

    # Remove from worktree to force fallback (path resolution alone would fail).
    header_path.unlink()

    os.environ["REACT_AGENT_V2_SRC_COMMIT"] = commit
    try:
        tools = AgentTools(KbIndex(str(kb_v1), str(kb_v2)), SourceManager(str(src_v1), str(src_v2)))
        out = tools.read_file_context(
            file_path="src/include/ndpi_typedefs.h",
            line_number=2,
            context=1,
            version="v2",
        )
    finally:
        os.environ.pop("REACT_AGENT_V2_SRC_COMMIT", None)

    assert out, out
    assert "ndpi_typedefs.h" in out, out
    assert "ptree" in out, out
    assert ">>" in out, out

print("OK")
PY

# Guardrail: do not add local __revert_* prototypes inside make_error_patch_override bodies.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import tempfile
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _override_no_local_revert_prototypes_guardrail_error  # noqa: E402

base = (
    "static int fn(void) {\\n"
    "  return __revert_deadbeef_target(1);\\n"
    "}\\n"
)
new_bad = (
    "static int fn(void) {\\n"
    "  int __revert_deadbeef_target(int);\\n"
    "  return __revert_deadbeef_target(1);\\n"
    "}\\n"
)

with tempfile.TemporaryDirectory() as td:
    base_path = Path(td) / "base.c"
    base_path.write_text(base, encoding="utf-8")
    st = AgentState(build_log_path="-", patch_path="bundle.patch2", error_scope="patch", error_line="x", snippet="")
    st.loop_base_func_code_artifact_path = str(base_path)

    bad_decision = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "args": {"new_func_code": new_bad, "patch_path": "bundle.patch2", "file_path": "/src/x.c", "line_number": 1},
    }
    err = _override_no_local_revert_prototypes_guardrail_error(st, bad_decision)
    assert err and "local `__revert_*` prototype" in err, err

    ok_decision = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "args": {"new_func_code": base, "patch_path": "bundle.patch2", "file_path": "/src/x.c", "line_number": 1},
    }
    assert _override_no_local_revert_prototypes_guardrail_error(st, ok_decision) is None

print("OK")
PY

# Guardrail: do not falsely flag __revert_* prefixed BASE function names as "renamed".
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import tempfile
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _override_preserve_function_name_guardrail_error  # noqa: E402

base = (
    "static const xmlChar *\\n"
    "__revert_e11519_xmlParseStartTag2(xmlParserCtxtPtr ctxt) {\\n"
    "  return NULL;\\n"
    "}\\n"
)

with tempfile.TemporaryDirectory() as td:
    base_path = Path(td) / "base.c"
    base_path.write_text(base, encoding="utf-8")
    st = AgentState(build_log_path="-", patch_path="bundle.patch2", error_scope="patch", error_line="x", snippet="")
    st.active_old_signature = "const xmlChar * xmlParseStartTag2(xmlParserCtxtPtr ctxt)"
    st.loop_base_func_code_artifact_path = str(base_path)
    decision = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "args": {"new_func_code": base, "patch_path": "bundle.patch2", "file_path": "/src/x.c", "line_number": 1},
    }
    err = _override_preserve_function_name_guardrail_error(st, decision)
    assert err is None, err
print("OK")
PY

# Guardrail repair prompts: do not include the initial patch-scope build-error blob (Build log path / Log context).
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import tempfile
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _build_guardrail_repair_messages, _build_messages  # noqa: E402

base = "int f(int x) { return x + 1; }\n"

with tempfile.TemporaryDirectory() as td:
    base_path = Path(td) / "base.c"
    base_path.write_text(base, encoding="utf-8")

    st = AgentState(
        build_log_path="build.log",
        patch_path="bundle.patch2",
        error_scope="patch",
        error_line="/src/a.c:1:1: error: e1",
        snippet="",
    )
    st.patch_key = "p1"
    st.active_patch_key = "p1"
    st.active_file_path = "/src/a.c"
    st.active_line_number = 1
    st.active_old_signature = "int f(int x)"
    st.loop_base_func_code_artifact_path = str(base_path)
    st.grouped_errors = [{"raw": "/src/a.c:1:1: error: e1", "file": "/src/a.c", "line": 1, "col": 1, "msg": "e1"}]

    msgs = _build_messages(st)
    assert any("Build log path:" in m.get("content", "") for m in msgs if m.get("role") == "user"), msgs

    rejected = {
        "type": "tool",
        "thought": "bad override",
        "tool": "make_error_patch_override",
        "args": {"patch_path": "bundle.patch2", "file_path": "/src/a.c", "line_number": 1, "new_func_code": base},
    }
    repair = _build_guardrail_repair_messages(st, msgs, rejected, "GUARDRAIL")

    joined = "\n".join(m.get("content", "") for m in repair if m.get("role") in {"user", "assistant", "system"})
    assert "Build log path:" not in joined, joined
    assert "Patch-scope active error:" not in joined, joined
    assert "Log context:" not in joined, joined
    assert "Guardrail repair context" not in joined, joined

print("OK")
PY

# Focus-error ordering (debug): allow prioritizing a specific error substring ahead of warnings.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import (  # noqa: E402
    _prioritize_focus_within_hunk,
    _prioritize_unknown_type_name_within_hunk,
    _prioritize_warnings_within_hunk,
)

errors = [
    {
        "level": "warning",
        "msg": "no previous prototype for function 'foo'",
        "raw": "/src/x.c:1:1: warning: no previous prototype for function 'foo'",
        "snippet": "warning block",
    },
    {
        "level": "error",
        "msg": "no member named 'nsdb' in 'struct _xmlParserCtxt'",
        "raw": "/src/y.c:2:2: error: no member named 'nsdb' in 'struct _xmlParserCtxt'",
        "snippet": "error block",
    },
]

ranked = _prioritize_focus_within_hunk(_prioritize_warnings_within_hunk(errors), "nsdb")
assert ranked[0]["level"] == "error", ranked
assert "nsdb" in ranked[0]["msg"], ranked

ranked2 = _prioritize_focus_within_hunk(_prioritize_warnings_within_hunk(errors), "")
assert ranked2[0]["level"] == "warning", ranked2

# Unknown-type ordering: prefer unknown type name errors first (even ahead of warnings).
errors2 = [
    {
        "level": "warning",
        "msg": "no previous prototype for function 'foo'",
        "raw": "/src/x.c:1:1: warning: no previous prototype for function 'foo'",
        "snippet": "warning block",
    },
    {
        "level": "error",
        "msg": "unknown type name 'foo_t'",
        "raw": "/src/y.c:2:2: error: unknown type name 'foo_t'",
        "snippet": "error block",
    },
]
ranked3 = _prioritize_warnings_within_hunk(errors2)
assert ranked3[0]["level"] == "warning", ranked3
ranked4 = _prioritize_unknown_type_name_within_hunk(ranked3)
assert ranked4[0]["level"] == "error", ranked4
assert "unknown type name" in ranked4[0]["msg"], ranked4

print("OK")
PY

# Retry classifier: treat OpenAI HTTP 5xx/429 as transient, but not auth failures.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import io
import sys
import urllib.error
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import _is_transient_agent_error  # noqa: E402
from models import ModelError  # noqa: E402


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="https://api.openai.com/v1/chat/completions",
        code=code,
        msg="x",
        hdrs=None,
        fp=io.BytesIO(b"body"),
    )


try:
    raise ModelError("OpenAI HTTPError: 502 Bad Gateway <html>cloudflare</html>") from http_error(502)
except Exception as exc:  # noqa: BLE001
    assert _is_transient_agent_error(exc) is True, exc

try:
    raise ModelError("OpenAI HTTPError: 401 Unauthorized") from http_error(401)
except Exception as exc:  # noqa: BLE001
    assert _is_transient_agent_error(exc) is False, exc

print("OK")
PY

# Guardrail: do not force make_extra_patch_override due to unrelated grouped errors when the active error is not undeclared.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _undeclared_symbol_extra_patch_guardrail_for_override  # noqa: E402

st = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line="/src/x.c:1:1: error: no member named 'nsdb' in 'struct _xmlParserCtxt'",
    snippet="if (ctxt->nsdb) {}",
)
st.patch_key = "p1"
st.grouped_errors = [
    {"raw": st.error_line, "file": "/src/x.c", "line": 1, "col": 1, "level": "error", "msg": "missing member"},
    {
        "raw": "/src/x.c:2:1: warning: call to undeclared function 'foo' [-Wimplicit-function-declaration]",
        "file": "/src/x.c",
        "line": 2,
        "col": 1,
        "level": "warning",
        "msg": "call to undeclared function 'foo'",
    },
]
# Simulate auto-loop state where mapping prereqs are already satisfied.
st.loop_base_func_code_artifact_path = "/tmp/base.c"

decision = {
    "type": "tool",
    "thought": "rewrite function",
    "tool": "make_error_patch_override",
    "args": {"patch_path": "bundle.patch2", "file_path": "/src/x.c", "line_number": 1, "new_func_code": "int f(void){return 0;}"},
}

forced = _undeclared_symbol_extra_patch_guardrail_for_override(st, decision)
assert forced is None, forced
print("OK")
PY

# Patch-scope prompt: include full log context for the active error only.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _build_messages  # noqa: E402

st = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line="/src/a.c:1:1: error: e1",
    snippet="",
)
st.patch_key = "p1"
st.grouped_errors = [
    {"raw": "/src/a.c:1:1: error: e1", "file": "/src/a.c", "line": 1, "col": 1, "msg": "e1", "snippet": "line1\\n  1 | bad\\n    | ^"},
    {"raw": "/src/b.c:2:3: error: e2", "file": "/src/b.c", "line": 2, "col": 3, "msg": "e2", "snippet": "line2\\n  2 | also bad\\n    |   ^"},
]

msgs = _build_messages(st)
user = next(m["content"] for m in msgs if m.get("role") == "user")
assert "Log context:" in user, user
assert "line1" in user, user
assert "/src/b.c:2:3: error: e2" not in user, user
assert "Other errors in this patch_key" not in user, user
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

st_undeclared = AgentState(
    build_log_path="-",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line="/src/x.c:1:1: error: use of undeclared identifier 'xmlHashedString'",
    snippet="",
)
p_undeclared = build_system_prompt(st_undeclared, tool_specs=TOOL_SPECS)
assert "Undeclared symbol/type errors (C/C++):" in p_undeclared, p_undeclared

st_tail = AgentState(build_log_path="-", patch_path="bundle.patch2", error_scope="patch", error_line="x", snippet="")
st_tail.active_old_signature = "int f(int x)"
st_tail.active_patch_types = ["Merged functions"]
p_tail = build_system_prompt(st_tail, tool_specs=TOOL_SPECS)
assert "Merged/tail hunks" in p_tail, p_tail

st_not_merged = AgentState(build_log_path="-", patch_path="bundle.patch2", error_scope="patch", error_line="x", snippet="")
st_not_merged.active_old_signature = "int f(int x)"
st_not_merged.active_patch_types = ["Recreated function"]
p_not_merged = build_system_prompt(st_not_merged, tool_specs=TOOL_SPECS)
assert "Mapped-slice rewrites" in p_not_merged, p_not_merged
assert "Merged/tail hunks" not in p_not_merged, p_not_merged

st_member = AgentState(
    build_log_path="-",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line="/src/x.c:1:1: error: no member named 'nbWarnings' in 'struct _xmlParserCtxt'",
    snippet="",
)
p_member = build_system_prompt(st_member, tool_specs=TOOL_SPECS)
assert "Struct-member errors:" in p_member, p_member
assert "Workflow (patch-scope):" in p_member, p_member
assert "get_error_patch_context" in p_member, p_member
assert "search_definition(symbol_name=\"struct <Name>\"" in p_member, p_member
assert "make_error_patch_override" in p_member, p_member
assert "ossfuzz_apply_patch_and_test" in p_member, p_member

print("OK")
PY

# Patch-scope prompt: show only the active error (no other errors).
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _build_messages  # noqa: E402

st = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line="/src/a.c:1:1: error: e1",
    snippet="",
)
st.patch_key = "p2"
st.grouped_errors = [
    {"raw": "/src/a.c:1:1: error: e1", "file": "/src/a.c", "line": 1, "col": 1, "msg": "e1"},
    {"raw": "/src/a.c:2:1: error: e2", "file": "/src/a.c", "line": 2, "col": 1, "msg": "e2"},
]

msgs = _build_messages(st)
user = next(m["content"] for m in msgs if m.get("role") == "user")

assert "Patch-scope active error:" in user, user
assert "/src/a.c:1:1: error: e1" in user, user
assert "Other errors in this patch_key" not in user, user
assert "/src/a.c:2:1: error: e2" not in user, user

print("OK")
PY

# Mapping regression: do not treat an `_extra_*` override diff as the active patch_key's override just because
# the override file happens to be nested under `.../<active_patch_key>/_extra_*/...`.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import pickle
import re
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _load_effective_patch_bundle_for_mapping  # noqa: E402
from migration_tools.types import PatchInfo  # noqa: E402

main_key = "p_main"
extra_key = "_extra_parser.c"

main_patch_text = (
    "diff --git a/parser.c b/parser.c\n"
    "--- a/parser.c\n"
    "+++ b/parser.c\n"
    "@@ -10,25 +10,25 @@\n"
    + "".join(f"-MAIN{i:02d}\n" for i in range(1, 51))
)
extra_patch_text = (
    "diff --git a/parser.c b/parser.c\n"
    "--- a/parser.c\n"
    "+++ b/parser.c\n"
    "@@ -90,6 +90,3 @@\n"
    "-EXTRA\n"
    "+EXTRA\n"
)

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(root)

    bundle_path = root / "bundle.patch2"
    patches = {
        main_key: PatchInfo(
            file_path_old="parser.c",
            file_path_new="parser.c",
            patch_text=main_patch_text,
            file_type="source",
            old_start_line=10,
            old_end_line=50,
            new_start_line=10,
            new_end_line=50,
            patch_type={"Recreated function"},
            old_signature="int main(void)",
            dependent_func=set(),
            hiden_func_dict={},
        ),
        extra_key: PatchInfo(
            file_path_old="parser.c",
            file_path_new="parser.c",
            patch_text=extra_patch_text,
            file_type="source",
            old_start_line=90,
            old_end_line=95,
            new_start_line=90,
            new_end_line=95,
            patch_type={"Extra"},
            old_signature="",
            dependent_func=set(),
            hiden_func_dict={},
        ),
    }
    bundle_path.write_bytes(pickle.dumps(patches))

    # The override diff applies to `_extra_parser.c`, but the file is nested under `<main_key>/_extra_parser.c/`.
    override_dir = root / main_key / extra_key
    override_dir.mkdir(parents=True, exist_ok=True)
    override_path = override_dir / "override__extra_parser.c.diff"
    override_path.write_text(extra_patch_text, encoding="utf-8")

    st = AgentState(build_log_path="-", patch_path=str(bundle_path), error_scope="patch", error_line="x", snippet="")
    st.patch_key = main_key
    st.active_patch_key = main_key
    st.patch_override_paths = [str(override_path)]
    st.patch_override_by_key = {}

    bundle, err = _load_effective_patch_bundle_for_mapping(st)
    assert err is None, err
    out_patches = getattr(bundle, "patches", None)
    assert isinstance(out_patches, dict), type(out_patches)
    assert str(out_patches[main_key].patch_text) == main_patch_text, "main patch_text was incorrectly overridden"

print("OK")
PY

# Prompt hygiene: do not include missing-struct-member summaries unless the active error is a missing-member diagnostic.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _build_messages  # noqa: E402

st = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line="/src/a.c:1:1: warning: call to undeclared function 'foo' [-Wimplicit-function-declaration]",
    snippet="",
)
st.patch_key = "p2"
st.grouped_errors = [
    {"raw": st.error_line, "file": "/src/a.c", "line": 1, "col": 1, "level": "warning", "msg": "call to undeclared function 'foo'"},
]

# Simulate stale/extra missing-member info from other errors in the same patch_key.
st.missing_struct_members = [{"struct": "struct _X", "members": ["y"]}]

msgs = _build_messages(st)
user = next(m["content"] for m in msgs if m.get("role") == "user")

assert "Missing struct members" not in user, user
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

log2 = "/src/libxml2/parser.c:16941:1: warning: no previous prototype for function '__revert_e11519_xmlParserNsCreate' [-Wmissing-prototypes]\\n"
errs2 = iter_compiler_errors(log2, snippet_lines=0)
assert errs2 and errs2[0].get("level") == "warning", errs2
assert errs2[0].get("file") == "/src/libxml2/parser.c", errs2
assert "__revert_e11519_xmlParserNsCreate" in str(errs2[0].get("msg") or ""), errs2
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

    # prefer_definition=True should insert the full function body into _extra_*.
    out_def = make_extra_patch_override(
        None,
        patch_path=str(bundle_path),
        file_path="/src/libxml2/dict.c",
        symbol_name="__revert_deadbeef_myfunc",
        version="v1",
        prefer_definition=True,
    )
    ref_def = out_def.get("patch_text") or {}
    assert isinstance(ref_def, dict) and ref_def.get("artifact_path"), out_def
    p_def = Path(str(ref_def.get("artifact_path"))).resolve()
    assert p_def.is_file(), p_def
    text_def = p_def.read_text(encoding="utf-8", errors="replace")
    assert "int __revert_deadbeef_myfunc(int x) {" in text_def, text_def
    assert "return x;" in text_def, text_def

print("OK")
PY

# Extra patch override tool: avoid confusing wasm3-style `_   (call());` statements with prototypes.
# If the bundle only contains a call site, fall back to KB to synthesize a real prototype.
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

    # Minimal KB + sources: v1 has `int myfunc(int x) { ... }`.
    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()
    v1_src = td / "v1_src"
    v2_src = td / "v2_src"
    v1_src.mkdir()
    v2_src.mkdir()

    (v1_src / "dict.c").write_text("int myfunc(int x) {\\n  return x;\\n}\\n", encoding="utf-8")
    (v2_src / "dict.c").write_text("/* v2 placeholder */\\n", encoding="utf-8")
    node = {
        "kind": "FUNCTION_DEFI",
        "spelling": "myfunc",
        "location": {"file": "dict.c", "line": 1, "column": 1},
        "extent": {
            "start": {"file": "dict.c", "line": 1, "column": 1},
            "end": {"file": "dict.c", "line": 3, "column": 1},
        },
    }
    (kb_v1 / "dict.c_analysis.json").write_text(json.dumps([node]), encoding="utf-8")

    kb_index = KbIndex(str(kb_v1), str(kb_v2))
    source_manager = SourceManager(str(v1_src), str(v2_src))
    agent_tools = AgentTools(kb_index, source_manager)

    # Bundle with a call site at column 1: `_   (__revert_deadbeef_myfunc(...));`
    bundle_path = td / "bundle.patch2"
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
        "@@ -10,5 +10,0 @@\n"
        "-static int caller(void) {\n"
        "-_   (__revert_deadbeef_myfunc(123));\n"
        "-  return 0;\n"
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
        old_signature="",
        dependent_func=set(),
        hiden_func_dict={},
    )
    bundle_path.write_bytes(
        pickle.dumps({extra_key: extra_patch, main_key: main_patch}, protocol=pickle.HIGHEST_PROTOCOL)
    )

    out = make_extra_patch_override(
        agent_tools,
        patch_path=str(bundle_path),
        file_path="/src/libxml2/dict.c",
        symbol_name="__revert_deadbeef_myfunc",
        version="v1",
    )
    assert out.get("patch_key") == extra_key, out
    ref = out.get("patch_text") or {}
    p = Path(str(ref.get("artifact_path") or "")).resolve()
    assert p.is_file(), p
    text = p.read_text(encoding="utf-8", errors="replace")
    assert "int __revert_deadbeef_myfunc(int x);" in text, text

print("OK")
PY

# _is_valid_function_prototype must reject bare call sites that lack a return type prefix.
# A bare `funcname(args);` at column 0 is a call site, not a prototype.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from tools.extra_patch_tools import _is_valid_function_prototype  # noqa: E402

# Call site: no return type before function name → reject
assert not _is_valid_function_prototype(
    ['__revert_3ac8a0_hfile_add_scheme_handler("s3", &handler);'],
    symbol_name="__revert_3ac8a0_hfile_add_scheme_handler",
), "Bare call site should NOT be accepted as a valid prototype"

# Real single-line prototype with return type → accept
assert _is_valid_function_prototype(
    ["void __revert_3ac8a0_hfile_add_scheme_handler(const char *scheme, const struct hFILE_scheme_handler *handler);"],
    symbol_name="__revert_3ac8a0_hfile_add_scheme_handler",
), "Real prototype with return type should be valid"

# Multi-line prototype (return type on separate line) → accept
assert _is_valid_function_prototype(
    ["static inline void", "__revert_3ac8a0_hfile_add_scheme_handler(const char *scheme);"],
    symbol_name="__revert_3ac8a0_hfile_add_scheme_handler",
), "Multi-line prototype with return type should be valid"

print("OK")
PY

# _strip_attribute_macros_from_prototype: strip ALL_CAPS attribute macros from prototypes.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
from tools.extra_patch_tools import _strip_attribute_macros_from_prototype

# HTS_OPT3 on a separate line before the function name should be stripped.
lines = ["static inline void HTS_OPT3", "__revert_9e1ffd_add33(uint8_t *a, const uint8_t *b, int32_t len);"]
result = _strip_attribute_macros_from_prototype(lines, func_name="__revert_9e1ffd_add33")
joined = " ".join(l.strip() for l in result)
assert "HTS_OPT3" not in joined, f"HTS_OPT3 should be stripped: {result}"
assert "__revert_9e1ffd_add33(uint8_t *a" in joined, f"function name should remain: {result}"
assert "static inline void" in joined, f"return type should remain: {result}"

# ALL_CAPS types in parameter list should NOT be stripped.
lines2 = ["void NOINLINE __revert_foo(BOOL x, DWORD y);"]
result2 = _strip_attribute_macros_from_prototype(lines2, func_name="__revert_foo")
joined2 = " ".join(l.strip() for l in result2)
assert "NOINLINE" not in joined2, f"NOINLINE should be stripped: {result2}"
assert "BOOL" in joined2, f"BOOL param type should remain: {result2}"
assert "DWORD" in joined2, f"DWORD param type should remain: {result2}"

# No ALL_CAPS tokens: should be unchanged.
lines3 = ["static int __revert_bar(int x);"]
result3 = _strip_attribute_macros_from_prototype(lines3, func_name="__revert_bar")
assert result3 == lines3, f"No-op expected: {result3}"

print("OK")
PY

# revise_patch_hunk: editable_hunk field and round-trip sign flip for mixed -/+ hunks.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import pickle
import re
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parent))

from migration_tools.tools import get_error_patch_context, revise_patch_hunk
from migration_tools.types import PatchInfo

# Build a mixed hunk: LLVMFuzzerTestOneInput with both - and + lines.
patch_text = (
    "diff --git a/harness.c b/harness.c\n"
    "--- a/harness.c\n"
    "+++ b/harness.c\n"
    "@@ -10,6 +10,4 @@\n"
    " int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
    "-    view_vcf(data, size, \"w\");\n"
    "-    view_vcf(data, size, \"wb\");\n"
    "+    view_vcf(ht_file);\n"
    "     return 0;\n"
    " }\n"
)
patch = PatchInfo(
    file_path_old="harness.c",
    file_path_new="harness.c",
    old_start_line="10",
    old_end_line="16",
    new_start_line="10",
    new_end_line="14",
    file_type="c",
    patch_text=patch_text,
    old_signature="int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)",
    new_signature="int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)",
)
bundle = {"harness.charness.c-10,6+10,4": patch}

with tempfile.TemporaryDirectory() as td:
    bp = os.path.join(td, "test.patch2")
    with open(bp, "wb") as f:
        pickle.dump(bundle, f)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = td

    # 1) get_error_patch_context returns editable_hunk with flipped signs.
    ctx = get_error_patch_context(
        patch_path=bp,
        file_path="/src/project/harness.c",
        line_number=11,
        error_text="too many arguments",
        allowed_roots=[td],
    )
    eh = ctx.get("editable_hunk", "")
    assert eh, f"editable_hunk should be non-empty for mixed hunk: {ctx}"
    eh_lines = eh.strip().split("\n")
    # '+' lines in editable_hunk = V1 code (originally '-' in patch)
    plus_lines = [l for l in eh_lines if l.startswith("+")]
    minus_lines = [l for l in eh_lines if l.startswith("-")]
    assert len(plus_lines) == 2, f"Expected 2 '+' lines (V1 calls): {plus_lines}"
    assert len(minus_lines) == 1, f"Expected 1 '-' line (V2 call): {minus_lines}"
    assert 'view_vcf(data, size, "w")' in plus_lines[0], plus_lines[0]
    assert "view_vcf(ht_file)" in minus_lines[0], minus_lines[0]

    # 2) revise_patch_hunk: edit the '+' lines (fix V1 code), keep '-' lines unchanged.
    revised = (
        "-    view_vcf(ht_file);\n"
        "+    view_vcf(ht_file);\n"
        "+    view_vcf(ht_file);\n"
    )
    result = revise_patch_hunk(
        patch_path=bp,
        file_path="/src/project/harness.c",
        line_number=11,
        revised_hunk=revised,
        allowed_roots=[td],
    )
    pt = result.get("patch_text", "")
    assert pt, f"patch_text should be non-empty: {result}"
    # After flipping back: '+' in revised → '-' in patch, '-' in revised → '+' in patch.
    pt_lines = pt.strip().split("\n")
    new_minus = [l for l in pt_lines if l.startswith("-") and not l.startswith("---")]
    new_plus = [l for l in pt_lines if l.startswith("+") and not l.startswith("+++")]
    # Two '-' lines: the fixed V1 code
    assert len(new_minus) == 2, f"Expected 2 '-' lines in output: {new_minus}"
    assert all("view_vcf(ht_file)" in l for l in new_minus), new_minus
    # One '+' line: V2 code preserved
    assert len(new_plus) == 1, f"Expected 1 '+' line in output: {new_plus}"
    assert "view_vcf(ht_file)" in new_plus[0], new_plus[0]

    # 3) revise_patch_hunk: changing V2 lines raises ValueError.
    bad_revised = (
        "-    MODIFIED_view_vcf(ht_file);\n"
        "+    view_vcf(ht_file);\n"
    )
    try:
        revise_patch_hunk(
            patch_path=bp,
            file_path="/src/project/harness.c",
            line_number=11,
            revised_hunk=bad_revised,
            allowed_roots=[td],
        )
        assert False, "Should have raised ValueError for modified V2 lines"
    except ValueError as e:
        assert "V2 code" in str(e), str(e)

    # 4) Pure minus hunk: editable_hunk should be empty.
    pure_minus_text = (
        "diff --git a/pure.c b/pure.c\n"
        "--- a/pure.c\n"
        "+++ b/pure.c\n"
        "@@ -5,3 +5,0 @@\n"
        "-void removed_func(void) {\n"
        "-    return;\n"
        "-}\n"
    )
    pure_patch = PatchInfo(
        file_path_old="pure.c",
        file_path_new="pure.c",
        old_start_line="5",
        old_end_line="8",
        new_start_line="5",
        new_end_line="5",
        file_type="c",
        patch_text=pure_minus_text,
        old_signature="void removed_func(void)",
    )
    bundle2 = {"pure.cpure.c-5,3+5,0": pure_patch}
    bp2 = os.path.join(td, "pure.patch2")
    with open(bp2, "wb") as f:
        pickle.dump(bundle2, f)
    ctx2 = get_error_patch_context(
        patch_path=bp2,
        file_path="/src/project/pure.c",
        line_number=5,
        allowed_roots=[td],
    )
    assert not ctx2.get("editable_hunk", "").strip(), \
        f"editable_hunk should be empty for pure minus hunk: {ctx2.get('editable_hunk')}"

    # 5) revise_patch_hunk on pure minus hunk: returns note to use make_error_patch_override.
    result2 = revise_patch_hunk(
        patch_path=bp2,
        file_path="/src/project/pure.c",
        line_number=5,
        revised_hunk="-void removed_func(void) {\n",
        allowed_roots=[td],
    )
    note = result2.get("note", "")
    assert "make_error_patch_override" in note, f"Expected redirect note: {note}"

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

    # V2 KB: xmlMutex is an opaque typedef (struct body not in headers) but provides xmlMutexPtr.
    v2_typedefs = [
        {
            "kind": "TYPEDEF_DECL",
            "spelling": "xmlMutex",
            "location": {"file": "threads.h", "line": 1, "column": 1},
            "extent": {"start": {"file": "threads.h", "line": 1, "column": 1}, "end": {"file": "threads.h", "line": 1, "column": 40}},
        },
        {
            "kind": "TYPEDEF_DECL",
            "spelling": "xmlMutexPtr",
            "location": {"file": "threads.h", "line": 2, "column": 1},
            "extent": {"start": {"file": "threads.h", "line": 2, "column": 1}, "end": {"file": "threads.h", "line": 2, "column": 40}},
        },
        {
            "kind": "STRUCT_DECL",
            "spelling": "_xmlMutex",
            "location": {"file": "threads.c", "line": 1, "column": 1},
            "extent": {"start": {"file": "threads.c", "line": 1, "column": 1}, "end": {"file": "threads.c", "line": 6, "column": 1}},
        },
    ]
    (kb_v2 / "threads.h_analysis.json").write_text(json.dumps(v2_typedefs), encoding="utf-8")

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
    (src_v2 / "threads.h").write_text("typedef struct _xmlMutex xmlMutex;\ntypedef xmlMutex *xmlMutexPtr;\n", encoding="utf-8")
    (src_v2 / "threads.c").write_text("struct _xmlMutex {\n  int x;\n};\n", encoding="utf-8")

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
    assert "static xmlMutexPtr xmlRngMutex;" in inserted, inserted
    assert "xmlInitMutex" not in inserted, inserted
    ref = out.get("patch_text") or {}
    p = Path(str(ref.get("artifact_path") or "")).resolve()
    assert p.is_file(), p
    text_out = p.read_text(encoding="utf-8", errors="replace")
    assert "static xmlMutexPtr xmlRngMutex;" in text_out, text_out
    assert "xmlInitMutex" not in text_out, text_out

print("OK")
PY

# Extra patch override node selection: DECL_REF_EXPR -> ENUM_CONSTANT_DECL should
# recover the parent ENUM_DECL so make_extra can insert a real declaration block.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import json
import os
import re
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from core.kb_index import KbIndex  # noqa: E402
from core.source_manager import SourceManager  # noqa: E402
from tools.extra_patch_tools import _kb_pick_insertable_node  # noqa: E402
from tools.symbol_tools import AgentTools  # noqa: E402

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(td)
    os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(td / "artifacts")

    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()

    src_v1 = td / "src_v1"
    src_v2 = td / "src_v2"
    (src_v1 / "cram").mkdir(parents=True)
    (src_v2 / "cram").mkdir(parents=True)

    enum_code = (
        "enum cram_block_method_int {\n"
        "    RAW = 0,\n"
        "    RANSPR = 5,\n"
        "    BM_ERROR = -1,\n"
        "};\n"
    )
    (src_v1 / "cram" / "cram_structs.h").write_text(enum_code, encoding="utf-8")
    (src_v2 / "cram" / "cram_structs.h").write_text("/* v2 */\n", encoding="utf-8")

    v1_nodes = [
        {
            "kind": "DECL_REF_EXPR",
            "spelling": "RANSPR",
            "location": {"file": "cram/cram_io.c", "line": 1940, "column": 57},
            "type_ref": {
                "target_kind": "ENUM_CONSTANT_DECL",
                "target_name": "RANSPR",
                "usr": "c:@E@cram_block_method_int@RANSPR",
                "typedef_extent": {
                    "start": {"file": "cram/cram_structs.h", "line": 3, "column": 5},
                    "end": {"file": "cram/cram_structs.h", "line": 3, "column": 17},
                },
            },
            "extent": {
                "start": {"file": "cram/cram_io.c", "line": 1940, "column": 57},
                "end": {"file": "cram/cram_io.c", "line": 1940, "column": 63},
            },
        },
        {
            "kind": "ENUM_DECL",
            "spelling": "cram_block_method_int",
            "usr": "c:@E@cram_block_method_int",
            "location": {"file": "cram/cram_structs.h", "line": 1, "column": 1},
            "extent": {
                "start": {"file": "cram/cram_structs.h", "line": 1, "column": 1},
                "end": {"file": "cram/cram_structs.h", "line": 5, "column": 2},
            },
        },
    ]
    (kb_v1 / "cram_structs.h_analysis.json").write_text(json.dumps(v1_nodes), encoding="utf-8")

    tools = AgentTools(KbIndex(str(kb_v1), str(kb_v2)), SourceManager(str(src_v1), str(src_v2)))

    picked = _kb_pick_insertable_node(tools, symbol="RANSPR", version="v1")
    assert picked is not None, picked
    assert picked.get("kind") == "ENUM_DECL", picked
    assert picked.get("spelling") == "cram_block_method_int", picked
    code = tools.source_manager.get_function_code(picked, "v1")
    assert "enum cram_block_method_int" in code, code
    assert "RANSPR" in code, code

print("OK")
PY

# Extra patch override tool: if the symbol is already present in the `_extra_*` hunk but the declaration
# uses an unsafe by-value opaque typedef (e.g. `static xmlMutex xmlRngMutex;` in V2), rewrite it to a
# pointer form and emit an override diff (do not no-op).
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

    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()

    v2_typedefs = [
        {
            "kind": "TYPEDEF_DECL",
            "spelling": "xmlMutex",
            "location": {"file": "threads.h", "line": 1, "column": 1},
            "extent": {
                "start": {"file": "threads.h", "line": 1, "column": 1},
                "end": {"file": "threads.h", "line": 1, "column": 40},
            },
        },
        {
            "kind": "TYPEDEF_DECL",
            "spelling": "xmlMutexPtr",
            "location": {"file": "threads.h", "line": 2, "column": 1},
            "extent": {
                "start": {"file": "threads.h", "line": 2, "column": 1},
                "end": {"file": "threads.h", "line": 2, "column": 40},
            },
        },
        {
            "kind": "STRUCT_DECL",
            "spelling": "_xmlMutex",
            "location": {"file": "threads.c", "line": 1, "column": 1},
            "extent": {"start": {"file": "threads.c", "line": 1, "column": 1}, "end": {"file": "threads.c", "line": 6, "column": 1}},
        },
    ]
    (kb_v2 / "threads.h_analysis.json").write_text(json.dumps(v2_typedefs), encoding="utf-8")

    src_v1 = td / "src_v1"
    src_v2 = td / "src_v2"
    src_v1.mkdir()
    src_v2.mkdir()
    (src_v2 / "threads.h").write_text("typedef struct _xmlMutex xmlMutex;\ntypedef xmlMutex *xmlMutexPtr;\n", encoding="utf-8")
    (src_v2 / "threads.c").write_text("struct _xmlMutex {\n  int x;\n};\n", encoding="utf-8")

    tools = AgentTools(KbIndex(str(kb_v1), str(kb_v2)), SourceManager(str(src_v1), str(src_v2)))

    bundle_path = td / "bundle.patch2"
    extra_key = "_extra_dict.c"
    extra_patch_text = (
        "diff --git a/dict.c b/dict.c\n"
        "--- a/dict.c\n"
        "+++ b/dict.c\n"
        "@@ -1,2 +1,0 @@\n"
        "-/* extra decls */\n"
        "-static xmlMutex xmlRngMutex;\n"
    )
    extra_patch = PatchInfo(
        file_path_old="dict.c",
        file_path_new="dict.c",
        patch_text=extra_patch_text,
        file_type="c",
        old_start_line=1,
        old_end_line=3,
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
    assert out.get("insert_kind") == "rewrite_existing_opaque_var_decl", out
    ref = out.get("patch_text") or {}
    p = Path(str(ref.get("artifact_path") or "")).resolve()
    assert p.is_file(), p
    text_out = p.read_text(encoding="utf-8", errors="replace")
    assert "-static xmlMutexPtr xmlRngMutex;" in text_out, text_out
    assert "-static xmlMutex xmlRngMutex;" not in text_out, text_out

print("OK")
PY

# Extra patch override tool: if the symbol is already present but only as a forward typedef
# (e.g. `typedef struct TAG Name;`), insert the tag body definition (struct/union/enum) from KB.
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

    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()

    # Only the underlying tag body exists in KB (mirrors real libxml2 where the alias is in a header).
    tag_node = {
        "kind": "STRUCT_DECL",
        "spelling": "_xmlParserNsData",
        "location": {"file": "parser.c", "line": 1, "column": 1},
        "extent": {"start": {"file": "parser.c", "line": 1, "column": 1}, "end": {"file": "parser.c", "line": 6, "column": 1}},
    }
    (kb_v1 / "parser.c_analysis.json").write_text(json.dumps([tag_node]), encoding="utf-8")

    src_v1 = td / "src_v1"
    src_v2 = td / "src_v2"
    src_v1.mkdir()
    src_v2.mkdir()
    (src_v1 / "parser.c").write_text(
        "struct _xmlParserNsData {\n"
        "    unsigned elementId;\n"
        "    int defaultNsIndex;\n"
        "};\n",
        encoding="utf-8",
    )

    tools = AgentTools(KbIndex(str(kb_v1), str(kb_v2)), SourceManager(str(src_v1), str(src_v2)))

    bundle_path = td / "bundle.patch2"
    extra_key = "_extra_parser.c"
    # Existing extra hunk: only a forward typedef, which is insufficient for field access.
    existing = (
        "diff --git a/parser.c b/parser.c\n"
        "--- a/parser.c\n"
        "+++ b/parser.c\n"
        "@@ -1,2 +1,0 @@\n"
        "-typedef struct _xmlParserNsData xmlParserNsData;\n"
        "-int marker = 0;\n"
    )
    extra_patch = PatchInfo(
        file_path_old="parser.c",
        file_path_new="parser.c",
        patch_text=existing,
        file_type="c",
        old_start_line=1,
        old_end_line=3,
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
        file_path="/src/libxml2/parser.c",
        symbol_name="xmlParserNsData",
        version="v1",
    )
    assert out.get("patch_key") == extra_key, out
    inserted = str(out.get("inserted_code") or "")
    assert "struct _xmlParserNsData" in inserted and "{" in inserted, inserted
    ref = out.get("patch_text") or {}
    p = Path(str(ref.get("artifact_path") or "")).resolve()
    assert p.is_file(), p
    text_out = p.read_text(encoding="utf-8", errors="replace")
    assert "struct _xmlParserNsData" in text_out, text_out
    assert "typedef struct _xmlParserNsData xmlParserNsData;" in text_out, text_out

print("OK")
PY

# Extra patch override tool: if the patch bundle has no `_extra_*` entries,
# synthesize a new `_extra_<file>` patch_key and emit an override diff anchored after includes.
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

from agent_langgraph import AgentState, _write_effective_patch_bundle  # noqa: E402
from core.kb_index import KbIndex  # noqa: E402
from core.source_manager import SourceManager  # noqa: E402
from migration_tools.patch_bundle import load_patch_bundle  # noqa: E402
from migration_tools.types import PatchInfo  # noqa: E402
from tools.extra_patch_tools import make_extra_patch_override  # noqa: E402
from tools.symbol_tools import AgentTools  # noqa: E402

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(td)
    os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(td / "artifacts")

    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()

    # V1 KB provides a typedef for the missing type.
    node = {
        "kind": "TYPEDEF_DECL",
        "spelling": "xmlHashedString",
        "location": {"file": "parser.c", "line": 10, "column": 1},
        "extent": {"start": {"file": "parser.c", "line": 10, "column": 1}, "end": {"file": "parser.c", "line": 10, "column": 40}},
    }
    (kb_v1 / "parser.c_analysis.json").write_text(json.dumps([node]), encoding="utf-8")

    src_v1 = td / "src_v1" / "libxml2"
    src_v2 = td / "src_v2" / "libxml2"
    src_v1.mkdir(parents=True)
    src_v2.mkdir(parents=True)

    # V1: definition snippet.
    v1_lines = ["/* filler */"] * 20
    v1_lines[9] = "typedef int xmlHashedString;"
    (src_v1 / "parser.c").write_text("\n".join(v1_lines) + "\n", encoding="utf-8")

    # V2: insertion anchor should be after comment + preprocessor region.
    v2_text = (
        "/* header */\n"
        "#include \"x.h\"\n"
        "#define X 1\n"
        "int marker = 0;\n"
        "int other = 1;\n"
    )
    (src_v2 / "parser.c").write_text(v2_text, encoding="utf-8")

    tools = AgentTools(KbIndex(str(kb_v1), str(kb_v2)), SourceManager(str(src_v1), str(src_v2)))

    # Bundle has no `_extra_*` keys.
    bundle_path = td / "bundle.patch2"
    main_key = "p_main"
    main_patch = PatchInfo(
        file_path_old="parser.c",
        file_path_new="parser.c",
        patch_text="diff --git a/parser.c b/parser.c\n--- a/parser.c\n+++ b/parser.c\n@@ -1,1 +1,1 @@\n-old\n+new\n",
        file_type="c",
        old_start_line=1,
        old_end_line=2,
        new_start_line=1,
        new_end_line=2,
        patch_type={"Recreated function"},
        old_signature="",
        dependent_func=set(),
        hiden_func_dict={},
    )
    bundle_path.write_bytes(pickle.dumps({main_key: main_patch}, protocol=pickle.HIGHEST_PROTOCOL))

    out = make_extra_patch_override(
        tools,
        patch_path=str(bundle_path),
        file_path="/src/libxml2/parser.c",
        symbol_name="xmlHashedString",
        version="v1",
    )
    assert out.get("patch_key") == "_extra_parser.c", out
    ref = out.get("patch_text") or {}
    p = Path(str(ref.get("artifact_path") or "")).resolve()
    assert p.is_file(), p
    text_out = p.read_text(encoding="utf-8", errors="replace")
    assert "diff --git a/parser.c b/parser.c" in text_out, text_out
    assert "typedef int xmlHashedString;" in text_out, text_out
    assert "@@ -4," in text_out, text_out
    assert " int marker = 0;" in text_out, text_out

    # Agent integration: effective bundle writer must add the new key.
    state = AgentState(
        build_log_path="build.log",
        patch_path=str(bundle_path),
        error_scope="patch",
        error_line="x",
        snippet="",
        artifacts_dir=str(td / "artifacts" / "p_main"),
    )
    effective_path, err = _write_effective_patch_bundle(
        state,
        patch_key=str(out.get("patch_key") or ""),
        patch_text=text_out,
    )
    assert not err and effective_path, (effective_path, err)
    bundle2 = load_patch_bundle(effective_path, allowed_roots=[td])
    assert "_extra_parser.c" in bundle2.patches, bundle2.patches.keys()
    assert "typedef int xmlHashedString;" in (bundle2.patches["_extra_parser.c"].patch_text or ""), bundle2.patches["_extra_parser.c"]

print("OK")
PY

# Extra patch override tool: when V2 analysis JSON is available, anchor the new `_extra_*` skeleton
# using an AST-derived insertion line (before the first function), not the include region heuristic.
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
    os.environ.pop("REACT_AGENT_EXTRA_SKELETON_ANCHOR_FUNC_SIG", None)

    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()

    # V1 KB provides a typedef for the missing type.
    node_v1 = {
        "kind": "TYPEDEF_DECL",
        "spelling": "xmlHashedString",
        "location": {"file": "parser.c", "line": 10, "column": 1},
        "extent": {"start": {"file": "parser.c", "line": 10, "column": 1}, "end": {"file": "parser.c", "line": 10, "column": 40}},
    }
    (kb_v1 / "parser.c_analysis.json").write_text(json.dumps([node_v1]), encoding="utf-8")

    # V2 KB provides a function definition extent so the skeleton can anchor before it.
    node_v2 = {
        "kind": "FUNCTION_DEFI",
        "spelling": "anchor",
        "signature": "void anchor(int x)",
        "location": {"file": "parser.c", "line": 3, "column": 1},
        "extent": {"start": {"file": "parser.c", "line": 3, "column": 1}, "end": {"file": "parser.c", "line": 5, "column": 2}},
    }
    (kb_v2 / "parser.c_analysis.json").write_text(json.dumps([node_v2]), encoding="utf-8")

    src_v1 = td / "src_v1" / "libxml2"
    src_v2 = td / "src_v2" / "libxml2"
    src_v1.mkdir(parents=True)
    src_v2.mkdir(parents=True)

    v1_lines = ["/* filler */"] * 20
    v1_lines[9] = "typedef int xmlHashedString;"
    (src_v1 / "parser.c").write_text("\n".join(v1_lines) + "\n", encoding="utf-8")

    v2_text = (
        "/* header */\n"
        "#include \"x.h\"\n"
        "void anchor(int x) {\n"
        "  (void)x;\n"
        "}\n"
        "int marker = 0;\n"
        "int other = 1;\n"
    )
    (src_v2 / "parser.c").write_text(v2_text, encoding="utf-8")

    tools = AgentTools(KbIndex(str(kb_v1), str(kb_v2)), SourceManager(str(src_v1), str(src_v2)))

    bundle_path = td / "bundle.patch2"
    main_key = "p_main"
    main_patch = PatchInfo(
        file_path_old="parser.c",
        file_path_new="parser.c",
        patch_text="diff --git a/parser.c b/parser.c\n--- a/parser.c\n+++ b/parser.c\n@@ -1,1 +1,1 @@\n-old\n+new\n",
        file_type="c",
        old_start_line=1,
        old_end_line=2,
        new_start_line=1,
        new_end_line=2,
        patch_type={"Recreated function"},
        old_signature="",
        dependent_func=set(),
        hiden_func_dict={},
    )
    bundle_path.write_bytes(pickle.dumps({main_key: main_patch}, protocol=pickle.HIGHEST_PROTOCOL))

    out = make_extra_patch_override(
        tools,
        patch_path=str(bundle_path),
        file_path="/src/libxml2/parser.c",
        symbol_name="xmlHashedString",
        version="v1",
    )
    ref = out.get("patch_text") or {}
    p = Path(str(ref.get("artifact_path") or "")).resolve()
    assert p.is_file(), p
    text_out = p.read_text(encoding="utf-8", errors="replace")
    # First function begins at line 3, so skeleton context should be anchored at line 3.
    assert "@@ -3," in text_out, text_out
    assert " void anchor(int x) {" in text_out, text_out
    assert "typedef int xmlHashedString;" in text_out, text_out

print("OK")
PY

# Extra patch override tool: for __revert_* functions, anchor the skeleton BEFORE the first
# function definition (not after the V2 function body), so forward declarations appear
# before call sites and avoid "conflicting types" errors.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import json
import os
import re
import sys
import tempfile
from types import SimpleNamespace
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from core.kb_index import KbIndex  # noqa: E402
from core.source_manager import SourceManager  # noqa: E402
import tools.extra_patch_tools as extra_patch_tools  # noqa: E402
from tools.extra_patch_tools import _ast_insert_line_number_for_extra_skeleton  # noqa: E402
from tools.extra_patch_tools import _new_extra_patch_skeleton  # noqa: E402
from tools.symbol_tools import AgentTools  # noqa: E402

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    os.environ.pop("REACT_AGENT_EXTRA_SKELETON_ANCHOR_FUNC_SIG", None)

    kb_v1 = td / "kb_v1"; kb_v1.mkdir()
    kb_v2 = td / "kb_v2"; kb_v2.mkdir()
    (td / "v1").mkdir()
    (td / "v2").mkdir()

    # V2 has two functions: early_func at lines 10-20, underlying_func at lines 100-200.
    # The __revert_* prototype must anchor at line 10 (first func), not line 201.
    early_func = {
        "kind": "FUNCTION_DEFI",
        "spelling": "early_func",
        "location": {"file": "test.c", "line": 10, "column": 1},
        "extent": {
            "start": {"file": "test.c", "line": 10, "column": 1},
            "end": {"file": "test.c", "line": 20, "column": 1},
        },
    }
    underlying_func = {
        "kind": "FUNCTION_DEFI",
        "spelling": "myfunc",
        "location": {"file": "test.c", "line": 100, "column": 1},
        "extent": {
            "start": {"file": "test.c", "line": 100, "column": 1},
            "end": {"file": "test.c", "line": 200, "column": 1},
        },
    }
    (kb_v2 / "test.c_analysis.json").write_text(
        json.dumps([early_func, underlying_func]), encoding="utf-8"
    )

    kb = KbIndex(str(kb_v1), str(kb_v2))
    tools = AgentTools(kb, SourceManager(str(td / "v1"), str(td / "v2")))

    # __revert_* function: must get line 10 (first func), NOT 201 (underlying end + 1)
    result = _ast_insert_line_number_for_extra_skeleton(
        tools, file_path="test.c", version="v2",
        symbol_name="__revert_deadbeef_myfunc",
    )
    assert result == 10, f"Expected 10 (first func start), got {result}"

    # Non-__revert_* symbol: should also get line 10 (default behavior unchanged)
    result2 = _ast_insert_line_number_for_extra_skeleton(
        tools, file_path="test.c", version="v2",
        symbol_name="some_other_symbol",
    )
    assert result2 == 10, f"Expected 10, got {result2}"

    # Tier 2 KB heuristic: with 3 functions, the __revert_* anchor should pick
    # the preceding function (caller_func at line 500), NOT the first function
    # in the file (first_func at line 10 which may precede type definitions).
    first_func = {
        "kind": "FUNCTION_DEFI",
        "spelling": "first_func",
        "location": {"file": "big.h", "line": 10, "column": 1},
        "extent": {
            "start": {"file": "big.h", "line": 10, "column": 1},
            "end": {"file": "big.h", "line": 20, "column": 1},
        },
    }
    caller_func = {
        "kind": "FUNCTION_DEFI",
        "spelling": "caller_func",
        "location": {"file": "big.h", "line": 500, "column": 1},
        "extent": {
            "start": {"file": "big.h", "line": 500, "column": 1},
            "end": {"file": "big.h", "line": 510, "column": 1},
        },
    }
    target_func = {
        "kind": "FUNCTION_DEFI",
        "spelling": "targetfn",
        "location": {"file": "big.h", "line": 600, "column": 1},
        "extent": {
            "start": {"file": "big.h", "line": 600, "column": 1},
            "end": {"file": "big.h", "line": 700, "column": 1},
        },
    }
    (kb_v2 / "big.h_analysis.json").write_text(
        json.dumps([first_func, caller_func, target_func]), encoding="utf-8"
    )
    kb3 = KbIndex(str(kb_v1), str(kb_v2))
    tools3 = AgentTools(kb3, SourceManager(str(td / "v1"), str(td / "v2")))

    result3 = _ast_insert_line_number_for_extra_skeleton(
        tools3, file_path="big.h", version="v2",
        symbol_name="__revert_deadbeef_targetfn",
    )
    assert result3 == 500, f"Expected 500 (preceding func), got {result3}"

    # Guardrail: if bundle evidence shows an earlier call site than Tier-2,
    # anchor before that earliest-use function instead of after it.
    early_caller = {
        "kind": "FUNCTION_DEFI",
        "spelling": "early_caller",
        "location": {"file": "big.h", "line": 619, "column": 1},
        "extent": {
            "start": {"file": "big.h", "line": 619, "column": 1},
            "end": {"file": "big.h", "line": 650, "column": 1},
        },
    }
    later_func = {
        "kind": "FUNCTION_DEFI",
        "spelling": "later_func",
        "location": {"file": "big.h", "line": 697, "column": 1},
        "extent": {
            "start": {"file": "big.h", "line": 697, "column": 1},
            "end": {"file": "big.h", "line": 710, "column": 1},
        },
    }
    target_late = {
        "kind": "FUNCTION_DEFI",
        "spelling": "targetfn",
        "location": {"file": "big.h", "line": 746, "column": 1},
        "extent": {
            "start": {"file": "big.h", "line": 746, "column": 1},
            "end": {"file": "big.h", "line": 770, "column": 1},
        },
    }
    (kb_v2 / "big.h_analysis.json").write_text(
        json.dumps([early_caller, later_func, target_late]), encoding="utf-8"
    )
    kb_guard = KbIndex(str(kb_v1), str(kb_v2))
    tools_guard = AgentTools(kb_guard, SourceManager(str(td / "v1"), str(td / "v2")))
    bundle = SimpleNamespace(
        patches={
            "tail-big.h-f1_": SimpleNamespace(
                patch_text=(
                    "diff --git a/big.h b/big.h\n"
                    "--- a/big.h\n"
                    "+++ b/big.h\n"
                    "@@ -620,1 +620,1 @@\n"
                    "-    return __revert_deadbeef_targetfn(x);\n"
                ),
                new_start_line=620,
            )
        }
    )
    result3_guard = _ast_insert_line_number_for_extra_skeleton(
        tools_guard, file_path="big.h", version="v2",
        symbol_name="__revert_deadbeef_targetfn",
        bundle=bundle,
    )
    assert result3_guard == 619, f"Expected 619 (before earliest use), got {result3_guard}"

    # Force Tier 1 for enum-style insertions: before the first function.
    result3_tier1 = _ast_insert_line_number_for_extra_skeleton(
        tools3, file_path="big.h", version="v2",
        symbol_name="__revert_deadbeef_targetfn",
        force_tier1=True,
    )
    assert result3_tier1 == 10, f"Expected 10 (forced Tier 1), got {result3_tier1}"

    # Non-__revert_* symbol still gets line 10 (first func, unchanged default).
    result4 = _ast_insert_line_number_for_extra_skeleton(
        tools3, file_path="big.h", version="v2",
        symbol_name="some_symbol",
    )
    assert result4 == 10, f"Expected 10 (first func), got {result4}"

    # file_index key mismatch: KB may use "subdir/file.h" as key while
    # file_path is just "file.h".  The lookup must fall back to basename
    # matching so that Tier 2 still works.
    subdir_func_a = {
        "kind": "FUNCTION_DEFI",
        "spelling": "func_a",
        "location": {"file": "mylib/api.h", "line": 50, "column": 1},
        "extent": {
            "start": {"file": "mylib/api.h", "line": 50, "column": 1},
            "end": {"file": "mylib/api.h", "line": 60, "column": 1},
        },
    }
    subdir_func_b = {
        "kind": "FUNCTION_DEFI",
        "spelling": "func_b",
        "location": {"file": "mylib/api.h", "line": 200, "column": 1},
        "extent": {
            "start": {"file": "mylib/api.h", "line": 200, "column": 1},
            "end": {"file": "mylib/api.h", "line": 250, "column": 1},
        },
    }
    # Write with "mylib/api.h" prefix so KbIndex keys by the full relative path.
    (kb_v2 / "mylib").mkdir(exist_ok=True)
    (kb_v2 / "mylib" / "api.h_analysis.json").write_text(
        json.dumps([subdir_func_a, subdir_func_b]), encoding="utf-8"
    )
    kb4 = KbIndex(str(kb_v1), str(kb_v2))
    tools4 = AgentTools(kb4, SourceManager(str(td / "v1"), str(td / "v2")))

    # Lookup by basename "api.h" must find the nodes keyed by "mylib/api.h".
    result5 = _ast_insert_line_number_for_extra_skeleton(
        tools4, file_path="api.h", version="v2",
        symbol_name="__revert_deadbeef_func_b",
    )
    assert result5 == 50, f"Expected 50 (preceding func via basename fallback), got {result5}"

    # Regression: backward boundary scanning must not place insertion before
    # `#endif` of a `#if 0` dead-code block.
    if0_source = "\n".join(
        [
            "#include <stdint.h>",
            "",
            "#if 0",
            "static int dead(void) {",
            "    return 0;",
            "}",
            "#endif",
            "",
            "static int live(void) {",
            "    return 1;",
            "}",
            "",
        ]
    )
    (td / "v2" / "if0_anchor.c").write_text(if0_source, encoding="utf-8")
    if0_live_node = {
        "kind": "FUNCTION_DEFI",
        "spelling": "live",
        "location": {"file": "if0_anchor.c", "line": 9, "column": 1},
        "extent": {
            "start": {"file": "if0_anchor.c", "line": 9, "column": 1},
            "end": {"file": "if0_anchor.c", "line": 11, "column": 1},
        },
    }
    (kb_v2 / "if0_anchor.c_analysis.json").write_text(
        json.dumps([if0_live_node]), encoding="utf-8"
    )
    kb_if0 = KbIndex(str(kb_v1), str(kb_v2))
    tools_if0 = AgentTools(kb_if0, SourceManager(str(td / "v1"), str(td / "v2")))
    skel = _new_extra_patch_skeleton(tools_if0, file_path="if0_anchor.c", symbol_name="dummy")
    assert skel, skel
    m = re.search(r"^@@ -(?P<old_start>\d+),(?P<old_len>\d+) \+(?P<new_start>\d+),(?P<new_len>\d+) @@", skel, re.MULTILINE)
    assert m, skel
    body = skel[m.end():].splitlines()
    first_ctx = next((line for line in body if line.startswith(" ")), "")
    assert first_ctx.strip() != "#endif", skel

    # Regression: for .c files, avoid anchoring inside active #ifdef blocks.
    # Simulate AST returning a line inside the conditional region.
    pp_source = "\n".join(
        [
            "#include <stdint.h>",
            "#ifdef FEATURE_TOGGLE",
            "static int hidden_fn(void) {",
            "  return 0;",
            "}",
            "#endif",
            "",
            "int always_visible(void) { return 1; }",
            "",
        ]
    )
    (td / "v2" / "pp_anchor.c").write_text(pp_source, encoding="utf-8")

    kb_pp = KbIndex(str(kb_v1), str(kb_v2))
    tools_pp = AgentTools(kb_pp, SourceManager(str(td / "v1"), str(td / "v2")))
    old_ast = extra_patch_tools._ast_insert_line_number_for_extra_skeleton
    extra_patch_tools._ast_insert_line_number_for_extra_skeleton = lambda *args, **kwargs: 3
    try:
        skel_pp = _new_extra_patch_skeleton(tools_pp, file_path="pp_anchor.c", symbol_name="dummy")
    finally:
        extra_patch_tools._ast_insert_line_number_for_extra_skeleton = old_ast

    assert skel_pp, skel_pp
    m_pp = re.search(
        r"^@@ -(?P<old_start>\d+),(?P<old_len>\d+) \+(?P<new_start>\d+),(?P<new_len>\d+) @@",
        skel_pp,
        re.MULTILINE,
    )
    assert m_pp, skel_pp
    start_pp = int(m_pp.group("old_start"))
    assert start_pp >= 7, f"expected insertion after #endif (>=7), got {start_pp}\n{skel_pp}"

print("OK")
PY

# Extra patch override internals: when inserting into the first hunk of a
# multi-hunk diff, keep later hunks' +start anchors stable (do not shift
# +691 -> +540, etc.).
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import re
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from tools.extra_patch_tools import _insert_minus_block_into_patch_text  # noqa: E402

patch_text = (
    "diff --git a/src/lib/ndpi_main.c b/src/lib/ndpi_main.c\n"
    "--- a/src/lib/ndpi_main.c\n"
    "+++ b/src/lib/ndpi_main.c\n"
    "@@ -81,42 +81,3 @@\n"
    "-int old_a;\n"
    " static inline uint8_t flow_is_proto(struct ndpi_flow_struct *flow, u_int16_t p) {\n"
    "@@ -691,41 +691,3 @@\n"
    "-int old_b;\n"
    " /* ******************************************************************** */\n"
    "@@ -2094,4 +2094,3 @@\n"
    "-int old_c;\n"
    " /* ****************************************** */\n"
)

updated = _insert_minus_block_into_patch_text(
    patch_text,
    insert_lines=["", "static const char *categories[] = {", "  \"X\"", "};"],
    prefer_prepend=True,
)

headers = re.findall(
    r"^@@ -(?P<old_start>\d+),(?P<old_len>\d+) \+(?P<new_start>\d+),(?P<new_len>\d+) @@",
    updated,
    re.MULTILINE,
)
assert len(headers) == 3, updated

# First hunk changed, but later +start anchors must stay at their original lines.
assert headers[1][2] == "691", updated
assert headers[2][2] == "2094", updated
assert "+540," not in updated, updated
assert "+1905," not in updated, updated

print("OK")
PY

# Extra patch override tool: when inserting an enum into an existing `_extra_*`
# hunk anchored late in the file, re-anchor the hunk to Tier 1 (before first
# function) and keep existing inserted declarations.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import json
import os
import pickle
import re
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

    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()

    src_v1 = td / "src_v1"
    src_v2 = td / "src_v2"
    src_v1.mkdir()
    src_v2.mkdir()

    (src_v1 / "a.c").write_text(
        "enum my_enum {\n"
        "    A = 0,\n"
        "    B = 1,\n"
        "};\n",
        encoding="utf-8",
    )

    v2_lines = []
    for i in range(1, 71):
        if i == 1:
            v2_lines.append("#include <stdio.h>")
        elif i == 3:
            v2_lines.append("typedef int marker_t;")
        elif i == 10:
            v2_lines.append("static int first_fn(void) { return 1; }")
        elif i == 60:
            v2_lines.append("static int late_context(void) { return 2; }")
        else:
            v2_lines.append("")
    (src_v2 / "a.c").write_text("\n".join(v2_lines) + "\n", encoding="utf-8")

    v1_enum = {
        "kind": "ENUM_DECL",
        "spelling": "my_enum",
        "location": {"file": "a.c", "line": 1, "column": 1},
        "extent": {
            "start": {"file": "a.c", "line": 1, "column": 1},
            "end": {"file": "a.c", "line": 4, "column": 2},
        },
    }
    v2_fn_first = {
        "kind": "FUNCTION_DEFI",
        "spelling": "first_fn",
        "location": {"file": "a.c", "line": 10, "column": 1},
        "extent": {
            "start": {"file": "a.c", "line": 10, "column": 1},
            "end": {"file": "a.c", "line": 10, "column": 40},
        },
    }
    v2_fn_late = {
        "kind": "FUNCTION_DEFI",
        "spelling": "late_context",
        "location": {"file": "a.c", "line": 60, "column": 1},
        "extent": {
            "start": {"file": "a.c", "line": 60, "column": 1},
            "end": {"file": "a.c", "line": 60, "column": 46},
        },
    }
    (kb_v1 / "a_analysis.json").write_text(json.dumps([v1_enum]), encoding="utf-8")
    (kb_v2 / "a_analysis.json").write_text(json.dumps([v2_fn_first, v2_fn_late]), encoding="utf-8")

    tools = AgentTools(KbIndex(str(kb_v1), str(kb_v2)), SourceManager(str(src_v1), str(src_v2)))

    extra_patch_text = (
        "diff --git a/a.c b/a.c\n"
        "--- a/a.c\n"
        "+++ b/a.c\n"
        "@@ -60,1 +60,0 @@\n"
        "-char *__revert_deadbeef_fn(enum my_enum m);\n"
        " static int late_context(void) { return 2; }\n"
    )
    extra_patch = PatchInfo(
        file_path_old="a.c",
        file_path_new="a.c",
        patch_text=extra_patch_text,
        file_type="c",
        old_start_line=60,
        old_end_line=61,
        new_start_line=60,
        new_end_line=60,
        patch_type={"Extra"},
        old_signature="",
        dependent_func=set(),
        hiden_func_dict={},
    )

    bundle_path = td / "bundle.patch2"
    bundle_path.write_bytes(pickle.dumps({"_extra_a.c": extra_patch}, protocol=pickle.HIGHEST_PROTOCOL))

    out = make_extra_patch_override(
        tools,
        patch_path=str(bundle_path),
        file_path="/src/proj/a.c",
        symbol_name="enum my_enum",
        version="v1",
    )

    ref = out.get("patch_text") or {}
    p = Path(str(ref.get("artifact_path") or "")).resolve()
    assert p.is_file(), out
    text = p.read_text(encoding="utf-8", errors="replace")

    assert "-enum my_enum {" in text, text
    assert "__revert_deadbeef_fn(enum my_enum m)" in text, text
    assert "@@ -60," not in text, text
    m = re.search(r"^@@ -(?P<old_start>\d+),(?P<old_len>\d+) \+(?P<new_start>\d+),(?P<new_len>\d+) @@", text, re.MULTILINE)
    assert m, text
    assert int(m.group("old_start")) < 30, text

print("OK")
PY

# Extra patch override tool: don't treat a type name mentioned only in prototypes as "already present",
# and prepend inserted typedefs before existing prototype blocks in `_extra_*`.
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
from tools.extra_patch_tools import _symbol_defined_in_extra_hunk, make_extra_patch_override  # noqa: E402
from tools.symbol_tools import AgentTools  # noqa: E402

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(td)
    os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(td / "artifacts")

    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()

    node = {
        "kind": "TYPEDEF_DECL",
        "spelling": "xmlHashedString",
        "location": {"file": "include/private/dict.h", "line": 1, "column": 1},
        "extent": {"start": {"file": "include/private/dict.h", "line": 1, "column": 1}, "end": {"file": "include/private/dict.h", "line": 1, "column": 28}},
    }
    (kb_v1 / "dict.h_analysis.json").write_text(json.dumps([node]), encoding="utf-8")

    src_v1 = td / "src_v1" / "libxml2"
    src_v2 = td / "src_v2" / "libxml2"
    src_v1.mkdir(parents=True)
    src_v2.mkdir(parents=True)

    inc = src_v1 / "include" / "private"
    inc.mkdir(parents=True)
    (inc / "dict.h").write_text("typedef int xmlHashedString;\n", encoding="utf-8")
    (src_v2 / "parser.c").write_text("#include \"x.h\"\nint marker = 0;\n", encoding="utf-8")

    tools = AgentTools(KbIndex(str(kb_v1), str(kb_v2)), SourceManager(str(src_v1), str(src_v2)))

    extra_key = "_extra_parser.c"
    extra_patch_text = (
        "diff --git a/parser.c b/parser.c\n"
        "--- a/parser.c\n"
        "+++ b/parser.c\n"
        "@@ -1,2 +1,0 @@\n"
        "-/* extra decls */\n"
        "-static int xmlParserNsPush(xmlParserCtxtPtr ctxt, const xmlHashedString *prefix);\n"
    )
    extra_patch = PatchInfo(
        file_path_old="parser.c",
        file_path_new="parser.c",
        patch_text=extra_patch_text,
        file_type="c",
        old_start_line=1,
        old_end_line=3,
        new_start_line=1,
        new_end_line=1,
        patch_type={"Extra"},
        old_signature="",
        dependent_func=set(),
        hiden_func_dict={},
    )

    bundle_path = td / "bundle.patch2"
    bundle_path.write_bytes(pickle.dumps({extra_key: extra_patch}, protocol=pickle.HIGHEST_PROTOCOL))

    assert _symbol_defined_in_extra_hunk(extra_patch_text, symbol_name="xmlHashedString") is False

    out = make_extra_patch_override(
        tools,
        patch_path=str(bundle_path),
        file_path="/src/libxml2/parser.c",
        symbol_name="xmlHashedString",
        version="v1",
    )
    assert out.get("patch_key") == extra_key, out
    ref = out.get("patch_text") or {}
    p = Path(str(ref.get("artifact_path") or "")).resolve()
    text_out = p.read_text(encoding="utf-8", errors="replace")
    assert "typedef int xmlHashedString;" in text_out, text_out

    typedef_pos = text_out.find("typedef int xmlHashedString;")
    proto_pos = text_out.find("xmlParserNsPush(")
    assert typedef_pos != -1 and proto_pos != -1 and typedef_pos < proto_pos, text_out

print("OK")
PY

# Extra patch override tool: normalize inherited malformed `_extra_*` hunks where
# __revert_* declarations were inserted into the middle of enum members.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import pickle
import re
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from migration_tools.types import PatchInfo  # noqa: E402
from tools.extra_patch_tools import make_extra_patch_override  # noqa: E402

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(td)
    os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(td / "artifacts")

    bad_extra_patch = (
        "diff --git a/cram/cram_io.c b/cram/cram_io.c\n"
        "--- a/cram/cram_io.c\n"
        "+++ b/cram/cram_io.c\n"
        "@@ -1,9 +1,0 @@\n"
        "-enum cram_block_method_int {\n"
        "-    BM_ERROR = -1,\n"
        "-\n"
        "-void __revert_deadbeef_cram_update_curr_slice(cram_container *c, int version);\n"
        "-\n"
        "-    RAW = 0,\n"
        "-};\n"
        " int marker(void) { return 0; }\n"
    )
    extra_patch = PatchInfo(
        file_path_old="cram/cram_io.c",
        file_path_new="cram/cram_io.c",
        patch_text=bad_extra_patch,
        file_type="c",
        old_start_line=1,
        old_end_line=10,
        new_start_line=1,
        new_end_line=1,
        patch_type={"Extra"},
        old_signature="",
        dependent_func=set(),
        hiden_func_dict={},
    )
    bundle_path = td / "bundle.patch2"
    bundle_path.write_bytes(pickle.dumps({"_extra_cram_io.c": extra_patch}, protocol=pickle.HIGHEST_PROTOCOL))

    out = make_extra_patch_override(
        None,
        patch_path=str(bundle_path),
        file_path="/src/htslib/cram/cram_io.c",
        symbol_name="__revert_deadbeef_cram_update_curr_slice",
        version="v1",
    )

    note = str(out.get("note") or "")
    assert "normalized malformed existing extra hunk" in note, out
    actions = out.get("normalization_actions") or []
    assert "move_revert_decls_out_of_enum" in actions, out

    ref = out.get("patch_text") or {}
    text_out = ""
    if isinstance(ref, dict):
        p = Path(str(ref.get("artifact_path") or "")).resolve()
        text_out = p.read_text(encoding="utf-8", errors="replace")
    elif isinstance(ref, str):
        text_out = ref
    assert text_out, out

    decl_pos = text_out.find("-void __revert_deadbeef_cram_update_curr_slice(")
    enum_close_pos = text_out.find("-};")
    bm_pos = text_out.find("BM_ERROR = -1")
    raw_pos = text_out.find("RAW = 0")
    assert decl_pos > 0 and enum_close_pos > 0 and bm_pos > 0 and raw_pos > 0, text_out
    assert enum_close_pos < decl_pos, text_out
    assert not (bm_pos < decl_pos < raw_pos), text_out

    # Header lengths must match body counts after normalization.
    lines = text_out.splitlines()
    hidx = next(i for i, l in enumerate(lines) if l.startswith("@@ "))
    m = re.match(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@", lines[hidx])
    assert m, lines[hidx]
    old_len_hdr = int(m.group(2) or "1")
    new_len_hdr = int(m.group(4) or "1")
    old_len = 0
    new_len = 0
    for l in lines[hidx + 1 :]:
        if l.startswith("@@ ") or l.startswith("diff --git "):
            break
        if l.startswith("-"):
            old_len += 1
        elif l.startswith("+"):
            new_len += 1
        elif l.startswith(" "):
            old_len += 1
            new_len += 1
    assert old_len == old_len_hdr, (old_len, old_len_hdr, lines[hidx])
    assert new_len == new_len_hdr, (new_len, new_len_hdr, lines[hidx])

print("OK")
PY

# Extra patch override tool: unwrap disabled enum blocks that were wrapped with
# `#if 0 /* enum duplicated ... */` and remove the leftover enum forward declaration.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import pickle
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from migration_tools.types import PatchInfo  # noqa: E402
from tools.extra_patch_tools import make_extra_patch_override  # noqa: E402

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(td)
    os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(td / "artifacts")

    bad_extra_patch = (
        "diff --git a/cram/cram_io.c b/cram/cram_io.c\n"
        "--- a/cram/cram_io.c\n"
        "+++ b/cram/cram_io.c\n"
        "@@ -1,10 +1,0 @@\n"
        "-#if 0 /* enum duplicated in cram_structs.h; use that definition instead */\n"
        "-enum cram_block_method_int {\n"
        "-    BM_ERROR = -1,\n"
        "-    RAW = 0,\n"
        "-};\n"
        "-#endif\n"
        "-/* Forward-declare the enum so the following prototype is visible at file scope. */\n"
        "-enum cram_block_method_int;\n"
        " int marker(void) { return 0; }\n"
    )
    extra_patch = PatchInfo(
        file_path_old="cram/cram_io.c",
        file_path_new="cram/cram_io.c",
        patch_text=bad_extra_patch,
        file_type="c",
        old_start_line=1,
        old_end_line=11,
        new_start_line=1,
        new_end_line=1,
        patch_type={"Extra"},
        old_signature="",
        dependent_func=set(),
        hiden_func_dict={},
    )
    bundle_path = td / "bundle.patch2"
    bundle_path.write_bytes(pickle.dumps({"_extra_cram_io.c": extra_patch}, protocol=pickle.HIGHEST_PROTOCOL))

    out = make_extra_patch_override(
        None,
        patch_path=str(bundle_path),
        file_path="/src/htslib/cram/cram_io.c",
        symbol_name="enum cram_block_method_int",
        version="v1",
    )

    note = str(out.get("note") or "")
    assert "normalized malformed existing extra hunk" in note, out
    actions = out.get("normalization_actions") or []
    assert "unwrap_disabled_enum_if0" in actions, out

    ref = out.get("patch_text") or {}
    text_out = ""
    if isinstance(ref, dict):
        p = Path(str(ref.get("artifact_path") or "")).resolve()
        text_out = p.read_text(encoding="utf-8", errors="replace")
    elif isinstance(ref, str):
        text_out = ref
    assert text_out, out

    assert "#if 0" not in text_out, text_out
    assert "#endif" not in text_out, text_out
    assert "-enum cram_block_method_int;" not in text_out, text_out
    assert "-enum cram_block_method_int {" in text_out, text_out

print("OK")
PY

# Extra patch override tool: if the KB points at a file that doesn't exist in the current v1-src working tree,
# SourceManager should still be able to extract it deterministically from git objects using REACT_AGENT_V1_SRC_COMMIT.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import json
import os
import pickle
import subprocess
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

    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()

    # KB node points at include/private/dict.h (mirrors real libxml2-e11519 KB),
    # but the v1-src working tree will not have that file.
    node = {
        "kind": "TYPEDEF_DECL",
        "spelling": "xmlHashedString",
        "location": {"file": "include/private/dict.h", "line": 1, "column": 1},
        "extent": {"start": {"file": "include/private/dict.h", "line": 1, "column": 1}, "end": {"file": "include/private/dict.h", "line": 1, "column": 28}},
    }
    (kb_v1 / "dict.h_analysis.json").write_text(json.dumps([node]), encoding="utf-8")

    src_v1 = td / "src_v1" / "libxml2"
    src_v2 = td / "src_v2" / "libxml2"
    src_v1.mkdir(parents=True)
    src_v2.mkdir(parents=True)

    # v1-src is a git repo; commit A contains include/private/dict.h, commit B removes it (HEAD lacks the file).
    subprocess.run(["git", "init"], cwd=src_v1, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=src_v1, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=src_v1, check=True)
    inc = src_v1 / "include" / "private"
    inc.mkdir(parents=True)
    (inc / "dict.h").write_text("typedef int xmlHashedString;\n", encoding="utf-8")
    subprocess.run(["git", "add", "include/private/dict.h"], cwd=src_v1, check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "commit", "-m", "add dict.h"], cwd=src_v1, check=True, stdout=subprocess.DEVNULL)
    commit_with_file = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=src_v1, text=True).strip()
    (inc / "dict.h").unlink()
    subprocess.run(["git", "add", "-A"], cwd=src_v1, check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "commit", "-m", "remove dict.h"], cwd=src_v1, check=True, stdout=subprocess.DEVNULL)

    os.environ["REACT_AGENT_V1_SRC_COMMIT"] = commit_with_file

    # v2-src provides a stable insertion anchor.
    (src_v2 / "parser.c").write_text("#include \"x.h\"\nint marker = 0;\n", encoding="utf-8")

    tools = AgentTools(KbIndex(str(kb_v1), str(kb_v2)), SourceManager(str(src_v1), str(src_v2)))

    bundle_path = td / "bundle.patch2"
    main_patch = PatchInfo(
        file_path_old="parser.c",
        file_path_new="parser.c",
        patch_text="diff --git a/parser.c b/parser.c\n--- a/parser.c\n+++ b/parser.c\n@@ -1,1 +1,1 @@\n-old\n+new\n",
        file_type="c",
        old_start_line=1,
        old_end_line=2,
        new_start_line=1,
        new_end_line=2,
        patch_type={"Recreated function"},
        old_signature="",
        dependent_func=set(),
        hiden_func_dict={},
    )
    bundle_path.write_bytes(pickle.dumps({"p_main": main_patch}, protocol=pickle.HIGHEST_PROTOCOL))

    out = make_extra_patch_override(
        tools,
        patch_path=str(bundle_path),
        file_path="/src/libxml2/parser.c",
        symbol_name="xmlHashedString",
        version="v1",
    )
    assert out.get("patch_key") == "_extra_parser.c", out
    inserted = str(out.get("inserted_code") or "")
    assert "typedef int xmlHashedString;" in inserted, inserted

print("OK")
PY

# SourceManager: when a commit hint is configured, prefer `git show <commit>:<path>` even if the file exists
# in the working tree. This avoids extracting the wrong lines when the worktree is checked out at a different
# revision than the KB JSON (line numbers drift).
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import json
import os
import pickle
import subprocess
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

    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()

    node = {
        "kind": "TYPEDEF_DECL",
        "spelling": "xmlParserNsData",
        "location": {"file": "include/libxml/parser.h", "line": 175, "column": 1},
        "extent": {
            "start": {"file": "include/libxml/parser.h", "line": 175, "column": 1},
            "end": {"file": "include/libxml/parser.h", "line": 175, "column": 80},
        },
    }
    (kb_v1 / "parser.c_analysis.json").write_text(json.dumps([node]), encoding="utf-8")

    src_v1 = td / "src_v1" / "libxml2"
    src_v2 = td / "src_v2" / "libxml2"
    src_v1.mkdir(parents=True)
    src_v2.mkdir(parents=True)

    # v1-src is a git repo; commit A has the typedef at line 175, but HEAD will have different content at that line.
    subprocess.run(["git", "init"], cwd=src_v1, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=src_v1, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=src_v1, check=True)

    hdr = src_v1 / "include" / "libxml"
    hdr.mkdir(parents=True)
    parser_h = hdr / "parser.h"

    lines = ["/* filler */"] * 200
    lines[174] = "typedef struct _xmlParserNsData xmlParserNsData;"
    parser_h.write_text("\n".join(lines) + "\n", encoding="utf-8")
    subprocess.run(["git", "add", "include/libxml/parser.h"], cwd=src_v1, check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "commit", "-m", "add typedef at line 175"], cwd=src_v1, check=True, stdout=subprocess.DEVNULL)
    commit_with_typedef = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=src_v1, text=True).strip()

    # Now change the *same* line in the working tree (file still exists, but the KB extent line points to a different token).
    lines[171] = "/**"
    lines[172] = " * xmlParserCtxt:"
    lines[173] = " *"
    lines[174] = " * The parser context."
    lines[175] = " */"
    parser_h.write_text("\n".join(lines) + "\n", encoding="utf-8")
    subprocess.run(["git", "add", "include/libxml/parser.h"], cwd=src_v1, check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "commit", "-m", "move typedef away (line drift)"], cwd=src_v1, check=True, stdout=subprocess.DEVNULL)

    os.environ["REACT_AGENT_V1_SRC_COMMIT"] = commit_with_typedef

    # v2-src provides a stable insertion anchor for `_extra_parser.c`.
    (src_v2 / "parser.c").write_text("#include \"x.h\"\nint marker = 0;\n", encoding="utf-8")

    tools = AgentTools(KbIndex(str(kb_v1), str(kb_v2)), SourceManager(str(src_v1), str(src_v2)))

    bundle_path = td / "bundle.patch2"
    main_patch = PatchInfo(
        file_path_old="parser.c",
        file_path_new="parser.c",
        patch_text="diff --git a/parser.c b/parser.c\n--- a/parser.c\n+++ b/parser.c\n@@ -1,1 +1,1 @@\n-old\n+new\n",
        file_type="c",
        old_start_line=1,
        old_end_line=2,
        new_start_line=1,
        new_end_line=2,
        patch_type={"Recreated function"},
        old_signature="",
        dependent_func=set(),
        hiden_func_dict={},
    )
    bundle_path.write_bytes(pickle.dumps({"p_main": main_patch}, protocol=pickle.HIGHEST_PROTOCOL))

    out = make_extra_patch_override(
        tools,
        patch_path=str(bundle_path),
        file_path="/src/libxml2/parser.c",
        symbol_name="xmlParserNsData",
        version="v1",
    )
    inserted = str(out.get("inserted_code") or "")
    assert "typedef struct _xmlParserNsData xmlParserNsData;" in inserted, inserted
    assert "The parser context" not in inserted, inserted

print("OK")
PY

# SourceManager + make_extra_patch_override: recover definitions from generated headers
# (for example version.h) by synthesizing target content from Makefile recipes.
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

    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()

    node = {
        "kind": "MACRO_DEFINITION",
        "spelling": "HTS_VERSION_TEXT",
        "location": {"file": "version.h", "line": 1, "column": 1},
        "extent": {
            "start": {"file": "version.h", "line": 1, "column": 1},
            "end": {"file": "version.h", "line": 1, "column": 64},
        },
    }
    (kb_v1 / "version.h_analysis.json").write_text(json.dumps([node]), encoding="utf-8")

    src_v1 = td / "src_v1" / "htslib"
    src_v2 = td / "src_v2" / "htslib"
    src_v1.mkdir(parents=True)
    src_v2.mkdir(parents=True)

    # version.h is generated (not present in the tree).
    (src_v1 / "Makefile").write_text(
        "PACKAGE_VERSION = 9.9.9\n"
        "version.h:\n"
        "\techo '#define HTS_VERSION_TEXT \"$(PACKAGE_VERSION)\"' > $@\n",
        encoding="utf-8",
    )

    # The missing file path should still resolve through include-form inputs.
    sm = SourceManager(str(src_v1), str(src_v2))
    seg = sm.get_code_segment('#include "version.h"', 1, 1, "v1")
    assert "#define HTS_VERSION_TEXT" in seg, seg

    # v2 file anchors where _extra_target.c should be inserted.
    (src_v2 / "target.c").write_text("#include \"x.h\"\nint marker = 0;\n", encoding="utf-8")

    tools = AgentTools(KbIndex(str(kb_v1), str(kb_v2)), sm)

    bundle_path = td / "bundle.patch2"
    main_patch = PatchInfo(
        file_path_old="target.c",
        file_path_new="target.c",
        patch_text="diff --git a/target.c b/target.c\n--- a/target.c\n+++ b/target.c\n@@ -1,1 +1,1 @@\n-old\n+new\n",
        file_type="c",
        old_start_line=1,
        old_end_line=2,
        new_start_line=1,
        new_end_line=2,
        patch_type={"Recreated function"},
        old_signature="",
        dependent_func=set(),
        hiden_func_dict={},
    )
    bundle_path.write_bytes(pickle.dumps({"p_main": main_patch}, protocol=pickle.HIGHEST_PROTOCOL))

    out = make_extra_patch_override(
        tools,
        patch_path=str(bundle_path),
        file_path="/src/htslib/target.c",
        symbol_name="HTS_VERSION_TEXT",
        version="v1",
    )
    inserted = str(out.get("inserted_code") or "")
    assert "#define HTS_VERSION_TEXT" in inserted, inserted
    assert '"9.9.9"' in inserted or '"$(PACKAGE_VERSION)"' in inserted, inserted

print("OK")
PY

# ToolRunner: print a warning when make_extra_patch_override returns the
# "KB has nodes ... none produced readable source code" diagnostic note.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import contextlib
import io
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
from tools.runner import ToolRunner  # noqa: E402
from tools.symbol_tools import AgentTools  # noqa: E402

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(td)
    os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(td / "artifacts")

    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()

    # v1 has symbol nodes, but source checkout intentionally lacks the file,
    # so SourceManager cannot read code and make_extra returns the guidance note.
    node = {
        "kind": "FUNCTION_DECL",
        "spelling": "tls_certificate_match",
        "location": {"file": "ssl/t1_lib.c", "line": 12, "column": 1},
        "extent": {
            "start": {"file": "ssl/t1_lib.c", "line": 12, "column": 1},
            "end": {"file": "ssl/t1_lib.c", "line": 12, "column": 40},
        },
    }
    (kb_v1 / "ssl").mkdir(parents=True)
    (kb_v1 / "ssl" / "t1_lib.c_analysis.json").write_text(json.dumps([node]), encoding="utf-8")

    src_v1 = td / "src_v1"
    src_v2 = td / "src_v2"
    src_v1.mkdir()
    src_v2.mkdir()

    bundle_path = td / "bundle.patch2"
    extra_patch = PatchInfo(
        file_path_old="target.c",
        file_path_new="target.c",
        patch_text=(
            "diff --git a/target.c b/target.c\n"
            "--- a/target.c\n"
            "+++ b/target.c\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
        ),
        file_type="c",
        old_start_line=1,
        old_end_line=2,
        new_start_line=1,
        new_end_line=2,
        patch_type={"Extra patch"},
        old_signature="",
        dependent_func=set(),
        hiden_func_dict={},
    )
    bundle_path.write_bytes(pickle.dumps({"_extra_target.c": extra_patch}, protocol=pickle.HIGHEST_PROTOCOL))

    tools = AgentTools(KbIndex(str(kb_v1), str(kb_v2)), SourceManager(str(src_v1), str(src_v2)))
    runner = ToolRunner(tools, mode="real")

    err_buf = io.StringIO()
    with contextlib.redirect_stderr(err_buf):
        obs = runner.call(
            "make_extra_patch_override",
            {
                "patch_path": str(bundle_path),
                "file_path": "/src/libtls/target.c",
                "symbol_name": "tls_certificate_match",
            },
        )

    assert obs.ok is True, obs
    note = str((obs.output or {}).get("note") or "")
    assert "KB has nodes for 'tls_certificate_match'" in note, note
    warn_text = err_buf.getvalue()
    assert "[WARNING][make_extra_patch_override]" in warn_text, warn_text
    assert "none produced readable source code" in warn_text, warn_text

print("OK")
PY

# search_definition tool: accept only v1/v2, but coerce common model mistakes (commit hashes) to v2.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import json
import os
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from agent_tools import AgentTools, KbIndex, SourceManager  # noqa: E402
from tools.runner import ToolRunner  # noqa: E402

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()

    node = {
        "kind": "TYPEDEF_DECL",
        "spelling": "FooType",
        "location": {"file": "foo.h", "line": 1, "column": 1},
        "extent": {"start": {"file": "foo.h", "line": 1, "column": 1}, "end": {"file": "foo.h", "line": 1, "column": 20}},
    }
    (kb_v2 / "foo.h_analysis.json").write_text(json.dumps([node]), encoding="utf-8")

    src_v1 = td / "src_v1" / "libxml2"
    src_v2 = td / "src_v2" / "libxml2"
    src_v1.mkdir(parents=True)
    src_v2.mkdir(parents=True)
    (src_v2 / "foo.h").write_text("typedef int FooType;\n", encoding="utf-8")

    tools = AgentTools(KbIndex(str(kb_v1), str(kb_v2)), SourceManager(str(src_v1), str(src_v2)))
    runner = ToolRunner(tools, mode="real")

    obs = runner.call("search_definition", {"symbol_name": "FooType", "version": "f0fd1b"})
    assert obs.ok is True, obs
    assert obs.args.get("version") == "v2", obs.args
    assert obs.args.get("version_raw") == "f0fd1b", obs.args
    assert "=== Version 2 ===" in str(obs.output or ""), obs.output

print("OK")
PY

# Extra patch override tool: do not treat macro *usage* as a definition. If a macro token appears
# inside other macro bodies (e.g. HASH_FINISH uses HASH_ROR) but isn't defined, we should still
# insert the real definition via KB.
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

    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()

    macro_node = {
        "kind": "MACRO_DEFINITION",
        "spelling": "HASH_ROR",
        "location": {"file": "dict.c", "line": 1, "column": 1},
        "extent": {"start": {"file": "dict.c", "line": 1, "column": 1}, "end": {"file": "dict.c", "line": 1, "column": 80}},
    }
    (kb_v1 / "dict.c_analysis.json").write_text(json.dumps([macro_node]), encoding="utf-8")

    src_v1 = td / "src_v1"
    src_v2 = td / "src_v2"
    src_v1.mkdir()
    src_v2.mkdir()
    (src_v1 / "dict.c").write_text("#define HASH_ROR(x,n) ((x) >> (n) | ((x) & 0xFFFFFFFF) << (32 - (n)))\n", encoding="utf-8")
    (src_v2 / "dict.c").write_text("/* v2 */\n", encoding="utf-8")

    tools = AgentTools(KbIndex(str(kb_v1), str(kb_v2)), SourceManager(str(src_v1), str(src_v2)))

    extra_key = "_extra_dict.c"
    bundle_path = td / "bundle.patch2"
    # Existing extra hunk references HASH_ROR but does not define it.
    existing = (
        "diff --git a/dict.c b/dict.c\n"
        "--- a/dict.c\n"
        "+++ b/dict.c\n"
        "@@ -1,2 +1,0 @@\n"
        "-#define HASH_FINISH(h1, h2) do { (h2) += HASH_ROR((h1), 6); } while (0)\n"
        "-/* extra */\n"
    )
    extra_patch = PatchInfo(
        file_path_old="dict.c",
        file_path_new="dict.c",
        patch_text=existing,
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
        symbol_name="HASH_ROR",
        version="v1",
    )
    assert out.get("patch_key") == extra_key, out
    inserted = str(out.get("inserted_code") or "")
    assert inserted.startswith("#define HASH_ROR"), inserted
    ref = out.get("patch_text") or {}
    assert isinstance(ref, dict) and ref.get("artifact_path"), out
    text_out = Path(str(ref.get("artifact_path"))).read_text(encoding="utf-8", errors="replace")
    assert "#define HASH_ROR" in text_out, text_out

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
import os
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import (  # noqa: E402
    AgentState,
    _block_make_extra_patch_override_after_unresolvable_lookup,
    _undeclared_symbol_extra_patch_guardrail_for_override,
)

# Non-__revert_* symbols should NOT be forced via make_extra_patch_override:
# a forward declaration alone doesn't provide an implementation and causes linker errors.
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
assert forced is None, f"non-__revert_ symbol should not trigger guardrail, got {forced}"

# __revert_* symbols SHOULD still be forced.
err_revert = "/src/libxml2/dict.c:1519:21: error: use of undeclared identifier '__revert_abc123_xmlRngMutex'"
state_rv = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line=err_revert,
    snippet="",
)
state_rv.grouped_errors = [{"raw": err_revert, "file": "/src/libxml2/dict.c", "line": 1519, "col": 21}]
state_rv.steps = list(state.steps)
state_rv.step_history = list(state_rv.steps)

forced_rv = _undeclared_symbol_extra_patch_guardrail_for_override(state_rv, decision)
assert forced_rv and forced_rv.get("tool") == "make_extra_patch_override", forced_rv
assert forced_rv.get("args", {}).get("symbol_name") == "__revert_abc123_xmlRngMutex", forced_rv
assert forced_rv.get("args", {}).get("file_path") == "/src/libxml2/dict.c", forced_rv

# If a prior make_extra lookup for the same __revert_ symbol reported unreadable source,
# guardrail should stop forcing make_extra and let model-guided override proceed.
state2 = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line=err_revert,
    snippet="",
)
state2.grouped_errors = [{"raw": err_revert, "file": "/src/libxml2/dict.c", "line": 1519, "col": 21}]
state2.steps = [
    {
        "decision": {"type": "tool", "tool": "get_error_patch_context", "args": {}},
        "observation": {"ok": True, "tool": "get_error_patch_context", "args": {}, "output": {"patch_key": "p"}, "error": None},
    },
    {
        "decision": {
            "type": "tool",
            "tool": "make_extra_patch_override",
            "args": {"patch_path": "bundle.patch2", "file_path": "/src/libxml2/dict.c", "symbol_name": "__revert_abc123_xmlRngMutex"},
        },
        "observation": {
            "ok": True,
            "tool": "make_extra_patch_override",
            "args": {"patch_path": "bundle.patch2", "file_path": "/src/libxml2/dict.c", "symbol_name": "__revert_abc123_xmlRngMutex"},
            "output": {
                "patch_path": "bundle.patch2",
                "file_path": "/src/libxml2/dict.c",
                "symbol_name": "__revert_abc123_xmlRngMutex",
                "patch_key": "_extra_dict.c",
                "patch_text": "",
                "note": "KB has nodes for '__revert_abc123_xmlRngMutex' (v1=1, v2=0), but none produced readable source code.",
            },
            "error": None,
        },
    },
]
state2.step_history = list(state2.steps)
state2.loop_base_func_code_artifact_path = "/tmp/base.c"

forced = _undeclared_symbol_extra_patch_guardrail_for_override(state2, decision)
assert forced is None, forced

forced = _block_make_extra_patch_override_after_unresolvable_lookup(
    state2,
    {"type": "tool", "tool": "make_extra_patch_override", "thought": "retry", "args": {"symbol_name": "__revert_abc123_xmlRngMutex"}},
    remaining_steps=10,
)
assert forced and forced.get("tool") == "read_artifact", forced
assert state2.pending_patch and state2.pending_patch.get("tool") == "make_error_patch_override", state2.pending_patch

os.environ["REACT_AGENT_ENABLE_UNDECLARED_SYMBOL_GUARDRAIL"] = "0"
forced = _undeclared_symbol_extra_patch_guardrail_for_override(state_rv, decision)
assert forced is None, forced

os.environ["REACT_AGENT_ENABLE_UNDECLARED_SYMBOL_GUARDRAIL"] = "1"
forced = _undeclared_symbol_extra_patch_guardrail_for_override(state_rv, decision)
assert forced and forced.get("tool") == "make_extra_patch_override", forced
assert forced.get("args", {}).get("symbol_name") == "__revert_abc123_xmlRngMutex", forced
assert forced.get("args", {}).get("file_path") == "/src/libxml2/dict.c", forced
print("OK")
PY

# Extra-hunk unknown-type guardrail: if the error is "unknown type name" inside an `_extra_*` hunk,
# do NOT keep extending the extra hunk via make_extra_patch_override.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import tempfile
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import (  # noqa: E402
    AgentState,
    _block_make_extra_patch_override_for_extra_hunk,
)

# Test 1: unknown type name error inside _extra_* hunk
err = "/src/libxml2/error.c:52:1: error: unknown type name 'foo_t'"
with tempfile.TemporaryDirectory() as td:
    base_path = Path(td) / "base.c"
    base_path.write_text("foo_t x;\n", encoding="utf-8")

    st = AgentState(
        build_log_path="build.log",
        patch_path="bundle.patch2",
        error_scope="patch",
        error_line=err,
        snippet="",
    )
    st.patch_key = "_extra_error.c"
    st.active_patch_key = "_extra_error.c"
    st.loop_base_func_code_artifact_path = str(base_path)

    decision = {"type": "tool", "tool": "make_extra_patch_override", "thought": "insert type", "args": {}}
    forced = _block_make_extra_patch_override_for_extra_hunk(st, decision, remaining_steps=10)
    assert forced and forced.get("tool") == "read_artifact", forced
    assert st.pending_patch and (st.pending_patch.get("tool") == "make_error_patch_override"), st.pending_patch

# Test 2: ANY error inside _extra_* hunk should block make_extra_patch_override (not just unknown type name)
err2 = "/src/libxml2/error.c:52:1: error: use of undeclared identifier 'SOME_MACRO'"
with tempfile.TemporaryDirectory() as td:
    base_path = Path(td) / "base.c"
    base_path.write_text("int x = SOME_MACRO;\n", encoding="utf-8")

    st = AgentState(
        build_log_path="build.log",
        patch_path="bundle.patch2",
        error_scope="patch",
        error_line=err2,
        snippet="",
    )
    st.patch_key = "_extra_threads.c"
    st.active_patch_key = "_extra_threads.c"
    st.loop_base_func_code_artifact_path = str(base_path)

    decision = {"type": "tool", "tool": "make_extra_patch_override", "thought": "insert macro", "args": {}}
    forced = _block_make_extra_patch_override_for_extra_hunk(st, decision, remaining_steps=10)
    assert forced and forced.get("tool") == "read_artifact", ("should block ANY error in _extra_* hunk", forced)
    assert st.pending_patch and (st.pending_patch.get("tool") == "make_error_patch_override"), st.pending_patch

print("OK")
PY

# Missing-prototype guardrail: for -Wmissing-prototypes warnings ("no previous prototype for function ..."),
# force make_extra_patch_override(symbol_name=<function>) so the prototype is inserted into `_extra_*`.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _missing_prototype_extra_patch_guardrail  # noqa: E402

warn = "/src/libxml2/parser.c:16941:1: warning: no previous prototype for function '__revert_e11519_xmlParserNsCreate' [-Wmissing-prototypes]"
state = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line=warn,
    snippet="",
)
state.grouped_errors = [{"raw": warn, "file": "/src/libxml2/parser.c", "line": 16941, "col": 1, "level": "warning"}]
state.steps = [
    {
        "decision": {"type": "tool", "tool": "get_error_patch_context", "args": {}},
        "observation": {"ok": True, "tool": "get_error_patch_context", "args": {}, "output": {"patch_key": "p"}, "error": None},
    },
]
state.step_history = list(state.steps)

decision = {"type": "tool", "tool": "make_error_patch_override", "thought": "rewrite function", "args": {}}
forced = _missing_prototype_extra_patch_guardrail(state, decision)
assert forced and forced.get("tool") == "make_extra_patch_override", forced
assert forced.get("args", {}).get("symbol_name") == "__revert_e11519_xmlParserNsCreate", forced
assert forced.get("args", {}).get("file_path") == "/src/libxml2/parser.c", forced

print("OK")
PY

# Revert-missing-definition guardrail: for unresolved __revert_* helpers (linker or undefined-internal),
# force make_extra_patch_override(..., prefer_definition=true) targeting the using file.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _revert_missing_definition_extra_patch_guardrail  # noqa: E402

err = "/usr/bin/ld: header.c:(.text.build_header_line+0x6d): undefined reference to `__revert_deadbeef_ks_resize'"
state = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line=err,
    snippet="",
)
state.grouped_errors = [
    {
        "kind": "linker",
        "raw": "header.c:(.text.build_header_line+0x6d): undefined reference to `__revert_deadbeef_ks_resize'",
        "msg": "undefined reference to `__revert_deadbeef_ks_resize'",
        "file": "/src/htslib/header.c",
        "symbol": "__revert_deadbeef_ks_resize",
        "function": "build_header_line",
        "line": 0,
        "col": 0,
    }
]

decision = {"type": "tool", "tool": "make_error_patch_override", "thought": "rewrite function", "args": {}}
forced = _revert_missing_definition_extra_patch_guardrail(state, decision)
assert forced and forced.get("tool") == "make_extra_patch_override", forced
assert forced.get("args", {}).get("symbol_name") == "__revert_deadbeef_ks_resize", forced
assert forced.get("args", {}).get("file_path") == "/src/htslib/header.c", forced
assert forced.get("args", {}).get("prefer_definition") is True, forced

# Once we've already attempted prefer_definition for this symbol, do not force again.
state.step_history = [
    {
        "decision": {
            "type": "tool",
            "tool": "make_extra_patch_override",
            "args": {
                "patch_path": "bundle.patch2",
                "file_path": "/src/htslib/header.c",
                "symbol_name": "__revert_deadbeef_ks_resize",
                "prefer_definition": True,
            },
        },
        "observation": {},
    }
]
forced2 = _revert_missing_definition_extra_patch_guardrail(state, decision)
assert forced2 is None, forced2

print("OK")
PY

# Patch-scope ordering: within a patch hunk, prioritize warnings (and missing-prototype warnings first)
# before errors when picking the next grouped error to solve.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import _prioritize_warnings_within_hunk  # noqa: E402

errs = [
    {"raw": "E", "level": "error", "msg": "something bad"},
    {"raw": "W1", "level": "warning", "msg": "call to undeclared function '__revert_x' [-Wimplicit-function-declaration]"},
    {"raw": "W2", "level": "warning", "msg": "no previous prototype for function '__revert_y' [-Wmissing-prototypes]"},
]
out = _prioritize_warnings_within_hunk(errs)
assert [e.get("raw") for e in out] == ["W2", "W1", "E"], out
print("OK")
PY

# Incomplete-type guardrail: for errors like "incomplete definition of type ..." / "sizeof to an incomplete type ...",
# force make_extra_patch_override before allowing make_error_patch_override to rewrite the function into a semantic no-op.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _incomplete_type_extra_patch_guardrail_for_override  # noqa: E402

err = "/src/libxml2/parser.c:16920:9: error: incomplete definition of type 'struct _xmlParserNsData'"
state = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line=err,
    snippet="",
)
state.grouped_errors = [{"raw": err, "file": "/src/libxml2/parser.c", "line": 16920, "col": 9}]
state.steps = [
    {
        "decision": {"type": "tool", "tool": "get_error_patch_context", "args": {}},
        "observation": {"ok": True, "tool": "get_error_patch_context", "args": {}, "output": {"patch_key": "p"}, "error": None},
    },
]
state.step_history = list(state.steps)

# Simulate one prior attempt (common sequence: typedef first, then tag body definition).
state.step_history.append(
    {"decision": {"type": "tool", "tool": "make_extra_patch_override", "args": {"symbol_name": "xmlParserNsData"}}, "observation": {}}
)

decision = {"type": "tool", "tool": "make_error_patch_override", "thought": "remove field access", "args": {}}
forced = _incomplete_type_extra_patch_guardrail_for_override(state, decision)
assert forced and forced.get("tool") == "make_extra_patch_override", forced
assert forced.get("args", {}).get("symbol_name") == "xmlParserNsData", forced
assert forced.get("args", {}).get("file_path") == "/src/libxml2/parser.c", forced

# Once we've already tried twice for both the alias and the struct tag, stop forcing to avoid loops.
state.step_history.append(
    {"decision": {"type": "tool", "tool": "make_extra_patch_override", "args": {"symbol_name": "xmlParserNsData"}}, "observation": {}}
)
state.step_history.append(
    {"decision": {"type": "tool", "tool": "make_extra_patch_override", "args": {"symbol_name": "_xmlParserNsData"}}, "observation": {}}
)
state.step_history.append(
    {"decision": {"type": "tool", "tool": "make_extra_patch_override", "args": {"symbol_name": "_xmlParserNsData"}}, "observation": {}}
)
forced2 = _incomplete_type_extra_patch_guardrail_for_override(state, decision)
assert forced2 is None, forced2

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

# Missing-member summary: only include the ACTIVE missing member (do not union members across grouped errors).
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import _missing_struct_member_summary_for_error_line  # noqa: E402

line1 = "/src/p.c:1:1: error: no member named 'nsdb' in 'struct _xmlParserCtxt'"
assert _missing_struct_member_summary_for_error_line(line1) == [
    {"struct": "struct _xmlParserCtxt", "members": ["nsdb"]}
]

line2 = "/src/p.c:2:1: error: no member named 'foo' in 'struct _xmlParserCtxt'"
assert _missing_struct_member_summary_for_error_line(line2) == [
    {"struct": "struct _xmlParserCtxt", "members": ["foo"]}
]

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

    # If the override includes the tail but drops most of the body, still reject it.
    short_with_tail = "\n".join(base_lines[:20] + base_lines[-10:]) + "\n"
    decision2 = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "thought": "oops, kept tail but dropped middle",
        "args": {"patch_path": "x", "file_path": "y", "line_number": 1, "new_func_code": short_with_tail},
    }
    err2 = _override_preserve_base_guardrail_error(state, decision2)
    assert err2 and "much shorter" in err2, err2

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

# Override guardrail: avoid broad renames/drops of __revert_* helper symbols while fixing an unrelated error.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _override_preserve_revert_symbols_guardrail_error  # noqa: E402

state = AgentState(
    build_log_path="build.log",
    patch_path="bundle.patch2",
    error_scope="patch",
    error_line="x:1:1: error: y",
    snippet="",
)

base_text = (
    "int __revert_deadbeef_a(void);\\n"
    "int __revert_deadbeef_b(int x);\\n"
    "int __revert_deadbeef_c(void);\\n"
    "int foo(void) {\\n"
    "  if (__revert_deadbeef_a()) return __revert_deadbeef_b(1);\\n"
    "  return __revert_deadbeef_c();\\n"
    "}\\n"
)

with tempfile.TemporaryDirectory() as td:
    baseline_path = Path(td) / "error_func_code.c"
    baseline_path.write_text(base_text, encoding="utf-8")
    state.active_error_func_code_artifact_path = str(baseline_path)

    renamed = (
        "int foo(void) {\\n"
        "  if (a()) return b(1);\\n"
        "  return c();\\n"
        "}\\n"
    )
    decision = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "thought": "oops, normalized helpers",
        "args": {"patch_path": "x", "file_path": "y", "line_number": 1, "new_func_code": renamed},
    }
    err = _override_preserve_revert_symbols_guardrail_error(state, decision)
    assert err and "__revert_*" in err, err

    # Allow at most one dropped __revert_* symbol (e.g. a single intentional rename).
    ok = (
        "int foo(void) {\\n"
        "  if (a()) return __revert_deadbeef_b(1);\\n"
        "  return __revert_deadbeef_c();\\n"
        "}\\n"
    )
    ok_decision = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "thought": "single rename only",
        "args": {"patch_path": "x", "file_path": "y", "line_number": 1, "new_func_code": ok},
    }
    assert _override_preserve_revert_symbols_guardrail_error(state, ok_decision) is None

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

# Override shrink recovery: when the base-preservation guardrail triggers, force a read_artifact
# of this round's get_error_patch_context.error_func_code before retrying an override.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _force_read_base_slice_for_shrunk_override, _override_preserve_base_guardrail_error  # noqa: E402

with tempfile.TemporaryDirectory() as td:
    base_path = str(Path(td) / "error_func_code.txt")
    Path(base_path).write_text("".join([f"LINE{i:03d}\\n" for i in range(80)]), encoding="utf-8")
    state = AgentState(
        build_log_path="build.log",
        patch_path="bundle.patch2",
        error_scope="patch",
        error_line="/src/p.c:1:1: error: x",
        snippet="",
    )
    state.active_error_func_code_artifact_path = base_path

    decision = {
        "type": "tool",
        "tool": "make_error_patch_override",
        "thought": "too short",
        "args": {"patch_path": "x", "file_path": "/src/p.c", "line_number": 1, "new_func_code": "int x;\\n"},
    }
    assert _override_preserve_base_guardrail_error(state, decision), "expected shrink guardrail to trigger"

    forced = _force_read_base_slice_for_shrunk_override(state)
    assert forced and forced.get("tool") == "read_artifact", forced
    assert (forced.get("args") or {}).get("artifact_path") == base_path, forced

    state.steps = [
        {
            "decision": {"type": "tool", "tool": "read_artifact", "args": {"artifact_path": base_path}},
            "observation": {"ok": True, "tool": "read_artifact", "args": {"artifact_path": base_path}, "output": {"text": "ok"}, "error": None},
            "context": {},
        }
    ]
    assert _force_read_base_slice_for_shrunk_override(state) is None, "expected no force when base already read"

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

# `_extra_*` follow-up rewrite support: when an extra hunk contains multiple inserted
# function definitions but no hiden_func_dict metadata, mapping should still select the
# correct function slice (not the full contiguous '-' block).
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import pickle
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from migration_tools.patch_bundle import load_patch_bundle  # noqa: E402
from migration_tools.tools import _get_error_patch_from_bundle, make_error_patch_override  # noqa: E402
from migration_tools.types import PatchInfo  # noqa: E402

with tempfile.TemporaryDirectory() as td:
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = td
    bundle_path = Path(td) / "bundle.patch2"
    patch_key = "_extra_demo.c"

    patch_text = (
        "diff --git a/demo.c b/demo.c\n"
        "--- a/demo.c\n"
        "+++ b/demo.c\n"
        "@@ -100,8 +100,1 @@\n"
        "-int helper_one(void) {\n"
        "-  return 1;\n"
        "-}\n"
        "-\n"
        "-int helper_two(void) {\n"
        "-  return 2;\n"
        "-}\n"
        " int anchor = 0;\n"
    )
    patch = PatchInfo(
        file_path_old="demo.c",
        file_path_new="demo.c",
        patch_text=patch_text,
        file_type="c",
        old_start_line=100,
        old_end_line=108,
        new_start_line=100,
        new_end_line=101,
        patch_type={"Extra"},
        old_signature="",
        dependent_func=set(),
        hiden_func_dict={},
    )
    bundle_path.write_bytes(pickle.dumps({patch_key: patch}, protocol=pickle.HIGHEST_PROTOCOL))

    bundle = load_patch_bundle(str(bundle_path), allowed_roots=[td])
    m1 = _get_error_patch_from_bundle(bundle, patch_path=str(bundle_path), file_path="/src/demo.c", line_number=101)
    m2 = _get_error_patch_from_bundle(bundle, patch_path=str(bundle_path), file_path="/src/demo.c", line_number=105)
    assert m1.get("patch_key") == patch_key, m1
    assert m2.get("patch_key") == patch_key, m2
    assert int(m2.get("func_start_index") or -1) > int(m1.get("func_start_index") or -1), (m1, m2)
    assert "helper_two" in str(m2.get("old_signature") or ""), m2

    out = make_error_patch_override(
        patch_path=str(bundle_path),
        file_path="/src/demo.c",
        line_number=105,
        new_func_code="int helper_two(void) { return 22; }\n",
        allowed_roots=[td],
    )
    assert out.get("patch_key") == patch_key, out
    updated = str(out.get("patch_text") or "")
    assert "helper_one(void)" in updated, updated
    assert "return 1;" in updated, updated
    assert "helper_two(void) { return 22; }" in updated, updated
    assert "return 2;" not in updated, updated
    upd_hiden = out.get("hiden_func_dict_updated")
    assert isinstance(upd_hiden, dict) and any("helper_two" in str(k) for k in upd_hiden.keys()), upd_hiden

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
for field in ("excerpt", "error_func_code"):
    val = obs.get(field)
    assert isinstance(val, dict) and val.get("artifact_path"), (field, val)
    ap = Path(val["artifact_path"]).resolve()
    assert ap.is_file(), ap
    assert artifact_dir in ap.parents, (artifact_dir, ap)

    snippet = read_artifact(artifact_path=str(ap), start_line=1, max_lines=20)
    assert snippet.get("text"), (field, snippet)

ef = obs.get("error_func_code") or {}
ef_text = read_artifact(artifact_path=str(ef.get("artifact_path")), start_line=1, max_lines=0, max_chars=0).get("text") or ""
assert ef_text.strip(), ef_text

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

extra_dir = (artifact_root / "_extra_error.c").resolve()
extra_dir.mkdir(parents=True, exist_ok=True)
extra_override_path = extra_dir / "override_extra.diff"
extra_override_text = (
    "diff --git a/error.c b/error.c\n"
    "--- a/error.c\n"
    "+++ b/error.c\n"
    "@@ -1,2 +1,0 @@\n"
    "-/* extra decls */\n"
    "-#define EXTRA_DECL 1\n"
)
extra_override_path.write_text(extra_override_text, encoding="utf-8", errors="replace")

out = merge_patch_bundle_with_overrides(
    patch_path=str(bundle_path),
    patch_override_paths=[str(override_path), str(extra_override_path)],
    output_name="merged_test.diff",
)
merged_path = Path(out.get("merged_patch_file_path", "")).resolve()
assert merged_path.is_file(), out
merged_text = merged_path.read_text(encoding="utf-8", errors="replace")
assert "OVERRIDE_LINE" in merged_text, merged_path
assert "p2" in (out.get("overridden_patch_keys") or []), out
assert "_extra_error.c" in (out.get("overridden_patch_keys") or []), out
assert "EXTRA_DECL" in merged_text, merged_path
assert merged_path.parent in {artifact_dir.resolve(), artifact_root.resolve()}, (merged_path, artifact_dir)

nested_extra_dir = (artifact_dir / "_extra_error.c").resolve()
nested_extra_dir.mkdir(parents=True, exist_ok=True)
nested_extra_override_path = nested_extra_dir / "override_extra_only.diff"
nested_extra_override_text = (
    "diff --git a/error.c b/error.c\n"
    "--- a/error.c\n"
    "+++ b/error.c\n"
    "@@ -1,2 +1,0 @@\n"
    "-/* extra decls */\n"
    "-#define EXTRA_ONLY_DECL 1\n"
)
nested_extra_override_path.write_text(nested_extra_override_text, encoding="utf-8", errors="replace")

out2 = merge_patch_bundle_with_overrides(
    patch_path=str(bundle_path),
    patch_override_paths=[str(nested_extra_override_path)],
    output_name="merged_test_extra_only.diff",
)
merged_path2 = Path(out2.get("merged_patch_file_path", "")).resolve()
assert merged_path2.is_file(), out2
merged_text2 = merged_path2.read_text(encoding="utf-8", errors="replace")
assert "_extra_error.c" in (out2.get("overridden_patch_keys") or []), out2
assert "EXTRA_ONLY_DECL" in merged_text2, merged_path2
assert merged_path2.parent in {artifact_dir.resolve(), artifact_root.resolve()}, (merged_path2, artifact_dir)

# Multiple override diffs for the same `_extra_*` key should be merged (not last-write-wins).
out3 = merge_patch_bundle_with_overrides(
    patch_path=str(bundle_path),
    patch_override_paths=[str(extra_override_path), str(nested_extra_override_path)],
    output_name="merged_test_extra_multi.diff",
)
merged_path3 = Path(out3.get("merged_patch_file_path", "")).resolve()
assert merged_path3.is_file(), out3
merged_text3 = merged_path3.read_text(encoding="utf-8", errors="replace")
assert "_extra_error.c" in (out3.get("overridden_patch_keys") or []), out3
assert "EXTRA_DECL" in merged_text3, merged_path3
assert "EXTRA_ONLY_DECL" in merged_text3, merged_path3

# Regression: split a multi-hunk override diff into separate single-hunk diff blocks.
multi_hunk_override_path = artifact_dir / "override_p2_multi_hunk.diff"
multi_hunk_override_text = (
    "diff --git a/error.c b/error.c\n"
    "--- a/error.c\n"
    "+++ b/error.c\n"
    "@@ -10,1 +10,1 @@\n"
    "-line2\n"
    "+OVERRIDE_MULTI_A\n"
    "@@ -20,1 +20,1 @@\n"
    "-line3\n"
    "+OVERRIDE_MULTI_B\n"
)
multi_hunk_override_path.write_text(multi_hunk_override_text, encoding="utf-8", errors="replace")

out_multi = merge_patch_bundle_with_overrides(
    patch_path=str(bundle_path),
    patch_override_paths=[str(multi_hunk_override_path)],
    output_name="merged_test_multi_hunk_split.diff",
)
merged_multi_path = Path(out_multi.get("merged_patch_file_path", "")).resolve()
assert merged_multi_path.is_file(), out_multi
merged_multi_text = merged_multi_path.read_text(encoding="utf-8", errors="replace")

pos_a = merged_multi_text.find("+OVERRIDE_MULTI_A")
pos_b = merged_multi_text.find("+OVERRIDE_MULTI_B")
assert pos_a >= 0, merged_multi_text
assert pos_b >= 0, merged_multi_text

def _diff_block_for_pos(text: str, pos: int) -> str:
    start = text.rfind("\ndiff --git ", 0, pos)
    if start >= 0:
        start += 1
    elif text.startswith("diff --git "):
        start = 0
    else:
        start = text.rfind("diff --git ", 0, pos)
    assert start >= 0, (pos, text[:200])
    end = text.find("\ndiff --git ", pos)
    if end < 0:
        end = len(text)
    return text[start:end]

block_a = _diff_block_for_pos(merged_multi_text, pos_a)
block_b = _diff_block_for_pos(merged_multi_text, pos_b)
assert block_a != block_b, (block_a, block_b)
assert sum(1 for ln in block_a.splitlines() if ln.startswith("@@")) == 1, block_a
assert sum(1 for ln in block_b.splitlines() if ln.startswith("@@")) == 1, block_b

bundle_out = write_patch_bundle_with_overrides(
    patch_path=str(bundle_path),
    patch_override_paths=[str(override_path), str(extra_override_path)],
    output_name="merged_test.patch2",
)
merged_bundle_path = Path(bundle_out.get("merged_patch_bundle_path", "")).resolve()
assert merged_bundle_path.is_file(), bundle_out
merged_bundle = load_patch_bundle(str(merged_bundle_path), allowed_roots=[str(bundle_path.parent)])
assert "p2" in merged_bundle.patches, merged_bundle_path
assert "OVERRIDE_LINE" in (merged_bundle.patches["p2"].patch_text or ""), merged_bundle_path
assert "_extra_error.c" in merged_bundle.patches, merged_bundle_path
assert "EXTRA_DECL" in (merged_bundle.patches["_extra_error.c"].patch_text or ""), merged_bundle_path

bundle_out2 = write_patch_bundle_with_overrides(
    patch_path=str(bundle_path),
    patch_override_paths=[str(override_path), str(extra_override_path), str(nested_extra_override_path)],
    output_name="merged_test_extra_multi.patch2",
)
merged_bundle_path2 = Path(bundle_out2.get("merged_patch_bundle_path", "")).resolve()
assert merged_bundle_path2.is_file(), bundle_out2
merged_bundle2 = load_patch_bundle(str(merged_bundle_path2), allowed_roots=[str(bundle_path.parent)])
assert "_extra_error.c" in merged_bundle2.patches, merged_bundle_path2
extra_text = merged_bundle2.patches["_extra_error.c"].patch_text or ""
assert "EXTRA_DECL" in extra_text, merged_bundle_path2
assert "EXTRA_ONLY_DECL" in extra_text, merged_bundle_path2

# Regression: `_extra_*` merge must treat multi-line prototypes atomically (avoid stray fragments like a lone `-int`).
proto_dir = (artifact_dir / "_extra_proto.c").resolve()
proto_dir.mkdir(parents=True, exist_ok=True)
proto_static_path = proto_dir / "000_proto_static.diff"
proto_int_path = proto_dir / "999_proto_int.diff"

proto_static_text = (
    "diff --git a/merge_proto.c b/merge_proto.c\n"
    "--- a/merge_proto.c\n"
    "+++ b/merge_proto.c\n"
    "@@ -1,2 +1,0 @@\n"
    "-static int\n"
    "-__revert_e11519_xmlHashGrow(void);\n"
)
proto_int_text = (
    "diff --git a/merge_proto.c b/merge_proto.c\n"
    "--- a/merge_proto.c\n"
    "+++ b/merge_proto.c\n"
    "@@ -1,2 +1,0 @@\n"
    "-int\n"
    "-__revert_e11519_xmlHashGrow(void);\n"
)
proto_static_path.write_text(proto_static_text, encoding="utf-8", errors="replace")
proto_int_path.write_text(proto_int_text, encoding="utf-8", errors="replace")

out4 = merge_patch_bundle_with_overrides(
    patch_path=str(bundle_path),
    patch_override_paths=[str(proto_static_path), str(proto_int_path)],
    output_name="merged_test_extra_proto.diff",
)
merged_path4 = Path(out4.get("merged_patch_file_path", "")).resolve()
assert merged_path4.is_file(), out4
merged_text4 = merged_path4.read_text(encoding="utf-8", errors="replace")

hdr = "diff --git a/merge_proto.c b/merge_proto.c"
start = merged_text4.find(hdr)
assert start >= 0, (hdr, merged_path4)
tail = merged_text4[start:]
end = tail.find("\ndiff --git ")
section = tail if end < 0 else tail[: end + 1]

section_lines = section.splitlines()
minus = []
in_hunk = False
for line in section_lines:
    if line.startswith("@@"):
        in_hunk = True
        continue
    if not in_hunk:
        continue
    if line.startswith("diff --git ") or line.startswith("@@"):
        break
    if line.startswith("---"):
        continue
    if line.startswith("-"):
        minus.append("" if line == "-" else line[1:])

blocks = []
cur = []
for l in minus:
    if l == "":
        if cur:
            blocks.append(cur)
            cur = []
        continue
    cur.append(l)
if cur:
    blocks.append(cur)

assert any("static int" in b[0] for b in blocks if b), blocks
assert "__revert_e11519_xmlHashGrow" in section, section
assert "\n-int\n" not in section, section
assert section.count("__revert_e11519_xmlHashGrow(") == 1, section

bundle_out3 = write_patch_bundle_with_overrides(
    patch_path=str(bundle_path),
    patch_override_paths=[str(proto_static_path), str(proto_int_path)],
    output_name="merged_test_extra_proto.patch2",
)
merged_bundle_path3 = Path(bundle_out3.get("merged_patch_bundle_path", "")).resolve()
assert merged_bundle_path3.is_file(), bundle_out3
merged_bundle3 = load_patch_bundle(str(merged_bundle_path3), allowed_roots=[str(bundle_path.parent)])
assert "_extra_proto.c" in merged_bundle3.patches, merged_bundle_path3
proto_patch_text = merged_bundle3.patches["_extra_proto.c"].patch_text or ""
assert "\n-static int\n" in proto_patch_text, proto_patch_text
assert "\n-int\n" not in proto_patch_text, proto_patch_text
assert proto_patch_text.count("__revert_e11519_xmlHashGrow(") == 1, proto_patch_text

# Regression: typedef/tag blocks must appear BEFORE prototypes in merged `_extra_*` hunks.
# This tests both: (1) identical texts skip merge to preserve order, (2) category ordering puts typedef before prototype.
typedef_dir = (artifact_dir / "_extra_typedef.c").resolve()
typedef_dir.mkdir(parents=True, exist_ok=True)

# Override diff with typedef BEFORE prototypes (the correct order)
typedef_override_text = (
    "diff --git a/typedef_test.c b/typedef_test.c\n"
    "--- a/typedef_test.c\n"
    "+++ b/typedef_test.c\n"
    "@@ -1,10 +1,0 @@\n"
    "-#define TEST_MACRO 42\n"
    "-\n"
    "-typedef struct _TestData {\n"
    "-    int value;\n"
    "-} TestData;\n"
    "-\n"
    "-TestData *\n"
    "-__revert_e11519_createTestData(void);\n"
    "-\n"
    "-void\n"
    "-__revert_e11519_freeTestData(TestData *data);\n"
)
typedef_override_path1 = typedef_dir / "override__extra_typedef.c.diff"
typedef_override_path2 = typedef_dir / "make_error_patch_override_patch_text_typedef_test.c.diff"
typedef_override_path1.write_text(typedef_override_text, encoding="utf-8", errors="replace")
typedef_override_path2.write_text(typedef_override_text, encoding="utf-8", errors="replace")

# Test 1: Two identical override diffs should skip merge and preserve original order
out5 = merge_patch_bundle_with_overrides(
    patch_path=str(bundle_path),
    patch_override_paths=[str(typedef_override_path1), str(typedef_override_path2)],
    output_name="merged_test_typedef_identical.diff",
)
merged_path5 = Path(out5.get("merged_patch_file_path", "")).resolve()
assert merged_path5.is_file(), out5
merged_text5 = merged_path5.read_text(encoding="utf-8", errors="replace")

# Find the typedef_test.c section
hdr5 = "diff --git a/typedef_test.c b/typedef_test.c"
start5 = merged_text5.find(hdr5)
assert start5 >= 0, (hdr5, merged_path5)
tail5 = merged_text5[start5:]
end5 = tail5.find("\ndiff --git ")
section5 = tail5 if end5 < 0 else tail5[: end5 + 1]

# Verify typedef appears BEFORE the prototype that references it
typedef_pos = section5.find("typedef struct _TestData")
proto_pos = section5.find("__revert_e11519_createTestData")
assert typedef_pos >= 0, ("typedef not found", section5)
assert proto_pos >= 0, ("prototype not found", section5)
assert typedef_pos < proto_pos, f"typedef must appear before prototype: typedef@{typedef_pos} proto@{proto_pos}\n{section5}"

# Test 2: Different override diffs should merge and still put typedef before prototypes
typedef_override_text2 = (
    "diff --git a/typedef_test.c b/typedef_test.c\n"
    "--- a/typedef_test.c\n"
    "+++ b/typedef_test.c\n"
    "@@ -1,5 +1,0 @@\n"
    "-int\n"
    "-__revert_e11519_processTestData(TestData *data);\n"
    "-\n"
    "-struct AnotherTag {\n"
    "-    char name[64];\n"
    "-};\n"
)
typedef_override_path3 = typedef_dir / "override__extra_typedef.c.2.diff"
typedef_override_path3.write_text(typedef_override_text2, encoding="utf-8", errors="replace")

out6 = merge_patch_bundle_with_overrides(
    patch_path=str(bundle_path),
    patch_override_paths=[str(typedef_override_path1), str(typedef_override_path3)],
    output_name="merged_test_typedef_different.diff",
)
merged_path6 = Path(out6.get("merged_patch_file_path", "")).resolve()
assert merged_path6.is_file(), out6
merged_text6 = merged_path6.read_text(encoding="utf-8", errors="replace")

# Find the typedef_test.c section
start6 = merged_text6.find(hdr5)
assert start6 >= 0, (hdr5, merged_path6)
tail6 = merged_text6[start6:]
end6 = tail6.find("\ndiff --git ")
section6 = tail6 if end6 < 0 else tail6[: end6 + 1]

# Verify ordering: macro < typedef < tag < prototypes
macro_pos6 = section6.find("#define TEST_MACRO")
typedef_pos6 = section6.find("typedef struct _TestData")
tag_pos6 = section6.find("struct AnotherTag")
proto_create_pos6 = section6.find("__revert_e11519_createTestData")
proto_process_pos6 = section6.find("__revert_e11519_processTestData")

assert macro_pos6 >= 0, ("macro not found", section6)
assert typedef_pos6 >= 0, ("typedef not found", section6)
assert tag_pos6 >= 0, ("tag not found", section6)
assert proto_create_pos6 >= 0, ("createTestData proto not found", section6)
assert proto_process_pos6 >= 0, ("processTestData proto not found", section6)

# Verify correct ordering: macro < typedef/tag < prototypes
assert macro_pos6 < typedef_pos6, f"macro must appear before typedef: macro@{macro_pos6} typedef@{typedef_pos6}"
assert macro_pos6 < tag_pos6, f"macro must appear before tag: macro@{macro_pos6} tag@{tag_pos6}"
assert typedef_pos6 < proto_create_pos6, f"typedef must appear before prototype: typedef@{typedef_pos6} proto@{proto_create_pos6}"
assert typedef_pos6 < proto_process_pos6, f"typedef must appear before prototype: typedef@{typedef_pos6} proto@{proto_process_pos6}"
assert tag_pos6 < proto_create_pos6, f"tag must appear before prototype: tag@{tag_pos6} proto@{proto_create_pos6}"
assert tag_pos6 < proto_process_pos6, f"tag must appear before prototype: tag@{tag_pos6} proto@{proto_process_pos6}"
PY

# Multi-agent override collection: keep multiple `_extra_*` overrides (per origin hunk).
"$PYTHON" - "$SCRIPT_DIR" "$bundle_path" <<'PY'
import tempfile
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
bundle_path = Path(sys.argv[2]).resolve()
sys.path.insert(0, str(script_dir))

from multi_agent import _collect_final_override_diffs  # noqa: E402

with tempfile.TemporaryDirectory() as td:
    root = Path(td).resolve()
    results = []
    for origin, marker in [("pA", "EXTRA_A"), ("pB", "EXTRA_B")]:
        out_dir = root / origin
        extra_dir = out_dir / "_extra_error.c"
        extra_dir.mkdir(parents=True, exist_ok=True)
        # Minimal unified diff; collector only needs it to be a file path.
        (extra_dir / "override__extra_error.c.diff").write_text(
            "diff --git a/error.c b/error.c\n"
            "--- a/error.c\n"
            "+++ b/error.c\n"
            "@@ -1,1 +1,0 @@\n"
            f"-#define {marker} 1\n",
            encoding="utf-8",
            errors="replace",
        )
        results.append({"patch_key": origin, "artifacts_dir": str(out_dir)})

    out = _collect_final_override_diffs(results, patch_path=str(bundle_path))
    paths = [str(p) for p in (out.get("override_paths") or [])]
    got = [p for p in paths if p.endswith("override__extra_error.c.diff")]
    assert len(got) == 2, got
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
from datetime import datetime  # noqa: E402
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
        if tool == "make_extra_patch_override":
            # Minimal stub diff: reverse-applied `-` lines become additions in patch-scope.
            # This just needs to be non-empty so agent_langgraph treats it as a generated patch.
            file_path = str(args.get("file_path") or "")
            symbol = str(args.get("symbol_name") or "")
            base = Path(file_path).name or "file.c"
            extra_key = f"_extra_{base}"
            stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
            patch_text = (
                f"diff --git a/{base} b/{base}\n"
                f"--- a/{base}\n"
                f"+++ b/{base}\n"
                f"@@ -1,0 +1,1 @@\n"
                f"-/* extra stub {stamp}: {symbol} */\n"
            )
            out = {
                "patch_path": str(args.get("patch_path") or ""),
                "file_path": file_path,
                "symbol_name": symbol,
                "patch_key": extra_key,
                "patch_text": patch_text,
            }
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
    # Undeclared-symbol guardrail is enabled by default; make_extra_patch_override is preferred for
    # undeclared identifiers/types/macros during auto-loop.
    assert (runner.calls.count("make_error_patch_override") + runner.calls.count("make_extra_patch_override")) >= 2, runner.calls
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
    patch_text_versions = sorted(root.glob("make_error_patch_override_patch_text*.diff")) + sorted(
        root.glob("make_extra_patch_override_patch_text*.diff")
    )
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
        if str(obs.get("tool") or "") in {"make_error_patch_override", "make_extra_patch_override"}:
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

# Patch-key status grouping: when mapping provides old_signature, do not collapse groups into "<unknown>".
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import pickle
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, ToolObservation, _summarize_active_patch_key_status  # noqa: E402
from migration_tools.types import PatchInfo  # noqa: E402


def fake_gepb(bundle, *, patch_path, file_path, line_number, **_kw):
    if int(line_number) == 10:
        return {"patch_key": "p", "old_signature": "int f(void)"}
    if int(line_number) == 20:
        return {"patch_key": "p", "old_signature": "int g(void)"}
    return {"patch_key": "p", "old_signature": "int f(void)"}


with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(root)

    import migration_tools.tools as mt  # noqa: E402

    mt._get_error_patch_from_bundle = fake_gepb

    bundle_path = root / "bundle.pkl"
    bundle_path.write_bytes(
        pickle.dumps(
            {
                "p": PatchInfo(
                    file_path_old="a.c",
                    file_path_new="a.c",
                    patch_text="diff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -1,1 +1,1 @@\n-old\n+new\n",
                    file_type="source",
                    old_start_line=1,
                    old_end_line=1,
                    new_start_line=1,
                    new_end_line=1,
                )
            }
        )
    )

    build_log = root / "build.log"
    build_log.write_text("/src/a.c:10:1: error: e1\n/src/a.c:20:1: error: e2\n", encoding="utf-8")

    st = AgentState(build_log_path="-", patch_path=str(bundle_path), error_scope="patch", error_line="old", snippet="")
    st.patch_key = "p"
    st.active_patch_key = "p"
    st.last_observation = ToolObservation(
        ok=True,
        tool="ossfuzz_apply_patch_and_test",
        args={},
        output={"build_output": {"artifact_path": str(build_log)}},
        error=None,
    )

    pkv = _summarize_active_patch_key_status(st)
    assert pkv.get("status") == "ok", pkv
    groups = pkv.get("function_groups") or []
    sigs = {g.get("old_signature") for g in groups if isinstance(g, dict)}
    assert "int f(void)" in sigs, sigs
    assert "int g(void)" in sigs, sigs

print("OK")
PY

# Patch-key status: new error at same line (different message) should NOT count as remaining.
# Only errors matching the original target_errors messages count as "remaining".
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import pickle
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, ToolObservation, _summarize_active_patch_key_status  # noqa: E402
from migration_tools.types import PatchInfo  # noqa: E402


def fake_gepb(bundle, *, patch_path, file_path, line_number, **_kw):
    return {"patch_key": "p", "old_signature": "int f(void)"}


with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(root)

    import migration_tools.tools as mt  # noqa: E402

    mt._get_error_patch_from_bundle = fake_gepb

    bundle_path = root / "bundle.pkl"
    bundle_path.write_bytes(
        pickle.dumps(
            {
                "p": PatchInfo(
                    file_path_old="a.c",
                    file_path_new="a.c",
                    patch_text="diff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -1,1 +1,1 @@\n-old\n+new\n",
                    file_type="source",
                    old_start_line=1,
                    old_end_line=1,
                    new_start_line=1,
                    new_end_line=1,
                )
            }
        )
    )

    # Build log has a NEW error (bar) at the same line — the ORIGINAL error (foo) was fixed.
    build_log = root / "build.log"
    build_log.write_text(
        "/src/a.c:10:1: error: use of undeclared identifier 'bar'\n",
        encoding="utf-8",
    )

    st = AgentState(build_log_path="-", patch_path=str(bundle_path), error_scope="patch", error_line="old", snippet="")
    st.patch_key = "p"
    st.active_patch_key = "p"
    # Original target error had message about 'foo', not 'bar'
    st.target_errors = [{"file": "/src/a.c", "msg": "use of undeclared identifier 'foo'", "patch_key": "p"}]
    st.last_observation = ToolObservation(
        ok=True,
        tool="ossfuzz_apply_patch_and_test",
        args={},
        output={"build_output": {"artifact_path": str(build_log)}},
        error=None,
    )

    pkv = _summarize_active_patch_key_status(st)
    assert pkv.get("status") == "ok", pkv
    # Original error is gone → remaining should be 0
    assert pkv.get("remaining_in_active_patch_key") == 0, f"expected 0 remaining, got {pkv}"
    # New error is tracked separately
    assert pkv.get("new_errors_in_active_patch_key") == 1, f"expected 1 new error, got {pkv}"

print("OK")
PY

# _iter_unfixed_undeclared_symbols_from_grouped: returns symbols from grouped_errors not yet overridden.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentState, _iter_unfixed_undeclared_symbols_from_grouped  # noqa: E402

st = AgentState(build_log_path="-", patch_path="", error_scope="first", error_line="old", snippet="")
st.grouped_errors = [
    {"raw": "/src/a.h:10:8: error: use of undeclared identifier '__revert_foo'", "file": "/src/a.h", "line": 10},
    {"raw": "/src/a.h:10:40: error: use of undeclared identifier '__revert_bar'", "file": "/src/a.h", "line": 10},
    {"raw": "/src/a.h:11:5: error: call to undeclared function 'legacy_call'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]", "file": "/src/a.h", "line": 11},
    {"raw": "/src/a.h:12:9: error: use of undeclared identifier 'RANSPR'", "file": "/src/a.h", "line": 12},
]

unfixed = _iter_unfixed_undeclared_symbols_from_grouped(st)
# Only __revert_* symbols are eligible; non-__revert (RANSPR, legacy_call) are excluded.
assert len(unfixed) == 2, f"expected 2 unfixed, got {unfixed}"
assert unfixed[0] == ("__revert_foo", "/src/a.h"), unfixed[0]
assert unfixed[1] == ("__revert_bar", "/src/a.h"), unfixed[1]

# Simulate fixing the first symbol
st.step_history = [
    {"decision": {"tool": "make_extra_patch_override", "args": {"symbol_name": "__revert_foo"}}},
]
unfixed2 = _iter_unfixed_undeclared_symbols_from_grouped(st)
assert len(unfixed2) == 1, f"expected 1 unfixed after fixing foo, got {unfixed2}"
assert unfixed2[0] == ("__revert_bar", "/src/a.h"), unfixed2[0]

# Simulate fixing all remaining eligible symbols
st.step_history.append(
    {"decision": {"tool": "make_extra_patch_override", "args": {"symbol_name": "__revert_bar"}}},
)
unfixed3 = _iter_unfixed_undeclared_symbols_from_grouped(st)
assert len(unfixed3) == 0, f"expected 0 unfixed after fixing all eligible symbols, got {unfixed3}"

print("OK")
PY

# After one generated patch, run OSS-Fuzz immediately (do not batch-fix additional grouped undeclared
# symbols via make_extra_patch_override before rebuilding).
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentConfig, AgentState, _run_langgraph  # noqa: E402
from artifacts import ArtifactStore  # noqa: E402
from models import ChatModel  # noqa: E402
from tools.runner import ToolObservation  # noqa: E402


class NoModel(ChatModel):
    def complete(self, messages):  # pragma: no cover - should not be called in this forced-build path
        raise AssertionError("Model should not be called.")


class Runner:
    def __init__(self):
        self.calls = []

    def call(self, tool, args):
        self.calls.append(tool)
        if tool == "ossfuzz_apply_patch_and_test":
            return ToolObservation(
                ok=True,
                tool=tool,
                args=args,
                output={"build_output": "ok\n", "check_build_output": "ok\n"},
                error=None,
            )
        return ToolObservation(ok=True, tool=tool, args=args, output={}, error=None)


with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(root)

    st = AgentState(
        build_log_path="-",
        patch_path=str(root / "bundle.patch2"),
        error_scope="patch",
        error_line="/src/a.c:1:1: error: use of undeclared identifier 'X'",
        snippet="",
        patch_generated=True,
        ossfuzz_test_attempted=False,
        ossfuzz_project="example",
        ossfuzz_commit="deadbeef",
        grouped_errors=[
            {"raw": "/src/a.c:2:1: error: use of undeclared identifier 'A'", "file": "/src/a.c"},
            {"raw": "/src/a.c:3:1: error: use of undeclared identifier 'B'", "file": "/src/a.c"},
        ],
        patch_override_paths=[str(root / "override.diff")],
    )

    cfg = AgentConfig(max_steps=3, tools_mode="fake", error_scope="patch")
    runner = Runner()
    final = _run_langgraph(NoModel(), runner, st, cfg, artifact_store=ArtifactStore(root, overwrite=False))

    assert final.get("type") == "final", final
    assert runner.calls, runner.calls
    assert runner.calls[0] == "ossfuzz_apply_patch_and_test", runner.calls
    assert "make_extra_patch_override" not in runner.calls, runner.calls

print("OK")
PY

# After stopping post-OSS-Fuzz (auto-loop disabled or loop-max hit), refresh the final error snapshot from
# the latest OSS-Fuzz logs so "Build error" matches "Current function groups".
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import os
import pickle
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import AgentConfig, AgentState, ToolObservation, _run_langgraph  # noqa: E402
from models import ChatModel  # noqa: E402
from migration_tools.types import PatchInfo  # noqa: E402


class NoModel(ChatModel):
    def complete(self, messages):
        raise AssertionError("Model should not be called in this scenario.")


class NoRunner:
    def call(self, tool, args):  # pragma: no cover
        raise AssertionError("No tool calls expected.")


def fake_gepb(bundle, *, patch_path, file_path, line_number, **_kw):
    return {"patch_key": "p", "old_signature": "int f(void)"}


with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(root)

    import migration_tools.tools as mt  # noqa: E402

    mt._get_error_patch_from_bundle = fake_gepb

    bundle_path = root / "bundle.pkl"
    bundle_path.write_bytes(
        pickle.dumps(
            {
                "p": PatchInfo(
                    file_path_old="a.c",
                    file_path_new="a.c",
                    patch_text="diff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -1,1 +1,1 @@\n-old\n+new\n",
                    file_type="source",
                    old_start_line=1,
                    old_end_line=1,
                    new_start_line=1,
                    new_end_line=1,
                )
            }
        )
    )

    build_log = root / "build.log"
    build_log.write_text("/src/a.c:10:1: error: e_new\n", encoding="utf-8")

    st = AgentState(
        build_log_path="old.log",
        patch_path=str(bundle_path),
        error_scope="patch",
        error_line="/src/a.c:1:1: error: e_old",
        snippet="",
        artifacts_dir=str(root),
        patch_key="p",
        active_patch_key="p",
        active_old_signature="int f(void)",
        grouped_errors=[{"raw": "/src/a.c:1:1: error: e_old", "file": "/src/a.c", "line": 1, "col": 1, "msg": "e_old"}],
        target_errors=[{"patch_key": "p", "msg": "e_old"}],
    )
    st.patch_generated = True
    st.ossfuzz_test_attempted = True
    st.last_observation = ToolObservation(
        ok=True,
        tool="ossfuzz_apply_patch_and_test",
        args={},
        output={"build_output": {"artifact_path": str(build_log)}},
        error=None,
    )

    cfg = AgentConfig(max_steps=1, tools_mode="fake", error_scope="patch", auto_ossfuzz_loop=False)
    final = _run_langgraph(NoModel(), NoRunner(), st, cfg, artifact_store=None)
    assert final.get("type") == "final", final
    err_line = str((final.get("error") or {}).get("line") or "")
    assert "/src/a.c:10:1: error: e_new" in err_line, err_line

print("OK")
PY

# Text output: include a round header before each set of tool calls (shows which error is being handled).
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from agent_langgraph import _render_final_text  # noqa: E402

final = {
    "type": "final",
    "thought": "",
    "summary": "",
    "next_step": "",
    "error": {"line": "/src/a.c:1:1: error: e", "snippet": "", "scope": "patch", "patch_key": "p"},
    "steps": [
        {
            "context": {"error_line": "/src/a.c:1:1: error: e1", "active_patch_key": "p", "active_old_signature": "int f(void)"},
            "decision": {"tool": "get_error_patch_context", "args": {"x": 1}, "thought": "t"},
            "observation": {"ok": True, "tool": "get_error_patch_context", "args": {"x": 1}, "output": {}, "error": None},
        },
        {
            "context": {"error_line": "/src/a.c:2:1: error: e2", "active_patch_key": "p", "active_old_signature": "int g(void)"},
            "decision": {"tool": "make_error_patch_override", "args": {"x": 2}, "thought": "t2"},
            "observation": {"ok": True, "tool": "make_error_patch_override", "args": {"x": 2}, "output": {}, "error": None},
        },
    ],
}

text = _render_final_text(final)
assert "Round 1" in text, text
assert "error: e1" in text, text
assert "Round 2" in text, text
assert "error: e2" in text, text
print("OK")
PY

# _extra_insert_block_semantic_id: skip comment lines when determining block type.
# A typedef block with a preceding comment like /* Forward declaration */ should
# still be classified as "typedef", not "text".
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from tools.ossfuzz_tools import _extra_insert_block_semantic_id, _is_comment_line  # noqa: E402

# Test _is_comment_line helper
assert _is_comment_line("// single line comment") is True
assert _is_comment_line("/* block comment */") is True
assert _is_comment_line("* continuation line in block comment") is True
assert _is_comment_line("   /* indented comment */") is True
assert _is_comment_line("   some text */") is True  # Multi-line comment end without leading /*
assert _is_comment_line("typedef int Foo;") is False
assert _is_comment_line("int x;") is False
assert _is_comment_line("") is False

# Test: typedef with preceding comment should be classified as "typedef"
block_with_comment = [
    "/* Forward declaration to satisfy references in this extra hunk. */",
    "typedef struct _xmlParserNsData xmlParserNsData;",
]
kind, name = _extra_insert_block_semantic_id(block_with_comment)
assert kind == "typedef", f"Expected 'typedef', got {kind!r}"
assert name == "xmlParserNsData", f"Expected 'xmlParserNsData', got {name!r}"

# Test: multi-line comment before typedef
block_multiline_comment = [
    "/*",
    " * Some documentation",
    " */",
    "typedef int MyInt;",
]
kind, name = _extra_insert_block_semantic_id(block_multiline_comment)
assert kind == "typedef", f"Expected 'typedef', got {kind!r}"
assert name == "MyInt", f"Expected 'MyInt', got {name!r}"

# Test: multi-line comment with continuation NOT starting with * (real-world case)
block_multiline_no_star = [
    "/* Forward declaration to satisfy references in this extra hunk. The full",
    "   definition lives in the core headers; don't modify shared public types. */",
    "typedef struct _xmlParserNsData xmlParserNsData;",
]
kind, name = _extra_insert_block_semantic_id(block_multiline_no_star)
assert kind == "typedef", f"Expected 'typedef', got {kind!r}"
assert name == "xmlParserNsData", f"Expected 'xmlParserNsData', got {name!r}"

# Test: comment before #define
block_comment_define = [
    "/* Max buffer size */",
    "#define MAX_BUF 1024",
]
kind, name = _extra_insert_block_semantic_id(block_comment_define)
assert kind == "define", f"Expected 'define', got {kind!r}"
assert name == "MAX_BUF", f"Expected 'MAX_BUF', got {name!r}"

# Test: comment before function prototype
block_comment_proto = [
    "/* Initialize the parser */",
    "void init_parser(int flags);",
]
kind, name = _extra_insert_block_semantic_id(block_comment_proto)
assert kind == "prototype", f"Expected 'prototype', got {kind!r}"
assert name == "init_parser", f"Expected 'init_parser', got {name!r}"

# Test: pure comment block should be "text"
block_only_comment = [
    "/* Just a comment */",
]
kind, name = _extra_insert_block_semantic_id(block_only_comment)
assert kind == "text", f"Expected 'text', got {kind!r}"

print("OK")
PY

# Test: iter_compiler_errors parses __revert_* undefined-internal warnings and maps to using TU.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from build_log import iter_compiler_errors  # noqa: E402

log = (
    "clang -Wall -c -o sam.o sam.c\n"
    "In file included from /src/htslib/sam.c:45:\n"
    "In file included from /src/htslib/cram/cram.h:46:\n"
    "/src/htslib/htslib/kstring.h:40:19: warning: function '__revert_deadbeef_ks_resize' has internal linkage but is not defined [-Wundefined-internal]\n"
    "   40 | static inline int __revert_deadbeef_ks_resize(kstring_t *s, size_t size);\n"
    "      |                   ^\n"
)
errs = iter_compiler_errors(log, snippet_lines=4)
assert len(errs) == 1, errs
err = errs[0]
assert err.get("level") == "warning", err
assert err.get("kind") == "undefined_internal", err
assert err.get("symbol") == "__revert_deadbeef_ks_resize", err
assert err.get("file") == "/src/htslib/sam.c", err
assert int(err.get("line") or 0) == 45, err

print("OK")
PY

# Test: iter_linker_errors parses linker undefined reference errors.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from build_log import iter_linker_errors  # noqa: E402

log = Path(script_dir / "fixtures" / "linker_undefined_reference.log").read_text(encoding="utf-8")
errs = iter_linker_errors(log, snippet_lines=2)

assert len(errs) == 2, f"Expected 2 linker errors, got {len(errs)}: {errs}"

# First error: defaultHandlers
err0 = errs[0]
assert err0.get("kind") == "linker", err0
assert "encoding.c" in err0.get("file", ""), err0
assert err0.get("symbol") == "defaultHandlers", err0
assert err0.get("function") == "__revert_e11519_xmlLookupCharEncodingHandler", err0
assert "undefined reference" in err0.get("msg", ""), err0

# Second error: xmlSaturatedAddSizeT
err1 = errs[1]
assert err1.get("kind") == "linker", err1
assert "parser.c" in err1.get("file", ""), err1
assert err1.get("symbol") == "xmlSaturatedAddSizeT", err1
assert err1.get("function") == "__revert_e11519_xmlSkipBlankChars", err1

print("OK")
PY

# Test: _error_type_priority returns correct priority for linker errors.
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from multi_agent import _error_type_priority  # noqa: E402

# Priority 0: unknown type name
err_unknown_type = {"msg": "unknown type name 'xmlChar'"}
assert _error_type_priority(err_unknown_type) == 0, f"Expected 0, got {_error_type_priority(err_unknown_type)}"

# Priority 1: implicit declaration of function
err_implicit = {"msg": "implicit declaration of function 'foo'"}
assert _error_type_priority(err_implicit) == 1, f"Expected 1, got {_error_type_priority(err_implicit)}"

# Priority 1: undeclared function
err_undeclared = {"msg": "call to undeclared function 'bar'"}
assert _error_type_priority(err_undeclared) == 1, f"Expected 1, got {_error_type_priority(err_undeclared)}"

# Priority 2: __revert_* undefined-internal warning
err_undef_internal = {
    "kind": "undefined_internal",
    "msg": "function '__revert_deadbeef_ks_resize' has internal linkage but is not defined [-Wundefined-internal]",
}
assert _error_type_priority(err_undef_internal) == 2, f"Expected 2, got {_error_type_priority(err_undef_internal)}"

# Priority 3: linker error by kind
err_linker_kind = {"kind": "linker", "msg": "undefined reference to `foo`"}
assert _error_type_priority(err_linker_kind) == 3, f"Expected 3, got {_error_type_priority(err_linker_kind)}"

# Priority 3: linker error by message content
err_linker_msg = {"msg": "undefined reference to `bar`"}
assert _error_type_priority(err_linker_msg) == 3, f"Expected 3, got {_error_type_priority(err_linker_msg)}"

# Priority 4: other errors
err_other = {"msg": "some other error"}
assert _error_type_priority(err_other) == 4, f"Expected 4, got {_error_type_priority(err_other)}"

print("OK")
PY

# ---------------------------------------------------------------------------
# Enum conflict detection: _extract_enum_constant_names
# ---------------------------------------------------------------------------
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from tools.extra_patch_tools import _extract_enum_constant_names

# Basic enum
code1 = """\
enum cram_block_method_int {
    BM_ERROR = -1,
    RAW     = 0,
    GZIP    = 1,
    BZIP2   = 2,
    LZMA    = 3,
    RANS    = 4,
    RANS0   = RANS,
    E_VARINT_UNSIGNED = 41, // Specialisation of EXTERNAL
    FQZ     = 7,
};
"""
names1 = _extract_enum_constant_names(code1)
assert "BM_ERROR" in names1, names1
assert "RAW" in names1, names1
assert "GZIP" in names1, names1
assert "RANS" in names1, names1
assert "RANS0" in names1, names1
assert "E_VARINT_UNSIGNED" in names1, names1
assert "FQZ" in names1, names1
assert "enum" not in names1, names1
assert "EXTERNAL" not in names1, names1

# Typedef enum
code2 = "typedef enum { A, B = 1, C } my_enum;"
names2 = _extract_enum_constant_names(code2)
assert names2 == ["A", "B", "C"], names2

# Empty enum
code3 = "enum empty {};"
names3 = _extract_enum_constant_names(code3)
assert names3 == [], names3

print("OK")
PY

# ---------------------------------------------------------------------------
# Enum conflict detection: _prefix_enum_source
# ---------------------------------------------------------------------------
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from tools.extra_patch_tools import _prefix_enum_source

code = """\
enum test {
    FOO = 0,
    BAR = 1,
    BAZ = FOO,
};
"""
names = ["FOO", "BAR", "BAZ"]
result, rename_map = _prefix_enum_source(code, names, "_revert_")
assert rename_map == {"FOO": "_revert_FOO", "BAR": "_revert_BAR", "BAZ": "_revert_BAZ"}, rename_map
assert "_revert_FOO" in result, result
assert "_revert_BAR" in result, result
assert "_revert_BAZ = _revert_FOO" in result, result
# Original names should not appear (except inside the prefix)
for line in result.splitlines():
    stripped = line.strip()
    if not stripped or stripped.startswith("enum") or stripped.startswith("}"):
        continue
    # After removing all _revert_ prefixed names, original names shouldn't remain
    import re
    cleaned = re.sub(r"_revert_\w+", "", stripped)
    for n in names:
        assert n not in cleaned, f"{n!r} found in cleaned line: {stripped!r}"

print("OK")
PY

# ---------------------------------------------------------------------------
# Enum conflict detection: _apply_rename_map_to_minus_lines
# ---------------------------------------------------------------------------
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from tools.extra_patch_tools import _apply_rename_map_to_minus_lines

rename_map = {"FOO": "_revert_FOO", "BAR": "_revert_BAR"}
patch_text = (
    "diff --git a/test.c b/test.c\n"
    "--- a/test.c\n"
    "+++ b/test.c\n"
    "@@ -10,5 +10,0 @@\n"
    "-  if (x == FOO) {\n"
    "-    return BAR;\n"
    " /* context line with FOO */\n"
    "+added line with FOO\n"
)
result = _apply_rename_map_to_minus_lines(patch_text, rename_map)
lines = result.splitlines()
# '-' lines should be renamed
assert "-  if (x == _revert_FOO) {" in lines, lines
assert "-    return _revert_BAR;" in lines, lines
# context and '+' lines should NOT be renamed
assert " /* context line with FOO */" in lines, lines
assert "+added line with FOO" in lines, lines

# Empty rename map should return original
assert _apply_rename_map_to_minus_lines(patch_text, {}) == patch_text

print("OK")
PY

# ---------------------------------------------------------------------------
# Enum conflict detection: _check_v2_enum_conflict with mock KB
# ---------------------------------------------------------------------------
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from tools.extra_patch_tools import _check_v2_enum_conflict

class MockKb:
    def __init__(self, v2_nodes):
        self._v2 = v2_nodes
    def query_all(self, name):
        return {"v2": self._v2.get(name, [])}

# V2 has BM_ERROR and RAW as ENUM_CONSTANT_DECL, but not FQZ
kb = MockKb({
    "BM_ERROR": [{"kind": "ENUM_CONSTANT_DECL"}],
    "RAW": [{"kind": "ENUM_CONSTANT_DECL"}],
    "GZIP": [{"kind": "VAR_DECL"}],  # Different kind, should not conflict
})

conflicts = _check_v2_enum_conflict(kb, ["BM_ERROR", "RAW", "GZIP", "FQZ"])
assert "BM_ERROR" in conflicts, conflicts
assert "RAW" in conflicts, conflicts
assert "GZIP" not in conflicts, conflicts
assert "FQZ" not in conflicts, conflicts

# No KB should return empty
assert _check_v2_enum_conflict(None, ["FOO"]) == set()

print("OK")
PY

# ---------------------------------------------------------------------------
# Enum conflict detection: _rename_enum_refs_in_bundle
# ---------------------------------------------------------------------------
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys, pickle, os, tempfile
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from migration_tools.types import PatchInfo
from tools.extra_patch_tools import _rename_enum_refs_in_bundle

main_patch_text = (
    "diff --git a/cram_io.c b/cram_io.c\n"
    "--- a/cram_io.c\n"
    "+++ b/cram_io.c\n"
    "@@ -100,5 +100,0 @@\n"
    "-  if (method == GZIP) {\n"
    "-    return RAW;\n"
    " /* context */\n"
)
extra_patch_text = (
    "diff --git a/cram_io.c b/cram_io.c\n"
    "--- a/cram_io.c\n"
    "+++ b/cram_io.c\n"
    "@@ -1,1 +1,0 @@\n"
    "-/* extra */\n"
)

class FakeBundle:
    def __init__(self, patches):
        self.patches = patches

main_patch = PatchInfo(
    file_path_old="cram_io.c", file_path_new="cram_io.c",
    patch_text=main_patch_text, file_type="c",
    old_start_line=100, old_end_line=105,
    new_start_line=100, new_end_line=100,
    patch_type=set(), old_signature="",
    dependent_func=set(), hiden_func_dict={},
)
extra_patch = PatchInfo(
    file_path_old="cram_io.c", file_path_new="cram_io.c",
    patch_text=extra_patch_text, file_type="c",
    old_start_line=1, old_end_line=2,
    new_start_line=1, new_end_line=1,
    patch_type=set(), old_signature="",
    dependent_func=set(), hiden_func_dict={},
)

bundle = FakeBundle({
    "tail-cram_io.c-f1_": main_patch,
    "_extra_cram_io.c": extra_patch,
})

rename_map = {"GZIP": "_revert_GZIP", "RAW": "_revert_RAW"}
overrides = _rename_enum_refs_in_bundle(bundle, "cram_io.c", rename_map)

# Should produce exactly one override for the main (non-extra) hunk
assert len(overrides) == 1, overrides
assert overrides[0]["patch_key"] == "tail-cram_io.c-f1_", overrides
modified = overrides[0]["patch_text"]
assert "_revert_GZIP" in modified, modified
assert "_revert_RAW" in modified, modified
# Context line should be untouched
assert " /* context */" in modified, modified

# Extra hunk should be skipped
assert not any(o["patch_key"].startswith("_extra_") for o in overrides), overrides

print("OK")
PY

# ---------------------------------------------------------------------------
# Enum conflict detection: end-to-end make_extra_patch_override with conflicting enum
# ---------------------------------------------------------------------------
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import json, os, pickle, sys, tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from core.kb_index import KbIndex
from core.source_manager import SourceManager
from migration_tools.types import PatchInfo
from tools.extra_patch_tools import make_extra_patch_override
from tools.symbol_tools import AgentTools

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(td)
    os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(td / "artifacts")

    # Set up KB and sources
    kb_v1 = td / "kb_v1"
    kb_v2 = td / "kb_v2"
    kb_v1.mkdir()
    kb_v2.mkdir()
    v1_src = td / "v1_src"
    v2_src = td / "v2_src"
    v1_src.mkdir()
    v2_src.mkdir()

    # V1 enum code
    v1_enum_code = (
        "enum cram_block_method_int {\n"
        "    BM_ERROR = -1,\n"
        "    RAW     = 0,\n"
        "    GZIP    = 1,\n"
        "    FQZ     = 7,\n"
        "};\n"
    )
    (v1_src / "cram_io.c").write_text(v1_enum_code + "\nint dummy(void) { return 0; }\n", encoding="utf-8")
    (v2_src / "cram_io.c").write_text("/* v2 */\nint dummy(void) { return 0; }\n", encoding="utf-8")

    # V1 KB: ENUM_DECL for cram_block_method_int
    v1_node = {
        "kind": "ENUM_DECL",
        "spelling": "cram_block_method_int",
        "usr": "c:@E@cram_block_method_int",
        "location": {"file": "cram_io.c", "line": 1, "column": 1},
        "extent": {"start": {"file": "cram_io.c", "line": 1, "column": 1},
                    "end": {"file": "cram_io.c", "line": 6, "column": 2}},
    }
    (kb_v1 / "cram_io_analysis.json").write_text(json.dumps([v1_node]), encoding="utf-8")

    # V2 KB: ENUM_CONSTANT_DECL nodes for conflicting names
    v2_nodes = [
        {"kind": "ENUM_CONSTANT_DECL", "spelling": "BM_ERROR",
         "usr": "c:@E@cram_block_method@BM_ERROR",
         "location": {"file": "cram_io.c", "line": 5, "column": 5},
         "extent": {"start": {"file": "cram_io.c", "line": 5, "column": 5},
                    "end": {"file": "cram_io.c", "line": 5, "column": 15}}},
        {"kind": "ENUM_CONSTANT_DECL", "spelling": "RAW",
         "usr": "c:@E@cram_block_method@RAW",
         "location": {"file": "cram_io.c", "line": 6, "column": 5},
         "extent": {"start": {"file": "cram_io.c", "line": 6, "column": 5},
                    "end": {"file": "cram_io.c", "line": 6, "column": 8}}},
    ]
    (kb_v2 / "cram_io_analysis.json").write_text(json.dumps(v2_nodes), encoding="utf-8")

    # Build the KB and SourceManager
    kb_index = KbIndex(str(kb_v1), str(kb_v2))
    sm = SourceManager(str(v1_src), str(v2_src))
    agent_tools = AgentTools(kb_index=kb_index, source_manager=sm)

    # Create bundle with a main hunk that references conflicting enum values
    main_patch_text = (
        "diff --git a/cram_io.c b/cram_io.c\n"
        "--- a/cram_io.c\n"
        "+++ b/cram_io.c\n"
        "@@ -10,4 +10,0 @@\n"
        "-  if (method == RAW) {\n"
        "-    return BM_ERROR;\n"
        "-  }\n"
        "-  return GZIP;\n"
    )
    extra_patch_text = (
        "diff --git a/cram_io.c b/cram_io.c\n"
        "--- a/cram_io.c\n"
        "+++ b/cram_io.c\n"
        "@@ -2,1 +2,1 @@\n"
        " int dummy(void) { return 0; }\n"
    )

    main_patch = PatchInfo(
        file_path_old="cram_io.c", file_path_new="cram_io.c",
        patch_text=main_patch_text, file_type="c",
        old_start_line=10, old_end_line=14,
        new_start_line=10, new_end_line=10,
        patch_type=set(), old_signature="",
        dependent_func=set(), hiden_func_dict={},
    )
    extra_patch = PatchInfo(
        file_path_old="cram_io.c", file_path_new="cram_io.c",
        patch_text=extra_patch_text, file_type="c",
        old_start_line=2, old_end_line=2,
        new_start_line=2, new_end_line=2,
        patch_type={"Extra"}, old_signature="",
        dependent_func=set(), hiden_func_dict={},
    )

    bundle_path = td / "bundle.patch2"
    bundle_path.write_bytes(pickle.dumps({
        "tail-cram_io.c-f1_": main_patch,
        "_extra_cram_io.c": extra_patch,
    }, protocol=pickle.HIGHEST_PROTOCOL))

    out = make_extra_patch_override(
        agent_tools,
        patch_path=str(bundle_path),
        file_path="/src/htslib/cram_io.c",
        symbol_name="cram_block_method_int",
        version="v1",
    )

    # Check that the extra hunk has only conflicting enum names prefixed
    ref = out.get("patch_text")
    assert isinstance(ref, dict) and ref.get("artifact_path"), f"Missing patch_text artifact: {out}"
    p = Path(str(ref.get("artifact_path"))).resolve()
    text = p.read_text(encoding="utf-8", errors="replace")
    assert "_revert_BM_ERROR" in text, f"Expected prefixed BM_ERROR in extra hunk:\n{text}"
    assert "_revert_RAW" in text, f"Expected prefixed RAW in extra hunk:\n{text}"
    assert "_revert_GZIP" not in text, f"Did not expect prefixed GZIP in extra hunk:\n{text}"
    assert "_revert_FQZ" not in text, f"Did not expect prefixed FQZ in extra hunk:\n{text}"

    # Tool returns enum_rename_overrides as inline text (no artifact files for other hunks).
    # Agent filters to active patch_key only at apply time.
    overrides = out.get("enum_rename_overrides") or []
    assert len(overrides) >= 1, f"Expected at least one enum_rename_override: {out}"
    ov = overrides[0]
    assert ov.get("patch_key") == "tail-cram_io.c-f1_", ov
    ov_text = ov.get("patch_text", "")
    assert isinstance(ov_text, str), f"Expected inline text, got: {type(ov_text)}"
    assert "_revert_RAW" in ov_text, f"Expected prefixed RAW in main hunk override:\n{ov_text}"
    assert "_revert_BM_ERROR" in ov_text, f"Expected prefixed BM_ERROR in main hunk override:\n{ov_text}"
    assert "_revert_GZIP" not in ov_text, f"Did not expect prefixed GZIP in main hunk override:\n{ov_text}"

print("OK")
PY

# ---------------------------------------------------------------------------
# Enum tag rename: _extract_enum_tag_from_code and _check_v2_enum_tag_conflict
# ---------------------------------------------------------------------------
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from tools.extra_patch_tools import _extract_enum_tag_from_code, _check_v2_enum_tag_conflict

# Named enum
assert _extract_enum_tag_from_code("enum htsExactFormat { a, b }") == "htsExactFormat"
assert _extract_enum_tag_from_code("typedef enum cram_block_method { X }") == "cram_block_method"
# Anonymous enum
assert _extract_enum_tag_from_code("enum { A, B }") == ""
assert _extract_enum_tag_from_code("typedef enum { X, Y } mytype;") == ""
# Empty
assert _extract_enum_tag_from_code("") == ""

# _check_v2_enum_tag_conflict with mock KB
class MockKB:
    def __init__(self, data):
        self._data = data
    def query_all(self, name):
        return self._data.get(name, {})

kb = MockKB({
    "htsExactFormat": {"v2": [{"kind": "ENUM_DECL", "spelling": "htsExactFormat"}]},
    "otherEnum": {"v2": [{"kind": "STRUCT_DECL", "spelling": "otherEnum"}]},
})
assert _check_v2_enum_tag_conflict(kb, "htsExactFormat") is True
assert _check_v2_enum_tag_conflict(kb, "otherEnum") is False
assert _check_v2_enum_tag_conflict(kb, "nonexistent") is False
assert _check_v2_enum_tag_conflict(None, "foo") is False
assert _check_v2_enum_tag_conflict(kb, "") is False

print("OK")
PY

# ---------------------------------------------------------------------------
# Enum tag rename: _prefix_enum_source with tag_rename_map
# ---------------------------------------------------------------------------
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from tools.extra_patch_tools import _prefix_enum_source

code = "enum htsExactFormat {\n    unknown_format = 0,\n    bam = 1,\n};\n"

# Rename both constants and tag
result, rmap = _prefix_enum_source(
    code, ["unknown_format"], "_revert_",
    tag_rename_map={"htsExactFormat": "_revert_htsExactFormat"},
)
assert "_revert_unknown_format" in result, result
assert "_revert_htsExactFormat" in result, result
assert "htsExactFormat" not in result.replace("_revert_htsExactFormat", ""), result
assert rmap["unknown_format"] == "_revert_unknown_format"
assert rmap["htsExactFormat"] == "_revert_htsExactFormat"

# Tag-only rename (no constant conflicts)
result2, rmap2 = _prefix_enum_source(
    code, [], "_revert_",
    tag_rename_map={"htsExactFormat": "_revert_htsExactFormat"},
)
assert "_revert_htsExactFormat" in result2, result2
assert "unknown_format" in result2 and "_revert_unknown_format" not in result2, result2
assert rmap2 == {"htsExactFormat": "_revert_htsExactFormat"}

# No tag rename (existing behavior)
result3, rmap3 = _prefix_enum_source(code, ["unknown_format"], "_revert_")
assert "_revert_unknown_format" in result3, result3
assert "enum htsExactFormat" in result3, result3  # tag unchanged
assert "htsExactFormat" not in rmap3  # tag not in rename map

print("OK")
PY

# ---------------------------------------------------------------------------
# Enum tag rename: _rename_conflicting_enum_constants_in_extra_hunk with tag
# ---------------------------------------------------------------------------
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from tools.extra_patch_tools import _rename_conflicting_enum_constants_in_extra_hunk

class MockKB:
    def __init__(self, data):
        self._data = data
    def query_all(self, name):
        return self._data.get(name, {})

# V2 has both the tag and some constants
kb = MockKB({
    "htsExactFormat": {"v2": [{"kind": "ENUM_DECL", "spelling": "htsExactFormat"}]},
    "unknown_format": {"v2": [{"kind": "ENUM_CONSTANT_DECL", "spelling": "unknown_format"}]},
})

patch_text = (
    "diff --git a/hts.c b/hts.c\n"
    "--- a/hts.c\n"
    "+++ b/hts.c\n"
    "@@ -10,5 +10,0 @@\n"
    "-enum htsExactFormat {\n"
    "-    unknown_format = 0,\n"
    "-    bam = 1,\n"
    "-    sam = 2,\n"
    "-};\n"
)

result, rmap = _rename_conflicting_enum_constants_in_extra_hunk(
    patch_text, kb_index=kb, enum_tag="htsExactFormat", prefix="_revert_",
)

# Both tag and constant should be renamed
assert "_revert_htsExactFormat" in result, f"Tag not renamed:\n{result}"
assert "_revert_unknown_format" in result, f"Constant not renamed:\n{result}"
assert "htsExactFormat" in rmap, f"Tag missing from rename_map: {rmap}"
assert "unknown_format" in rmap, f"Constant missing from rename_map: {rmap}"
# Non-conflicting constants should be untouched
assert "bam" in result and "_revert_bam" not in result, result
assert "sam" in result and "_revert_sam" not in result, result

print("OK")
PY

# ---------------------------------------------------------------------------
# Enum tag rename: tag-only conflict (no constant conflicts)
# ---------------------------------------------------------------------------
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from tools.extra_patch_tools import _rename_conflicting_enum_constants_in_extra_hunk

class MockKB:
    def __init__(self, data):
        self._data = data
    def query_all(self, name):
        return self._data.get(name, {})

# V2 has the tag but none of the constants
kb = MockKB({
    "htsExactFormat": {"v2": [{"kind": "ENUM_DECL", "spelling": "htsExactFormat"}]},
})

patch_text = (
    "diff --git a/hts.c b/hts.c\n"
    "--- a/hts.c\n"
    "+++ b/hts.c\n"
    "@@ -10,4 +10,0 @@\n"
    "-enum htsExactFormat {\n"
    "-    val_a = 0,\n"
    "-    val_b = 1,\n"
    "-};\n"
)

result, rmap = _rename_conflicting_enum_constants_in_extra_hunk(
    patch_text, kb_index=kb, enum_tag="htsExactFormat", prefix="_revert_",
)

# Tag should be renamed, constants should NOT (no constant conflicts)
assert "_revert_htsExactFormat" in result, f"Tag not renamed:\n{result}"
assert "val_a" in result and "_revert_val_a" not in result, f"val_a incorrectly renamed:\n{result}"
assert "val_b" in result and "_revert_val_b" not in result, f"val_b incorrectly renamed:\n{result}"
assert rmap == {"htsExactFormat": "_revert_htsExactFormat"}, f"Unexpected rename_map: {rmap}"

print("OK")
PY

# ---------------------------------------------------------------------------
# Enum tag rename: end-to-end make_extra_patch_override with tag conflict
# ---------------------------------------------------------------------------
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import json, os, pickle, sys, tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from core.kb_index import KbIndex
from core.source_manager import SourceManager
from migration_tools.types import PatchInfo
from tools.extra_patch_tools import make_extra_patch_override
from tools.symbol_tools import AgentTools

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    os.environ["REACT_AGENT_PATCH_ALLOWED_ROOTS"] = str(td)
    os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(td / "artifacts")

    kb_v1 = td / "kb_v1"; kb_v1.mkdir()
    kb_v2 = td / "kb_v2"; kb_v2.mkdir()
    v1_src = td / "v1_src"; v1_src.mkdir()
    v2_src = td / "v2_src"; v2_src.mkdir()

    # V1 enum code
    v1_code = (
        "enum htsExactFormat {\n"
        "    unknown_format = 0,\n"
        "    bam = 1,\n"
        "    sam = 2,\n"
        "};\n"
    )
    (v1_src / "hts.c").write_text(v1_code + "\nint dummy(void) { return 0; }\n", encoding="utf-8")
    (v2_src / "hts.c").write_text("/* v2 */\nint dummy(void) { return 0; }\n", encoding="utf-8")

    # V1 KB: ENUM_DECL
    v1_node = {
        "kind": "ENUM_DECL",
        "spelling": "htsExactFormat",
        "usr": "c:@E@htsExactFormat",
        "location": {"file": "hts.c", "line": 1, "column": 1},
        "extent": {"start": {"file": "hts.c", "line": 1, "column": 1},
                    "end": {"file": "hts.c", "line": 5, "column": 2}},
    }
    (kb_v1 / "hts_analysis.json").write_text(json.dumps([v1_node]), encoding="utf-8")

    # V2 KB: ENUM_DECL for the tag + ENUM_CONSTANT_DECL for unknown_format
    v2_nodes = [
        {"kind": "ENUM_DECL", "spelling": "htsExactFormat",
         "usr": "c:@E@htsExactFormat",
         "location": {"file": "hts.c", "line": 5, "column": 1},
         "extent": {"start": {"file": "hts.c", "line": 5, "column": 1},
                    "end": {"file": "hts.c", "line": 10, "column": 2}}},
        {"kind": "ENUM_CONSTANT_DECL", "spelling": "unknown_format",
         "usr": "c:@E@htsExactFormat@unknown_format",
         "location": {"file": "hts.c", "line": 6, "column": 5},
         "extent": {"start": {"file": "hts.c", "line": 6, "column": 5},
                    "end": {"file": "hts.c", "line": 6, "column": 19}}},
    ]
    (kb_v2 / "hts_analysis.json").write_text(json.dumps(v2_nodes), encoding="utf-8")

    kb_index = KbIndex(str(kb_v1), str(kb_v2))
    sm = SourceManager(str(v1_src), str(v2_src))
    agent_tools = AgentTools(kb_index=kb_index, source_manager=sm)

    # Create bundle with a main hunk that references enum tag and constants
    main_patch_text = (
        "diff --git a/hts.c b/hts.c\n"
        "--- a/hts.c\n"
        "+++ b/hts.c\n"
        "@@ -20,3 +20,0 @@\n"
        "-  enum htsExactFormat fmt = unknown_format;\n"
        "-  if (fmt == bam) return 1;\n"
        "-  return 0;\n"
    )
    extra_patch_text = (
        "diff --git a/hts.c b/hts.c\n"
        "--- a/hts.c\n"
        "+++ b/hts.c\n"
        "@@ -2,1 +2,1 @@\n"
        " int dummy(void) { return 0; }\n"
    )

    main_patch = PatchInfo(
        file_path_old="hts.c", file_path_new="hts.c",
        patch_text=main_patch_text, file_type="c",
        old_start_line=20, old_end_line=23,
        new_start_line=20, new_end_line=20,
        patch_type=set(), old_signature="",
        dependent_func=set(), hiden_func_dict={},
    )
    extra_patch = PatchInfo(
        file_path_old="hts.c", file_path_new="hts.c",
        patch_text=extra_patch_text, file_type="c",
        old_start_line=2, old_end_line=2,
        new_start_line=2, new_end_line=2,
        patch_type={"Extra"}, old_signature="",
        dependent_func=set(), hiden_func_dict={},
    )

    bundle_path = td / "bundle.patch2"
    bundle_path.write_bytes(pickle.dumps({
        "tail-hts.c-f1_": main_patch,
        "_extra_hts.c": extra_patch,
    }, protocol=pickle.HIGHEST_PROTOCOL))

    out = make_extra_patch_override(
        agent_tools,
        patch_path=str(bundle_path),
        file_path="/src/htslib/hts.c",
        symbol_name="enum htsExactFormat",
        version="v1",
    )

    ref = out.get("patch_text")
    assert isinstance(ref, dict) and ref.get("artifact_path"), f"Missing patch_text artifact: {out}"
    p = Path(str(ref.get("artifact_path"))).resolve()
    text = p.read_text(encoding="utf-8", errors="replace")

    # Enum tag should be renamed
    assert "_revert_htsExactFormat" in text, f"Tag not renamed in extra hunk:\n{text}"
    # Conflicting constant should be renamed
    assert "_revert_unknown_format" in text, f"Constant not renamed in extra hunk:\n{text}"
    # Non-conflicting constants should be untouched
    assert "bam" in text and "_revert_bam" not in text, f"bam incorrectly renamed:\n{text}"

    # Check enum rename overrides propagated to main hunk
    overrides = out.get("enum_rename_overrides") or []
    assert len(overrides) >= 1, f"Expected enum_rename_overrides: {out}"
    ov = overrides[0]
    ov_text = ov.get("patch_text", "")
    # Main hunk references "enum htsExactFormat" and "unknown_format" in - lines
    assert "_revert_htsExactFormat" in ov_text, f"Tag not renamed in main hunk:\n{ov_text}"
    assert "_revert_unknown_format" in ov_text, f"Constant not renamed in main hunk:\n{ov_text}"

print("OK")
PY

# ---------------------------------------------------------------------------
# Multi-anchor _extra_* merge: _extract_override_anchor and multi-hunk output
# ---------------------------------------------------------------------------
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from tools.ossfuzz_tools import (
    _extract_override_anchor,
    _merge_extra_hunk_override_texts,
)

# --- _extract_override_anchor ---
assert _extract_override_anchor(
    "diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n@@ -97,5 +97,3 @@\n-foo\n ctx\n"
) == 97
assert _extract_override_anchor(
    "diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n@@ -847,6 +847,3 @@\n-bar\n ctx\n"
) == 847
assert _extract_override_anchor("no hunk header at all") == 0

# --- Multi-anchor merge produces two hunks ---
ovr_97 = (
    "diff --git a/f.c b/f.c\n"
    "--- a/f.c\n"
    "+++ b/f.c\n"
    "@@ -97,4 +97,3 @@\n"
    "-#define MYMACRO 42\n"
    " void first_func(void)\n"
    " {\n"
)
ovr_847 = (
    "diff --git a/f.c b/f.c\n"
    "--- a/f.c\n"
    "+++ b/f.c\n"
    "@@ -847,4 +847,3 @@\n"
    "-void helper(int x);\n"
    " int later_func(void)\n"
    " {\n"
)

merged = _merge_extra_hunk_override_texts(base_text="", override_texts=[ovr_97, ovr_847])

# Should have two @@ hunks
hunk_count = merged.count("@@ -")
assert hunk_count == 2, f"Expected 2 hunks, got {hunk_count}:\n{merged}"

# Both blocks should be present
assert "#define MYMACRO 42" in merged, f"Missing macro in merged:\n{merged}"
assert "void helper(int x);" in merged, f"Missing prototype in merged:\n{merged}"

# First hunk should be at line 97, second at 847
lines = merged.splitlines()
hunk_lines = [l for l in lines if l.startswith("@@ -")]
assert "97" in hunk_lines[0], f"First hunk not at 97: {hunk_lines[0]}"
assert "847" in hunk_lines[1], f"Second hunk not at 847: {hunk_lines[1]}"

# Only one diff --git header
assert merged.count("diff --git") == 1, f"Expected 1 diff header:\n{merged}"

# --- Same-anchor merge still produces one hunk (no regression) ---
ovr_97b = (
    "diff --git a/f.c b/f.c\n"
    "--- a/f.c\n"
    "+++ b/f.c\n"
    "@@ -97,4 +97,3 @@\n"
    "-int other_func(void);\n"
    " void first_func(void)\n"
    " {\n"
)

merged_same = _merge_extra_hunk_override_texts(base_text="", override_texts=[ovr_97, ovr_97b])
hunk_count_same = merged_same.count("@@ -")
assert hunk_count_same == 1, f"Expected 1 hunk for same anchor, got {hunk_count_same}:\n{merged_same}"
assert "#define MYMACRO 42" in merged_same, f"Missing macro:\n{merged_same}"
assert "int other_func(void);" in merged_same, f"Missing prototype:\n{merged_same}"

print("OK")
PY

# ---------------------------------------------------------------------------
# Cross-anchor dedup: identical enum at two anchors → keep only topmost
# ---------------------------------------------------------------------------
echo "  - cross-anchor dedup (identical enum)"
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from tools.ossfuzz_tools import _merge_extra_hunk_override_texts

# Two overrides: identical enum at line 61 and line 556
ovr_61 = (
    "diff --git a/hts.c b/hts.c\n"
    "--- a/hts.c\n"
    "+++ b/hts.c\n"
    "@@ -61,14 +61,3 @@\n"
    "-\n"
    "-enum _revert_htsExactFormat {\n"
    "-    _revert_unknown_format,\n"
    "-    _revert_sam, _revert_bam, _revert_vcf,\n"
    "-    _revert_htsget,\n"
    "-    _revert_empty_format,\n"
    "-    _revert_hts_crypt4gh_format,\n"
    "-    _revert_format_maximum = 32767\n"
    "-};\n"
    "-#define HTS_VERSION_TEXT \"1.0\"\n"
    "-\n"
    " KHASH_INIT2(s2i,, kh_cstr_t, int64_t, 1, kh_str_hash_func, kh_str_hash_equal)\n"
    " \n"
    " int hts_verbose = HTS_LOG_WARNING;\n"
)

ovr_556 = (
    "diff --git a/hts.c b/hts.c\n"
    "--- a/hts.c\n"
    "+++ b/hts.c\n"
    "@@ -556,13 +556,3 @@\n"
    "-\n"
    "-enum _revert_htsExactFormat {\n"
    "-    _revert_unknown_format,\n"
    "-    _revert_sam, _revert_bam, _revert_vcf,\n"
    "-    _revert_htsget,\n"
    "-    _revert_empty_format,\n"
    "-    _revert_hts_crypt4gh_format,\n"
    "-    _revert_format_maximum = 32767\n"
    "-};\n"
    "-htsFile *hts_hopen(hFILE *hfile, const char *fn, const char *mode);\n"
    " \n"
    " htsFile *hts_open_format(const char *fn, const char *mode, const htsFormat *fmt)\n"
    " {\n"
)

merged = _merge_extra_hunk_override_texts(base_text="", override_texts=[ovr_61, ovr_556])

# Enum should appear only ONCE in merged output
enum_count = merged.count("enum _revert_htsExactFormat")
assert enum_count == 1, f"Expected enum once, got {enum_count} times:\n{merged}"

# Enum should be at the topmost anchor (line 61), not at 556
lines = merged.splitlines()
hunk_lines = [l for l in lines if l.startswith("@@ -")]
first_hunk = hunk_lines[0] if hunk_lines else ""
assert "61" in first_hunk, f"Enum should be in first hunk (line 61): {first_hunk}"
# Find which hunk contains the enum
enum_hunk_idx = None
current_hunk = -1
for l in lines:
    if l.startswith("@@ -"):
        current_hunk += 1
    if "enum _revert_htsExactFormat" in l:
        enum_hunk_idx = current_hunk
        break
assert enum_hunk_idx == 0, f"Enum should be in hunk 0, found in hunk {enum_hunk_idx}"

# HTS_VERSION_TEXT should still be present (it's unique to line-61 hunk)
assert "HTS_VERSION_TEXT" in merged, f"Missing HTS_VERSION_TEXT:\n{merged}"

# hts_hopen prototype should still be present (it's unique to line-556 hunk)
assert "hts_hopen" in merged, f"Missing hts_hopen prototype:\n{merged}"

# There should still be a second hunk at line 556 (for the prototype)
assert len(hunk_lines) == 2, f"Expected 2 hunks, got {len(hunk_lines)}:\n{merged}"

print("OK")
PY

# ---------------------------------------------------------------------------
# Cross-anchor dedup: all blocks removed → hunk dropped
# ---------------------------------------------------------------------------
echo "  - cross-anchor dedup (hunk dropped when empty)"
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from tools.ossfuzz_tools import _merge_extra_hunk_override_texts

# Override at line 61: has the enum
ovr_61 = (
    "diff --git a/f.c b/f.c\n"
    "--- a/f.c\n"
    "+++ b/f.c\n"
    "@@ -61,7 +61,3 @@\n"
    "-\n"
    "-enum MyEnum { A, B, C };\n"
    "-#define FOO 1\n"
    "-\n"
    " void first_func(void)\n"
    " {\n"
    "     return;\n"
)

# Override at line 500: ONLY has the same enum (no other blocks)
ovr_500 = (
    "diff --git a/f.c b/f.c\n"
    "--- a/f.c\n"
    "+++ b/f.c\n"
    "@@ -500,5 +500,3 @@\n"
    "-\n"
    "-enum MyEnum { A, B, C };\n"
    " void second_func(void)\n"
    " {\n"
    "     return;\n"
)

merged = _merge_extra_hunk_override_texts(base_text="", override_texts=[ovr_61, ovr_500])

# Enum should appear only once
enum_count = merged.count("enum MyEnum")
assert enum_count == 1, f"Expected enum once, got {enum_count}:\n{merged}"

# The 500-anchor hunk should be dropped (it only had the enum)
hunk_lines = [l for l in merged.splitlines() if l.startswith("@@ -")]
assert len(hunk_lines) == 1, f"Expected 1 hunk (500-hunk dropped), got {len(hunk_lines)}:\n{merged}"
assert "61" in hunk_lines[0], f"Remaining hunk should be at 61: {hunk_lines[0]}"

# FOO define should still be present
assert "FOO" in merged, f"Missing #define FOO:\n{merged}"

print("OK")
PY

# ---------------------------------------------------------------------------
# Cross-anchor dedup: non-duplicate blocks preserved at different anchors
# ---------------------------------------------------------------------------
echo "  - cross-anchor dedup (non-duplicates preserved)"
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from tools.ossfuzz_tools import _merge_extra_hunk_override_texts

# Two anchors with completely different blocks → no dedup, both preserved
ovr_a = (
    "diff --git a/f.c b/f.c\n"
    "--- a/f.c\n"
    "+++ b/f.c\n"
    "@@ -100,4 +100,3 @@\n"
    "-#define MACRO_A 1\n"
    " void func_a(void)\n"
    " {\n"
    "     return;\n"
)

ovr_b = (
    "diff --git a/f.c b/f.c\n"
    "--- a/f.c\n"
    "+++ b/f.c\n"
    "@@ -800,4 +800,3 @@\n"
    "-void helper_b(int x);\n"
    " int func_b(void)\n"
    " {\n"
    "     return 0;\n"
)

merged = _merge_extra_hunk_override_texts(base_text="", override_texts=[ovr_a, ovr_b])

# Both blocks should be present
assert "MACRO_A" in merged, f"Missing MACRO_A:\n{merged}"
assert "helper_b" in merged, f"Missing helper_b:\n{merged}"

# Two hunks
hunk_lines = [l for l in merged.splitlines() if l.startswith("@@ -")]
assert len(hunk_lines) == 2, f"Expected 2 hunks, got {len(hunk_lines)}:\n{merged}"

print("OK")
PY

# ---------------------------------------------------------------------------
# Cross-anchor dedup: near-duplicate (best version kept at top)
# ---------------------------------------------------------------------------
echo "  - cross-anchor dedup (near-duplicate, best version at top)"
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from tools.ossfuzz_tools import _merge_extra_hunk_override_texts

# Topmost anchor has a shorter enum; lower anchor has a longer (more complete) version
ovr_short = (
    "diff --git a/f.c b/f.c\n"
    "--- a/f.c\n"
    "+++ b/f.c\n"
    "@@ -50,5 +50,3 @@\n"
    "-enum Fmt { A, B };\n"
    "-void func_x(void);\n"
    " void top_func(void)\n"
    " {\n"
    "     return;\n"
)

ovr_long = (
    "diff --git a/f.c b/f.c\n"
    "--- a/f.c\n"
    "+++ b/f.c\n"
    "@@ -300,5 +300,3 @@\n"
    "-enum Fmt { A, B, C, D };\n"
    "-void func_y(void);\n"
    " void bottom_func(void)\n"
    " {\n"
    "     return;\n"
)

merged = _merge_extra_hunk_override_texts(base_text="", override_texts=[ovr_short, ovr_long])

# Enum should appear only once
enum_count = merged.count("enum Fmt")
assert enum_count == 1, f"Expected enum once, got {enum_count}:\n{merged}"

# The longer version (A, B, C, D) should be kept (heuristic: prefer longer for tags)
assert "C, D" in merged, f"Expected longer enum version (with C, D):\n{merged}"

# Both unique prototypes should be present
assert "func_x" in merged, f"Missing func_x:\n{merged}"
assert "func_y" in merged, f"Missing func_y:\n{merged}"

print("OK")
PY

# ---------------------------------------------------------------------------
# build_errors.py: redefinition of enumerator pattern
# ---------------------------------------------------------------------------
"$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
from pathlib import Path
script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parents[0]))

from migration_tools.build_errors import parse_build_errors

log = """\
/src/htslib/cram/cram_io.c:42:5: error: redefinition of enumerator 'BM_ERROR'
/src/htslib/cram/cram_io.c:43:5: error: redefinition of enumerator 'RAW'
/src/htslib/cram/cram_io.c:80:10: error: duplicate case value
"""
result = parse_build_errors(log)
redefs = result.get("redefinition_enumerators", [])
assert len(redefs) == 2, redefs
assert redefs[0]["name"] == "BM_ERROR", redefs
assert redefs[1]["name"] == "RAW", redefs

dupes = result.get("duplicate_case_values", [])
assert len(dupes) == 1, dupes
assert dupes[0]["line"] == 80, dupes

print("OK")
PY

echo "OK"
