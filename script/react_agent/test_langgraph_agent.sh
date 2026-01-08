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
    store, out_dir = resolve_artifact_dir(cli_dir="", disabled=False, patch_key="_extra_encoding.c")
    assert Path(out_dir).name == "_extra_encoding.c", out_dir

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
# agent_langgraph should force search_text("#define TOKEN") first.
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
assert forced and forced.get("tool") == "search_text", forced
assert "EMPTY_ICONV" in (forced.get("args") or {}).get("query", ""), forced
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
    "search_text",
    "list_patch_bundle",
    "get_patch",
    "search_patches",
    "get_error_patch_context",
    "get_error_v1_code_slice",
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
assert tools[1] == "get_error_v1_code_slice", tools
assert "v1" in versions and "v2" in versions, versions

# Patch generation is followed by mandatory OSS-Fuzz test; artifact reads only happen right before patch generation.
assert "make_error_patch_override" in tools, tools
idx_patch = tools.index("make_error_patch_override")
assert idx_patch > 0 and tools[idx_patch - 1] == "read_artifact", tools
assert "ossfuzz_apply_patch_and_test" in tools[idx_patch + 1 :], tools

if "search_text" in tools:
    first_search_text = tools.index("search_text")
    first_v2 = next(i for i, s in enumerate(steps) if (s.get("decision") or {}).get("tool") == "search_definition" and ((s.get("decision") or {}).get("args") or {}).get("version") == "v2")
    assert first_search_text > first_v2, tools
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

output="$(REACT_AGENT_PATCH_ALLOWED_ROOTS="$tmp_dir" REACT_AGENT_ARTIFACT_DIR="$artifact_dir" "$PYTHON" "$SCRIPT_DIR/agent_langgraph.py" \
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
os.environ["REACT_AGENT_ARTIFACT_DIR"] = str(artifact_dir)

from tools.artifact_tools import read_artifact  # noqa: E402

steps = obj.get("steps") or []
assert len(steps) >= 2, steps

tool = (steps[1].get("decision") or {}).get("tool")
assert tool == "get_error_patch_context", tool

obs = (steps[1].get("observation") or {}).get("output") or {}
excerpt = obs.get("excerpt")
assert isinstance(excerpt, dict) and excerpt.get("artifact_path"), excerpt
ap = Path(excerpt["artifact_path"]).resolve()
assert ap.is_file(), ap
assert artifact_dir in ap.parents, (artifact_dir, ap)

snippet = read_artifact(artifact_path=str(ap), start_line=1, max_lines=20)
assert snippet.get("text"), snippet

try:
    read_artifact(artifact_path=str(Path("/etc/hosts")), max_lines=5)
    raise AssertionError("expected allowlist failure")
except ValueError:
    pass
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

artifact_dir = (artifact_root / "p2").resolve()
artifact_dir.mkdir(parents=True, exist_ok=True)
os.environ["REACT_AGENT_ARTIFACT_DIR"] = str(artifact_dir)

from tools.ossfuzz_tools import merge_patch_bundle_with_overrides  # noqa: E402

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

from agent_langgraph import AgentState, ToolObservation, _summarize_target_error_status  # noqa: E402
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

    build_log.write_text(f"/src/libxml2/hash.c:554:52: error: {msg}\n", encoding="utf-8")
    verdict2 = _summarize_target_error_status(st)
    assert verdict2.get("status") == "ok", verdict2
    assert verdict2.get("fixed") is True, verdict2
PY

echo "OK"
