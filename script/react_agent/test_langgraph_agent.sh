#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

fixtures=(
  "$SCRIPT_DIR/fixtures/implicit_function.log"
  "$SCRIPT_DIR/fixtures/struct_missing_member.log"
  "$SCRIPT_DIR/fixtures/syntax_error.log"
)

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
    "inspect_symbol",
    "read_artifact",
    "read_file_context",
    "search_definition",
    "search_definition_in_v1",
    "search_text",
    "list_patch_bundle",
    "get_patch",
    "search_patches",
    "get_error_patch",
    "get_error_patch_context",
    "get_error_v1_function_code",
    "make_error_function_patch",
    "parse_build_errors",
}

for step in obj["steps"]:
    decision = step.get("decision") or {}
    tool = decision.get("tool")
    if tool is None:
        continue
    assert tool in allowed, (tool, step)

if fixture.endswith("implicit_function.log"):
    assert any((s.get("decision") or {}).get("tool") == "inspect_symbol" for s in obj["steps"]), obj
elif fixture.endswith("struct_missing_member.log"):
    assert any((s.get("decision") or {}).get("tool") == "inspect_symbol" for s in obj["steps"]), obj
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
  --model stub --tools fake --max-steps 6 --error-scope patch --patch-path "$bundle_path" \
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
assert tools[1] == "get_error_v1_function_code", tools
assert "v1" in versions and "v2" in versions, versions

# Patch generation must be last; artifact reads only happen right before it.
assert tools[-1] == "make_error_function_patch", tools
assert tools[-2] == "read_artifact", tools

if "search_text" in tools:
    first_search_text = tools.index("search_text")
    first_v2 = next(i for i, s in enumerate(steps) if (s.get("decision") or {}).get("tool") == "search_definition" and ((s.get("decision") or {}).get("args") or {}).get("version") == "v2")
    assert first_search_text > first_v2, tools
PY

# Guardrail: block suggestions to edit V2 type definitions by default.
output="$(REACT_AGENT_PATCH_ALLOWED_ROOTS="$tmp_dir" REACT_AGENT_STUB_SUGGEST_V2_TYPE_EDIT=1 "$PYTHON" "$SCRIPT_DIR/agent_langgraph.py" \
  --model stub --tools fake --max-steps 6 --error-scope patch --patch-path "$bundle_path" \
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
assert tools and tools[-1] == "make_error_function_patch", tools
PY

# Patch-aware runs: if read_file_context is used, it must use pre-patch line numbers.
output="$(REACT_AGENT_PATCH_ALLOWED_ROOTS="$tmp_dir" "$PYTHON" "$SCRIPT_DIR/agent_langgraph.py" \
  --model stub --tools fake --max-steps 4 --error-scope patch --patch-path "$bundle_path" \
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

echo "OK"
