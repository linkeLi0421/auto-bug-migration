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
    "read_file_context",
    "search_definition",
    "search_definition_in_v1",
    "list_patch_bundle",
    "get_patch",
    "search_patches",
    "get_error_patch",
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

echo "OK"
