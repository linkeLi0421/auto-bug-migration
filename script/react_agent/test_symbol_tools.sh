#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

fixture_dir="$SCRIPT_DIR/fixtures/definition_bundle"
json_dir="$fixture_dir/json"
src_dir="$fixture_dir/src"

PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - "$SCRIPT_DIR" "$json_dir" "$src_dir" <<'PY'
import sys
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
json_dir = Path(sys.argv[2]).resolve()
src_dir = Path(sys.argv[3]).resolve()

sys.path.insert(0, str(script_dir))

from core.kb_index import KbIndex  # noqa: E402
from core.source_manager import SourceManager  # noqa: E402
from tools.symbol_tools import AgentTools  # noqa: E402

kb = KbIndex(str(json_dir), str(json_dir))
sm = SourceManager(str(src_dir), str(src_dir))
tools = AgentTools(kb, sm)

out = tools.search_definition("T", version="v2")
print(out)

assert "Primary match" in out, out
assert "include/a.h" in out, out
assert "include/b.h" in out, out
assert "Real definition" in out, out
assert "...[truncated" not in out, out
assert "field_130" in out, out
PY

echo "OK"
