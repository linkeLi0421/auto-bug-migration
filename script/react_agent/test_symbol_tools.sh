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

# Regression: ensure TYPE_REF typedef_extent candidates don't get deduped away (libxml2 _xmlHashTable case).
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - "$SCRIPT_DIR" <<'PY'
import sys
import tempfile
from pathlib import Path

script_dir = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(script_dir))

from core.kb_index import KbIndex  # noqa: E402
from core.source_manager import SourceManager  # noqa: E402
from tools.symbol_tools import AgentTools  # noqa: E402

kb = KbIndex("data/libxml2-f0fd1b", "data/libxml2-f0fd1b")

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    (root / "include/libxml").mkdir(parents=True, exist_ok=True)

    hash_h_lines = ["// filler"] * 40
    hash_h_lines[20] = "typedef struct _xmlHashTable xmlHashTable;"
    (root / "include/libxml/hash.h").write_text("\n".join(hash_h_lines) + "\n", encoding="utf-8")

    hash_c_lines = ["// filler"] * 120
    struct_lines = [
        "struct _xmlHashTable {",
        "  int size;",
        "};",
    ]
    start = 68
    for i, line in enumerate(struct_lines):
        hash_c_lines[start - 1 + i] = line
    (root / "hash.c").write_text("\n".join(hash_c_lines) + "\n", encoding="utf-8")

    sm = SourceManager(str(root), str(root))
    tools = AgentTools(kb, sm)

    out = tools.search_definition("struct _xmlHashTable", version="v2")
    print(out)
    assert "Real definition" in out, out
    assert "hash.c:68-76" in out, out
    assert "struct _xmlHashTable {" in out, out
PY

echo "OK"
