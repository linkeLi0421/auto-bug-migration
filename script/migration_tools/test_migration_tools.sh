#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

PYTHON="${PYTHON:-python3}"

fixture_b64="$SCRIPT_DIR/fixtures/sample.patch2.b64"

tmp_dir="$(mktemp -d "$REPO_ROOT/script/migration_tools/fixtures/.tmp_patch.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
bundle_path="$tmp_dir/_fixture_sample.patch2"

"$PYTHON" - "$fixture_b64" "$bundle_path" <<'PY'
import base64
import json
import sys
from pathlib import Path

fixture_b64 = Path(sys.argv[1])
bundle_path = Path(sys.argv[2])
allowed_roots = [str(bundle_path.parent)]

data = base64.b64decode(fixture_b64.read_text(encoding="utf-8").strip())
bundle_path.parent.mkdir(parents=True, exist_ok=True)
bundle_path.write_bytes(data)

from script.migration_tools.patch_bundle import load_patch_bundle
from script.migration_tools.tools import (
    get_error_patch,
    get_error_v1_function_code,
    get_patch,
    list_patch_bundle,
    parse_build_errors_tool,
    search_patches,
)

try:
    load_patch_bundle(bundle_path)
    raise AssertionError("expected allowlist refusal")
except ValueError:
    pass

bundle = load_patch_bundle(bundle_path, allowed_roots=allowed_roots)
assert len(bundle.patches) == 2, len(bundle.patches)

listed = list_patch_bundle(patch_path=str(bundle_path), limit=10, allowed_roots=allowed_roots)
json.dumps(listed)  # JSON-serializable
assert listed["matched"] == 2, listed

searched = search_patches(patch_path=str(bundle_path), query="bar(", limit=10, allowed_roots=allowed_roots)
json.dumps(searched)
assert searched["matched"] >= 1, searched

err = get_error_patch(
    patch_path=str(bundle_path), file_path="/src/libxml2/error.c", line_number=52, allowed_roots=allowed_roots
)
json.dumps(err)
assert err["patch_key"] == "p2", err
assert err["old_signature"] and "bar" in err["old_signature"], err
assert err["func_start_index"] is not None, err

func = get_error_v1_function_code(
    patch_path=str(bundle_path),
    file_path="/src/libxml2/error.c",
    line_number=52,
    max_lines=200,
    max_chars=20000,
    allowed_roots=allowed_roots,
)
json.dumps(func)
assert func["patch_key"] == "p2", func
assert func.get("old_signature") and "bar" in func["old_signature"], func
assert func.get("func_code") and "ctx2" in func["func_code"], func

patch = get_patch(patch_path=str(bundle_path), patch_key="p2", include_text=True, max_lines=3, allowed_roots=allowed_roots)
json.dumps(patch)
assert patch.get("patch_text_truncated") is True, patch
assert (patch.get("patch_text_lines_returned") or 0) <= 3, patch

parsed = parse_build_errors_tool(build_log_text="/src/libxml2/error.c:52:1: error: unknown type name 'foo_t'\\n")
json.dumps(parsed)
assert any(i.get("kind") == "unknown_type_name" for i in parsed.get("undeclared_identifiers", [])), parsed

print("OK")
PY
