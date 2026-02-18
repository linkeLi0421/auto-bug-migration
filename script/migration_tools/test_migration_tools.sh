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
    get_error_patch_context,
    get_patch,
    list_patch_bundle,
    make_error_patch_override,
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

ctx = get_error_patch_context(
    patch_path=str(bundle_path),
    file_path="/src/libxml2/error.c",
    line_number=52,
    error_text="/src/libxml2/error.c:52:1: error: unknown type name 'foo_t'",
    allowed_roots=allowed_roots,
)
func_code = ctx.get("error_func_code") or ""
patch_minus_code = ctx.get("patch_minus_code") or ""
json.dumps({"error_func_code": func_code, "patch_minus_code": patch_minus_code})
assert func_code and "ctx2" in func_code, ctx
assert func_code.strip() in patch_minus_code, (func_code[:200], patch_minus_code[:200])

replacement = "ctx2_fixed\nctx2_extra"
patch_replace = make_error_patch_override(
    patch_path=str(bundle_path),
    file_path="/src/libxml2/error.c",
    line_number=52,
    new_func_code=replacement,
    context_lines=0,
    max_lines=2000,
    max_chars=200000,
    allowed_roots=allowed_roots,
)
json.dumps(patch_replace)
assert patch_replace["patch_key"] == "p2", patch_replace
assert patch_replace.get("patch_text_truncated") is False, patch_replace
patch_text = patch_replace.get("patch_text") or ""
assert "diff --git a/error.c b/error.c" in patch_text, patch_text[:200]
assert "-ctx2_fixed" in patch_text and "-ctx2_extra" in patch_text, patch_text
assert "+ctx2_fixed" not in patch_text, patch_text
assert "@@ -50,6 +50,6 @@" in patch_text, patch_text

# make_error_patch_override must never truncate patch_text, even if callers pass tiny limits.
patch_replace_tiny = make_error_patch_override(
    patch_path=str(bundle_path),
    file_path="/src/libxml2/error.c",
    line_number=52,
    new_func_code=replacement,
    context_lines=0,
    max_lines=1,
    max_chars=1,
    allowed_roots=allowed_roots,
)
json.dumps(patch_replace_tiny)
assert patch_replace_tiny.get("patch_text_truncated") is False, patch_replace_tiny
assert patch_replace_tiny.get("patch_text_lines_total") == patch_replace_tiny.get("patch_text_lines_returned"), patch_replace_tiny
patch_text_tiny = patch_replace_tiny.get("patch_text") or ""
assert "diff --git a/error.c b/error.c" in patch_text_tiny, patch_text_tiny[:200]
assert "-ctx2_fixed" in patch_text_tiny and "-ctx2_extra" in patch_text_tiny, patch_text_tiny

patch = get_patch(patch_path=str(bundle_path), patch_key="p2", include_text=True, max_lines=3, allowed_roots=allowed_roots)
json.dumps(patch)
assert patch.get("patch_text_truncated") is True, patch
assert (patch.get("patch_text_lines_returned") or 0) <= 3, patch

parsed = parse_build_errors_tool(build_log_text="/src/libxml2/error.c:52:1: error: unknown type name 'foo_t'\\n")
json.dumps(parsed)
assert any(i.get("kind") == "unknown_type_name" for i in parsed.get("undeclared_identifiers", [])), parsed

print("OK")
PY

# get_error_patch_context should return the entire unified-diff hunk, even if the hunk is large.
bundle_path="$tmp_dir/_fixture_large_hunk.patch2"

"$PYTHON" - "$bundle_path" <<'PY'
import json
import pickle
import sys
from pathlib import Path

bundle_path = Path(sys.argv[1])
allowed_roots = [str(bundle_path.parent)]

repo_root = bundle_path.parents[4]
script_dir = repo_root / "script"
sys.path.insert(0, str(script_dir))

from migration_tools.patch_bundle import load_patch_bundle
from migration_tools.tools import get_error_patch_context
from migration_tools.types import PatchInfo

minus_lines = [f"-LINE{i:04d}" for i in range(1100)]
patch_text = "\n".join(
    [
        "diff --git a/x.c b/x.c",
        "--- a/x.c",
        "+++ b/x.c",
        "@@ -1,1100 +1,0 @@",
        *minus_lines,
        "",
    ]
)

data = {
    "p1": PatchInfo(
        file_path_old="x.c",
        file_path_new="x.c",
        patch_text=patch_text,
        file_type="c",
        old_start_line=1,
        old_end_line=1100,
        new_start_line=1,
        new_end_line=1,
        patch_type=set(["Function body change"]),
    )
}
bundle_path.write_bytes(pickle.dumps(data))
bundle = load_patch_bundle(bundle_path, allowed_roots=allowed_roots)
assert list(bundle.patches.keys()) == ["p1"], list(bundle.patches.keys())

out = get_error_patch_context(
    patch_path=str(bundle_path),
    file_path="/src/libxml2/x.c",
    line_number=10,
    context_lines=0,
    max_total_lines=1,
    allowed_roots=allowed_roots,
)
json.dumps(out)

assert out.get("excerpt_truncated") is False, out
excerpt = out.get("excerpt") or ""
assert "@@ -1,1100 +1,0 @@" in excerpt, excerpt[:200]
assert "-LINE0000" in excerpt and "-LINE1099" in excerpt, excerpt[-200:]

patch_minus = out.get("patch_minus_code") or ""
assert "LINE0000" in patch_minus and "LINE1099" in patch_minus, patch_minus[:200]
assert "...[truncated]" not in patch_minus, patch_minus[-200:]
assert out.get("patch_minus_code_lines_total") == 1100, out.get("patch_minus_code_lines_total")
assert len(patch_minus.splitlines()) == 1100, len(patch_minus.splitlines())

hunk_total = int(out.get("hunk_lines_total") or 0)
assert hunk_total >= 1101, hunk_total  # header + 1100 '-' lines

lines = excerpt.splitlines()
assert lines and lines[0].startswith("diff --git "), lines[:4]
hunk_idx = next((i for i, l in enumerate(lines) if l.startswith("@@")), -1)
assert hunk_idx >= 0, lines[:10]
minus_count = sum(1 for l in lines[hunk_idx + 1 :] if l.startswith("-") and not l.startswith("---"))
assert minus_count == 1100, minus_count

print("OK")
PY

# Non-function patches (macros/consts/decls) should also be rewriteable by slice.
bundle_path="$tmp_dir/_fixture_macro_hunk.patch2"

"$PYTHON" - "$bundle_path" <<'PY'
import json
import pickle
import sys
from pathlib import Path

bundle_path = Path(sys.argv[1])
allowed_roots = [str(bundle_path.parent)]

repo_root = bundle_path.parents[4]
script_dir = repo_root / "script"
sys.path.insert(0, str(script_dir))

from migration_tools.patch_bundle import load_patch_bundle
from migration_tools.tools import get_error_patch, get_error_patch_context, make_error_patch_override
from migration_tools.types import PatchInfo

patch_text = "\n".join(
    [
        "diff --git a/encoding.c b/encoding.c",
        "index 0000000..1111111 100644",
        "--- a/encoding.c",
        "+++ b/encoding.c",
        "@@ -100,3 +100,0 @@",
        "-#define FOO 1",
        "-#define BAR 2",
        "-#define BAZ(x) ((x)+1)",
    ]
)

data = {
    "p1": PatchInfo(
        file_path_old="encoding.c",
        file_path_new="encoding.c",
        patch_text=patch_text,
        file_type="c",
        old_start_line=100,
        old_end_line=102,
        new_start_line=100,
        new_end_line=102,
        patch_type=set(["Macro"]),
    )
}

bundle_path.write_bytes(pickle.dumps(data))

bundle = load_patch_bundle(bundle_path, allowed_roots=allowed_roots)
assert list(bundle.patches.keys()) == ["p1"], list(bundle.patches.keys())

err = get_error_patch(
    patch_path=str(bundle_path), file_path="/src/libxml2/encoding.c", line_number=101, allowed_roots=allowed_roots
)
json.dumps(err)
assert err["patch_key"] == "p1", err
assert err["func_start_index"] is not None and err["func_end_index"] is not None, err

ctx = get_error_patch_context(
    patch_path=str(bundle_path),
    file_path="/src/libxml2/encoding.c",
    line_number=101,
    allowed_roots=allowed_roots,
)
json.dumps(ctx)
patch_minus = ctx.get("patch_minus_code") or ""
assert "#define FOO 1" in patch_minus, patch_minus[:200]
defined = set(ctx.get("defined_macros") or [])
assert {"FOO", "BAR", "BAZ"} <= defined, defined
missing = set(ctx.get("macro_tokens_not_defined_in_slice") or [])
assert not ({"FOO", "BAR", "BAZ"} & missing), missing

out = make_error_patch_override(
    patch_path=str(bundle_path),
    file_path="/src/libxml2/encoding.c",
    line_number=101,
    new_func_code="#define FOO 10\n#define BAR 20",
    max_lines=2000,
    max_chars=200000,
    allowed_roots=allowed_roots,
)
json.dumps(out)
patch_text_out = out.get("patch_text") or ""
assert "@@ -100,2 +100,0 @@" in patch_text_out, patch_text_out
assert "-#define FOO 10" in patch_text_out and "-#define BAR 20" in patch_text_out, patch_text_out

print("OK")
PY

# Macro dependency hint: detect macro tokens referenced but not defined in the slice.
bundle_path="$tmp_dir/_fixture_macro_deps.patch2"

"$PYTHON" - "$bundle_path" <<'PY'
import json
import pickle
import sys
from pathlib import Path

bundle_path = Path(sys.argv[1])
allowed_roots = [str(bundle_path.parent)]

repo_root = bundle_path.parents[4]
script_dir = repo_root / "script"
sys.path.insert(0, str(script_dir))

from migration_tools.patch_bundle import load_patch_bundle
from migration_tools.tools import get_error_patch_context, make_error_patch_override
from migration_tools.types import PatchInfo

patch_text = "\n".join(
    [
        "diff --git a/encoding.c b/encoding.c",
        "index 0000000..1111111 100644",
        "--- a/encoding.c",
        "+++ b/encoding.c",
        "@@ -100,2 +100,0 @@",
        "-#define MAKE_HANDLER(name, in, out) \\",
        "-    { (char *) name, in, out EMPTY_ICONV EMPTY_UCONV }",
    ]
)

data = {
    "p1": PatchInfo(
        file_path_old="encoding.c",
        file_path_new="encoding.c",
        patch_text=patch_text,
        file_type="c",
        old_start_line=100,
        old_end_line=101,
        new_start_line=100,
        new_end_line=101,
        patch_type=set(["Macro"]),
    )
}

bundle_path.write_bytes(pickle.dumps(data))
bundle = load_patch_bundle(bundle_path, allowed_roots=allowed_roots)
assert list(bundle.patches.keys()) == ["p1"], list(bundle.patches.keys())

ctx = get_error_patch_context(
    patch_path=str(bundle_path),
    file_path="/src/libxml2/encoding.c",
    line_number=100,
    allowed_roots=allowed_roots,
)
json.dumps(ctx)
missing = set(ctx.get("macro_tokens_not_defined_in_slice") or [])
assert {"EMPTY_ICONV", "EMPTY_UCONV"} <= missing, missing


out = make_error_patch_override(
    patch_path=str(bundle_path),
    file_path="/src/libxml2/encoding.c",
    line_number=100,
    new_func_code="#define EMPTY_ICONV\n#define EMPTY_UCONV\n#define MAKE_HANDLER(name, in, out) \\\n    { (char *) name, in, out EMPTY_ICONV EMPTY_UCONV }",
    max_lines=2000,
    max_chars=200000,
    allowed_roots=allowed_roots,
)
json.dumps(out)
patch_text_out = out.get("patch_text") or ""
assert "@@ -100,4 +100,0 @@" in patch_text_out, patch_text_out
assert "-#define EMPTY_ICONV" in patch_text_out and "-#define EMPTY_UCONV" in patch_text_out, patch_text_out

print("OK")
PY

# Recreated+merged hunk mapping: hiden_func_dict offsets are body indices.
# Ensure get_error_patch_context picks the correct merged function slice (not the first call-site block).
bundle_path="$tmp_dir/_fixture_recreated_merged_offsets.patch2"

"$PYTHON" - "$bundle_path" <<'PY'
import json
import pickle
import sys
from pathlib import Path

bundle_path = Path(sys.argv[1])
allowed_roots = [str(bundle_path.parent)]

repo_root = bundle_path.parents[4]
script_dir = repo_root / "script"
sys.path.insert(0, str(script_dir))

from migration_tools.patch_bundle import load_patch_bundle
from migration_tools.tools import get_error_patch, get_error_patch_context
from migration_tools.types import PatchInfo

patch_text = "\n".join(
    [
        "diff --git a/src/lib/protocols/http.c b/src/lib/protocols/http.c",
        "--- a/src/lib/protocols/http.c",
        "+++ b/src/lib/protocols/http.c",
        "@@ -10,20 +10,8 @@",
        " context1",
        " context2",
        "-  __revert_f25dee_ndpi_set_bitmask_protocol_detection(\"HTTP\", ndpi_struct, detection_bitmask, *id,",
        "-    NDPI_PROTOCOL_HTTP,",
        "-    ndpi_search_http_tcp,",
        "-    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,",
        "-    SAVE_DETECTION_BITMASK_AS_UNKNOWN,",
        "-    ADD_TO_DETECTION_BITMASK);",
        "+  ndpi_set_bitmask_protocol_detection(\"HTTP\", ndpi_struct, detection_bitmask, *id,",
        "+    NDPI_PROTOCOL_HTTP,",
        "+    ndpi_search_http_tcp,",
        "+    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,",
        "+    SAVE_DETECTION_BITMASK_AS_UNKNOWN,",
        "+    ADD_TO_DETECTION_BITMASK);",
        " context3",
        " context4",
        "-static void __revert_f25dee_ndpi_check_http_header(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {",
        "-  int i;",
        "-  struct ndpi_packet_struct *packet = &ndpi_struct->packet;",
        "-  if(packet) return;",
        "-}",
        "-static int __revert_f25dee_is_a_suspicious_header(void){",
        "-  return 0;",
        "-}",
    ]
)

data = {
    "p1": PatchInfo(
        file_path_old="src/lib/protocols/http.c",
        file_path_new="src/lib/protocols/http.c",
        patch_text=patch_text,
        file_type="c",
        old_start_line=10,
        old_end_line=30,
        new_start_line=10,
        new_end_line=18,
        patch_type=set(["Function removed", "Function body change", "Merged functions", "Recreated function"]),
        old_signature="no change trace function ndpi_set_bitmask_protocol_detection",
        new_signature="no change trace function ndpi_set_bitmask_protocol_detection",
        hiden_func_dict={
            "no change trace function ndpi_set_bitmask_protocol_detection": 2,
            "void ndpi_check_http_header(struct ndpi_detection_module_struct * ndpi_struct, struct ndpi_flow_struct * flow)": 16,
            "int is_a_suspicious_header(void)": 21,
        },
    )
}

bundle_path.write_bytes(pickle.dumps(data))

bundle = load_patch_bundle(bundle_path, allowed_roots=allowed_roots)
assert list(bundle.patches.keys()) == ["p1"], list(bundle.patches.keys())

# old line 22 is inside ndpi_check_http_header in this hunk.
err = get_error_patch(
    patch_path=str(bundle_path),
    file_path="/src/ndpi/src/lib/protocols/http.c",
    line_number=22,
    allowed_roots=allowed_roots,
)
json.dumps(err)
assert err["patch_key"] == "p1", err
assert err["func_start_index"] == 16 and err["func_end_index"] == 21, err
assert "ndpi_check_http_header" in str(err.get("old_signature") or ""), err

ctx = get_error_patch_context(
    patch_path=str(bundle_path),
    file_path="/src/ndpi/src/lib/protocols/http.c",
    line_number=22,
    allowed_roots=allowed_roots,
)
json.dumps(ctx)
func_code = str(ctx.get("error_func_code") or "")
assert "__revert_f25dee_ndpi_check_http_header" in func_code, func_code
assert "ndpi_struct->packet" in func_code, func_code

print("OK")
PY

# Multi-hunk header rewrite: later hunks must get +new_start adjusted when the first hunk delta changes.
fixture_b64="$SCRIPT_DIR/fixtures/multi_hunk.patch2.b64"
bundle_path="$tmp_dir/_fixture_multi_hunk.patch2"

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
from script.migration_tools.tools import make_error_patch_override

bundle = load_patch_bundle(bundle_path, allowed_roots=allowed_roots)
assert list(bundle.patches.keys()) == ["p2"], list(bundle.patches.keys())

out = make_error_patch_override(
    patch_path=str(bundle_path),
    file_path="/src/libxml2/error.c",
    line_number=11,
    new_func_code="NEW1\nNEW2",
    max_lines=2000,
    max_chars=200000,
    allowed_roots=allowed_roots,
)
json.dumps(out)
patch_text = out.get("patch_text") or ""
assert "@@ -10,4 +10,2 @@" in patch_text, patch_text
assert "@@ -30,2 +28,3 @@" in patch_text, patch_text
assert "-NEW1" in patch_text and "-NEW2" in patch_text, patch_text

print("OK")
PY
