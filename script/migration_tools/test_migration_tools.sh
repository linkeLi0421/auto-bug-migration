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
    get_error_v1_code_slice,
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
func = get_error_v1_code_slice(excerpt=ctx.get("excerpt") or "", allowed_roots=allowed_roots)
json.dumps(func)
assert func.get("func_code") and "ctx2" in func["func_code"], func

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

# get_error_v1_code_slice: return full text and never inject a "[truncated]" marker.
"$PYTHON" - <<'PY'
import json

from script.migration_tools.tools import get_error_v1_code_slice

minus_lines = [f"-LINE{i:04d} " + ("X" * 40) for i in range(50)]
diff_text = "\n".join(
    [
        "diff --git a/x.c b/x.c",
        "--- a/x.c",
        "+++ b/x.c",
        "@@ -1,50 +1,0 @@",
        *minus_lines,
        "",
    ]
)

out = get_error_v1_code_slice(excerpt=diff_text)
json.dumps(out)
assert out["func_code_lines_total"] == 50, out
assert out["func_code_lines_returned"] == 50, out
assert out["func_code_truncated"] is False, out
code = out.get("func_code") or ""
assert "...[truncated]" not in code, code[-200:]

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
from migration_tools.tools import get_error_patch, get_error_patch_context, get_error_v1_code_slice, make_error_patch_override
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
code = get_error_v1_code_slice(excerpt=ctx.get("excerpt") or "", allowed_roots=allowed_roots)
json.dumps(code)
assert "#define FOO 1" in (code.get("func_code") or ""), code
defined = set(code.get("defined_macros") or [])
assert {"FOO", "BAR", "BAZ"} <= defined, defined
missing = set(code.get("macro_tokens_not_defined_in_slice") or [])
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
from migration_tools.tools import get_error_patch_context, get_error_v1_code_slice, make_error_patch_override
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
code = get_error_v1_code_slice(excerpt=ctx.get("excerpt") or "", allowed_roots=allowed_roots)
json.dumps(code)
missing = set(code.get("macro_tokens_not_defined_in_slice") or [])
assert {"EMPTY_ICONV", "EMPTY_UCONV"} <= missing, missing

# Guardrail: a no-op rewrite (new_func_code identical to the existing '-' slice) should be rejected.
try:
    make_error_patch_override(
        patch_path=str(bundle_path),
        file_path="/src/libxml2/encoding.c",
        line_number=100,
        new_func_code=code.get("func_code") or "",
        max_lines=2000,
        max_chars=200000,
        allowed_roots=allowed_roots,
    )
    raise AssertionError("expected ValueError for no-op rewrite")
except ValueError:
    pass

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

# Excerpt-based slicing: get_error_v1_code_slice can operate on a single-hunk excerpt artifact.
"$PYTHON" - "$tmp_dir" <<'PY'
import os
import sys
from pathlib import Path

tmp_dir = Path(sys.argv[1]).resolve()
repo_root = tmp_dir.parents[3]
sys.path.insert(0, str(repo_root))

from script.migration_tools.tools import get_error_v1_code_slice  # noqa: E402

artifact_dir = tmp_dir / "artifacts"
artifact_dir.mkdir(parents=True, exist_ok=True)
os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(artifact_dir)

excerpt_path = artifact_dir / "excerpt.diff"
excerpt_path.write_text(
    "\n".join(
        [
            "diff --git a/encoding.c b/encoding.c",
            "--- a/encoding.c",
            "+++ b/encoding.c",
            "@@ -100,2 +100,0 @@",
            "-#define MAKE_HANDLER(name, in, out) \\",
            "-    { (char *) name, in, out EMPTY_ICONV EMPTY_UCONV }",
        ]
    )
    + "\n",
    encoding="utf-8",
    errors="replace",
)

out = get_error_v1_code_slice(excerpt={"artifact_path": str(excerpt_path)})
code = out.get("func_code") or ""
assert "MAKE_HANDLER" in code, code
missing = set(out.get("macro_tokens_not_defined_in_slice") or [])
assert {"EMPTY_ICONV", "EMPTY_UCONV"} <= missing, missing

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
