#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

export REACT_AGENT_PATCH_ALLOWED_ROOTS="$tmp_dir"
export REACT_AGENT_ARTIFACT_ROOT="$tmp_dir/artifacts"
export REACT_AGENT_ARTIFACT_DIR="$tmp_dir/global_artifacts"

PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - <<'PY'
import contextlib
import io
import sys

from script.react_agent.tools.ossfuzz_tools import _run

out_buf = io.StringIO()
err_buf = io.StringIO()
with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
    res = _run([sys.executable, "-c", "print('hello')"], label="unit")

assert out_buf.getvalue() == "", out_buf.getvalue()
assert "[ossfuzz_apply_patch_and_test]" in err_buf.getvalue(), err_buf.getvalue()
assert res["output"].strip() == "hello", res
PY

bundle_path="$tmp_dir/bundle.patch2"
build_log="$tmp_dir/build.log"

PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - "$bundle_path" "$build_log" <<'PY'
import pickle
import sys
from pathlib import Path

bundle_path = Path(sys.argv[1]).resolve()
build_log = Path(sys.argv[2]).resolve()

sys.path.insert(0, str(Path.cwd() / "script"))
from migration_tools.types import PatchInfo  # noqa: E402

patches = {
    "p1": PatchInfo(
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
    "p2": PatchInfo(
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

build_log.write_text(
    "/src/libxml2/hash.c:295:11: error: no member named 'randomSeed' in 'struct _xmlHashTable'\n"
    "/src/libxml2/hash.c:554:52: error: no member named 'randomSeed' in 'struct _xmlHashTable'\n",
    encoding="utf-8",
)
PY

out_path="$tmp_dir/out.json"
"$PYTHON" "$SCRIPT_DIR/multi_agent.py" "$build_log" \
  --patch-path "$bundle_path" \
  --jobs 2 \
  --auto-ossfuzz-loop --ossfuzz-loop-max 2 \
  --recursion-limit 123 \
  --openai-api-key dummy_key_for_test \
  --openai-model dummy-model \
  --model stub --tools fake --max-steps 3 \
  --ossfuzz-project libxml2 --ossfuzz-commit f0fd1b \
  --output-format json-pretty >"$out_path"

PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - "$out_path" <<'PY'
import json
import sys
from pathlib import Path

obj = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace"))
assert obj["type"] == "multi_agent", obj
assert obj.get("summary_json_path"), obj
assert Path(obj["summary_json_path"]).is_file(), obj["summary_json_path"]
keys = [r["patch_key"] for r in obj.get("results") or []]
assert set(keys) >= {"p1", "p2"}, keys
for r in obj["results"]:
    assert r["artifacts_dir"], r
    assert r["agent_stdout_path"], r
    assert r["patch_key_dirname"], r
    assert "hunk_fixed" in r, r
    assert "target_fixed" in r, r
    assert "ossfuzz_verdict" in r, r
    assert "patch_key_verdict" in r, r
    # Ensure the spawned agent did not inherit the global REACT_AGENT_ARTIFACT_DIR.
    agent = json.loads(Path(r["agent_stdout_path"]).read_text(encoding="utf-8", errors="replace"))
    artifacts_dir = (agent.get("error") or {}).get("artifacts_dir", "")
    assert artifacts_dir, agent
    assert str(artifacts_dir) == str(r["artifacts_dir"]), (artifacts_dir, r["artifacts_dir"])
    cmd_path = Path(r["artifacts_dir"]) / "agent_cmd.txt"
    cmd = cmd_path.read_text(encoding="utf-8", errors="replace")
    assert "--auto-ossfuzz-loop" in cmd, cmd
    assert "--ossfuzz-loop-max 2" in cmd, cmd
    assert "--recursion-limit 123" in cmd, cmd
    assert "--openai-api-key REDACTED" in cmd, cmd
    assert "--openai-model dummy-model" in cmd, cmd
PY

echo "OK"
