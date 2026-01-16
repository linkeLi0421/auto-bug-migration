#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

export REACT_AGENT_PATCH_ALLOWED_ROOTS="$tmp_dir"
export REACT_AGENT_ARTIFACT_ROOT="$tmp_dir/artifacts"
export REACT_AGENT_OSSFUZZ_LOCK_PATH="$tmp_dir/ossfuzz_apply_patch_and_test.lock"

PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - <<'PY'
import contextlib
import io
import os
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

# Cross-process lock: concurrent OSS-Fuzz tool calls should serialize.
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - <<'PY'
import os
import subprocess
import sys
import time

lock_path = os.environ.get("REACT_AGENT_OSSFUZZ_LOCK_PATH")
assert lock_path, "missing REACT_AGENT_OSSFUZZ_LOCK_PATH"

child_code = r"""
import sys
import time
from script.react_agent.tools.ossfuzz_tools import _FileLock, _ossfuzz_lock_path

label = sys.argv[1]
lock = _ossfuzz_lock_path()
with _FileLock(lock, wait_message=""):
    acquired = time.time()
    print(f"{label} acquired {acquired}", flush=True)
    time.sleep(0.4)
    releasing = time.time()
    print(f"{label} releasing {releasing}", flush=True)
"""

env = dict(os.environ)
p1 = subprocess.Popen([sys.executable, "-c", child_code, "p1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
time.sleep(0.05)
p2 = subprocess.Popen([sys.executable, "-c", child_code, "p2"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)

out1, err1 = p1.communicate(timeout=10)
out2, err2 = p2.communicate(timeout=10)
assert p1.returncode == 0, (p1.returncode, out1, err1)
assert p2.returncode == 0, (p2.returncode, out2, err2)

def parse_times(out: str) -> tuple[float, float]:
    acquired = None
    releasing = None
    for line in (out or "").splitlines():
        parts = line.strip().split()
        if len(parts) != 3:
            continue
        if parts[1] == "acquired":
            acquired = float(parts[2])
        elif parts[1] == "releasing":
            releasing = float(parts[2])
    assert acquired is not None and releasing is not None, out
    return acquired, releasing

a1, r1 = parse_times(out1)
a2, r2 = parse_times(out2)

if a1 <= a2:
    first_acq, first_rel, second_acq = a1, r1, a2
else:
    first_acq, first_rel, second_acq = a2, r2, a1

assert second_acq >= first_rel, (out1, out2, err1, err2)
assert (second_acq - first_acq) >= 0.25, (out1, out2, err1, err2)
PY

# Pick the latest make_error_patch_override override diff (e.g. ".8.diff" beats ".diff").
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - <<'PY'
import os
import tempfile
from pathlib import Path

import sys

sys.path.insert(0, str(Path.cwd() / "script" / "react_agent"))
import multi_agent  # noqa: E402

with tempfile.TemporaryDirectory() as td:
    root = Path(td).resolve()
    diff0 = root / "make_error_patch_override_patch_text_parser.c.diff"
    diff8 = root / "make_error_patch_override_patch_text_parser.c.8.diff"
    diff0.write_text("diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n", encoding="utf-8")
    diff8.write_text("diff --git a/b b/b\n--- a/b\n+++ b/b\n@@ -1 +1 @@\n-old\n+new\n", encoding="utf-8")

    # Ensure predictable ordering across filesystems.
    os.utime(diff0, (1, 1))
    os.utime(diff8, (2, 2))

    picked = multi_agent._latest_make_error_patch_override_diff(root)
    assert picked is not None, picked
    assert picked.name.endswith(".8.diff"), picked.name
PY

# Combined overrides should be ordered bottom-up (PatchInfo.new_start_line desc), like script/revert_patch_test.py.
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - "$tmp_dir" <<'PY'
import os
import pickle
import sys
from pathlib import Path

tmp_dir = Path(sys.argv[1]).resolve()

sys.path.insert(0, str(Path.cwd() / "script"))
from migration_tools.types import PatchInfo  # noqa: E402

sys.path.insert(0, str(Path.cwd() / "script" / "react_agent"))
import multi_agent  # noqa: E402

bundle_path = tmp_dir / "bundle_override_order.patch2"
patch_text = "diff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -1 +1 @@\n-old\n+new\n"
patches = {
    "p_low": PatchInfo(
        file_path_old="a.c",
        file_path_new="a.c",
        patch_text=patch_text,
        file_type="source",
        old_start_line=10,
        old_end_line=10,
        new_start_line=10,
        new_end_line=10,
    ),
    "p_high": PatchInfo(
        file_path_old="a.c",
        file_path_new="a.c",
        patch_text=patch_text,
        file_type="source",
        old_start_line=100,
        old_end_line=100,
        new_start_line=100,
        new_end_line=100,
    ),
}
bundle_path.write_bytes(pickle.dumps(patches))

art_low = tmp_dir / "art_low"
art_high = tmp_dir / "art_high"
art_low.mkdir(parents=True, exist_ok=True)
art_high.mkdir(parents=True, exist_ok=True)
(art_low / "make_error_patch_override_patch_text_x.diff").write_text(patch_text, encoding="utf-8")
(art_high / "make_error_patch_override_patch_text_x.diff").write_text(patch_text, encoding="utf-8")

# Reverse the input order on purpose; output should still be p_high then p_low.
results = [
    {"patch_key": "p_low", "artifacts_dir": str(art_low)},
    {"patch_key": "p_high", "artifacts_dir": str(art_high)},
]
out = multi_agent._collect_final_override_diffs(results, patch_path=str(bundle_path))
ordered = [x.get("patch_key") for x in (out.get("per_hunk") or [])]
assert ordered[:2] == ["p_high", "p_low"], ordered
PY

# Merged patch output should not overwrite prior iterations (unique paths).
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - "$tmp_dir" <<'PY'
import os
import pickle
import sys
from pathlib import Path

tmp_dir = Path(sys.argv[1]).resolve()
allow_root = Path(os.environ["REACT_AGENT_ARTIFACT_ROOT"]).expanduser().resolve()
allow_root.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(Path.cwd() / "script"))
from migration_tools.types import PatchInfo  # noqa: E402

bundle_path = tmp_dir / "bundle_merge.patch2"
patch_text = (
    "diff --git a/libxml2/hash.c b/libxml2/hash.c\n"
    "--- a/libxml2/hash.c\n"
    "+++ b/libxml2/hash.c\n"
    "@@ -1,1 +1,1 @@\n"
    "-old\n"
    "+new\n"
)
patches = {
    "p1": PatchInfo(
        file_path_old="libxml2/hash.c",
        file_path_new="libxml2/hash.c",
        patch_text=patch_text,
        file_type="source",
        old_start_line=1,
        old_end_line=1,
        new_start_line=1,
        new_end_line=1,
    )
}
bundle_path.write_bytes(pickle.dumps(patches))

override_dir = allow_root / "p1"
override_dir.mkdir(parents=True, exist_ok=True)
override_path = override_dir / "override.diff"
override_path.write_text(patch_text + ("\n" if not patch_text.endswith("\n") else ""), encoding="utf-8")

from script.react_agent.tools.ossfuzz_tools import merge_patch_bundle_with_overrides  # noqa: E402

out1 = merge_patch_bundle_with_overrides(
    patch_path=str(bundle_path),
    patch_override_paths=[str(override_path)],
    output_name="ossfuzz_merged.diff",
)
out2 = merge_patch_bundle_with_overrides(
    patch_path=str(bundle_path),
    patch_override_paths=[str(override_path)],
    output_name="ossfuzz_merged.diff",
)

p1 = Path(out1["merged_patch_file_path"]).resolve()
p2 = Path(out2["merged_patch_file_path"]).resolve()
assert p1.is_file(), p1
assert p2.is_file(), p2
assert p1 != p2, (p1, p2)

# When patch_override_paths is empty (effective bundle contains the updated patch_text),
# still write merged_patch_file_path under the bundle's patch_key directory.
bundle_path2 = override_dir / "bundle_inferred.patch2"
bundle_path2.write_bytes(pickle.dumps(patches))
out3 = merge_patch_bundle_with_overrides(
    patch_path=str(bundle_path2),
    patch_override_paths=[],
    output_name="ossfuzz_merged.diff",
)
p3 = Path(out3["merged_patch_file_path"]).resolve()
assert p3.is_file(), p3
assert p3.parent == override_dir.resolve(), (p3, override_dir)
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
  --max-restarts-per-hunk 0 \
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
assert obj.get("max_groups_requested") == 20, obj.get("max_groups_requested")
assert obj.get("max_restarts_per_hunk") == 0, obj.get("max_restarts_per_hunk")
assert obj.get("patch_key_groups_found") == 2, obj.get("patch_key_groups_found")
assert obj.get("patch_key_groups_after_allowlist") == 2, obj.get("patch_key_groups_after_allowlist")
assert obj.get("patch_key_groups_selected") == 2, obj.get("patch_key_groups_selected")
assert isinstance(obj.get("task_status_counts"), dict), obj.get("task_status_counts")
assert isinstance(obj.get("not_fixed"), list), obj.get("not_fixed")
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
    assert r.get("attempts") == 1, r.get("attempts")
    assert r.get("restarts_attempted") == 0, r.get("restarts_attempted")
    assert isinstance(r.get("attempt_history"), list) and len(r.get("attempt_history") or []) == 1, r.get("attempt_history")
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

# Restart mode: with --max-restarts-per-hunk 1, retry non-fixed hunks once and keep only the final attempt's artifacts.
out_path2="$tmp_dir/out_restart.json"
"$PYTHON" "$SCRIPT_DIR/multi_agent.py" "$build_log" \
  --patch-path "$bundle_path" \
  --jobs 2 \
  --max-restarts-per-hunk 1 \
  --model stub --tools fake --max-steps 1 \
  --ossfuzz-project libxml2 --ossfuzz-commit f0fd1b \
  --output-format json-pretty >"$out_path2"

PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - "$out_path2" <<'PY'
import json
import sys
from pathlib import Path

obj = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace"))
assert obj["type"] == "multi_agent", obj
assert obj.get("max_restarts_per_hunk") == 1, obj.get("max_restarts_per_hunk")
assert obj.get("hunks_restarted") == 2, obj.get("hunks_restarted")
assert obj.get("restarts_attempted_total") == 2, obj.get("restarts_attempted_total")
for r in obj.get("results") or []:
    assert r.get("attempts") == 2, r.get("attempts")
    assert r.get("restarts_attempted") == 1, r.get("restarts_attempted")
    hist = r.get("attempt_history") or []
    assert isinstance(hist, list) and len(hist) == 2, hist
PY

echo "OK"
