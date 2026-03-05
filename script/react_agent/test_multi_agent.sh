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

# Collect override diffs from agent_stdout steps (not just next_step) so we don't miss a main-hunk
# make_error_patch_override when the run ends on a make_extra_patch_override.
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - "$tmp_dir" <<'PY'
import json
import os
import pickle
import sys
from pathlib import Path

tmp_dir = Path(sys.argv[1]).resolve()

sys.path.insert(0, str(Path.cwd() / "script"))
from migration_tools.types import PatchInfo  # noqa: E402

sys.path.insert(0, str(Path.cwd() / "script" / "react_agent"))
import multi_agent  # noqa: E402

bundle_path = tmp_dir / "bundle_override_steps.patch2"
patch_text = "diff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -1 +1 @@\n-old\n+new\n"
patches = {
    "p_main": PatchInfo(
        file_path_old="a.c",
        file_path_new="a.c",
        patch_text=patch_text,
        file_type="source",
        old_start_line=10,
        old_end_line=10,
        new_start_line=100,
        new_end_line=100,
    ),
    "_extra_a.c": PatchInfo(
        file_path_old="a.c",
        file_path_new="a.c",
        patch_text=patch_text,
        file_type="source",
        old_start_line=1,
        old_end_line=1,
        new_start_line=5,
        new_end_line=5,
    ),
}
bundle_path.write_bytes(pickle.dumps(patches))

root = tmp_dir / "override_steps_artifacts"
root.mkdir(parents=True, exist_ok=True)
art_main = root / "p_main"
art_extra = root / "_extra_a.c"
art_main.mkdir(parents=True, exist_ok=True)
art_extra.mkdir(parents=True, exist_ok=True)

main_diff = art_main / "make_error_patch_override_patch_text_a.c.5.diff"
extra_diff = art_extra / "make_extra_patch_override_patch_text_a.c_HASH_ROR.diff"
main_diff.write_text(patch_text, encoding="utf-8")
extra_diff.write_text(patch_text, encoding="utf-8")

agent_payload = {
    "type": "final",
    "summary": "x",
    "next_step": f"Override diff: {extra_diff}",
    "steps": [
        {
            "decision": {"type": "tool", "tool": "make_error_patch_override", "args": {}},
            "observation": {"ok": True, "tool": "make_error_patch_override", "args": {}, "output": {"patch_key": "p_main", "patch_text": {"artifact_path": str(main_diff)}}},
        },
        {
            "decision": {"type": "tool", "tool": "make_extra_patch_override", "args": {}},
            "observation": {"ok": True, "tool": "make_extra_patch_override", "args": {}, "output": {"patch_key": "_extra_a.c", "patch_text": {"artifact_path": str(extra_diff)}}},
        },
    ],
}
(art_main / "agent_stdout.json").write_text(json.dumps(agent_payload), encoding="utf-8")

results = [{"patch_key": "p_main", "artifacts_dir": str(art_main)}]
out = multi_agent._collect_final_override_diffs(results, patch_path=str(bundle_path))
paths = out.get("override_paths") or []
assert str(main_diff.resolve()) in paths, paths
assert str(extra_diff.resolve()) in paths, paths

ordered = [x.get("patch_key") for x in (out.get("per_hunk") or [])]
# Both patch keys should appear, ordered by new_start_line desc (p_main before _extra_a.c).
assert ordered[:2] == ["p_main", "_extra_a.c"], ordered
PY

# agent_stdout steps: tolerate "patch_text" being a unified diff string (not a path/artifact).
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - <<'PY'
import json
import tempfile
from pathlib import Path

import sys

sys.path.insert(0, str(Path.cwd() / "script" / "react_agent"))
import multi_agent  # noqa: E402

payload = {
    "type": "final",
    "summary": "x",
    "steps": [
        {
            "decision": {"type": "tool", "tool": "make_error_patch_override", "args": {}},
            "observation": {
                "ok": True,
                "tool": "make_error_patch_override",
                "args": {},
                "output": {
                    "patch_key": "p1",
                    "patch_text": "diff --git a/parser.c b/parser.c\n--- a/parser.c\n+++ b/parser.c\n@@ -1 +1 @@\n-old\n+new\n",
                },
            },
        }
    ],
}

with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "agent_stdout.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    out = multi_agent._extract_override_diffs_from_agent_stdout_steps(p)
    assert out == [], out
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

# Resume mode: skip already-fixed patch_keys from a prior artifacts root.
resume_root="$tmp_dir/resume_artifacts"
mkdir -p "$resume_root/p1" "$resume_root/p2"
cat >"$resume_root/p1/agent_stdout.json" <<'JSON'
{"type":"final","summary":"ok","next_step":"","steps":[]}
JSON
cat >"$resume_root/p2/agent_stdout.json" <<'JSON'
{"type":"final","summary":"fail","next_step":"","steps":[]}
JSON

PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - "$resume_root" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
progress = {
    "type": "multi_agent",
    "results": [
        {"patch_key": "p1", "task_status": "fixed", "hunk_fixed": True, "attempts": 7, "restarts_attempted": 0, "artifacts_dir": str(root / "p1"), "agent_stdout_path": str(root / "p1" / "agent_stdout.json"), "patch_key_dirname": "p1", "agent_exit_code": 0},
        {"patch_key": "p2", "task_status": "agent_failed", "hunk_fixed": None, "attempts": 1, "restarts_attempted": 0, "artifacts_dir": str(root / "p2"), "agent_stdout_path": str(root / "p2" / "agent_stdout.json"), "patch_key_dirname": "p2", "agent_exit_code": 1},
    ],
}
(root / "progress.json").write_text(json.dumps(progress, indent=2) + "\n", encoding="utf-8")
PY

out_path3="$tmp_dir/out_resume.json"
"$PYTHON" "$SCRIPT_DIR/multi_agent.py" "$build_log" \
  --patch-path "$bundle_path" \
  --resume-from "$resume_root" \
  --jobs 1 \
  --max-restarts-per-hunk 0 \
  --model stub --tools fake --max-steps 1 \
  --ossfuzz-project libxml2 --ossfuzz-commit f0fd1b \
  --output-format json-pretty >"$out_path3"

PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - "$out_path3" <<'PY'
import json
import sys
from pathlib import Path

obj = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace"))
assert obj["type"] == "multi_agent", obj
assert "progress.json" in (obj.get("resumed_from") or ""), obj.get("resumed_from")
rmap = {r["patch_key"]: r for r in (obj.get("results") or [])}
assert rmap["p1"].get("task_status") == "fixed", rmap["p1"]
assert rmap["p1"].get("attempts") == 7, rmap["p1"]  # skipped (not rerun)
assert rmap["p2"].get("attempts") == 1, rmap["p2"]  # rerun once in this resumed invocation
PY

########################################################################
# Test: __revert_* linker errors with unmapped file fall back to _extra_<file>
########################################################################
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - "$tmp_dir" <<'PY'
import os, pickle, sys
from pathlib import Path

tmp = sys.argv[1]
sys.path.insert(0, str(Path.cwd() / "script"))
sys.path.insert(0, str(Path.cwd() / "script" / "react_agent"))

from multi_agent import _group_errors_by_patch_key
from migration_tools.types import PatchInfo

# Create a minimal patch bundle with a kstring.c patch that contains ks_resize
# but NO patch for hfile.c or multipart.c.
patches = {}
patches["_extra_kstring.c"] = PatchInfo(
    file_path_old="kstring.c", file_path_new="kstring.c",
    patch_text=(
        "diff --git a/kstring.c b/kstring.c\n"
        "--- a/kstring.c\n"
        "+++ b/kstring.c\n"
        "@@ -36,4 +36,3 @@\n"
        "-static inline int __revert_abc123_ks_resize(kstring_t *s, size_t size);\n"
        " int kputd(double d, kstring_t *s) {\n"
    ),
    file_type="c",
    old_start_line=36, old_end_line=40,
    new_start_line=36, new_end_line=39,
    patch_type={"Extra"},
    old_signature="",
    dependent_func=set(),
    hiden_func_dict={},
)

bundle_path = os.path.join(tmp, "test_linker_fallback.patch2")
with open(bundle_path, "wb") as f:
    f.write(pickle.dumps(patches, protocol=pickle.HIGHEST_PROTOCOL))

# Simulate a build log with linker errors in hfile.c and multipart.c
build_log = """\
/usr/bin/ld: libhts.a(hfile.o): in function `haddextension':
hfile.c:(.text.haddextension[haddextension]+0x148): undefined reference to `__revert_abc123_ks_resize'
/usr/bin/ld: libhts.a(multipart.o): in function `hopen_htsget_redirect':
multipart.c:(.text.hopen_htsget_redirect[hopen_htsget_redirect]+0x843): undefined reference to `__revert_abc123_ks_resize'
clang++: error: linker command failed with exit code 1
"""

groups = _group_errors_by_patch_key(build_log_text=build_log, patch_path=bundle_path)

# The errors should be grouped under _extra_hfile.c and _extra_multipart.c (fallback keys)
assert "_extra_hfile.c" in groups, f"Expected _extra_hfile.c in groups, got: {sorted(groups.keys())}"
assert "_extra_multipart.c" in groups, f"Expected _extra_multipart.c in groups, got: {sorted(groups.keys())}"

hfile_errs = groups["_extra_hfile.c"]
assert len(hfile_errs) == 1, f"Expected 1 error in _extra_hfile.c, got {len(hfile_errs)}"
assert hfile_errs[0]["kind"] == "linker", hfile_errs[0]
assert hfile_errs[0]["symbol"] == "__revert_abc123_ks_resize", hfile_errs[0]

multi_errs = groups["_extra_multipart.c"]
assert len(multi_errs) == 1, f"Expected 1 error in _extra_multipart.c, got {len(multi_errs)}"
assert multi_errs[0]["symbol"] == "__revert_abc123_ks_resize", multi_errs[0]

print("  __revert_* linker error fallback to _extra_<file> OK")
PY

########################################################################
# Test: _split_extra_patch_keys_in_bundle splits multi-hunk _extra_* entries
########################################################################
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - "$tmp_dir" <<'PY'
import os, pickle, sys
from pathlib import Path

tmp = sys.argv[1]
sys.path.insert(0, str(Path.cwd() / "script"))
sys.path.insert(0, str(Path.cwd() / "script" / "react_agent"))

from multi_agent import _split_extra_patch_keys_in_bundle
from migration_tools.types import PatchInfo

# --- Case 1: multi-hunk, non-overlapping → should split ---
patches = {}
patches["some_other_key"] = PatchInfo(
    file_path_old="foo.c", file_path_new="foo.c",
    patch_text=(
        "diff --git a/foo.c b/foo.c\n"
        "--- a/foo.c\n"
        "+++ b/foo.c\n"
        "@@ -10,3 +10,3 @@\n"
        " context\n"
    ),
    file_type="c",
    old_start_line=10, old_end_line=12,
    new_start_line=10, new_end_line=12,
    patch_type={"Modify"},
)
patches["_extra_ndpi_main.c"] = PatchInfo(
    file_path_old="ndpi_main.c", file_path_new="ndpi_main.c",
    patch_text=(
        "diff --git a/ndpi_main.c b/ndpi_main.c\n"
        "--- a/ndpi_main.c\n"
        "+++ b/ndpi_main.c\n"
        "@@ -81,4 +81,6 @@\n"
        " context_line_1\n"
        "-old_line_at_81\n"
        "+new_line_at_81a\n"
        "+new_line_at_81b\n"
        " context_line_2\n"
        "@@ -691,3 +693,5 @@\n"
        " context_line_3\n"
        "-old_line_at_691\n"
        "+new_line_at_691a\n"
        "+new_line_at_691b\n"
        "+new_line_at_691c\n"
        " context_line_4\n"
    ),
    file_type="c",
    old_start_line=81, old_end_line=694,
    new_start_line=81, new_end_line=698,
    patch_type={"Extra"},
)

bundle_path = os.path.join(tmp, "test_split.patch2")
with open(bundle_path, "wb") as f:
    f.write(pickle.dumps(patches, protocol=pickle.HIGHEST_PROTOCOL))

arts = Path(os.path.join(tmp, "split_arts"))
arts.mkdir(parents=True, exist_ok=True)

result = _split_extra_patch_keys_in_bundle(bundle_path, arts)
assert result != bundle_path, f"Expected new path, got original: {result}"
assert result.endswith(".split_extra.patch2"), result

# Load the split bundle and verify
with open(result, "rb") as f:
    split_patches = pickle.load(f)

assert "some_other_key" in split_patches, f"Non-extra key should be preserved: {sorted(split_patches.keys())}"
assert "_extra_ndpi_main.c" not in split_patches, f"Original multi-hunk key should be removed: {sorted(split_patches.keys())}"
assert "_extra_ndpi_main.c__h81" in split_patches, f"Expected split key __h81: {sorted(split_patches.keys())}"
assert "_extra_ndpi_main.c__h691" in split_patches, f"Expected split key __h691: {sorted(split_patches.keys())}"

h81 = split_patches["_extra_ndpi_main.c__h81"]
assert h81.old_start_line == 81, h81.old_start_line
assert h81.old_end_line == 84, h81.old_end_line  # 81 + 4 - 1
assert h81.new_start_line == 81, h81.new_start_line
assert h81.new_end_line == 86, h81.new_end_line  # 81 + 6 - 1
assert h81.file_path_old == "ndpi_main.c", h81.file_path_old
assert "Extra" in h81.patch_type, h81.patch_type
assert "@@ -81,4 +81,6 @@" in h81.patch_text, h81.patch_text
assert "@@ -691" not in h81.patch_text, "h81 should not contain hunk 691"

h691 = split_patches["_extra_ndpi_main.c__h691"]
assert h691.old_start_line == 691, h691.old_start_line
assert h691.new_start_line == 693, h691.new_start_line
assert "@@ -691,3 +693,5 @@" in h691.patch_text, h691.patch_text
assert "@@ -81" not in h691.patch_text, "h691 should not contain hunk 81"

# Verify .diff file was also generated with correct bottom-up ordering
diff_path = arts / "test_split.split_extra.diff"
assert diff_path.is_file(), f"Expected .diff file at {diff_path}"
diff_text = diff_path.read_text()
pos_691 = diff_text.index("@@ -691,3 +693,5 @@")
pos_81 = diff_text.index("@@ -81,4 +81,6 @@")
pos_10 = diff_text.index("@@ -10,3 +10,3 @@")
assert pos_691 < pos_81, f"h691 should come before h81 (bottom-up ordering)"
assert pos_81 < pos_10, f"h81 should come before foo.c (bottom-up ordering)"

print("  split multi-hunk _extra_* OK (incl. .diff ordering)")

# --- Case 2: single-hunk _extra_* → no split ---
patches2 = {}
patches2["_extra_single.c"] = PatchInfo(
    file_path_old="single.c", file_path_new="single.c",
    patch_text=(
        "diff --git a/single.c b/single.c\n"
        "--- a/single.c\n"
        "+++ b/single.c\n"
        "@@ -10,3 +10,4 @@\n"
        " context\n"
        "-old\n"
        "+new1\n"
        "+new2\n"
    ),
    file_type="c",
    old_start_line=10, old_end_line=12,
    new_start_line=10, new_end_line=13,
    patch_type={"Extra"},
)

bundle_path2 = os.path.join(tmp, "test_no_split.patch2")
with open(bundle_path2, "wb") as f:
    f.write(pickle.dumps(patches2, protocol=pickle.HIGHEST_PROTOCOL))

result2 = _split_extra_patch_keys_in_bundle(bundle_path2, arts)
assert result2 == bundle_path2, f"Single-hunk should return original path: {result2}"

print("  single-hunk _extra_* no split OK")

# --- Case 3: overlapping hunks → no split ---
patches3 = {}
patches3["_extra_overlap.c"] = PatchInfo(
    file_path_old="overlap.c", file_path_new="overlap.c",
    patch_text=(
        "diff --git a/overlap.c b/overlap.c\n"
        "--- a/overlap.c\n"
        "+++ b/overlap.c\n"
        "@@ -10,8 +10,9 @@\n"
        " ctx\n"
        "-old\n"
        "+new\n"
        "+new2\n"
        " ctx\n"
        " ctx\n"
        " ctx\n"
        " ctx\n"
        " ctx\n"
        "@@ -15,3 +16,4 @@\n"
        " ctx\n"
        "-old2\n"
        "+new3\n"
        "+new4\n"
    ),
    file_type="c",
    old_start_line=10, old_end_line=17,
    new_start_line=10, new_end_line=19,
    patch_type={"Extra"},
)

bundle_path3 = os.path.join(tmp, "test_overlap.patch2")
with open(bundle_path3, "wb") as f:
    f.write(pickle.dumps(patches3, protocol=pickle.HIGHEST_PROTOCOL))

result3 = _split_extra_patch_keys_in_bundle(bundle_path3, arts)
assert result3 == bundle_path3, f"Overlapping hunks should return original path: {result3}"

print("  overlapping hunks no split OK")
PY

########################################################################
# Test: linker error fallback finds split _extra_* keys
########################################################################
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - "$tmp_dir" <<'PY'
import os, pickle, sys
from pathlib import Path

tmp = sys.argv[1]
sys.path.insert(0, str(Path.cwd() / "script"))
sys.path.insert(0, str(Path.cwd() / "script" / "react_agent"))

from multi_agent import _group_errors_by_patch_key
from migration_tools.types import PatchInfo

# Bundle with split keys (no unsplit _extra_hfile.c)
patches = {}
patches["_extra_hfile.c__h50"] = PatchInfo(
    file_path_old="hfile.c", file_path_new="hfile.c",
    patch_text=(
        "diff --git a/hfile.c b/hfile.c\n"
        "--- a/hfile.c\n"
        "+++ b/hfile.c\n"
        "@@ -50,3 +50,4 @@\n"
        " ctx\n"
        "-old\n"
        "+new1\n"
        "+new2\n"
    ),
    file_type="c",
    old_start_line=50, old_end_line=52,
    new_start_line=50, new_end_line=53,
    patch_type={"Extra"},
)
patches["_extra_hfile.c__h200"] = PatchInfo(
    file_path_old="hfile.c", file_path_new="hfile.c",
    patch_text=(
        "diff --git a/hfile.c b/hfile.c\n"
        "--- a/hfile.c\n"
        "+++ b/hfile.c\n"
        "@@ -200,3 +201,4 @@\n"
        " ctx\n"
        "-old\n"
        "+new1\n"
        "+new2\n"
    ),
    file_type="c",
    old_start_line=200, old_end_line=202,
    new_start_line=201, new_end_line=204,
    patch_type={"Extra"},
)

bundle_path = os.path.join(tmp, "test_split_linker.patch2")
with open(bundle_path, "wb") as f:
    f.write(pickle.dumps(patches, protocol=pickle.HIGHEST_PROTOCOL))

build_log = """\
/usr/bin/ld: libhts.a(hfile.o): in function `haddextension':
hfile.c:(.text.haddextension[haddextension]+0x148): undefined reference to `__revert_abc123_ks_resize'
clang++: error: linker command failed with exit code 1
"""

groups = _group_errors_by_patch_key(build_log_text=build_log, patch_path=bundle_path)

# Should fall back to the first split key (_extra_hfile.c__h50)
assert "_extra_hfile.c__h50" in groups, f"Expected _extra_hfile.c__h50, got: {sorted(groups.keys())}"
assert "_extra_hfile.c" not in groups, f"Unsplit key should not be created: {sorted(groups.keys())}"

print("  linker error fallback to split _extra_* keys OK")
PY

########################################################################
# Test: _infer_extra_patch_key finds split variants
########################################################################
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" - "$tmp_dir" <<'PY'
import os, pickle, sys
from pathlib import Path
from types import SimpleNamespace

tmp = sys.argv[1]
sys.path.insert(0, str(Path.cwd() / "script"))
sys.path.insert(0, str(Path.cwd() / "script" / "react_agent"))

from tools.extra_patch_tools import _infer_extra_patch_key
from migration_tools.types import PatchInfo

# Bundle with split keys only
patches = {}
patches["_extra_foo.c__h10"] = PatchInfo(
    file_path_old="foo.c", file_path_new="foo.c",
    patch_text="@@ -10,3 +10,4 @@\n ctx\n",
    file_type="c",
    old_start_line=10, old_end_line=12,
    new_start_line=10, new_end_line=13,
    patch_type={"Extra"},
)
patches["_extra_foo.c__h100"] = PatchInfo(
    file_path_old="foo.c", file_path_new="foo.c",
    patch_text="@@ -100,3 +101,4 @@\n ctx\n",
    file_type="c",
    old_start_line=100, old_end_line=102,
    new_start_line=101, new_end_line=104,
    patch_type={"Extra"},
)

bundle = SimpleNamespace(patches=patches)

result = _infer_extra_patch_key(bundle=bundle, file_path="/src/project/foo.c")
assert result == "_extra_foo.c__h10", f"Expected _extra_foo.c__h10, got: {result}"

# With unsplit key present, should prefer it
patches["_extra_bar.c"] = PatchInfo(
    file_path_old="bar.c", file_path_new="bar.c",
    patch_text="@@ -5,3 +5,4 @@\n ctx\n",
    file_type="c",
    old_start_line=5, old_end_line=7,
    new_start_line=5, new_end_line=8,
    patch_type={"Extra"},
)
result2 = _infer_extra_patch_key(bundle=bundle, file_path="bar.c")
assert result2 == "_extra_bar.c", f"Expected _extra_bar.c, got: {result2}"

# With no matching keys, should return synthesized name
result3 = _infer_extra_patch_key(bundle=bundle, file_path="unknown.c")
assert result3 == "_extra_unknown.c", f"Expected _extra_unknown.c, got: {result3}"

print("  _infer_extra_patch_key with split variants OK")
PY

echo "OK"
