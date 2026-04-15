#!/usr/bin/env python3
"""Offline dispatch-wrapped merge of per-bug transplant patches.

Pre-wraps each bug's patch with dispatch gating before merging so bugs
can coexist without runtime interference. Each bug gets a bit in
__bug_dispatch[]; the fuzzer reads the dispatch byte from the first
byte(s) of the test input.

Usage:
    sudo -E python3 script/bug_transplant_merge_offline.py \
        --summary data/bug_transplant/batch_c-blosc2_79e921d9/summary.json \
        --bug_info osv_testcases_summary.json \
        --target c-blosc2 \
        --testcases-dir ~/oss-fuzz-for-select/pocs/tmp/ \
        --build_csv ~/log/c-blosc2_builds.csv
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR.parent / "data"
HOME_DIR = Path.home()

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# Import shared utilities from the existing merge script
sys.path.insert(0, str(SCRIPT_DIR))
from bug_transplant_merge import (
    _load_prompt,
    _exec,
    _exec_capture,
    _compile_cmd,
    _inject_dispatch_files,
    _apply_all_dispatch_bytes as _apply_all_dispatch_bytes_orig,
    _ensure_dispatch_capacity,
    _modify_harness_for_dispatch,
    _restore_testcases,
    _stage_untracked_source,
    start_merge_container,
    verify_bug_triggers,
    verify_all_bugs,
    _find_crash_log,
    compute_merge_order,
    files_in_diff,
    known_harness_source_paths,
    _prepare_container_testcases_dir,
    _save_work_testcase_to_host,
    CONTAINER_TESTCASES_DIR,
)


def _apply_all_dispatch_bytes(container, dispatch_state):
    """Prepend dispatch bytes to PoCs in /work/.

    Idempotent: compares the file size in /work/ against the pristine
    original in /testcases/.  If the file is already larger (i.e. the
    prefix was prepended by a previous call), it is left unchanged.

    The old implementation used ``d.startswith(prefix)`` which is a
    false-positive for zero-valued dispatch bytes (local bugs) when the
    testcase content naturally starts with 0x00 (e.g. H.264 NAL streams).
    """
    nbytes = dispatch_state.get("dispatch_bytes", 1)
    for bug_id, dval in dispatch_state["poc_bytes"].items():
        testcase = f"testcase-{bug_id}"
        prefix = dval.to_bytes(nbytes, "little")
        prefix_list = ",".join(str(b) for b in prefix)
        _exec_capture(
            container,
            f"if [ ! -f /work/{testcase} ]; then cp "
            f"{CONTAINER_TESTCASES_DIR}/{testcase} /work/{testcase}"
            f" 2>/dev/null; fi; python3 -c \""
            f"import os; p=bytes([{prefix_list}]); "
            f"orig=os.path.getsize('{CONTAINER_TESTCASES_DIR}/{testcase}') "
            f"if os.path.exists('{CONTAINER_TESTCASES_DIR}/{testcase}') else -1; "
            f"d=open('/work/{testcase}','rb').read(); "
            f"open('/work/{testcase}','wb').write(d if len(d)!=orig else p+d)\"",
        )


def _resolve_host_testcase_bytes(
    project: str,
    bug: dict,
    staged_dir: Path,
) -> bytes | None:
    """Return the host testcase bytes that should back `/work/<testcase>`."""
    testcase_name = bug.get("testcase", f"testcase-{bug['bug_id']}")
    explicit_patched = bug.get("patched_testcase")
    if explicit_patched and Path(explicit_patched).is_file():
        return Path(explicit_patched).read_bytes()

    out_dir = DATA_DIR / "bug_transplant" / f"{project}_{bug['bug_id']}"
    if out_dir.exists():
        for tc in out_dir.glob(f"{testcase_name}*"):
            if tc.is_file() and tc.stat().st_size > 0:
                return tc.read_bytes()

    staged_path = staged_dir / testcase_name
    if staged_path.is_file():
        return staged_path.read_bytes()
    return None


def _restore_testcases_with_dispatch(
    container: str,
    project: str,
    bugs: list[dict],
    staged_dir: Path,
    dispatch_state: dict,
) -> None:
    """Restore testcases and always write the exact dispatch-prefixed bytes.

    The generic size-based idempotence check breaks when a bug's minimized
    testcase differs in size from the original staged testcase. In that case
    it wrongly assumes dispatch bytes are already present and skips prefixing,
    so the bug-specific gate never turns on during verification.
    """
    nbytes = dispatch_state.get("dispatch_bytes", 1)
    for bug in bugs:
        testcase_name = bug.get("testcase", f"testcase-{bug['bug_id']}")
        payload = _resolve_host_testcase_bytes(project, bug, staged_dir)
        if payload is None:
            continue
        prefix = dispatch_state["poc_bytes"][bug["bug_id"]].to_bytes(nbytes, "little")
        subprocess.run(
            ["docker", "exec", "-i", container,
             "bash", "-c", f"cat > /work/{testcase_name}"],
            input=prefix + payload,
            timeout=10,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False,
        )
from bug_transplant import (
    CODEX_CONFIG, setup_codex_creds, build_codex_command, _exec_interactive,
    _source_dir,
)
from codex_usage import CodexUsageTracker

# Pathspecs to exclude build artifacts from git diff
_DIFF_EXCLUDES = (
    "':(exclude)CMakeFiles/' ':(exclude)*/CMakeFiles/' "
    "':(exclude)CMakeCache.txt' ':(exclude)cmake_install.cmake' "
    "':(exclude)*/cmake_install.cmake' ':(exclude)CTestTestfile.cmake' "
    "':(exclude)*/CTestTestfile.cmake' ':(exclude)CPackConfig.cmake' "
    "':(exclude)CPackSourceConfig.cmake' ':(exclude)cmake_uninstall.cmake' "
    "':(exclude)Makefile' ':(exclude)*/Makefile' "
    "':(exclude)*.o' ':(exclude)*.a' ':(exclude)*.so' ':(exclude)*.so.*' "
    "':(exclude)*.d' ':(exclude)*.pc' ':(exclude)config.h' "
    "':(exclude)blosc/config.h' "
    "':(exclude)build/' ':(exclude)_build/' "
    "':(exclude)obj/' ':(exclude)obj*' ':(exclude)bin/' "
    "':(exclude)tiff-config*' "
    "':(exclude)cups/' ':(exclude)freetype/' ':(exclude)zlib/' "
    "':(exclude)examples/' "
    "':(exclude).codex/'"
)
_DIFF_INCLUDES = (
    "'*.c' '*.h' '*.cc' '*.cpp' '*.cxx' '*.hpp' '*.hh' '*.hxx' "
    "'*.cmake' '*.sh' "
    "'CMakeLists.txt' 'Makefile.am' '*/Makefile.am'"
)


# Session-wide token/cost tracker (shared across all codex invocations)
_usage_tracker = CodexUsageTracker()


def _strip_build_artifact_hunks(diff_text: str) -> str:
    """Remove diff hunks for build-artifact paths (CMakeFiles/, etc.)."""
    import re
    # Split into per-file sections on 'diff --git' boundaries
    parts = re.split(r'(?=^diff --git )', diff_text, flags=re.MULTILINE)
    artifact_header = re.compile(
        r"^diff --git a/(?:"
        r"cups/|freetype/|zlib/|examples/|"
        r"obj(?:[./-]|$)|obj\.stale-root-[^/]+/|"
        r"tiff-config(?:[./-]|$)|tiff-config\.stale-root-[^/]+/|"
        r"(?:.*/)?CMakeFiles/|"
        r".*\.o$|.*\.a$|.*\.so(?:\..*)?$"
        r")",
        re.MULTILINE,
    )
    kept = [p for p in parts if not artifact_header.search(p.split('\n', 1)[0])]
    return ''.join(kept)


def _clean_diff(container: str, project: str) -> str:
    """Get a clean git diff excluding build artifacts."""
    _stage_untracked_source(container, project)
    _, diff = _exec_capture(
        container,
        f"cd {_source_dir(project)} && git diff HEAD -- {_DIFF_INCLUDES} {_DIFF_EXCLUDES}",
    )
    return _strip_build_artifact_hunks(diff)


def _clean_diff_against(container: str, project: str, base_rev: str) -> str:
    """Get a clean git diff against a specific baseline revision."""
    _stage_untracked_source(container, project)
    _, diff = _exec_capture(
        container,
        f"cd {_source_dir(project)} && git diff {shlex.quote(base_rev)} -- {_DIFF_INCLUDES} {_DIFF_EXCLUDES}",
    )
    return _strip_build_artifact_hunks(diff)


def _save_source_snapshot(container: str, project: str) -> None:
    """Save a git stash snapshot of the source tree."""
    _exec_capture(container,
                  f"cd {_source_dir(project)} && git add -A && "
                  f"git stash push -m snapshot --include-untracked 2>/dev/null; true")


def _restore_source_snapshot(container: str, project: str) -> None:
    """Restore the most recent source snapshot."""
    _exec_capture(container,
                  f"cd {_source_dir(project)} && git checkout -f HEAD && "
                  f"git stash pop 2>/dev/null; true")


def _clean_container_working_tree_before_harness_diff(container: str, project: str) -> None:
    """Reset /src/<project> before reapplying a saved harness diff."""
    _exec_capture(
        container,
        f"cd {_source_dir(project)} && "
        "(git reset --hard HEAD 2>/dev/null || true) && "
        "(git clean -fdx -e '*.tar.gz' -e '*.tar.bz2' -e '*.tar.xz' -e '*.zip' 2>/dev/null || true) && "
        "rm -f __bug_dispatch.c __bug_dispatch.h 2>/dev/null || true",
    )


def _create_harness_baseline_commit(container: str, project: str) -> str:
    """Create a temporary commit for the harness-applied baseline."""
    ret, out = _exec_capture(
        container,
        f"cd {_source_dir(project)} && "
        "git add -A && "
        "git -c user.name='Codex' -c user.email='codex@example.com' "
        "commit --allow-empty -m 'codex harness baseline' >/dev/null 2>&1 && "
        "git rev-parse HEAD 2>/dev/null",
    )
    if ret != 0:
        raise RuntimeError(f"failed to create harness baseline commit: {out[-500:]}")
    # Extract the SHA — filter out git warnings (e.g. line-ending messages)
    # that may appear in captured stderr.
    for line in reversed(out.strip().splitlines()):
        line = line.strip()
        if len(line) >= 40 and all(c in '0123456789abcdef' for c in line[:40]):
            return line
    raise RuntimeError(f"no valid SHA found in harness baseline output: {out[-500:]}")


def _restore_harness_baseline(container: str, project: str, baseline_rev: str) -> None:
    """Restore the exact harness baseline snapshot."""
    ret, out = _exec_capture(
        container,
        f"cd {_source_dir(project)} && "
        f"git checkout -f {shlex.quote(baseline_rev)} >/dev/null 2>&1 && "
        f"git reset --hard {shlex.quote(baseline_rev)} >/dev/null 2>&1 && "
        "git clean -fdx -e '*.tar.gz' -e '*.tar.bz2' -e '*.tar.xz' -e '*.zip' >/dev/null 2>&1 || true",
    )
    if ret != 0:
        raise RuntimeError(f"failed to restore harness baseline: {out[-500:]}")

_MAX_WRAP_RETRIES = 1


def _patch_build_sh_for_project(content: str, project: str) -> str:
    """Apply project-specific build.sh hygiene before repeated compiles."""
    if project == "ntopng":
        # json-c's side build directory can survive between compiles when
        # containers are reused.
        content = re.sub(
            r"^(\s*)mkdir\s+build\s*$",
            r"\1mkdir -p build",
            content,
            flags=re.MULTILINE,
        )

    if project != "ghostscript":
        return content

    patched: list[str] = []
    for line in content.splitlines(keepends=True):
        stripped = line.strip()
        # Ghostscript's OSS-Fuzz build.sh destructively removes tracked source
        # directories. In merge mode those removals pollute git diff and break
        # resume, so keep the vendored directories in place.
        if re.match(r"^rm -rf (cups/libs|freetype|zlib)(?:\s|$)", stripped):
            continue
        patched.append(line)

    content = "".join(patched)
    content = re.sub(
        r"^mv \$SRC/freetype freetype$",
        'if [ ! -d freetype ] && [ -d "$SRC/freetype" ]; then cp -a "$SRC/freetype" freetype; fi',
        content,
        flags=re.MULTILINE,
    )
    content = re.sub(
        r"^if \[ -d \"\$SRC/freetype\" \]; then cp -a \"\$SRC/freetype\" freetype; fi$",
        'if [ ! -d freetype ] && [ -d "$SRC/freetype" ]; then cp -a "$SRC/freetype" freetype; fi',
        content,
        flags=re.MULTILINE,
    )
    return content


def _patch_build_sh_make_tolerant(content: str, project: str) -> str:
    """Patch build.sh for repeated merge compiles.

    Dispatch-wrapped library sources reference ``__bug_dispatch`` which is
    only linked into fuzz targets.  Non-fuzzer binaries (e.g. ndpiReader)
    will fail to link — but that's harmless.  ``make -k || true`` lets the
    build continue past those failures, and the fuzz-target existence
    check ensures we catch real compilation errors.
    """
    content = _patch_build_sh_for_project(content, project)
    lines = content.splitlines(keepends=True)
    patched: list[str] = []
    for line in lines:
        stripped = line.strip()
        # Match bare "make" or "make -jN" / "make -j$(nproc)" but not
        # "make install", "make -C subdir", "make clean", etc.
        if re.match(r'^make\s*(-j\S*)?\s*$', stripped):
            indent = line[:len(line) - len(line.lstrip())]
            patched.append(f"{indent}{stripped} -k 2>&1 || true\n")
        else:
            patched.append(line)
    return "".join(patched)


def _save_build_sh(container: str, output_dir: Path, project: str) -> None:
    """Snapshot /src/build.sh so it can be restored on resume.

    The agent may modify /src/build.sh to compile __bug_dispatch.c, but
    that file lives outside the project git repo and isn't captured by
    ``git diff``.  We save it alongside harness.diff.
    """
    ret, content = _exec_capture(container, "cat /src/build.sh 2>/dev/null")
    if ret != 0:
        return
    content = _patch_build_sh_make_tolerant(content, project)
    dst = output_dir / "harness_build.sh"
    dst.write_text(content)
    logger.info("Saved /src/build.sh (%d bytes) to %s", len(content), dst)


def _restore_build_sh(container: str, output_dir: Path, project: str) -> None:
    """Restore a previously saved /src/build.sh into the container."""
    src = output_dir / "harness_build.sh"
    if not src.exists():
        return
    content = _patch_build_sh_make_tolerant(src.read_text(errors='replace'), project)
    _exec_capture(
        container,
        f"cat > /src/build.sh << 'BUILDEOF'\n{content}BUILDEOF",
    )
    _exec_capture(container, "chmod +x /src/build.sh")
    logger.info("Restored /src/build.sh from %s", src)


def _candidate_fuzzer_source_paths(project: str, fuzzer: str) -> list[str]:
    """Return likely OSS-Fuzz harness source paths for a fuzzer."""
    exts = ("cc", "cpp", "cxx", "c")
    roots = ["/src", _source_dir(project), f"/src/{project}"]
    paths: list[str] = known_harness_source_paths(project, fuzzer)
    for root in roots:
        for ext in exts:
            paths.append(f"{root}/{fuzzer}.{ext}")
    return list(dict.fromkeys(paths))


def _find_harness_source_paths(
    container: str,
    project: str,
    fuzzer: str,
) -> list[str]:
    """Find existing harness source files for the primary fuzzer."""
    candidates = " ".join(
        shlex.quote(path) for path in _candidate_fuzzer_source_paths(project, fuzzer)
    )
    ret, out = _exec_capture(
        container,
        "for p in "
        f"{candidates}"
        "; do [ -f \"$p\" ] && grep -q 'LLVMFuzzerTestOneInput' \"$p\" "
        "&& printf '%s\n' \"$p\"; done",
    )
    paths = [line.strip() for line in out.splitlines() if line.strip()] if ret == 0 else []
    if paths:
        return list(dict.fromkeys(paths))

    ret, out = _exec_capture(
        container,
        f"find /src {_source_dir(project)} -maxdepth 3 -type f "
        f"\\( -name {shlex.quote(fuzzer + '.cc')} "
        f"-o -name {shlex.quote(fuzzer + '.cpp')} "
        f"-o -name {shlex.quote(fuzzer + '.cxx')} "
        f"-o -name {shlex.quote(fuzzer + '.c')} \\) "
        "-exec grep -l 'LLVMFuzzerTestOneInput' {} \\; 2>/dev/null",
    )
    return list(dict.fromkeys(line.strip() for line in out.splitlines() if line.strip()))


def _harness_source_sets_dispatch(
    container: str,
    source_path: str,
) -> bool:
    """Return True when a harness source copies input bytes into __bug_dispatch."""
    qpath = shlex.quote(source_path)
    ret, _ = _exec_capture(
        container,
        "grep -q 'LLVMFuzzerTestOneInput' "
        f"{qpath} && grep -q '__bug_dispatch' {qpath} && "
        "grep -Eq 'memcpy[[:space:]]*\\([^;]*__bug_dispatch|"
        "__bug_dispatch\\[[^]]+\\][[:space:]]*=' "
        f"{qpath}",
    )
    return ret == 0


def _harness_dispatch_consumer_present(
    container: str,
    project: str,
    fuzzer: str,
) -> bool:
    """Return True if the primary fuzzer consumes dispatch bytes."""
    return any(
        _harness_source_sets_dispatch(container, path)
        for path in _find_harness_source_paths(container, project, fuzzer)
    )


def _harness_sources_dir(output_dir: Path) -> Path:
    return output_dir / "harness_sources"


def _harness_sources_manifest(output_dir: Path) -> Path:
    return _harness_sources_dir(output_dir) / "manifest.json"


def _snapshot_name(container_path: str) -> str:
    return container_path.strip("/").replace("/", "__")


def _save_harness_sources(
    container: str,
    project: str,
    fuzzer: str,
    output_dir: Path,
) -> bool:
    """Save out-of-repo harness sources that git diff cannot capture."""
    snapshot_dir = _harness_sources_dir(output_dir)
    snapshot_dir.mkdir(exist_ok=True)
    manifest = []

    for source_path in _find_harness_source_paths(container, project, fuzzer):
        if not _harness_source_sets_dispatch(container, source_path):
            continue
        ret, content = _exec_capture(container, f"cat {shlex.quote(source_path)}")
        if ret != 0:
            continue
        snapshot = _snapshot_name(source_path)
        (snapshot_dir / snapshot).write_text(content)
        manifest.append({"container_path": source_path, "snapshot": snapshot})

    if not manifest:
        logger.warning("No dispatch-consuming harness source snapshot saved")
        return False

    _harness_sources_manifest(output_dir).write_text(json.dumps(manifest, indent=2))
    logger.info("Saved %d harness source snapshot(s) to %s", len(manifest), snapshot_dir)
    return True


def _restore_harness_sources(container: str, output_dir: Path) -> bool:
    """Restore saved out-of-repo harness sources into a fresh container."""
    manifest_path = _harness_sources_manifest(output_dir)
    if not manifest_path.exists():
        return False

    restored = 0
    for entry in json.loads(manifest_path.read_text()):
        container_path = entry["container_path"]
        snapshot = _harness_sources_dir(output_dir) / entry["snapshot"]
        if not snapshot.exists():
            continue
        if _container_write_text(container, container_path, snapshot.read_text(errors='replace')):
            restored += 1

    if restored:
        logger.info("Restored %d harness source snapshot(s)", restored)
    return restored > 0


def _inject_dispatch_deps_fixer(container: str) -> None:
    """Inject a helper script + build.sh hook that creates autotools dep stubs.

    When Makefile.am references $(top_srcdir)/__bug_dispatch.c, autotools
    generates ``include .deps/<prefix>__bug_dispatch.P{o,lo}`` but never
    creates the top-level ``.deps/`` directory.  This writes a helper that
    scans generated Makefiles for those targets and touches them, then
    injects a one-line call in build.sh right before ``make``.
    """
    _exec_capture(
        container,
        "cat > /tmp/_fix_dispatch_deps.sh << 'FIXEOF'\n"
        "#!/bin/bash\n"
        "mkdir -p .deps\n"
        "grep -rh '__bug_dispatch.*\\.Pl\\|__bug_dispatch.*\\.Po' "
        "  */Makefile */*/Makefile */*/*/Makefile 2>/dev/null | "
        "grep -oE '[^ ]*__bug_dispatch[^ ]*' | sort -u | "
        "while read p; do mkdir -p $(dirname \"$p\") && touch \"$p\"; done\n"
        "FIXEOF\n"
        "chmod +x /tmp/_fix_dispatch_deps.sh",
    )
    _exec_capture(
        container,
        "grep -q '_fix_dispatch_deps' /src/build.sh 2>/dev/null || "
        "sed -i '/^make/i /tmp/_fix_dispatch_deps.sh' /src/build.sh",
    )


_MAKEFILE_SOURCES_RE = re.compile(r"^\s*[\w@.-]+_SOURCES\s*(?:\+?=|:=)")


def _container_write_text(container: str, path: str, content: str) -> bool:
    """Write text into a file inside the running container."""
    result = subprocess.run(
        ["docker", "exec", "-i", container, "bash", "-c", f"cat > {shlex.quote(path)}"],
        input=content.encode("utf-8"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    if result.returncode == 0:
        return True
    logger.warning(
        "Failed to write %s inside %s: %s",
        path, container, result.stderr.decode("utf-8", errors="replace")[-200:],
    )
    return False


def _iter_makefile_source_blocks(lines: list[str]) -> list[tuple[int, int]]:
    """Return inclusive line ranges for ``*_SOURCES`` assignments."""
    blocks: list[tuple[int, int]] = []
    i = 0
    while i < len(lines):
        if not _MAKEFILE_SOURCES_RE.match(lines[i]):
            i += 1
            continue
        start = i
        while lines[i].rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
        blocks.append((start, i))
        i += 1
    return blocks


def _patch_makefile_dispatch_source(
    content: str,
    source_markers: set[str],
) -> tuple[str, bool]:
    """Add ``$(top_srcdir)/__bug_dispatch.c`` to matching Makefile blocks."""
    lines = content.splitlines()
    changed = False

    for marker in sorted(source_markers):
        marker_name = PurePosixPath(marker).name
        for start, end in _iter_makefile_source_blocks(lines):
            block = lines[start:end + 1]
            block_text = "\n".join(block)
            if "__bug_dispatch.c" in block_text:
                if marker in block_text or marker_name in block_text:
                    break
                continue
            if marker not in block_text and marker_name not in block_text:
                continue

            if start == end and not lines[end].rstrip().endswith("\\"):
                lines[start] = f"{lines[start]} $(top_srcdir)/__bug_dispatch.c"
            else:
                if not lines[end].rstrip().endswith("\\"):
                    lines[end] = f"{lines[end]} \\"
                lines.insert(end + 1, "\t$(top_srcdir)/__bug_dispatch.c")
            changed = True
            break

    new_content = "\n".join(lines)
    if content.endswith("\n"):
        new_content += "\n"
    return new_content, changed


def _ensure_dispatch_linked_everywhere(container: str, project: str) -> None:
    """Ensure __bug_dispatch.c is compiled into libraries, not just fuzzers.

    Per-bug patches may add ``#include "__bug_dispatch.h"`` to library
    source files (e.g. libopensc).  Non-fuzzer tools that link the
    library will fail with undefined ``__bug_dispatch`` unless the
    object is also part of the library.  This function finds every
    Makefile.am that builds a library whose sources were patched and
    adds __bug_dispatch.c to it.
    """
    # Find all source files that reference __bug_dispatch after wrapping.
    ret, out = _exec_capture(
        container,
        f"cd {_source_dir(project)} && "
        "git grep -l '__bug_dispatch' -- '*.c' '*.cc' '*.cpp' '*.cxx' "
        "':(exclude)__bug_dispatch.c' 2>/dev/null",
    )
    if ret != 0 or not out.strip():
        return

    repo_root = PurePosixPath(_source_dir(project))
    makefile_cache: dict[str, str] = {}
    makefile_sources: dict[str, set[str]] = {}

    for rel_source in out.strip().splitlines():
        rel_source = rel_source.strip()
        if not rel_source:
            continue

        source_path = PurePosixPath(rel_source)
        for parent in source_path.parents:
            makefile_rel = (
                PurePosixPath("Makefile.am")
                if str(parent) == "."
                else parent / "Makefile.am"
            )
            makefile_rel_str = makefile_rel.as_posix()
            makefile_abs = (repo_root / makefile_rel).as_posix()
            if makefile_rel_str not in makefile_cache:
                ret2, makefile = _exec_capture(
                    container,
                    f"cat {shlex.quote(makefile_abs)} 2>/dev/null",
                )
                if ret2 != 0:
                    continue
                makefile_cache[makefile_rel_str] = makefile
            makefile = makefile_cache[makefile_rel_str]
            if "_SOURCES" not in makefile:
                continue

            parent_dir = "." if str(parent) == "." else parent.as_posix()
            rel_from_makefile = posixpath.relpath(source_path.as_posix(), parent_dir)
            if rel_from_makefile not in makefile and source_path.name not in makefile:
                continue

            makefile_sources.setdefault(makefile_rel_str, set()).add(rel_from_makefile)
            break

    for makefile_rel, source_markers in sorted(makefile_sources.items()):
        updated, changed = _patch_makefile_dispatch_source(
            makefile_cache[makefile_rel],
            source_markers,
        )
        if not changed:
            continue
        makefile_abs = (repo_root / PurePosixPath(makefile_rel)).as_posix()
        if _container_write_text(container, makefile_abs, updated):
            logger.info("Added __bug_dispatch.c to %s", makefile_rel)

    _inject_dispatch_deps_fixer(container)


# build_codex_command is now imported from bug_transplant


# ---------------------------------------------------------------------------
# Bug loading and categorization
# ---------------------------------------------------------------------------

_OSV_ID_RE = re.compile(r"^OSV-(\d+)-(\d+)$")


def _bug_id_sort_key(bug: dict) -> tuple[int, int, str]:
    """Sort OSV IDs numerically so dispatch bit assignment is stable."""
    bug_id = bug.get("bug_id", "")
    match = _OSV_ID_RE.match(bug_id)
    if not match:
        return (sys.maxsize, sys.maxsize, bug_id)
    return (int(match.group(1)), int(match.group(2)), bug_id)


def load_and_categorize_bugs(
    summary_path: str,
    bug_info_path: str,
    project: str,
    local_bug_overrides: list[str] | None = None,
    testcases_dir: str | None = None,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Load bugs and split into local, testcase-only, and diff bugs.

    Returns (local_bugs, testcase_only_bugs, diff_bugs).
    """
    with open(summary_path) as f:
        summary = json.load(f)
    with open(bug_info_path) as f:
        bug_info_dataset = json.load(f)

    target_commit = summary["target_commit"]
    bug_transplant_dir = DATA_DIR / "bug_transplant"

    # --- Local bugs (already trigger at target) ---
    local_bug_ids = set(local_bug_overrides or summary.get("bugs_already_trigger_ids", []))
    local_bugs = []
    for bid in local_bug_ids:
        info = bug_info_dataset.get(bid, {})
        reproduce = info.get("reproduce", {})
        fuzzer = reproduce.get("fuzz_target", "")
        sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
        if not fuzzer:
            continue
        crash_log = _find_crash_log(bid, info)
        local_bugs.append({
            "bug_id": bid,
            "fuzzer": fuzzer,
            "testcase": f"testcase-{bid}",
            "sanitizer": sanitizer,
            "crash_log": crash_log,
            "type": "local",
        })

    # --- Transplanted bugs ---
    testcase_only_bugs = []
    diff_bugs = []
    seen = set(local_bug_ids)

    for result in summary.get("results", []):
        bid = result.get("bug_id", "")
        if not bid or bid in seen:
            continue
        if result.get("status") not in (None, "success"):
            continue

        out_dir = bug_transplant_dir / f"{project}_{bid}"
        if not out_dir.exists():
            continue

        # Skip impossible
        if (out_dir / "bug_transplant.impossible").exists():
            logger.info("Skipping %s: declared impossible", bid)
            continue

        # Find diff
        diff_path = None
        for name in ("bug_transplant.diff", "git_diff.diff"):
            p = out_dir / name
            if p.exists():
                diff_path = str(p)
                break

        has_diff = diff_path and Path(diff_path).stat().st_size > 0

        # Find patched testcase
        patched_testcase = None
        for tc in out_dir.glob(f"testcase-{bid}*"):
            if tc.is_file() and tc.stat().st_size > 0:
                patched_testcase = str(tc)
                break

        if not has_diff and not patched_testcase:
            continue

        info = bug_info_dataset.get(bid, {})
        reproduce = info.get("reproduce", {})
        fuzzer = reproduce.get("fuzz_target", "")
        sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
        if sanitizer not in ("address", "undefined"):
            continue
        if not fuzzer:
            continue

        crash_log = _find_crash_log(bid, info)
        seen.add(bid)

        entry = {
            "bug_id": bid,
            "diff_path": diff_path if has_diff else None,
            "patched_testcase": patched_testcase,
            "fuzzer": fuzzer,
            "testcase": f"testcase-{bid}",
            "sanitizer": sanitizer,
            "crash_log": crash_log,
            "type": "transplant",
        }

        if has_diff:
            diff_bugs.append(entry)
        else:
            testcase_only_bugs.append(entry)

    # Also scan disk for bug dirs not in summary
    for d in bug_transplant_dir.iterdir():
        if not d.is_dir() or not d.name.startswith(f"{project}_"):
            continue
        bid = d.name[len(f"{project}_"):]
        if bid in seen:
            continue
        if (d / "bug_transplant.impossible").exists():
            continue

        diff_path = None
        for name in ("bug_transplant.diff", "git_diff.diff"):
            p = d / name
            if p.exists():
                diff_path = str(p)
                break
        has_diff = diff_path and Path(diff_path).stat().st_size > 0

        patched_testcase = None
        for tc in d.glob(f"testcase-{bid}*"):
            if tc.is_file() and tc.stat().st_size > 0:
                patched_testcase = str(tc)
                break

        if not has_diff and not patched_testcase:
            continue

        info = bug_info_dataset.get(bid, {})
        reproduce = info.get("reproduce", {})
        fuzzer = reproduce.get("fuzz_target", "")
        sanitizer = reproduce.get("sanitizer", "address").split(" ")[0]
        if sanitizer not in ("address", "undefined") or not fuzzer:
            continue

        crash_log = _find_crash_log(bid, info)
        seen.add(bid)

        entry = {
            "bug_id": bid,
            "diff_path": diff_path if has_diff else None,
            "patched_testcase": patched_testcase,
            "fuzzer": fuzzer,
            "testcase": f"testcase-{bid}",
            "sanitizer": sanitizer,
            "crash_log": crash_log,
            "type": "transplant",
        }
        if has_diff:
            diff_bugs.append(entry)
        else:
            testcase_only_bugs.append(entry)

    local_bugs.sort(key=_bug_id_sort_key)
    testcase_only_bugs.sort(key=_bug_id_sort_key)
    diff_bugs.sort(key=_bug_id_sort_key)
    return local_bugs, testcase_only_bugs, diff_bugs


# ---------------------------------------------------------------------------
# Dispatch bit assignment
# ---------------------------------------------------------------------------

def assign_dispatch_bits(
    diff_bugs: list[dict],
    local_bugs: list[dict],
    testcase_only_bugs: list[dict],
) -> dict:
    """Assign dispatch bits to bugs with diffs. Return dispatch_state."""
    dispatch_bytes = max(1, (len(diff_bugs) - 1) // 8 + 1) if diff_bugs else 1
    poc_bytes: dict[str, int] = {}

    # Diff bugs get bits
    bits = {}
    for i, bug in enumerate(diff_bugs):
        bits[i] = {"bug_id": bug["bug_id"]}
        poc_bytes[bug["bug_id"]] = 1 << i

    # Local + testcase-only bugs get dispatch value 0 (no bit set)
    for bug in local_bugs + testcase_only_bugs:
        poc_bytes[bug["bug_id"]] = 0

    return {
        "next_bit": len(diff_bugs),
        "dispatch_bytes": dispatch_bytes,
        "bits": bits,
        "poc_bytes": poc_bytes,
        "harness_modified": False,
        "dispatch_file_injected": False,
    }


# ---------------------------------------------------------------------------
# Per-bug offline wrapping
# ---------------------------------------------------------------------------

def wrap_bug_with_dispatch(
    container: str,
    project: str,
    bug: dict,
    bit_index: int,
    dispatch_state: dict,
    model: str | None = None,
    codex_mode: str = "exec",
) -> tuple[bool, str]:
    """Invoke codex to wrap a bug's patch with dispatch gating.

    Returns (success, output).
    """
    bug_id = bug["bug_id"]
    diff_path = bug["diff_path"]
    dispatch_bit = bit_index % 8
    dispatch_byte = bit_index // 8
    dispatch_value = 1 << bit_index

    # Copy diff into container
    diff_content = Path(diff_path).read_text(errors='replace')
    _exec_capture(
        container,
        f"cat > /tmp/patch_{bug_id}.diff << 'PATCH_EOF'\n{diff_content}PATCH_EOF",
    )

    # Copy testcase (patched if available, else original)
    ptc = bug.get("patched_testcase")
    if ptc and Path(ptc).exists():
        tc_data = Path(ptc).read_bytes()
        subprocess.run(
            ["docker", "exec", "-i", container,
             "bash", "-c", f"cat > /work/{bug['testcase']}"],
            input=tc_data, timeout=10,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    # Setup codex credentials
    setup_codex_creds(container)

    prompt = _load_prompt(
        "dispatch_wrap_offline",
        project=project,
        bug_id=bug_id,
        dispatch_bit=str(dispatch_bit),
        dispatch_byte=str(dispatch_byte),
        dispatch_value=str(dispatch_value),
        patch_path=f"/tmp/patch_{bug_id}.diff",
        testcase_path=f"/work/{bug['testcase']}",
        output_testcase_path=f"/work/{bug['testcase']}",
    )

    agent_cmd = build_codex_command(prompt, model, mode=codex_mode)

    logger.info("[%s] Invoking codex for dispatch wrapping (bit %d)...",
                bug_id, bit_index)
    if codex_mode == "interactive":
        ret, output = _exec_interactive(container, agent_cmd, timeout=1800)
    else:
        ret, output = _exec_capture(container, agent_cmd, timeout=1800)

    _usage_tracker.log_usage(f"{bug_id} wrap", output, model)

    if ret != 0:
        logger.error("[%s] Agent failed (exit %d)", bug_id, ret)
        return False, output

    # Verify build — clear /out/ fuzz targets first so we only see freshly built binaries.
    fuzzer_name = bug.get("fuzzer", "")
    # Remove known fuzz targets so we can verify they get rebuilt.
    _exec_capture(container, "rm -f /out/fuzz_* /out/*_fuzzer /out/*_fuzzer_* 2>/dev/null")
    ret, build_out = _exec_capture(container, _compile_cmd(container), timeout=1800)
    # Check for the specific fuzzer binary, or fall back to any *fuzzer* pattern.
    if fuzzer_name:
        ret2, fuzz_bins = _exec_capture(container, f"ls /out/{fuzzer_name} 2>/dev/null")
    else:
        ret2, fuzz_bins = _exec_capture(container, "ls /out/fuzz_* /out/*_fuzzer 2>/dev/null")
    if ret2 != 0 or not fuzz_bins.strip():
        # Fuzz targets didn't build — real failure.
        logger.error("[%s] Build failed after wrapping (fuzz targets missing)",
                     bug_id)
        logger.error("[%s] Build tail: %s",
                     bug_id, build_out[-1000:] if build_out else "(no output)")
        return False, build_out
    if ret != 0:
        logger.warning("[%s] Compile had errors but fuzz targets built OK", bug_id)

    logger.info("[%s] Dispatch wrapping OK", bug_id)
    return True, output


# ---------------------------------------------------------------------------
# Main merge logic
# ---------------------------------------------------------------------------

def run_offline_merge(args: argparse.Namespace) -> int:
    """Run the full offline dispatch merge pipeline."""
    with open(args.summary) as f:
        summary = json.load(f)
    target_commit = args.target_commit or summary["target_commit"]
    project = args.target

    # Output directory
    output_dir = DATA_DIR / "bug_transplant" / f"merge_offline_{project}_{target_commit[:8]}"
    output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 1. Load and categorize bugs
    # ------------------------------------------------------------------
    local_bugs, testcase_only_bugs, diff_bugs = load_and_categorize_bugs(
        args.summary, args.bug_info, project,
        local_bug_overrides=args.local_bugs,
        testcases_dir=args.testcases_dir,
    )

    logger.info("Local bugs: %d", len(local_bugs))
    logger.info("Testcase-only bugs: %d", len(testcase_only_bugs))
    logger.info("Bugs with diffs (need dispatch): %d", len(diff_bugs))

    all_bugs = local_bugs + testcase_only_bugs + diff_bugs
    if not all_bugs:
        logger.error("No bugs to merge")
        return 1
    primary_fuzzer = (diff_bugs + testcase_only_bugs + local_bugs)[0]["fuzzer"]
    testcase_stage_dir = _prepare_container_testcases_dir(
        args.testcases_dir,
        output_dir / "testcases",
        testcase_names=[bug["testcase"] for bug in all_bugs],
    )

    # ------------------------------------------------------------------
    # 2. Assign dispatch bits
    # ------------------------------------------------------------------
    dispatch_state = assign_dispatch_bits(diff_bugs, local_bugs, testcase_only_bugs)
    logger.info("Dispatch bits assigned: %d bits, %d bytes",
                dispatch_state["next_bit"], dispatch_state["dispatch_bytes"])

    for i, bug in enumerate(diff_bugs):
        logger.info("  bit %d → %s (value %d)",
                     i, bug["bug_id"], dispatch_state["poc_bytes"][bug["bug_id"]])

    dispatch_order = [
        dispatch_state["bits"][i]["bug_id"]
        for i in sorted(dispatch_state["bits"])
    ]
    dispatch_order_path = output_dir / "dispatch_order.json"
    reuse_wrapped_cache = False
    if dispatch_order_path.exists():
        try:
            reuse_wrapped_cache = json.loads(dispatch_order_path.read_text()) == dispatch_order
        except Exception:
            reuse_wrapped_cache = False
    if not reuse_wrapped_cache:
        logger.info(
            "Dispatch order changed or not recorded; regenerating wrapped diffs"
        )

    if args.dry_run:
        logger.info("Dry run — exiting")
        return 0

    # ------------------------------------------------------------------
    # 3. Start container
    # ------------------------------------------------------------------
    container, build_ok = start_merge_container(
        project, target_commit,
        testcases_dir=str(testcase_stage_dir),
        build_csv=args.build_csv,
        extra_volumes=args.volume,
    )
    if not build_ok:
        logger.error("Container startup / initial build failed")
        return 1

    try:
        # ------------------------------------------------------------------
        # 4. Inject dispatch files and modify harness
        # ------------------------------------------------------------------
        # If we already have a harness diff from a previous run, reuse it.
        # This avoids re-invoking a code agent unnecessarily and keeps resume
        # behavior deterministic.
        harness_diff_path = output_dir / "harness.diff"
        if getattr(args, "regenerate_harness", False):
            logger.info("Ignoring existing harness artifacts because --regenerate-harness was set")
            harness_diff_path = None
        elif harness_diff_path.exists() and harness_diff_path.stat().st_size > 0:
            logger.info("Harness diff already exists, reusing: %s", harness_diff_path)
            _clean_container_working_tree_before_harness_diff(container, project)
            # Use docker cp instead of heredoc to avoid "Argument list too long"
            # for large diffs (e.g. ghostscript's 56MB harness diff).
            subprocess.run(
                ["docker", "cp", str(harness_diff_path), f"{container}:/tmp/harness.diff"],
                check=True, timeout=30,
            )
            ret, out = _exec_capture(container,
                                     f"cd {_source_dir(project)} && git apply /tmp/harness.diff 2>&1")
            if ret != 0:
                logger.error("Failed to apply existing harness.diff")
                logger.error(out)
                return 1
            _restore_build_sh(container, output_dir, project)
            _restore_harness_sources(container, output_dir)
            # If harness_build.sh was lost, re-save from container state.
            if not (output_dir / "harness_build.sh").exists():
                _save_build_sh(container, output_dir, project)
            # The harness diff references the global __bug_dispatch[] symbol,
            # but the .c/.h that defines it live outside git and weren't
            # restored above. Inject them before the dispatch-deps Makefile
            # fixer / build, otherwise the link fails with
            # "undefined reference to __bug_dispatch".
            _inject_dispatch_files(container, project, dispatch_state["dispatch_bytes"])
            _inject_dispatch_deps_fixer(container)
            # ntopng's hand-written fuzz Makefile doesn't pick up __bug_dispatch.c
            # automatically; the saved harness_build.sh restored above doesn't
            # contain the compile+link patch either. Re-apply it on resume.
            if project == "ntopng":
                from bug_transplant_merge import _patch_ntopng_build_sh_for_dispatch
                _patch_ntopng_build_sh_for_dispatch(container)
            if not _harness_dispatch_consumer_present(container, project, primary_fuzzer):
                logger.error(
                    "Existing harness artifacts do not restore a dispatch-byte "
                    "consumer for %s. Rerun with --regenerate-harness or remove "
                    "%s and the stale wrapped/combined outputs.",
                    primary_fuzzer,
                    harness_diff_path,
                )
                return 1
            ret, out = _exec_capture(container, _compile_cmd(container), timeout=1800)
            if ret != 0:
                logger.error("Build failed after applying existing harness.diff")
                logger.error(out[-500:] if out else "(no output)")
                return 1
            dispatch_state["dispatch_file_injected"] = True
            dispatch_state["harness_modified"] = True
        else:
            harness_diff_path = None

        if harness_diff_path is None:
            _inject_dispatch_files(container, project, dispatch_state["dispatch_bytes"])
            dispatch_state["dispatch_file_injected"] = True
            ok = _modify_harness_for_dispatch(
                container, project, primary_fuzzer,
                model=args.model,
            )
            if not ok:
                logger.error("Failed to modify harness for dispatch")
                return 1
            if not _harness_dispatch_consumer_present(container, project, primary_fuzzer):
                logger.error(
                    "Harness modification completed, but %s still does not "
                    "write input dispatch bytes into __bug_dispatch",
                    primary_fuzzer,
                )
                return 1
            dispatch_state["harness_modified"] = True

            # Capture the harness diff immediately so we can re-apply it after
            # every git checkout -f during phase 1 and phase 2.
            harness_diff = _clean_diff(container, project)
            harness_diff_path = output_dir / "harness.diff"
            if harness_diff.strip():
                harness_diff_path.write_text(harness_diff)
                logger.info("Harness diff saved (%d bytes)", len(harness_diff))
            else:
                logger.warning("No harness diff captured after modification!")
                harness_diff_path = None

            # Save /src/build.sh — the agent may have modified it to
            # compile __bug_dispatch.c, but it's outside the git repo.
            _save_build_sh(container, output_dir, project)
            _save_harness_sources(container, project, primary_fuzzer, output_dir)

        harness_baseline_rev = _create_harness_baseline_commit(container, project)
        logger.info("Harness baseline commit: %s", harness_baseline_rev[:12])

        # Stash ASAN binaries (harness modification already built with ASAN)
        _exec_capture(container,
                      "mkdir -p /out/address && "
                      "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && "
                      "cp \"$f\" /out/address/; done; "
                      # Mirror auxiliary directories (ntopng's install/,
                      # data-dir/, docs/, scripts/) so the stashed binary
                      # can find them when run from /out/address/.
                      "for d in /out/*/; do "
                      "name=$(basename \"$d\"); "
                      "[ \"$name\" = address ] && continue; "
                      "[ \"$name\" = ubsan ] && continue; "
                      "ln -sfn \"$d\" \"/out/address/$name\"; done; true")
        # Copy testcases (originals + patched)
        _restore_testcases_with_dispatch(
            container, project, all_bugs, testcase_stage_dir, dispatch_state,
        )

        # Persist patched local testcases into this run's testcase dir before
        # local verification. Later restores will prefer these patched files.
        for bug in local_bugs:
            tc_name = bug["testcase"]
            staged_patched = testcase_stage_dir / f"{tc_name}-patched"
            if _save_work_testcase_to_host(container, tc_name, staged_patched):
                logger.info("[%s] Staged patched local testcase: %s",
                            bug["bug_id"], staged_patched)

        # ------------------------------------------------------------------
        # 5. Verify local bugs at baseline
        # ------------------------------------------------------------------
        logger.info("\n=== Verifying local bugs at baseline ===")
        for bug in local_bugs:
            triggers = verify_bug_triggers(
                container, bug["bug_id"], bug["fuzzer"],
                bug["testcase"], bug.get("sanitizer", "address"),
                bug.get("crash_log"),
            )
            status = "OK" if triggers else "FAIL"
            logger.info("[%s] local: %s", bug["bug_id"], status)

        # ------------------------------------------------------------------
        # 6. Verify testcase-only bugs
        # ------------------------------------------------------------------
        logger.info("\n=== Verifying testcase-only bugs ===")
        for bug in testcase_only_bugs:
            triggers = verify_bug_triggers(
                container, bug["bug_id"], bug["fuzzer"],
                bug["testcase"], bug.get("sanitizer", "address"),
                bug.get("crash_log"),
            )
            status = "OK" if triggers else "FAIL"
            logger.info("[%s] testcase-only: %s", bug["bug_id"], status)

        # ------------------------------------------------------------------
        # 7. Phase 1: Wrap each patch independently on clean source
        # ------------------------------------------------------------------
        wrapped_diffs: dict[str, str] = {}  # bug_id -> wrapped diff path
        merge_results: list[dict] = []

        # Load previously wrapped diffs from disk only if the dispatch bit
        # order is unchanged. Otherwise stale wrappers check the wrong bit.
        if reuse_wrapped_cache:
            for bd in diff_bugs:
                bid = bd["bug_id"]
                existing = output_dir / f"wrapped_{bid}.diff"
                if existing.exists() and existing.stat().st_size > 0:
                    wrapped_diffs[bid] = str(existing)
                    logger.info("[%s] Loaded existing wrapped diff (%d bytes)",
                                bid, existing.stat().st_size)

        start_step = getattr(args, "start_step", 0)
        for i, bd in enumerate(diff_bugs):
            bug_id = bd["bug_id"]
            bit_index = next(
                idx for idx, info in dispatch_state["bits"].items()
                if info["bug_id"] == bug_id
            )

            # Skip if already wrapped (resume) or before start-step
            if bug_id in wrapped_diffs:
                logger.info("[%s] Already wrapped, skipping", bug_id)
                continue
            if i < start_step:
                logger.info("[%s] Before start-step %d, skipping", bug_id, start_step)
                continue

            logger.info("\n=== Wrap %d/%d: %s (bit %d) ===",
                        i + 1, len(diff_bugs), bug_id, bit_index)

            step = {
                "step": i + 1,
                "bug_id": bug_id,
                "bit_index": bit_index,
                "success": False,
            }

            # Reset source to the exact harness baseline, then apply only the
            # bug-specific wrapped delta on top of it.
            _restore_harness_baseline(container, project, harness_baseline_rev)
            _restore_build_sh(container, output_dir, project)

            output = ""
            for attempt in range(_MAX_WRAP_RETRIES + 1):
                success, output = wrap_bug_with_dispatch(
                    container, project, bd, bit_index,
                    dispatch_state, model=args.model,
                    codex_mode=getattr(args, "codex_mode", "exec"),
                )

                if success:
                    # Extract only the delta from the harness baseline.
                    wrapped_diff = _clean_diff_against(
                        container, project, harness_baseline_rev,
                    )
                    if wrapped_diff.strip():
                        wrapped_path = output_dir / f"wrapped_{bug_id}.diff"
                        wrapped_path.write_text(wrapped_diff)
                        wrapped_diffs[bug_id] = str(wrapped_path)
                        step["success"] = True
                        logger.info("[%s] Wrapped diff saved: %s (%d bytes)",
                                    bug_id, wrapped_path, len(wrapped_diff))
                        break
                    else:
                        logger.warning("[%s] Agent produced no diff after wrapping", bug_id)

                logger.warning("[%s] Attempt %d failed, retrying...",
                               bug_id, attempt + 1)
                # Reset for retry to the exact harness baseline.
                _restore_harness_baseline(container, project, harness_baseline_rev)
                _restore_build_sh(container, output_dir, project)

            if not step["success"]:
                logger.error("[%s] FAILED after %d attempts, skipping",
                             bug_id, _MAX_WRAP_RETRIES + 1)

            step["output"] = output[-500:] if output else ""
            merge_results.append(step)
            _save_progress(output_dir, dispatch_state, merge_results,
                           list(wrapped_diffs.keys()))

        # ------------------------------------------------------------------
        # 8. Phase 2: Merge all wrapped diffs via code agent
        # ------------------------------------------------------------------
        combined_path = output_dir / "combined.diff"
        if (
            reuse_wrapped_cache
            and combined_path.exists()
            and combined_path.stat().st_size > 0
        ):
            # Reuse existing combined diff — skip the agent merge entirely.
            logger.info("combined.diff already exists, reusing: %s (%d bytes)",
                        combined_path, combined_path.stat().st_size)
            _restore_harness_baseline(container, project, harness_baseline_rev)
            cdiff = combined_path.read_text(errors='replace')
            _exec_capture(container,
                          f"cat > /tmp/combined.diff << 'CEOF'\n{cdiff}CEOF")
            ret, out = _exec_capture(
                container,
                f"cd {_source_dir(project)} && git apply /tmp/combined.diff 2>&1",
            )
            if ret != 0:
                logger.error("Failed to apply existing combined.diff: %s", out[-500:])
                return 1
            _ensure_dispatch_linked_everywhere(container, project)
            ret, out = _exec_capture(container, _compile_cmd(container), timeout=1800)
            if ret != 0:
                logger.error("Build failed after applying combined.diff: %s",
                             out[-500:] if out else "(no output)")
                return 1
            applied_bugs = list(wrapped_diffs.keys())
        else:
            logger.info("\n=== Merging %d wrapped diffs ===", len(wrapped_diffs))

            # Reset source to the exact harness baseline before merging wrapped
            # bug deltas.
            _restore_harness_baseline(container, project, harness_baseline_rev)

            # Copy all wrapped patches into container
            patch_descriptions = []
            for bug_id, wdiff_path in wrapped_diffs.items():
                diff_content = Path(wdiff_path).read_text(errors='replace')
                if not diff_content.strip():
                    continue
                fname = f"wrapped_{bug_id}.diff"
                _exec_capture(container,
                              f"cat > /tmp/{fname} << 'DIFFEOF'\n{diff_content}DIFFEOF")
                patch_descriptions.append(f"- `/tmp/{fname}` — {bug_id}")

            if not patch_descriptions:
                logger.info("No patches to merge (all were dispatch-only)")
                applied_bugs = list(wrapped_diffs.keys())
            else:
                # Use code agent to merge patches in chunks (avoid single huge prompt).
                # We keep the existing merge prompt/behavior, but run it multiple times.
                # Each chunk is merged on top of the previous chunk's result.
                max_chunk = 15
                total_patches = len(patch_descriptions)
                logger.info(
                    "Merging %d patches in chunks of <=%d via codex",
                    total_patches, max_chunk,
                )

                applied_bugs = []
                merge_failed = False
                for chunk_idx, start in enumerate(range(0, total_patches, max_chunk), start=1):
                    chunk = patch_descriptions[start:start + max_chunk]
                    patch_list = "\n".join(chunk)
                    merge_prompt = _load_prompt(
                        "merge_wrapped_patches",
                        project=project,
                        target_commit=target_commit,
                        patch_list=patch_list,
                        source_dir=_source_dir(project),
                    )

                    setup_codex_creds(container)
                    codex_mode = getattr(args, "codex_mode", "exec")
                    agent_cmd = build_codex_command(
                        merge_prompt, args.model, mode=codex_mode,
                    )

                    logger.info(
                        "Invoking codex to merge chunk %d (%d patches: %d..%d/%d)",
                        chunk_idx,
                        len(chunk),
                        start + 1,
                        min(start + len(chunk), total_patches),
                        total_patches,
                    )
                    if codex_mode == "interactive":
                        ret, output = _exec_interactive(container, agent_cmd, timeout=3600)
                    else:
                        ret, output = _exec_capture(container, agent_cmd, timeout=3600)
                    _usage_tracker.log_usage(f"merge chunk {chunk_idx}", output, args.model)
                    if ret != 0:
                        logger.error(
                            "Agent failed on chunk %d (exit %d). Output tail: %s",
                            chunk_idx, ret, output[-500:] if output else "",
                        )
                        merge_failed = True
                        break

                    # Verify build after each chunk so failures are localized.
                    ret, build_out = _exec_capture(
                        container, _compile_cmd(container), timeout=1800,
                    )
                    if ret != 0:
                        logger.error(
                            "Build failed after chunk %d: %s",
                            chunk_idx, build_out[-500:],
                        )
                        merge_failed = True
                        break

                    # Track which bug IDs were included in this chunk
                    for desc in chunk:
                        m = re.search(r"—\s+(OSV-[0-9]{4}-[0-9]+)\s*$", desc)
                        if m:
                            applied_bugs.append(m.group(1))

                if not merge_failed:
                    # If everything succeeded, consider all wrapped diffs merged.
                    applied_bugs = list(wrapped_diffs.keys())

        # Build ASAN with all patches applied
        logger.info("Building with all patches applied...")
        _ensure_dispatch_linked_everywhere(container, project)
        _exec_capture(container, _compile_cmd(container), timeout=1800)
        _exec_capture(container,
                      "mkdir -p /out/address && "
                      "for f in /out/*; do [ -f \"$f\" ] && [ -x \"$f\" ] && "
                      "cp \"$f\" /out/address/; done; "
                      # Mirror auxiliary directories (ntopng's install/,
                      # data-dir/, docs/, scripts/) so the stashed binary
                      # can find them when run from /out/address/.
                      "for d in /out/*/; do "
                      "name=$(basename \"$d\"); "
                      "[ \"$name\" = address ] && continue; "
                      "[ \"$name\" = ubsan ] && continue; "
                      "ln -sfn \"$d\" \"/out/address/$name\"; done; true")

        # Restore testcases with dispatch bytes
        _restore_testcases_with_dispatch(
            container, project, all_bugs, testcase_stage_dir, dispatch_state,
        )

        # ------------------------------------------------------------------
        # 9. Final verification
        # ------------------------------------------------------------------
        logger.info("\n=== Final verification ===")
        _restore_testcases_with_dispatch(
            container, project, all_bugs, testcase_stage_dir, dispatch_state,
        )

        final_results = verify_all_bugs(container, all_bugs)
        triggered = sum(1 for v in final_results.values() if v)
        total = len(final_results)
        logger.info("\nRESULT: %d / %d bugs triggering", triggered, total)
        for bid, ok in final_results.items():
            logger.info("  %s: %s", bid, "OK" if ok else "FAIL")

        # ------------------------------------------------------------------
        # 10. Save combined diff + testcases
        # ------------------------------------------------------------------
        combined_diff = _clean_diff_against(container, project, harness_baseline_rev)
        combined_path = output_dir / "combined.diff"
        combined_path.write_text(combined_diff)
        logger.info("Combined diff: %s (%d bytes)", combined_path, len(combined_diff))

    # Save testcases
        tc_dir = output_dir / "testcases"
        tc_dir.mkdir(exist_ok=True)
        # Only mark artifacts as "patched" if we actually introduced dispatch
        # bytes / harness changes. (In this offline pipeline this is normally
        # true, but keep the check to avoid misleading filenames.)
        mark_patched = bool(dispatch_state.get("dispatch_bytes", 0)) and bool(
            dispatch_state.get("harness_modified")
        )
        for bug in all_bugs:
            tc_name = bug["testcase"]
            tc_ret = subprocess.run(
                ["docker", "exec", container,
                 "bash", "-c", f"cat /work/{tc_name}"],
                capture_output=True, timeout=10,
            )
            if tc_ret.returncode == 0 and tc_ret.stdout:
                if mark_patched:
                    # After rewrite, treat the saved artifact as the patched testcase.
                    (tc_dir / f"{tc_name}-patched").write_bytes(tc_ret.stdout)
                else:
                    (tc_dir / tc_name).write_bytes(tc_ret.stdout)

        logger.info("Testcases saved to %s", tc_dir)

        # Save summary
        merge_summary = {
            "project": project,
            "target_commit": target_commit,
            "local_bugs": len(local_bugs),
            "testcase_only_bugs": len(testcase_only_bugs),
            "diff_bugs": len(diff_bugs),
            "applied": applied_bugs,
            "dispatch_state": {k: v for k, v in dispatch_state.items()
                               if k != "bits"},
            "triggered": triggered,
            "total": total,
            "results": {bid: ok for bid, ok in final_results.items()},
            "steps": merge_results,
        }
        (output_dir / "summary.json").write_text(
            json.dumps(merge_summary, indent=2))
        dispatch_order_path.write_text(json.dumps(dispatch_order, indent=2) + "\n")
        logger.info("Summary: %s", output_dir / "summary.json")

        _usage_tracker.log_session_total()

        return 0 if triggered == total else 1

    finally:
        if not args.keep_container:
            logger.info("Destroying container %s...", container)
            subprocess.call(
                ["docker", "rm", "-f", container],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        else:
            logger.info("Container kept: docker exec -it %s bash", container)


def _save_progress(output_dir, dispatch_state, merge_results, applied_bugs):
    """Save intermediate progress to disk."""
    progress = {
        "dispatch_state": {k: v for k, v in dispatch_state.items()
                           if k != "bits"},
        "applied_bugs": applied_bugs,
        "steps": merge_results,
    }
    (output_dir / "progress.json").write_text(json.dumps(progress, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Offline dispatch-wrapped merge of per-bug transplant patches",
    )
    parser.add_argument("--summary", required=True,
                        help="Path to batch summary.json")
    parser.add_argument("--bug_info", required=True,
                        help="Path to osv_testcases_summary.json")
    parser.add_argument("--target", required=True,
                        help="OSS-Fuzz project name")
    parser.add_argument("--target-commit", default=None,
                        help="Override target commit")
    parser.add_argument("--build_csv", default=None,
                        help="Build CSV for historical image pinning")
    parser.add_argument("--testcases-dir", default=None,
                        help="Directory containing testcase files")
    parser.add_argument("--local-bugs", nargs="*", default=None,
                        help="Bug IDs that already trigger at target")
    parser.add_argument("--model", default=None,
                        help="Model override for codex")
    parser.add_argument("-v", "--volume", action="append",
                        help="Extra Docker volume mounts")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show plan without executing")
    parser.add_argument("--keep-container", action="store_true",
                        help="Keep container for debugging")
    parser.add_argument("--regenerate-harness", action="store_true",
                        help="Ignore saved harness artifacts and rebuild the "
                             "dispatch-consuming fuzz harness")
    parser.add_argument("--start-step", type=int, default=0,
                        help="Resume from step N")
    parser.add_argument("--max-steps", type=int, default=None,
                        help="Stop after N steps")
    parser.add_argument("--codex-mode", choices=["exec", "interactive"],
                        default="exec",
                        help="Agent invocation mode: exec (default, JSONL) "
                             "or interactive (TUI via tmux)")
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    return run_offline_merge(args)


if __name__ == "__main__":
    sys.exit(main())
