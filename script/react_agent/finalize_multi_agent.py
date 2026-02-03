#!/usr/bin/env python3
"""
Finalize a multi-agent run by collecting all override diffs, merging them,
testing the result, and writing summary.json.

Usage:
    python3 script/react_agent/finalize_multi_agent.py <artifacts_root>
"""

import json
import os
import sys
from pathlib import Path

# Add script/react_agent to path for imports
script_dir = Path(__file__).parent.resolve()
sys.path.insert(0, str(script_dir))

from multi_agent import _collect_final_override_diffs


def main():
    if len(sys.argv) < 2:
        print("Usage: finalize_multi_agent.py <artifacts_root>", file=sys.stderr)
        sys.exit(1)

    artifacts_root = Path(sys.argv[1]).expanduser().resolve()
    progress_path = artifacts_root / "progress.json"

    if not progress_path.is_file():
        print(f"ERROR: progress.json not found at {progress_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading progress.json from {progress_path}")
    with open(progress_path, "r", encoding="utf-8") as f:
        progress = json.load(f)

    results = progress.get("results", [])
    patch_path = progress.get("patch_path", "")

    if not results:
        print("ERROR: No results found in progress.json", file=sys.stderr)
        sys.exit(1)

    if not patch_path:
        print("ERROR: No patch_path found in progress.json", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(results)} results")
    print(f"Patch path: {patch_path}")

    # Count fixed hunks
    hunks_fixed = sum(1 for r in results if r.get("hunk_fixed") is True)
    hunks_not_fixed = sum(1 for r in results if r.get("hunk_fixed") is False)
    print(f"Hunks fixed: {hunks_fixed}, not fixed: {hunks_not_fixed}")

    # Collect override diffs
    print("\nCollecting override diffs...")
    overrides = _collect_final_override_diffs(results, patch_path=patch_path)
    override_paths = list(overrides.get("override_paths") or [])
    print(f"Found {len(override_paths)} override diffs")

    if not override_paths:
        print("WARNING: No override diffs found")
        # Write summary anyway
        summary = {
            "status": "no_overrides",
            "hunks_fixed": hunks_fixed,
            "hunks_not_fixed": hunks_not_fixed,
            "override_count": 0,
            "merged_patch_bundle_path": "",
            "final_build_result": None,
        }
        summary_path = artifacts_root / "summary.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"\nWrote summary to {summary_path}")
        return

    # Set artifact root for tools
    os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(artifacts_root)

    # Merge overrides into patch bundle
    print("\nMerging overrides into patch bundle...")
    from tools.ossfuzz_tools import write_patch_bundle_with_overrides

    base = Path(patch_path).stem or "bundle"
    out = write_patch_bundle_with_overrides(
        patch_path=str(patch_path),
        patch_override_paths=override_paths,
        output_name=f"{base}.final_merged.patch2",
    )
    merged_bundle_path = str(out.get("merged_patch_bundle_path", "") or "").strip()
    print(f"Merged bundle: {merged_bundle_path}")

    # Extract ossfuzz params from agent logs or use defaults
    ossfuzz_project = "libxml2"
    ossfuzz_commit = "f0fd1b"
    ossfuzz_build_csv = "/home/user/log/libxml2_builds.csv"

    # Try to extract from first agent's stderr log for accurate params
    for r in results:
        artifacts_dir = r.get("artifacts_dir", "")
        if artifacts_dir:
            stderr_log = Path(artifacts_dir) / "agent_stderr.log"
            if stderr_log.is_file():
                content = stderr_log.read_text(errors="replace")
                # Extract commit
                import re
                m = re.search(r"--commit\s+(\S+)", content)
                if m:
                    ossfuzz_commit = m.group(1)
                # Extract build_csv
                m = re.search(r"--build_csv\s+(\S+)", content)
                if m:
                    ossfuzz_build_csv = m.group(1)
                # Extract project (last argument before options)
                m = re.search(r"build_version.*?(\w+)\s*$", content, re.MULTILINE)
                if m:
                    ossfuzz_project = m.group(1)
                break

    print(f"OSS-Fuzz params: project={ossfuzz_project}, commit={ossfuzz_commit}")

    # Test the merged bundle
    print("\nTesting merged patch bundle with OSS-Fuzz...")
    from tools.ossfuzz_tools import ossfuzz_apply_patch_and_test

    try:
        test_result = ossfuzz_apply_patch_and_test(
            project=ossfuzz_project,
            commit=ossfuzz_commit,
            patch_path=merged_bundle_path,
            patch_override_paths=[],
            build_csv=ossfuzz_build_csv,
            sanitizer="address",
            architecture="x86_64",
            engine="libfuzzer",
            fuzz_target="",
            use_sudo=True,
        )
        build_success = test_result.get("build_ok", False)
        build_output_info = test_result.get("build_output", {})

        # Read actual build log text from artifact path
        build_log_path = build_output_info.get("artifact_path", "") if isinstance(build_output_info, dict) else ""
        if build_log_path and Path(build_log_path).is_file():
            build_output_text = Path(build_log_path).read_text(errors="replace")
        else:
            build_output_text = ""

        # Count remaining errors
        from tools.migration_tools import parse_build_errors
        errors = parse_build_errors(build_log_text=build_output_text)
        # Count all error categories
        error_count = (
            len(errors.get("undeclared_identifiers", []))
            + len(errors.get("undeclared_functions", []))
            + len(errors.get("missing_struct_members", []))
            + len(errors.get("function_call_issues", []))
            + len(errors.get("incomplete_types", []))
        )

        print(f"Build {'succeeded' if build_success else 'failed'}")
        print(f"Remaining errors: {error_count}")

    except Exception as exc:
        print(f"OSS-Fuzz test failed: {type(exc).__name__}: {exc}")
        test_result = {"status": "error", "error": str(exc)}
        build_success = False
        error_count = -1
        errors = {}
        build_log_path = ""

    # Write summary
    summary = {
        "status": "ok" if build_success else "build_failed",
        "hunks_fixed": hunks_fixed,
        "hunks_not_fixed": hunks_not_fixed,
        "override_count": len(override_paths),
        "merged_patch_bundle_path": merged_bundle_path,
        "final_build_success": build_success,
        "final_error_count": error_count,
        "final_build_log": build_log_path,
        "final_errors": {
            "undeclared_identifiers": errors.get("undeclared_identifiers", [])[:10],
            "undeclared_functions": errors.get("undeclared_functions", [])[:10],
            "missing_struct_members": errors.get("missing_struct_members", [])[:10],
            "function_call_issues": errors.get("function_call_issues", [])[:10],
            "incomplete_types": errors.get("incomplete_types", [])[:10],
        },
        "override_paths": override_paths[:50],  # Truncate for readability
        "override_paths_truncated": len(override_paths) > 50,
    }

    summary_path = artifacts_root / "summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"\nWrote summary to {summary_path}")

    # Also print summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Status: {summary['status']}")
    print(f"Hunks fixed: {hunks_fixed}")
    print(f"Hunks not fixed: {hunks_not_fixed}")
    print(f"Override diffs: {len(override_paths)}")
    print(f"Final build success: {build_success}")
    print(f"Remaining errors: {error_count}")
    print(f"Merged bundle: {merged_bundle_path}")


if __name__ == "__main__":
    main()
