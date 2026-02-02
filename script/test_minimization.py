#!/usr/bin/env python3
"""Test program for patch minimization with _extra_* patch handling.

Usage:
    python3 script/test_minimization.py --bug-id OSV-2023-560
    python3 script/test_minimization.py --bug-id OSV-2023-560 --merged-bundle path/to/*.patch2
    python3 script/test_minimization.py --bug-id OSV-2023-560 --test-build
    python3 script/test_minimization.py --bug-id OSV-2023-560 --test-minimize
"""

import argparse
import ast
import glob
import os
import re
import sys

# Add script directory to path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from utils import load_patches_pickle, extract_extra_patches
from monitor_crash import extract_function_stack


def parse_trace_from_log(log_path: str) -> list:
    """Parse trace1 from log file."""
    trace1 = []
    with open(log_path) as f:
        for line in f:
            if "Trace function set:" in line:
                match = re.search(r'\[.*\]', line)
                if match:
                    try:
                        trace_list = ast.literal_eval(match.group())
                        for i, (func_name, location) in enumerate(trace_list):
                            trace1.append((i, f"{func_name} {location}"))
                    except Exception:
                        pass
                break
    return trace1


def crash_stack_to_trace(crash_log_path: str) -> list:
    """Convert crash stack to trace1 format for minimize_with_trace_and_cached_extras.

    Parses crash log to extract function names and file paths.
    Format: #N 0x... in function_name /path/to/file.c:line:col
    """
    if not os.path.exists(crash_log_path):
        return []

    trace1 = []
    # Pattern: #N 0x... in function_name /path/to/file:line:col
    stack_pattern = re.compile(r"#(\d+)\s+0x[0-9a-f]+\s+in\s+(\S+)\s+(/\S+:\d+:\d+)", re.IGNORECASE)

    with open(crash_log_path) as f:
        for line in f:
            match = stack_pattern.search(line)
            if match:
                idx = int(match.group(1))
                func_name = match.group(2)
                location = match.group(3)

                # Clean function name (remove template/signature noise)
                clean_name = func_name.split('(')[0].split('<')[0]

                # trace1 format: (index, "func_name /path:line:col")
                trace1.append((idx, f"{clean_name} {location}"))

            if 'LLVMFuzzerTestOneInput' in line:
                break

    return trace1


def find_crash_log(bug_id: str, target: str) -> str | None:
    """Find crash log file for a bug."""
    # Try common patterns
    patterns = [
        f"data/crash/*{bug_id}*.txt",
        f"data/crash/target_crash-*-testcase-{bug_id}.txt",
    ]
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    return None


def find_merged_bundle(target: str = "opensc") -> str | None:
    """Find most recent merged bundle for target project."""
    pattern = f"data/react_agent_artifacts/multi_*/{target}.merged_overrides*.patch2"
    bundles = glob.glob(pattern)
    if not bundles:
        return None
    # Sort by modification time, return most recent
    return sorted(bundles, key=os.path.getmtime)[-1]


def flatten_patches(data: dict) -> dict:
    """Flatten nested patches dict (tuple-keyed outer dict -> flat PatchInfo dict)."""
    result = {}
    for key, value in data.items():
        if isinstance(key, tuple):
            # This is a nested structure: (bug_id, commit, fuzzer, funcs) -> {patch_key: PatchInfo}
            if isinstance(value, dict):
                result.update(value)
        else:
            # Already flat
            result[key] = value
    return result


def test_extract_extra_patches(patches_dict: dict, verbose: bool = True) -> bool:
    """Test that extract_extra_patches correctly filters _extra_* keys."""
    if verbose:
        print("\nTest 1: extract_extra_patches")

    # Count input extras
    input_extras = sum(1 for k in patches_dict.keys() if str(k).startswith('_extra_'))
    if verbose:
        print(f"  Input: {len(patches_dict)} patches, {input_extras} with _extra_ prefix")

    # Extract extras
    extras = extract_extra_patches(patches_dict)
    if verbose:
        print(f"  Output: {len(extras)} patches extracted")

    # Check all extracted keys start with _extra_
    all_extra = all(str(k).startswith('_extra_') for k in extras.keys())
    if verbose:
        status = "[PASS]" if all_extra else "[FAIL]"
        print(f"  {status} All extracted keys start with _extra_")

    if not all_extra:
        bad_keys = [k for k in extras.keys() if not str(k).startswith('_extra_')]
        print(f"    Bad keys: {bad_keys[:5]}")
        return False

    # Check deep copy (modify extracted dict, verify original unchanged)
    if extras:
        test_key = list(extras.keys())[0]
        original_patch = patches_dict[test_key]
        extracted_patch = extras[test_key]

        # They should be different objects
        deep_copied = original_patch is not extracted_patch
        if verbose:
            status = "[PASS]" if deep_copied else "[FAIL]"
            print(f"  {status} Deep copy verified (no shared refs)")

        if not deep_copied:
            return False

    # Check count matches
    count_matches = len(extras) == input_extras
    if not count_matches:
        if verbose:
            print(f"  [FAIL] Count mismatch: expected {input_extras}, got {len(extras)}")
        return False

    return True


def test_extra_patches_present(patches_dict: dict, verbose: bool = True) -> bool:
    """Test that the merged bundle contains _extra_* patches."""
    if verbose:
        print("\nTest 2: extra_patches_present")

    extras = extract_extra_patches(patches_dict)
    non_extras = {k: v for k, v in patches_dict.items() if not str(k).startswith('_extra_')}

    if verbose:
        print(f"  Total patches: {len(patches_dict)}")
        print(f"  Extra patches: {len(extras)}")
        print(f"  Non-extra patches: {len(non_extras)}")

    # Must have both extra and non-extra patches
    has_extras = len(extras) > 0
    has_non_extras = len(non_extras) > 0

    if verbose:
        status = "[PASS]" if has_extras else "[FAIL]"
        print(f"  {status} Bundle contains _extra_* patches")
        status = "[PASS]" if has_non_extras else "[FAIL]"
        print(f"  {status} Bundle contains non-extra patches")

    if has_extras and verbose:
        print(f"  Extra patch keys:")
        for k in list(extras.keys())[:5]:
            print(f"    - {k}")
        if len(extras) > 5:
            print(f"    ... and {len(extras) - 5} more")

    return has_extras and has_non_extras


def test_build_with_cached_extras(
    patches_dict: dict,
    extras_cache: dict,
    target: str,
    commit: str,
    bug_id: str,
    verbose: bool = True
) -> bool:
    """Test that build_with_cached_extras includes cached extras in trial diff."""
    if verbose:
        print("\nTest 3: build_with_cached_extras")

    try:
        from revert_patch_test import build_with_cached_extras
    except ImportError as e:
        if verbose:
            print(f"  [SKIP] Cannot import build_with_cached_extras: {e}")
        return True  # Skip, not a failure

    # Get non-extra patches for subset
    non_extras = {k: v for k, v in patches_dict.items() if not str(k).startswith('_extra_')}

    if not non_extras:
        if verbose:
            print("  [SKIP] No non-extra patches to test with")
        return True

    # Use all non-extra patches
    subset_keys = list(non_extras.keys())
    if verbose:
        print(f"  Testing with {len(subset_keys)} patches + {len(extras_cache)} extras")

    # Build (this requires Docker/OSS-Fuzz infrastructure)
    try:
        success, log = build_with_cached_extras(
            subset_keys,
            patches_dict,
            extras_cache,
            target,
            commit,
            "address",  # sanitizer
            bug_id,
            "fuzz_pkcs15init",  # fuzzer
            "",  # build_csv
            "x86_64"  # arch
        )

        if verbose:
            status = "[PASS]" if success else "[FAIL]"
            print(f"  {status} Build {'succeeded' if success else 'failed'}")

        # Check trial diff file
        patch_folder = os.path.join(script_dir, '..', 'patch')
        trial_diff_path = os.path.join(patch_folder, f"{bug_id}_{commit}_min_trial.diff")

        if os.path.exists(trial_diff_path):
            with open(trial_diff_path) as f:
                trial_content = f.read()

            # Verify extra patches are included
            extras_included = all(
                extras_cache[k].patch_text in trial_content
                for k in extras_cache
            )
            if verbose:
                status = "[PASS]" if extras_included else "[FAIL]"
                print(f"  {status} Extra patches included in trial diff")

            return extras_included
        else:
            if verbose:
                print(f"  [WARN] Trial diff not found: {trial_diff_path}")
            return success

    except Exception as e:
        if verbose:
            print(f"  [FAIL] Build error: {e}")
        return False


def test_minimize_with_trace(
    patches_dict: dict,
    target: str,
    commit: str,
    bug_id: str,
    fuzzer: str,
    log_path: str | None = None,
    crash_log_path: str | None = None,
    verbose: bool = True
) -> bool:
    """Test minimize_with_trace_and_cached_extras function.

    This simulates what happens at line 79-83 in the log:
    - Initial revert patch set
    - Cached N extra patches
    - Static filter
    - Trial build
    """
    if verbose:
        print("\nTest 4: minimize_with_trace_and_cached_extras")

    try:
        from revert_patch_test import minimize_with_trace_and_cached_extras
    except ImportError as e:
        if verbose:
            print(f"  [SKIP] Cannot import minimize_with_trace_and_cached_extras: {e}")
        return True

    # Get non-extra patches as diff_results
    non_extras = {k: v for k, v in patches_dict.items() if not str(k).startswith('_extra_')}

    # Create patch_pair_list (each patch as a single-element tuple)
    patch_pair_list = [(k,) for k in non_extras.keys()]

    if verbose:
        print(f"  Initial patch set: {len(patch_pair_list)} groups")

    # Try crash log first (crash stack), then execution trace log
    trace1 = []
    if crash_log_path and os.path.exists(crash_log_path):
        trace1 = crash_stack_to_trace(crash_log_path)
        if verbose:
            print(f"  Loaded crash stack: {len(trace1)} functions from {crash_log_path}")
            if trace1:
                funcs = [t[1].split()[0] for t in trace1[:5]]
                print(f"    Top functions: {funcs}")
    elif log_path and os.path.exists(log_path):
        trace1 = parse_trace_from_log(log_path)
        if verbose:
            print(f"  Loaded execution trace: {len(trace1)} entries from {log_path}")

    if not trace1:
        if verbose:
            print(f"  No trace (use --crash-log or --log to provide trace data)")

    # Empty dependency graph
    depen_graph = {}

    # next_commit dict
    next_commit = {'commit_id': commit}

    if verbose:
        print(f"  patches_without_context has {len(patches_dict)} entries")
        extras_count = len(extract_extra_patches(patches_dict))
        print(f"  Expected cached extras: {extras_count}")

    try:
        # This should print "Cached N extra patches" where N > 0
        minimized, extra_cache = minimize_with_trace_and_cached_extras(
            patch_pair_list,
            patches_dict,  # patches_without_context - must have _extra_* patches
            non_extras,    # diff_results
            trace1,
            depen_graph,
            target,
            next_commit,
            "address",     # sanitizer
            bug_id,
            fuzzer,
            "",            # build_csv
            "x86_64"       # arch
        )

        if verbose:
            print(f"  Returned extra_cache: {len(extra_cache)} patches")
            print(f"  Minimized to: {len(minimized)} groups")

        # Verify extra_cache is populated
        success = len(extra_cache) > 0
        if verbose:
            status = "[PASS]" if success else "[FAIL]"
            print(f"  {status} Extra patches cache populated ({len(extra_cache)} patches)")

        return success

    except Exception as e:
        if verbose:
            print(f"  [FAIL] Error: {e}")
            import traceback
            traceback.print_exc()
        return False


def main():
    parser = argparse.ArgumentParser(description="Test patch minimization with _extra_* handling")
    parser.add_argument("--bug-id", required=True, help="Bug ID (e.g., OSV-2023-560)")
    parser.add_argument("--target", default="opensc", help="Target project name")
    parser.add_argument("--commit", default="2192a2", help="Commit hash")
    parser.add_argument("--fuzzer", default="fuzz_pkcs15init", help="Fuzzer name")
    parser.add_argument("--merged-bundle", help="Path to merged patch bundle")
    parser.add_argument("--log", help="Path to log file with execution trace data")
    parser.add_argument("--crash-log", help="Path to crash log file with stack trace")
    parser.add_argument("--test-build", action="store_true", help="Run build_with_cached_extras test")
    parser.add_argument("--test-minimize", action="store_true", help="Run minimize_with_trace_and_cached_extras test")
    parser.add_argument("--quiet", action="store_true", help="Suppress verbose output")
    args = parser.parse_args()

    verbose = not args.quiet

    print(f"=== Minimization Test: {args.bug_id} ===")

    # Find merged bundle
    merged_bundle = args.merged_bundle or find_merged_bundle(args.target)
    if not merged_bundle or not os.path.exists(merged_bundle):
        print(f"ERROR: Merged bundle not found")
        print(f"  Searched pattern: data/react_agent_artifacts/multi_*/{args.target}.merged_overrides*.patch2")
        print(f"  Use --merged-bundle to specify path")
        return 1

    print(f"Loading merged bundle from: {merged_bundle}")
    patches = load_patches_pickle(merged_bundle)
    patches = flatten_patches(patches)
    extras_count = len(extract_extra_patches(patches))
    print(f"  Found {len(patches)} patches ({extras_count} extra)")

    all_passed = True

    # Test 1: extract_extra_patches
    if not test_extract_extra_patches(patches, verbose):
        all_passed = False

    # Test 2: extra_patches_present
    if not test_extra_patches_present(patches, verbose):
        all_passed = False

    # Test 3: build_with_cached_extras (optional)
    if args.test_build:
        extras_cache = extract_extra_patches(patches)
        if not test_build_with_cached_extras(patches, extras_cache, args.target, args.commit, args.bug_id, verbose):
            all_passed = False
    else:
        if verbose:
            print("\nTest 3: build_with_cached_extras (skipped - use --test-build)")

    # Test 4: minimize_with_trace_and_cached_extras (optional)
    if args.test_minimize:
        log_path = args.log or f"log/revert_patch/{args.target}/{args.bug_id}.log"
        crash_log_path = args.crash_log or find_crash_log(args.bug_id, args.target)
        if not test_minimize_with_trace(patches, args.target, args.commit, args.bug_id, args.fuzzer, log_path, crash_log_path, verbose):
            all_passed = False
    else:
        if verbose:
            print("\nTest 4: minimize_with_trace_and_cached_extras (skipped - use --test-minimize)")

    print()
    if all_passed:
        print("=== All tests passed ===")
        return 0
    else:
        print("=== Some tests failed ===")
        return 1


if __name__ == "__main__":
    sys.exit(main())
