import subprocess
import sys
import os
import time
import logging
from fuzz_helper import OSS_FUZZ_DIR
from run_fuzz_test import py3

logger = logging.getLogger(__name__)   # __name__ makes it module-specific
logger.setLevel(logging.DEBUG)         # Set the minimum log level
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)
current_file_path = os.path.dirname(os.path.abspath(__file__))


test_data = {
    'OSV-2021-485': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2021-485_83d00f_patches.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "x86_64",
        "target": "c-blosc2",
        "fuzzer": "decompress_frame_fuzzer",
    },
    'OSV-2021-496': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2021-496_83d00f_patches.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "x86_64",
        "target": "c-blosc2",
        "fuzzer": "decompress_frame_fuzzer",
    },
    'OSV-2021-622': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2021-622_83d00f_patches.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "x86_64",
        "target": "c-blosc2",
        "fuzzer": "decompress_frame_fuzzer",
    },
    'OSV-2021-639': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2021-639_83d00f_patches1.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "x86_64",
        "target": "c-blosc2",
        "fuzzer": "decompress_frame_fuzzer",
    },
    'OSV-2021-1672': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2021-1672_83d00f_patches2.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "x86_64",
        "target": "c-blosc2",
        "fuzzer": "decompress_frame_fuzzer",
    },
    'OSV-2021-640': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2021-640_83d00f_patches.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "i386",
        "target": "c-blosc2",
        "fuzzer": "decompress_frame_fuzzer",
    },
    'OSV-2021-1712': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2021-1712_83d00f_patches.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "x86_64",
        "target": "c-blosc2",
        "fuzzer": "decompress_chunk_fuzzer",
    },
    'OSV-2022-33': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2022-33_83d00f_patches.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "x86_64",
        "target": "c-blosc2",
        "fuzzer": "decompress_chunk_fuzzer",
    },
    'OSV-2021-1755': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2021-1755_83d00f_patches.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "i386",
        "target": "c-blosc2",
        "fuzzer": "decompress_chunk_fuzzer",
    },
    'OSV-2021-997': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2021-997_83d00f_patches.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "x86_64",
        "target": "c-blosc2",
        "fuzzer": "decompress_frame_fuzzer",
    },
    'OSV-2021-1589': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2021-1589_83d00f_patches.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "x86_64",
        "target": "c-blosc2",
        "fuzzer": "decompress_frame_fuzzer",
    },
    'OSV-2021-779': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2021-779_83d00f_patches.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "i386",
        "target": "c-blosc2",
        "fuzzer": "decompress_frame_fuzzer",
    },
    'OSV-2021-897': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2021-897_83d00f_patches.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "x86_64",
        "target": "c-blosc2",
        "fuzzer": "decompress_frame_fuzzer",
    },
    'OSV-2021-973': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2021-973_83d00f_patches.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "i386",
        "target": "c-blosc2",
        "fuzzer": "decompress_frame_fuzzer",
    },
    'OSV-2022-34': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2022-34_83d00f_patches.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "x86_64",
        "target": "c-blosc2",
        "fuzzer": "decompress_frame_fuzzer",
    },
    'OSV-2022-4': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2022-4_83d00f_patches.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "x86_64",
        "target": "c-blosc2",
        "fuzzer": "decompress_frame_fuzzer",
    },
    'OSV-2021-1791': {
        "commit_id": "83d00f",
        "sanitizer": "address",
        "patch_file_path": "/home/user/oss-fuzz-for-select/patch/OSV-2021-1791_83d00f_patches.diff",
        "build_csv": "/home/user/log/c-blosc2_builds.csv",
        "arch": "x86_64",
        "target": "c-blosc2",
        "fuzzer": "decompress_frame_fuzzer",
    },
}


def build_fuzzer(commit_id: str, sanitizer: str, patch_file_path: str, build_csv: str, arch: str, target: str):
    cmd = [
        "python3", f"{current_file_path}/fuzz_helper.py", "build_version", "--commit", commit_id, "--sanitizer", sanitizer,
        "--patch", patch_file_path, '--build_csv', build_csv, '--no_corpus', '--architecture', arch , target
    ]
    logger.debug(' '.join(cmd))
    subprocess.run(cmd, capture_output=True, text=True)


def test_fuzzer_build(project: str, sanitizer: str = "address", arch = 'x86_64', engine: str = "libfuzzer") -> bool:
    """
    Run OSS-Fuzz check_build to validate fuzzer build and configuration.
    It is used after I change the source code of target software.

    Args:
        project (str): OSS-Fuzz project name.
        sanitizer (str): Sanitizer to check (address, memory, undefined, etc.).
        engine (str): Fuzzing engine to check (libfuzzer, afl, honggfuzz).
        arch (str): Architecture to test (x86_64, i386, etc.).
    
    Returns:
        bool: True if check_build passes, False otherwise.
    """
    
    cmd = [
        "sudo", "-E",
        py3,
        f"{OSS_FUZZ_DIR}/infra/helper.py", "check_build",
        "--sanitizer", sanitizer,
        "--engine", engine,
        "--architecture", arch,
        "-e", "ASAN_OPTIONS=detect_leaks=0",
        project
    ]

    logger.debug(f"[*] Running check_build for project: {project}")
    logger.debug(f"[*] Sanitizer: {sanitizer}, Engine: {engine}")
    logger.debug(f'{" ".join(cmd)}')
    
    try:
        start_time = time.time()
        proc = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            timeout=300  # 5 minute timeout for check_build
        )
        runtime = int(time.time() - start_time)
        
        output = proc.stdout.decode(errors="replace")
        
        logger.debug(f"[*] check_build completed in {runtime} seconds")
        logger.debug(f"[*] Return code: {proc.returncode}")
        logger.debug(f"[*] Output:\n{output}")
        
        # Check if build validation passed
        success = proc.returncode == 0
        if success:
            logger.debug("[+] check_build PASSED - Build is valid")
        else:
            logger.error("[-] check_build FAILED - Build has issues")
            
        return success
        
    except subprocess.TimeoutExpired:
        logger.error("[-] check_build timed out after 5 minutes")
        return False
    except Exception as e:
        logger.error(f"[-] Error running check_build: {e}")
        return False


def test_specific_fuzzer(project: str, fuzz_target: str, quick_test: bool = True) -> bool:
    """
    Test a specific fuzzer target by running it briefly to check for immediate crashes.
    
    Args:
        project (str): OSS-Fuzz project name.
        fuzz_target (str): Specific fuzz target binary name to test.
        quick_test (bool): If True, run for 30 seconds; if False, run for 2 minutes.
    
    Returns:
        bool: True if fuzzer runs without immediate crashes, False otherwise.
    """
    
    test_duration = 30 if quick_test else 120
    
    cmd = [
        "sudo", "-E",
        py3,
        f"{OSS_FUZZ_DIR}/infra/helper.py", "run_fuzzer",
        "-e", "ASAN_OPTIONS=detect_leaks=0",
        project, fuzz_target,
        "--",
        f"-max_total_time={test_duration}",
        "-timeout=5"
    ]

    logger.debug(f"[*] Testing specific fuzzer: {fuzz_target} for {test_duration} seconds")
    logger.debug(f'{" ".join(cmd)}')
    
    try:
        start_time = time.time()
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=test_duration + 60  # Extra buffer for startup/cleanup
        )
        runtime = int(time.time() - start_time)
        
        output = proc.stdout.decode(errors="replace")
        
        logger.debug(f"[*] Fuzzer test completed in {runtime} seconds")
        logger.debug(f"[*] Return code: {proc.returncode}")
        logger.debug(f"[*] Output:\n{output}")
        
        # Check for common failure indicators in output
        failure_indicators = [
            "ABORTING",
            "ERROR: AddressSanitizer",
            "ERROR: libFuzzer",
            "Segmentation fault",
            "Bus error",
            "Illegal instruction"
        ]
        
        has_critical_error = any(indicator in output for indicator in failure_indicators)
        
        if has_critical_error:
            logger.error("[-] Fuzzer has critical runtime errors")
            return False
        elif proc.returncode != 0:
            logger.warning(f"[!] Fuzzer exited with non-zero code: {proc.returncode}")
            # Non-zero exit might be normal for fuzzers (timeout, etc.)
            return True
        else:
            logger.debug("[+] Fuzzer test completed successfully")
            return True
            
    except subprocess.TimeoutExpired:
        logger.error(f"[-] Fuzzer test timed out after {test_duration + 60} seconds")
        return False
    except Exception as e:
        logger.error(f"[-] Error testing fuzzer: {e}")
        return False


def comprehensive_fuzzer_test(project: str, fuzz_target: str = None, arch : str = 'x86_64', sanitizer: str = "address") -> bool:
    """
    Comprehensive fuzzer testing: first check_build, then optionally test specific target.
    
    Args:
        project (str): OSS-Fuzz project name.
        fuzz_target (str): Optional specific fuzz target to test after build check.
        sanitizer (str): Sanitizer configuration to test.
    
    Returns:
        bool: True if all tests pass, False otherwise.
    """
    
    logger.debug(f"[*] Starting comprehensive test for project: {project}")
    
    # Step 1: Run check_build
    build_ok = test_fuzzer_build(project, sanitizer, arch)
    if not build_ok:
        logger.error("[-] Build validation failed, skipping runtime test")
        return False
    
    # Step 2: Optionally test specific fuzzer
    if fuzz_target:
        logger.debug(f"[*] Build validation passed, testing specific fuzzer: {fuzz_target}")
        runtime_ok = test_specific_fuzzer(project, fuzz_target, quick_test=True)
        if not runtime_ok:
            logger.error("[-] Runtime test failed")
            return False
        logger.debug("[+] Runtime test passed")
    
    logger.debug("[+] All tests completed successfully")
    return True


if __name__ == "__main__":
    successful_bugs = []
    failed_bugs = []
    for bug_id, data in test_data.items():
        build_fuzzer(data['commit_id'], data['sanitizer'], data['patch_file_path'], data['build_csv'], data['arch'], data['target'])
        if comprehensive_fuzzer_test(data['target'], data['sanitizer'], data['arch']):
            successful_bugs.append(bug_id)
        else:
            failed_bugs.append(bug_id)
            
    logger.info(f"[*] Testing completed. Successful bugs: {successful_bugs if successful_bugs else 'None'}")
    logger.info(f"[*] Testing completed. Failed bugs: {failed_bugs if failed_bugs else 'None'}")