import subprocess
import sys
import os
import time
from fuzz_helper import OSS_FUZZ_DIR
from run_fuzz_test import py3

current_file_path = os.path.dirname(os.path.abspath(__file__))


test_data = {
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
        "--patch", patch_file_path, '--build_csv', build_csv, '--architecture', arch , target
    ]
    print(' '.join(cmd))
    subprocess.run(cmd, capture_output=True, text=True)


def test_fuzzer(project: str, fuzz_target: str, max_time: int = 30) -> None:
    """
    Run an OSS-Fuzz fuzzer for a given duration and check if it crashes early. 
    It is used after I change the source code of target software.

    Args:
        project (str): OSS-Fuzz project name.
        fuzz_target (str): Fuzz target binary name.
        max_time (int): Duration in seconds to run the fuzzer.
    """

    cmd = [
        "sudo", "-E",
        py3,
        f"{OSS_FUZZ_DIR}/infra/helper.py", "run_fuzzer",
        "-e", "ASAN_OPTIONS=detect_leaks=0",
        project, fuzz_target,
        "--",
        f"-max_total_time={max_time}",
        "-timeout=5"
    ]

    total_runtime = 0
    print(f"[*] Starting fuzz test for {max_time} seconds...")
    for i in range(10):
        start_time = time.time()
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        runtime = int(time.time() - start_time)
        output = proc.stdout.decode(errors="replace")
        total_runtime += runtime
    
    print(f"[*] Fuzzer ran {total_runtime/10} seconds on average.")


if __name__ == "__main__":

    for bug_id, data in test_data.items():
        build_fuzzer(data['commit_id'], data['sanitizer'], data['patch_file_path'], data['build_csv'], data['arch'], data['target'])
        test_fuzzer(data['target'], data['fuzzer'])
    