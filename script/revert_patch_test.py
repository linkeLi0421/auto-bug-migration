import csv
import re
import sys
import argparse
import subprocess
import sys
import json
import os
from git import Repo
from unidiff import PatchSet
from io import StringIO
import logging

from buildAndtest import checkout_latest_commit
from run_fuzz_test import read_json_file
from run_fuzz_test import py3
from compare_trace import extract_function_calls
from compare_trace import compare_traces
from CParser import CParser
from get_fix_related import demangle_cpp_symbol

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

current_file_path = os.path.dirname(os.path.abspath(__file__))
ossfuzz_path = os.path.abspath(os.path.join(current_file_path, '..', 'oss-fuzz'))
data_path = os.path.abspath(os.path.join(current_file_path, '..', 'data'))

def mangle_cpp_function(signature):
    """
    Mangles a C++ member function signature (Itanium ABI style).
    Handles `void` return types and no parameters (simplified).
    """
    # Normalize whitespace and strip any leading/trailing spaces
    signature = re.sub(r'\s+', ' ', signature).strip()
    
    parts = signature.split()
    if len(parts) < 2 or "::" not in parts[1]:
        return signature  # Not a valid member function
    
    return_type = parts[0]
    class_func = parts[1].split("::")
    class_name = class_func[0]
    func_name = class_func[1].replace("()", "")  # Remove parentheses
    
    # Mangle class and function names (length-prefixed)
    mangled_class = f"{len(class_name)}{class_name}"
    mangled_func = f"{len(func_name)}{func_name}"
    
    # Mangled return type (simplified; only handles 'void')
    return_code = "v" if return_type == "void" else ""
    
    # Full mangled name (e.g., _ZN7LibRaw10apply_tiffEv)
    mangled = f"_ZN{mangled_class}{mangled_func}E{return_code}"
    return mangled


def mangle_string(input_str):
    """Process a set of strings, mangling C++ function signatures."""
    # Regex to match "void Class::Function()" as standalone strings
    pattern = re.compile(r'^\s*\w+\s+\w+::\w+\(\)\s*$')
    mangled_item = input_str
    
    if pattern.match(input_str.strip()):
        mangled_item = mangle_cpp_function(input_str)
    
    return mangled_item


def get_commit_patch_gitpython(repo_path, commit_id, parent_commit_id):
    repo = Repo(repo_path)
    commit = repo.commit(commit_id)
    parent = repo.commit(parent_commit_id)

    if parent:
        diffs = parent.diff(commit, create_patch=True)
    else:
        # For the initial commit with no parents
        diffs = commit.diff(NULL_TREE, create_patch=True)

    return diffs


def parse_arguments():
    parser = argparse.ArgumentParser(description='Run fuzzing tests with trace collection')
    parser.add_argument('target_test_result',
                        help='Csv file that contains all poc test result on all commits of a target project')
    parser.add_argument('--bug_info', required=True,
                        help='JSON config all bug info details')
    parser.add_argument('--build_csv', required=True,
                        help='this file contains a target project commit id and corresponding commit id')
    return parser.parse_args()


def parse_csv_file(file_path):
    with open(file_path, 'r') as file:
        csv_content = file.read()
    return parse_csv_data(csv_content)


def parse_csv_data(csv_content):
    lines = csv_content.strip().split('\n')
    headers = lines[0].split(',')
    data = []
    
    for line in lines[1:]:
        values = line.split(',')
        if len(values) >= 2:  # Ensure there are at least commit ID and one OSV column
            row = {
                'commit_id': values[0],
                'osv_statuses': {},  # Store all OSV statuses in a dictionary
                'poc_count': values[-1] if values[-1] else 0
            }
            
            # Process all OSV columns (skipping first and last columns)
            for i in range(1, len(values) - 1):
                if i < len(headers):
                    bug_id = headers[i]
                    row['osv_statuses'][bug_id] = values[i] if values[i] else None
            
            data.append(row)
    
    return data


def find_transitions(data):
    transitions = []
    
    for i in range(len(data) - 1):
        current = data[i]
        next_commit = data[i + 1]
        
        # Check for transitions in each OSV
        for bug_id, status in current['osv_statuses'].items():
            if status and re.match(r'1\|.+', status) and bug_id in next_commit['osv_statuses']:
                if next_commit['osv_statuses'][bug_id] == "0|0" or next_commit['osv_statuses'][bug_id] == "0|1":
                    transitions.append((current, next_commit, bug_id))
    
    return transitions


def analyze_diffindex(diff_index, target_repo_path: str, fix_commit: str):
    """
    Analyze a GitPython DiffIndex and return metadata per hunk.
    Target repo checkout to fix commit here.
    """
    results = []
    for diff in diff_index:
        # Choose the post-change path if available, else pre-change:
        path = diff.b_path or diff.a_path
        # Derive file extension/type from path:
        ext  = path.rsplit('.', 1)[-1] if '.' in path else ''

        # Decode patch text; skip diffs without patch bodies
        patch_bytes = diff.diff or b''
        patch_text = patch_bytes.decode('utf-8', errors='ignore')

        # Split into hunks on lines starting with '@@'
        hunks = re.split(r'(?m)^@@', patch_text)
        # The first element is the header before any hunk; skip it
        for h in hunks[1:]:
            # The hunk header is before the first newline
            header, *body = h.split('\n', 1)
            # Extract section/function name (text after second '@@')
            section = header.split('@@')[-1].strip() or "<no-section>"

            # Count added and removed lines in this hunk
            added   = sum(1 for line in body[0].splitlines() if line.startswith('+') and not line.startswith('+++'))
            removed = sum(1 for line in body[0].splitlines() if line.startswith('-') and not line.startswith('---'))
            
            # parse to get function signature
            new_code = [line[1:] for line in body[0].splitlines() if line.startswith('+') and not line.startswith('+++')]
            parser = CParser()
            file_path = os.path.join(target_repo_path, path)
            
            # checkout target repo to the fix commit, and parse the code from that
            os.chdir(target_repo_path)
            subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["git", "checkout", '-f', fix_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            signature = 'unknown'
            for item in parser.iterate_code(file_path, file_type=ext):
                # If all lines in new_code are in the function defination, save the function signature
                if item['type'] == 'function' and all(code_line in item['code'] for code_line in new_code):
                    signature = item['signature']

            header = f"diff --git a/{diff.a_path} b/{diff.b_path}\n"
            header += f"--- a/{diff.a_path}\n+++ b/{diff.b_path}\n"
            patch_text = header + '@@' + h

            results.append({
                'file_path':   path,
                'file_type':   ext,
                'change_type': diff.change_type,
                'hunk_header': section,
                'added':       added,
                'removed':     removed,
                'patch_text':  patch_text,
                'signature':   signature,
            })
    return results


def revert_patch(repo_path: str, patch_text):
    repo = Repo(repo_path)
    # Build full patch text with headers

    # Write to temporary file
    tmp_path = os.path.join(repo_path, 'tmp.diff')
    with open(tmp_path, 'w') as tmp:
        tmp.write(patch_text)
        logger.info(f"Applying reverse patch to {tmp_path}\n{patch_text}")
    # Reverse-apply the patch
    repo.git.apply(['--reverse', tmp_path])
    os.remove(tmp_path)


def build_and_test_fuzzer(target, commit_id, target_repo_path, sanitizer, bug_id, ossfuzz_path):
    """
    Build the fuzzer after patch reversion and test if it works
    
    Args:
        target: The target project name
        commit_id: The commit ID being tested
        target_repo_path: Path to the target repo
        sanitizer: The sanitizer to use (e.g., 'address', 'undefined')
        bug_id: The bug ID being tested
        ossfuzz_path: Path to the OSS-Fuzz directory
    
    Returns:
        bool: True if the build succeeds, False otherwise
    """
    cmd = [
        "python3", f"{ossfuzz_path}/infra/helper.py", "build_fuzzers", '--clean',
        target, target_repo_path, "--sanitizer", sanitizer
    ]
    logger.info(' '.join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Check for build errors
    build_error_patterns = [
        "Building fuzzers failed",
        "Docker build failed",
        "clang++: error:",
        "g++: error:",
        "cmake: error:",
        "fatal error:",
        "undefined reference to",
        "cannot find -l",
        "No such file or directory",
        "error: command",
        "error: 'struct",
        "error: conflicting types",
        "error: invalid conversion",
        "make: *** [Makefile:",
        "ninja: build stopped:",
        "Compilation failed",
        "failed with exit status"
    ]
    
    if any(error_pattern in result.stderr or error_pattern in result.stdout 
            for error_pattern in build_error_patterns) or result.returncode != 0:
        logger.info(f"Build failed after patch reversion for bug {bug_id}")
        return False
    
    logger.info(f"Successfully built fuzzer after reverting patch for bug {bug_id}")
    return True


def rever_patch_test(args):
    csv_file_path = args.target_test_result
    bug_info_dataset = read_json_file(args.bug_info)
    checkout_latest_commit(ossfuzz_path)
    # Get repo path from environment variable
    repo_path = os.getenv('REPO_PATH')
    if not repo_path:
        print("REPO_PATH environment variable not set. Exiting.")
        exit(1)

    parsed_data = parse_csv_file(csv_file_path)
    transitions = find_transitions(parsed_data)
    
    for commit, next_commit, bug_id in transitions:
        bug_info = bug_info_dataset[bug_id]
        target = bug_info['reproduce']['project']
        fuzzer = bug_info['reproduce']['fuzz_target']
        sanitizer = bug_info['reproduce']['sanitizer'].split(' ')[0]
        trace_path1 = os.path.join(data_path, f'target_trace-{commit['commit_id']}-testcase-{bug_id}.txt')
        trace_path2 = os.path.join(data_path, f'target_trace-{next_commit['commit_id']}-testcase-{bug_id}.txt')
        target_repo_path = os.path.join(repo_path, target)
        diff_results = []
    
        target_dockerfile_path = f'{ossfuzz_path}/projects/{target}/Dockerfile'
        # Replace '--depth=1' in the Dockerfile
        with open(target_dockerfile_path, 'r') as dockerfile:
            dockerfile_content = dockerfile.read()
        
        dockerfile_content = dockerfile_content.replace('--depth 1', '')
        updated_content = dockerfile_content.replace('--depth=1', '')
        
        with open(target_dockerfile_path, 'w') as dockerfile:
            dockerfile.write(updated_content)
    
        collect_trace_cmd = [py3, f'{current_file_path}/fuzz_helper.py', 'collect_trace', '--commit', commit['commit_id']]
        testcases_env = os.getenv('TESTCASES', '')
        if testcases_env:
            collect_trace_cmd.extend(['--testcases', testcases_env])
        else:
            print("TESTCASES environment variable not set. Exiting.")
            exit(1)

        collect_trace_cmd.extend(['--build_csv', args.build_csv])

        collect_trace_cmd.extend(['--test_input', 'testcase-' + bug_id])

        collect_trace_cmd.append(target)

        collect_trace_cmd.append(fuzzer)
    
        if not os.path.exists(trace_path1):
            # Print the command being executed
            print("Running command:", " ".join(collect_trace_cmd))
            # Execute the command
            try:
                result = subprocess.run(collect_trace_cmd, check=True, text=True)
                print(f"Command completed with exit code {result.returncode}")
            except subprocess.CalledProcessError as e:
                print(f"Command failed with exit code {e.returncode}")
                
        if not os.path.exists(trace_path2):
            collect_trace_cmd[4] = next_commit['commit_id']
            # Print the command being executed
            print("Running command:", " ".join(collect_trace_cmd))
            # Execute the command
            try:
                result = subprocess.run(collect_trace_cmd, check=True, text=True)
                print(f"Command completed with exit code {result.returncode}")
            except subprocess.CalledProcessError as e:
                print(f"Command failed with exit code {e.returncode}")
        
        trace1 = extract_function_calls(trace_path1)
        trace2 = extract_function_calls(trace_path2)
        common_part, remaining_trace1, remaining_trace2 = compare_traces(trace1, trace2)
        diffs = get_commit_patch_gitpython(target_repo_path, next_commit['commit_id'], commit['commit_id'])
        diff_results.extend(analyze_diffindex(diffs, target_repo_path, next_commit['commit_id']))
        
        trace_func_set = {func for _, func in common_part}
        patch_to_apply = []
        for diff_result in diff_results:
            if diff_result['file_type'] == 'cpp':
                patch_func = mangle_string(diff_result['signature'])
            else:
                patch_func = diff_result['signature']
            
            # If both bug commit's and fix commit's trace contain this patched function,
            # the patch of the function is likely related to the bug fixing. So try to
            # revert it. 
            if patch_func in trace_func_set:
                logger.info(f'Function {demangle_cpp_symbol(patch_func)} in both bug and fix traces, revert patch related to it')
                patch_to_apply.append(diff_result['patch_text'])
        
        # patch reverting finish here, target repo has been set to fix commit in analyze_diffindex
        for patch_text in patch_to_apply:
            revert_patch(target_repo_path, patch_text)
        
        # build and test if it works, oss-fuzz version has been set in collect_trace_cmd
        build_success = build_and_test_fuzzer(target, next_commit['commit_id'], 
                                                target_repo_path, sanitizer, bug_id, ossfuzz_path)
        if build_success:
            # Run the fuzzer to test if the bug is reproduced
            fuzzer_path = os.path.join(ossfuzz_path, "build/out", target, fuzzer)
            testcase_path = os.path.join(testcases_env, 'testcase-' + bug_id)
            test_result = subprocess.run([fuzzer_path, testcase_path], encoding='utf-8')
            
        break


if __name__ == "__main__":
    args = parse_arguments()
    rever_patch_test(args)