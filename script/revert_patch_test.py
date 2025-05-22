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
from collections import OrderedDict

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

current_file_path = os.path.dirname(os.path.abspath(__file__))
ossfuzz_path = os.path.abspath(os.path.join(current_file_path, '..', 'oss-fuzz'))
data_path = os.path.abspath(os.path.join(current_file_path, '..', 'data'))


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


def find_transitions(data, repo_path):
    # Build commit graph for easy parent/child lookup, and commits stored ordered by time
    commit_graph = OrderedDict()
    repo = Repo(repo_path)
    know_bug_ids = set() # a set of bugs that already have a fix
    
    # Initialize the graph with all commits
    for entry in data:
        commit_id = entry['commit_id']
        commit_graph[commit_id] = {
            'parents': [],
            'children': [],
            'data': entry
        }
    
    # Fill in parent/child relationships
    for i in range(len(data)):
        current_commit = data[i]['commit_id']
        commit = repo.commit(current_commit)
        # Add parents
        for parent in commit.parents:
            parent_id = parent.hexsha
            if parent_id in commit_graph:
                commit_graph[current_commit]['parents'].append(parent_id)
                commit_graph[parent_id]['children'].append(current_commit)
            
    transitions = []
    
    # Find transitions using the commit graph
    for commit_id, node in commit_graph.items():
        # Skip if commit has no children
        if not node['children']:
            continue
            
        # Check all OSV statuses for this commit
        for bug_id, status in node['data']['osv_statuses'].items():
            # we only keep one earlier fix commit for each bug_id, later fix commit is likely a merge
            if bug_id in know_bug_ids:
                continue
            # Check if this commit has a vulnerable status (1|0 or 1|1)
            if status in ["1|1"]:
                # Check all children for this commit
                for child_id in node['children']:
                    # Skip if child doesn't have this bug_id in its status
                    if bug_id not in commit_graph[child_id]['data']['osv_statuses']:
                        continue
                        
                    child_status = commit_graph[child_id]['data']['osv_statuses'][bug_id]
                    
                    # 1. Check if the child has a fixed status (0|0 or 0|1)
                    if child_status in ["0|0", "0|1"]:
                        # 2. Check if all parents of this child have a vulnerable status for this bug
                        all_parents_vulnerable = True
                        for parent_id in commit_graph[child_id]['parents']:
                            if parent_id in commit_graph:
                                parent_status = commit_graph[parent_id]['data']['osv_statuses'].get(bug_id)
                                if parent_status not in ["1|0", "1|1"]:
                                    all_parents_vulnerable = False
                                    break
                        # Skip if not all parents are vulnerable
                        if not all_parents_vulnerable:
                            continue
                        
                        # 3. Check if none of the descendants of the child have a vulnerable status
                        all_fixed = True
                        descendant_id = commit_graph[child_id]['children']
                        # DFS to check if any descendants have a vulnerable status
                        stack = [(desc_id, 1) for desc_id in commit_graph[child_id]['children']]
                        while stack and all_fixed:
                            current_id, depth = stack.pop()
                            # Check max search depth
                            if depth > 10:
                                continue
                            
                            descendant_status = commit_graph[current_id]['data']['osv_statuses'].get(bug_id)
                            if descendant_status in ["1|0", "1|1"]:
                                all_fixed = False
                                break
                            
                            # Add children to stack with incremented depth
                            for next_id in commit_graph[current_id]['children']:
                                stack.append((next_id, depth + 1))
                        
                        if all_fixed:
                            know_bug_ids.add(bug_id)
                            transitions.append((node['data'], commit_graph[child_id]['data'], bug_id))
                            # do not check other children
                            break
    
    return transitions


'''
Function-Level Changes
* **Function Signature Change**:
    * `Function Rename`: Changing the name of a function.
    * `Parameter Addition`: Adding one or more parameters to a function.
    * `Parameter Removal`: Removing one or more parameters from a function.
    * `Parameter Type Change`: Modifying the data type of one or more function parameters.
    * `Parameter Order Change`: Reordering existing function parameters.
    * `Return Type Change`: Modifying the data type of the function's return value.
    * `Qualifier Change`: Adding/removing `const`, `static`, `inline`, `virtual`, `explicit`, `volatile` qualifiers to a function.
* **Function Body Change**:
    * `Logic Change`: Modifying the internal logic or algorithm within a function.
    * `Statement Addition`: Adding new lines of executable code.
    * `Statement Deletion`: Removing existing lines of executable code.
    * `Statement Modification`: Changing existing lines of executable code.
    * `Function Call Added`: Introducing a call to another function.
    * `Function Call Removed`: Removing a call to another function.
    * `Function Call Argument Change`: Modifying arguments passed to a function call.
* **Function Definition/Declaration**:
    * `Function Added`: A new function is defined.
    * `Function Removed`: An existing function definition is removed.
    * `Function Declaration Added/Removed/Modified`: Changes to forward declarations, typically in header files.

Class/Struct-Level Changes (primarily C++)
* **Class/Struct Definition**:
    * `Class/Struct Added`: A new class or struct is defined.
    * `Class/Struct Removed`: An existing class or struct definition is removed.
    * `Class/Struct Rename`: Changing the name of a class or struct.
* **Member Changes**:
    * `Member Variable Added`: Adding a new data member.
    * `Member Variable Removed`: Removing an existing data member.
    * `Member Variable Type Change`: Changing the type of a data member.
    * `Member Variable Rename`: Renaming a data member.
    * `Member Function Added` (see Function-Level Changes for methods).
    * `Member Function Removed` (see Function-Level Changes for methods).
    * `Access Specifier Change`: Changing `public`, `protected`, or `private` status of members.
* **Inheritance/Polymorphism**:
    * `Base Class Added`: Adding a new base class (inheritance).
    * `Base Class Removed`: Removing a base class.
    * `Virtual Function Added/Removed/Modified`: Changes related to polymorphism.
    * `Override Specifier Added/Removed`: Adding/removing `override`.
    * `Final Specifier Added/Removed`: Adding/removing `final`.
* **Constructor/Destructor Changes**:
    * `Constructor Added/Removed/Modified`.
    * `Destructor Added/Removed/Modified`.
    * `Default Constructor/Destructor Added/Removed` (e.g., `= default`, `= delete`).

Control Flow Changes
* `Conditional Statement Added/Removed/Modified`: Changes to `if`, `else if`, `else`, `switch` statements.
* `Loop Added/Removed/Modified`: Changes to `for`, `while`, `do-while` loops.
* `Break/Continue Statement Added/Removed`.
* `Return Statement Added/Removed/Modified`.
* `Goto Statement Added/Removed/Modified` (less common, but possible).

Data Type Changes
* `Typedef Change`: Modifying a `typedef` definition.
* `Using Alias Change` (C++): Modifying a `using` alias for a type.
* `Enum Definition Added/Removed/Modified`: Changes to enumerations.
* `Union Definition Added/Removed/Modified`: Changes to unions.

Preprocessor Changes
* `Macro Definition Added/Removed/Modified`: Changes to `#define`.
* `Include Directive Added/Removed/Modified`: Changes to `#include`.
* `Conditional Compilation Added/Removed/Modified`: Changes involving `#ifdef`, `#ifndef`, `#if`, `#else`, `#elif`, `#endif`.

Variable/Attribute Changes
* `Variable Declaration Added/Removed`: Adding or removing local or global variables.
* `Variable Initialization Change`: Modifying how a variable is initialized.
* `Variable Type Change`: Changing the data type of a variable.
* `Static Variable Added/Removed/Modified`.
* `Extern Variable Declaration Added/Removed/Modified`.
* `Constant Definition Added/Removed/Modified`: Changes to `const` variables.

Error Handling Changes
* `Exception Handling Added/Removed/Modified` (C++): Changes to `try`, `catch`, `throw`.
* `Error Code Check Added/Removed/Modified`: Changes in how function return values or error flags are checked.

Memory Management Changes
* `Dynamic Memory Allocation Added/Removed/Modified`: Changes involving `new`/`delete` (C++) or `malloc`/`calloc`/`realloc`/`free` (C).
* `Smart Pointer Usage Added/Removed/Modified` (C++): e.g., `std::unique_ptr`, `std::shared_ptr`.

Concurrency Changes (C++11 and later, or using pthreads, etc.)
* `Thread Creation/Management Change`.
* `Mutex/Lock/Semaphore Usage Added/Removed/Modified`.
* `Atomic Operation Added/Removed/Modified`.
* `Condition Variable Usage Added/Removed/Modified`.

Style/Formatting Changes
* `Whitespace Change`: Modifications to spaces, tabs, newlines that don't affect logic.
* `Comment Added/Removed/Modified`.
* `Code Reformatting`: Changes that only alter the layout of the code (e.g., brace style, indentation). *Often, these are filtered out or handled separately in semantic diff tools.*
'''
def get_diff_type(diff):
    pass


def extract_revert_patch(h, line_start, line_end, version):
    """
    Extract and create a partial revert patch from a given diff hunk.
    
    Args:
        h: String containing the hunk content
        line_start: Starting line number to extract
        line_end: Ending line number to extract
        version: Version of the code (old or new)
    
    Returns:
        String containing the extracted patch
    """
    # Split the hunk content into lines
    lines = h.split('\n')
    logger.debug(f'line_start: {line_start}, line_end: {line_end} version: {version}')
    
    inside_hunk = True  # We're already inside a hunk
    patch_lines = []
    new_line_cursor = {"num": 0} # next line to be check
    old_line_cursor = {"num": 0} # next line to be check
    # line to be check
    if version == 'old':
        target_line_cursor = old_line_cursor
    elif version == 'new':
        target_line_cursor = new_line_cursor
    else:
        raise ValueError("Version must be 'old' or 'new'")
    
    # First line contains the hunk header
    header_line = lines[0]
    
    # Parse header line like: " -1223,17 +1224,73 @@"
    match = re.match(r'^.*-(\d+),?\d* \+(\d+),?(\d*) .*', header_line)
    if match:
        old_line_cursor['num'] = int(match.group(1))
        new_line_cursor['num'] = int(match.group(2))
        
    get_sub_patch_start = False
    old_line_start = 0
    new_line_start = 0
    
    # Process the actual diff content
    for line in lines[1:]:
        if not line:
            continue
        
        logger.debug(f'target_line_cursor: {target_line_cursor["num"]} old_line_cursor: {old_line_cursor["num"]} new_line_cursor: {new_line_cursor["num"]}')
        
        if target_line_cursor['num'] >= line_start and target_line_cursor['num'] <= line_end:
            if not get_sub_patch_start:
                if version == 'new' and line.startswith('+') or version == 'old' and line.startswith('-') or line.startswith(' '):
                    get_sub_patch_start = True
                    new_line_start = new_line_cursor['num']
                    old_line_start = old_line_cursor['num']
            if get_sub_patch_start:
                patch_lines.append(line)
                logger.debug(f'add line: {line}')
            
        if target_line_cursor['num'] > line_end:
            # We've reached the end of the target lines
            break
        
        # Check the first character of the line to determine the type of change
        if line.startswith(' '):
            # Context line, increment both cursors
                new_line_cursor['num'] += 1
                old_line_cursor['num'] += 1
        elif line.startswith('+'):
            # Added line, increment new line cursor
            new_line_cursor['num'] += 1
        elif line.startswith('-'):
            # Removed line, increment old line cursor
            old_line_cursor['num'] += 1
                
    new_header_line = f"@@ -{new_line_start},{old_line_cursor['num']-old_line_start} +{new_line_start},{new_line_cursor['num']-new_line_start} @@\n"
    patch_lines.insert(0, new_header_line)
    return '\n'.join(patch_lines), old_line_start, old_line_cursor['num'], new_line_start, new_line_cursor['num']


def analyze_diffindex(diff_index, target_repo_path: str, new_commit: str, old_commit: str):
    """
    Analyze a GitPython DiffIndex and return metadata per hunk.
    Target repo checkout to fix commit here.
    """
    results = dict()
    for diff in diff_index:
        type_set = set()
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
        
        # checkout target repo to the new commit, and parse the code from that
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', new_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for h in hunks[1:]:
            # The hunk header is before the first newline
            header, body = h.split('\n', 1)
            old_line_num = header.split('@@')[-2].strip().split(' ')[0][1:]
            old_begin_num = int(old_line_num.split(',')[0]) + 3
            old_end_num = old_begin_num + int(old_line_num.split(',')[1]) - 7

            new_line_num = header.split('@@')[-2].strip().split('+')[1].strip()
            # diff codes have extra 3 lines
            begin_num = int(new_line_num.split(',')[0]) + 3
            end_num = begin_num + int(new_line_num.split(',')[1]) - 7
            # Extract section/function name (text after second '@@')
            section = header.split('@@')[-1].strip() or "<no-section>"

            # parse to get function signature
            parser = CParser()
            file_path = os.path.join(target_repo_path, path)

            if not os.path.exists(file_path):
                logger.info(f"File {file_path} does not exist, skipping parsing")
                continue
            
            signature = 'unknown'
            for item in parser.iterate_code(file_path, file_type=ext):
                patch_header = f"diff --git a/{diff.a_path} b/{diff.b_path}\n"
                patch_header += f"--- a/{diff.a_path}\n+++ b/{diff.b_path}\n"
                # diff inside a function definition
                if item['type'] == 'function' and item['start_point'][0]+1 <= begin_num and item['end_point'][0] >= end_num:
                    signature = item['signature']
                    patch_text = patch_header + f'@@ -{new_line_num.split(',')[0]},{old_line_num.split(',')[1]} +{new_line_num.split(',')[0]},{new_line_num.split(',')[1]} @@\n' + body

                    # use old patch location as key
                    results[f'{diff.a_path}{diff.b_path}-{old_line_num}+{new_line_num}'] = {
                        'file_path':   path,
                        'file_type':   ext,
                        'change_type': diff.change_type,
                        'hunk_header': section,
                        'patch_text':  patch_text,
                        'new_signature':   signature,
                        'patch_type': type_set,
                    }
                    break
                # part or all of function definitions inside the diff
                if item['type'] == 'function' and item['end_point'][0] >= begin_num and item['start_point'][0]+1 <= end_num:
                    signature = item['signature']
                    diff_result_begin = max(item['start_point'][0], begin_num)
                    diff_result_end = min(item['end_point'][0], end_num) + 1
                    # not include context lines, because they may add some changes not related to the function
                    sub_patch, old_line_start, old_line_cursor, new_line_start, new_line_cursor = extract_revert_patch(h, diff_result_begin, diff_result_end, 'new')
                    patch_text = header + sub_patch
                    results[f'{diff.a_path}{diff.b_path}-{old_line_start},{old_line_cursor-old_line_start}+{new_line_start},{new_line_cursor-new_line_start}'] = {
                        'file_path':   path,
                        'file_type':   ext,
                        'change_type': diff.change_type,
                        'hunk_header': section,
                        'patch_text':  patch_text,
                        'new_signature':   signature,
                        'patch_type': type_set,
                    }
        
        # checkout target repo to the old commit, and parse the code from that
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', old_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for h in hunks[1:]:
            # The hunk header is before the first newline
            header, body = h.split('\n', 1)
            old_line_num = header.split('@@')[-2].strip().split(' ')[0][1:]
            old_begin_num = int(old_line_num.split(',')[0]) + 3
            old_end_num = old_begin_num + int(old_line_num.split(',')[1]) - 7

            new_line_num = header.split('@@')[-2].strip().split('+')[1].strip()
            # Extract section/function name (text after second '@@')
            section = header.split('@@')[-1].strip() or "<no-section>"

            # parse to get function signature
            parser = CParser()
            file_path = os.path.join(target_repo_path, path)

            if not os.path.exists(file_path):
                logger.info(f"File {file_path} does not exist, skipping parsing")
                continue
            
            signature = 'unknown'
            for item in parser.iterate_code(file_path, file_type=ext):
                patch_header = f"diff --git a/{diff.a_path} b/{diff.b_path}\n"
                patch_header += f"--- a/{diff.a_path}\n+++ b/{diff.b_path}\n"
                # diff inside a function definition
                if item['type'] == 'function' and item['start_point'][0]+1 <= old_begin_num and item['end_point'][0] >= old_end_num:
                    signature = item['signature']
                    patch_text = patch_header + f'@@ -{new_line_num.split(',')[0]},{old_line_num.split(',')[1]} +{new_line_num.split(',')[0]},{new_line_num.split(',')[1]} @@\n' + body

                    if f'{diff.a_path}{diff.b_path}-{old_line_num}+{new_line_num}' in results:
                        results[f'{diff.a_path}{diff.b_path}-{old_line_num}+{new_line_num}']['old_signature'] = signature
                    else:
                        results[f'{diff.a_path}{diff.b_path}-{old_line_num}+{new_line_num}'] = {
                            'file_path':   path,
                            'file_type':   ext,
                            'change_type': diff.change_type,
                            'hunk_header': section,
                            'patch_text':  patch_text,
                            'old_signature':   signature,
                            'patch_type': type_set,
                        }
                    break
                # part of function definitions inside the diff
                if item['type'] == 'function' and item['end_point'][0] >= old_begin_num and item['start_point'][0]+1 <= old_end_num:
                    signature = item['signature']
                    diff_result_begin = max(item['start_point'][0], old_begin_num)
                    diff_result_end = min(item['end_point'][0], old_end_num) + 1
                    # not include context lines, because they may add some changes not related to the function
                    sub_patch, old_line_start, old_line_cursor, new_line_start, new_line_cursor = extract_revert_patch(h, diff_result_begin, diff_result_end, 'old')
                    patch_text = header + sub_patch
                    
                    if f'{diff.a_path}{diff.b_path}-{old_line_start},{old_line_cursor-old_line_start}+{new_line_start},{new_line_cursor-new_line_start}' in results:
                        results[f'{diff.a_path}{diff.b_path}-{old_line_start},{old_line_cursor-old_line_start}+{new_line_start},{new_line_cursor-new_line_start}']['old_signature'] = signature
                    else:
                        results[f'{diff.a_path}{diff.b_path}-{old_line_start},{old_line_cursor-old_line_start}+{new_line_start},{new_line_cursor-new_line_start}'] = {
                            'file_path':   path,
                            'file_type':   ext,
                            'change_type': diff.change_type,
                            'hunk_header': section,
                            'patch_text':  patch_text,
                            'old_signature':   signature,
                            'patch_type': type_set,
                        }
                    
    
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


def build_and_test_fuzzer(target, commit_id, sanitizer, bug_id, patch_file_path, fuzzer, build_csv, arch):
    cmd = [
        "python3", f"{current_file_path}/fuzz_helper.py", "build_version", "--commit", commit_id, "--sanitizer", sanitizer,
        "--patch", patch_file_path, '--build_csv', build_csv, '--architecture', arch , target
    ]

    logger.debug(' '.join(cmd))
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
        "error: patch failed:",
        "make: *** [Makefile:",
        "ninja: build stopped:",
        "Compilation failed",
        "failed with exit status"
    ]
    
    fuzzer_path = os.path.join(ossfuzz_path, 'build/out', target, fuzzer)
    if not os.path.exists(fuzzer_path) and any(error_pattern in result.stderr or error_pattern in result.stdout 
            for error_pattern in build_error_patterns) or result.returncode != 0:
        logger.info(f"Build failed after patch reversion for bug {bug_id}\n")
        return False
    
    logger.info(f"Successfully built fuzzer after reverting patch for bug {bug_id}")
    return True


def revert_patch_test(args):
    csv_file_path = args.target_test_result
    bug_info_dataset = read_json_file(args.bug_info)
    checkout_latest_commit(ossfuzz_path)
    revert_and_trigger_set = set()
    revert_and_trigger_fail_set = set()
    # Get repo path from environment variable
    repo_path = os.getenv('REPO_PATH')
    if not repo_path:
        logger.info("REPO_PATH environment variable not set. Exiting.")
        exit(1)

    parsed_data = parse_csv_file(csv_file_path)
    target = csv_file_path.split('/')[-1].split('.')[0]
    target_repo_path = os.path.join(repo_path, target)
    target_dockerfile_path = f'{ossfuzz_path}/projects/{target}/Dockerfile'
    transitions = find_transitions(parsed_data, target_repo_path)
    logger.info(f"Transitions found: {len(transitions)}")
    
    for commit, next_commit, bug_id in transitions:
        logger.info(f"Processing transition for bug {bug_id} from commit {commit['commit_id']} to {next_commit['commit_id']}")
        bug_info = bug_info_dataset[bug_id]
        fuzzer = bug_info['reproduce']['fuzz_target']
        sanitizer = bug_info['reproduce']['sanitizer'].split(' ')[0]
        bug_type = bug_info['reproduce']['crash_type']
        job_type = bug_info['reproduce']['job_type']
        if len(job_type.split('_')) > 3:
            arch = job_type.split('_')[2]
        else:
            arch = 'x86_64'
        trace_path1 = os.path.join(data_path, f'target_trace-{commit['commit_id']}-testcase-{bug_id}.txt')
        trace_path2 = os.path.join(data_path, f'target_trace-{next_commit['commit_id']}-testcase-{bug_id}.txt')
    
        # Replace '--depth=1' in the Dockerfile
        with open(target_dockerfile_path, 'r') as dockerfile:
            dockerfile_content = dockerfile.read()
        
        dockerfile_content = dockerfile_content.replace('--depth 1', '')
        updated_content = dockerfile_content.replace('--depth=1', '')
        
        with open(target_dockerfile_path, 'w') as dockerfile:
            dockerfile.write(updated_content)
    
        collect_trace_cmd = [py3, f'{current_file_path}/fuzz_helper.py', 'collect_trace', '--commit', commit['commit_id'], '--sanitizer', sanitizer,
                            '--build_csv', args.build_csv, '--architecture', arch]
        testcases_env = os.getenv('TESTCASES', '')
        if testcases_env:
            collect_trace_cmd.extend(['--testcases', testcases_env])
        else:
            logger.info("TESTCASES environment variable not set. Exiting.")
            exit(1)

        collect_trace_cmd.extend(['--build_csv', args.build_csv])

        collect_trace_cmd.extend(['--test_input', 'testcase-' + bug_id])

        collect_trace_cmd.append(target)

        collect_trace_cmd.append(fuzzer)
    
        if not os.path.exists(trace_path1) or os.path.exists(trace_path1) and 'No such file or directory' in open(trace_path1).read():
            # logger.info the command being executed
            logger.info(f"Running command: {" ".join(collect_trace_cmd)}")
            # Execute the command
            try:
                result = subprocess.run(collect_trace_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError as e:
                logger.info(f"Command failed with exit code {e.returncode}")
                
        if not os.path.exists(trace_path2)  or os.path.exists(trace_path2) and 'No such file or directory' in open(trace_path2).read():
            collect_trace_cmd[4] = next_commit['commit_id']
            # logger.info the command being executed
            logger.info(f"Running command: {" ".join(collect_trace_cmd)}")
            # Execute the command
            try:
                result = subprocess.run(collect_trace_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError as e:
                logger.info(f"Command failed with exit code {e.returncode}")
        
        trace1 = extract_function_calls(trace_path1)
        trace2 = extract_function_calls(trace_path2)
        common_part, remaining_trace1, remaining_trace2 = compare_traces(trace1, trace2)
        diffs = get_commit_patch_gitpython(target_repo_path, next_commit['commit_id'], commit['commit_id']) # every file get a diff
        diff_results = analyze_diffindex(diffs, target_repo_path, next_commit['commit_id'], commit['commit_id'])

        trace_func_set = set()
        # checkout target repo to the bug commit, get function signature from source code using code location
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', commit['commit_id']], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        func_dict = dict()
        for _, func in common_part: # may consume a lot of time
            if func in func_dict:
                continue
            func_loc = func.split(' ')[1]
            file_path = os.path.join(target_repo_path, func_loc.split(':')[0])
            line_num = func_loc.split(':')[1]
            col_num = func_loc.split(':')[2]
            parser = CParser()
            if os.path.exists(file_path):
                func_dict[func] = parser.function_signature(file_path, int(line_num), int(col_num), file_path.split('.')[-1])
                trace_func_set.add(func_dict[func])
            else:
                trace_func_set.add(func.split(' ')[0])
                
        logger.debug(f"Trace function set: {trace_func_set}")
        if not trace_func_set:
            logger.info(f'No function signatures found in trace for bug {bug_id}\n')
            continue
        # checkout target repo to the bug commit, get function signature from source code using code location
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', next_commit['commit_id']], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        patch_to_apply = []
        for key, diff_result in diff_results.items():
            if 'new_signature' in diff_result:
                logger.debug(f'newsignature{diff_result['new_signature']}')
                patch_func = diff_result['new_signature']
            if 'old_signature' in diff_result:
                logger.debug(f'oldsignature{diff_result['old_signature']}')
                patch_func = diff_result['old_signature']
            logger.debug(f'Diff result: {key} \n{diff_result['patch_text']}')
            logger.debug(f'Patch Function: {patch_func}')
            # If both bug commit's and fix commit's trace contain this patched function,
            # the patch of the function is likely related to the bug fixing. So try to
            # revert it. 
            for trace_func in trace_func_set:
                if trace_func in patch_func:
                    logger.debug(f'Function {demangle_cpp_symbol(trace_func)} in both bug and fix traces, revert patch related to it')
                    patch_to_apply.append(diff_result['patch_text'])
                    break

        patch_folder = os.path.abspath(os.path.join(current_file_path, '..', 'patch'))
        
        if not os.path.exists(patch_folder):
            os.makedirs(patch_folder, exist_ok=True)
        
        # Save all patches to a single file
        if patch_to_apply:
            patch_file_path = os.path.join(patch_folder, f"{bug_id}_{next_commit['commit_id']}_patches.diff")
            with open(patch_file_path, 'w') as patch_file:
                for patch in patch_to_apply:
                    patch_file.write(patch)
                    patch_file.write('\n\n')  # Add separator between patches
        else:
            logger.error(f"No relevant patches found to revert for bug {bug_id}\n")
            continue
        
        # build and test if it works, oss-fuzz version has been set in collect_trace_cmd
        build_success = build_and_test_fuzzer(target, next_commit['commit_id'], sanitizer, bug_id, patch_file_path, fuzzer, args.build_csv, arch)
        if build_success:
            # Run the fuzzer to test if the bug is reproduced
            testcase_path = os.path.join(testcases_env, 'testcase-' + bug_id)
            reproduce_cmd = [
                py3, f'{current_file_path}/fuzz_helper.py', 'reproduce', target, fuzzer, testcase_path
            ]
            test_result = subprocess.run(reproduce_cmd, capture_output=True, text=True)
            if bug_type.lower() in test_result.stdout.lower() or bug_type.lower() in test_result.stderr.lower():
                # trigger the bug
                revert_and_trigger_set.add((bug_id, next_commit['commit_id'], fuzzer))
                logger.info(f"Bug {bug_id} triggered successfully with fuzzer {fuzzer} on commit {next_commit['commit_id']}\n")
            else:
                revert_and_trigger_fail_set.add((bug_id, next_commit['commit_id'], fuzzer))
                logger.info(f"Bug {bug_id} not triggered with fuzzer {fuzzer} on commit {next_commit['commit_id']}\n")

    logger.info(f"Revert and trigger set: {len(revert_and_trigger_set)} {revert_and_trigger_set}")
    logger.info(f"Revert and trigger fail set: {len(revert_and_trigger_fail_set)} {revert_and_trigger_fail_set}")

if __name__ == "__main__":
    args = parse_arguments()
    revert_patch_test(args)