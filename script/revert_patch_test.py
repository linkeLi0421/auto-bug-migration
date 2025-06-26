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


def get_diff_unified(repo_path, commit1, commit2, context_lines=3):
    """
    Get unified diff format between two commits.
    
    Args:
        repo_path (str): Path to the git repository
        commit1 (str): First commit hash/reference
        commit2 (str): Second commit hash/reference
        context_lines (int): Number of context lines around changes
    
    Returns:
        str: Unified diff content without a/ and b/ prefixes.
    """
    try:
        repo = Repo(repo_path)
        
        # Use git diff with --minimal, --no-prefix and context lines options
        diff_output = repo.git.diff(
            '--minimal',
            '--no-prefix',
            commit1, 
            commit2, 
            unified=context_lines
        )
        
        return diff_output
        
    except Exception as e:
        raise RuntimeError(f"Error generating unified diff: {e}")


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
        version: Version of the code (old or new or both)
    
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
    elif version == 'both':
        target_line_cursor = None
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
        
        logger.debug(f'version: {version} old_line_cursor: {old_line_cursor["num"]} new_line_cursor: {new_line_cursor["num"]}')
        
        if (not target_line_cursor and old_line_cursor['num'] >= line_start and new_line_cursor['num'] <= line_end) or (target_line_cursor and target_line_cursor['num'] >= line_start and target_line_cursor['num'] <= line_end):
            if not get_sub_patch_start:
                if not target_line_cursor or version == 'new' and line.startswith('+') or version == 'old' and line.startswith('-') or line.startswith(' '):
                    get_sub_patch_start = True
                    new_line_start = new_line_cursor['num']
                    old_line_start = old_line_cursor['num']
            if get_sub_patch_start:
                patch_lines.append(line)
                logger.debug(f'add line: {line}')
            
        if target_line_cursor and target_line_cursor['num'] > line_end or not target_line_cursor and new_line_cursor['num'] > line_end:
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
                
    new_header_line = f"@@ -{new_line_start},{old_line_cursor['num']-old_line_start} +{new_line_start},{new_line_cursor['num']-new_line_start} @@"
    patch_lines.insert(0, new_header_line)
    
    if not get_sub_patch_start:
        # get nothing
        return '\n'.join(patch_lines), old_line_cursor['num']-1, old_line_cursor['num']-1, new_line_cursor['num']-1, new_line_cursor['num']-1
    
    return '\n'.join(patch_lines), old_line_start, old_line_cursor['num'], new_line_start, new_line_cursor['num']


def update_type_set(patch):
    """
    Determine the type of changes in a patch.
    
    Args:
        patch: The patch text to analyze.
    
    Returns:
        a list of signature changed function pairs
    """
    type_set = patch.get('patch_type', set())
    sig_change_list = []
    old_signature = patch.get('old_signature', '')
    new_signature = patch.get('new_signature', '')
    logger.debug(f'\nold_signature: {old_signature}\nnew_signature: {new_signature}')
    if old_signature != '' and new_signature != '' and old_signature != new_signature:
        # function signature changed
        type_set.add('Function added')
        type_set.add('Function removed')
        type_set.add('Function signature change')
        sig_change_list.append((old_signature, new_signature))
    patch['patch_type'] = type_set

    return sig_change_list


def analyze_diffindex(diff_text, target_repo_path: str, new_commit: str, old_commit: str, target: str):
    """
    Analyze a GitPython DiffIndex and return metadata per hunk.
    Target repo checkout to fix commit here.
    """
    results = dict()
    func_kinds = {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}
    for diff in diff_text.split('diff --git')[1:]:
        # Choose the post-change path if available, else pre-change:
        diff_lines = diff.splitlines()
        if len(diff_lines) < 5:
            logger.info(f'diff is too short, skipping: {diff}')
            # Skip if the diff is too short to contain valid information, like binary files or empty diffs
            continue
        path_a = None
        path_b = None
        for diff_line in diff_lines:
            if diff_line.startswith('---'):
                path_a = diff_line.split(' ')[-1]
            elif diff_line.startswith('+++'):
                path_b = diff_line.split(' ')[-1]
            if path_a and path_b:
                break
        path = path_b if 'dev/null' not in path_b else path_a
        # Derive file extension/type from path:
        ext  = path.rsplit('.', 1)[-1] if '.' in path else ''
        if ext not in ['c', 'cpp', 'h', 'hpp', 'cxx', 'cc']:
            # Skip non-C/C++ files
            logger.info(f'Skipping non-C/C++ file: {path}')
            continue

        patch_text = diff

        # Split into hunks on lines starting with '@@'
        hunks = re.split(r'(?m)^@@', patch_text)
        # The first element is the header before any hunk; skip it
        
        # checkout target repo to the new commit, and parse the code from that
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', new_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for h in hunks[1:]:
            # diff codes have extra 3 lines
            if len(h.split('\n')) >= 8:
                # The hunk header is before the first newline
                header, body = h.split('\n', 1)
                old_line_num = header.split('@@')[-2].strip().split(' ')[0][1:]
                lines_body = body.split('\n')
                first_index = None
                last_index = None
                for idx, line in enumerate(lines_body):
                    if line.startswith('-') or line.startswith('+'):
                        first_index = idx
                        break
                
                for idx, line in enumerate(lines_body[::-1]):
                    if line.startswith('-') or line.startswith('+'):
                        last_index = idx-1
                        break
                old_begin_num = int(old_line_num.split(',')[0]) + first_index
                old_end_num = max(old_begin_num, old_begin_num + int(old_line_num.split(',')[1]) - first_index - last_index - 1)

                new_line_num = header.split('@@')[-2].strip().split('+')[1].strip()
                begin_num = int(new_line_num.split(',')[0]) + first_index
                end_num = max(begin_num, begin_num + int(new_line_num.split(',')[1]) - first_index - last_index - 1)
            else:
                # If the hunk is too short, skip it TODO: maybe find a better way to handle this
                logger.debug(f'Skipping short hunk: {h}')
                continue
                
            file_path = os.path.join(target_repo_path, path_b)
            parsing_path = os.path.join(data_path, f'{target}-{new_commit[:6]}', f'{path_b}_analysis.json')
            if not os.path.exists(file_path) or not os.path.exists(parsing_path):
                logger.debug(f"File {file_path} or {parsing_path} does not exist, skipping parsing")
                continue
            
            # read data for function signature mapping
            with open(parsing_path, 'r') as f:
                ast_nodes = json.load(f)

            patch_header = f"diff --git a/{path_a if path_a != '/dev/null' else path_b} b/{path_b if path_b != '/dev/null' else path_a}\n"
            patch_header += f"--- {'a/' if path_a != '/dev/null' else ''}{path_a}\n+++ {'b/' if path_b != '/dev/null' else ''}{path_b}\n"
            signature = 'unknown'
            # filter for function‐like nodes (clang cursors for functions, methods, etc.)
            for node in ast_nodes:
                if node.get('kind') not in func_kinds:
                    continue
                if node['location']['file'] == path_b and node['extent']['end']['line'] >= begin_num and node['extent']['start']['line'] <= end_num:
                    signature = node['signature']
                    diff_result_begin = max(node['extent']['start']['line'], begin_num)
                    diff_result_end = min(node['extent']['end']['line'], end_num)
                    # not include context lines, because they may add some changes not related to the function
                    sub_patch, old_line_start, old_line_cursor, new_line_start, new_line_cursor = extract_revert_patch(h, diff_result_begin, diff_result_end, 'new')
                    key_new = f'{path_a}{path_b}-{old_line_start},{old_line_cursor-old_line_start}+{new_line_start},{new_line_cursor-new_line_start}'
                    patch_text = patch_header + sub_patch
                    type_set = {'Function body change'}
                    if old_line_cursor == old_line_start:
                        type_set.add('Function added')
                    if new_line_cursor == new_line_start:
                        type_set.add('Function removed')
                    
                    dependent_func = set()
                    results[f'{path_a}{path_b}-{old_line_start},{old_line_cursor-old_line_start}+{new_line_start},{new_line_cursor-new_line_start}'] = {
                        'file_path_old':   path_a,
                        'file_path_new':   path_b,
                        'file_type':   ext,
                        'patch_text':  patch_text,
                        'new_signature':   signature,
                        'patch_type': type_set,
                        'dependent_func': dependent_func,
                        'new_start_line': int(new_line_start),
                        'new_end_line': int(new_line_cursor),
                        'old_start_line': int(old_line_start),
                        'old_end_line': int(old_line_cursor),
                        'new_function_start_line': int(node['extent']['start']['line']),
                        'new_function_end_line': int(node['extent']['end']['line']),
                    }
        
        # checkout target repo to the new commit, and parse the code from that
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', old_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        for h in hunks[1:]:
            # The hunk header is before the first newline
            header, body = h.split('\n', 1)
            old_line_num = header.split('@@')[-2].strip().split(' ')[0][1:]
            old_line_num = old_line_num if old_line_num.count(',') else '0,' + old_line_num

            lines_body = body.split('\n')
            first_index = 0
            last_index = 0
            for idx, line in enumerate(lines_body):
                if line.startswith('-') or line.startswith('+'):
                    first_index = idx
                    break
            
            for idx, line in enumerate(lines_body[::-1]):
                if line.startswith('-') or line.startswith('+'):
                    last_index = idx-1
                    break
            
            old_begin_num = int(old_line_num.split(',')[0]) + first_index
            old_end_num = max(old_begin_num, old_begin_num + int(old_line_num.split(',')[1]) - first_index - last_index - 1)

            new_line_num = header.split('@@')[-2].strip().split('+')[1].strip()

            file_path = os.path.join(target_repo_path, path_a)
            parsing_path = os.path.join(data_path, f'{target}-{old_commit[:6]}', f'{path_a}_analysis.json')

            if not os.path.exists(file_path) or not os.path.exists(parsing_path):
                logger.debug(f"File {file_path} or {parsing_path} does not exist, skipping parsing")
                continue
            
            # read data for function signature mapping
            with open(parsing_path, 'r') as f:
                ast_nodes = json.load(f)
            
            patch_header = f"diff --git a/{path_a if path_a != '/dev/null' else path_b} b/{path_b if path_b != '/dev/null' else path_a}\n"
            patch_header += f"--- {'a/' if path_a != '/dev/null' else ''}{path_a}\n+++ {'b/' if path_b != '/dev/null' else ''}{path_b}\n"
            signature = 'unknown'
            # filter for function‐like nodes (clang cursors for functions, methods, etc.)
            func_kinds = {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}
            for node in ast_nodes:
                if node.get('kind') not in func_kinds:
                    continue
                if node['location']['file'] == path_a and node['extent']['end']['line'] >= old_begin_num and node['extent']['start']['line'] <= old_end_num:
                    signature = node['signature']
                    diff_result_begin = max(node['extent']['start']['line'], old_begin_num)
                    diff_result_end = min(node['extent']['end']['line'], old_end_num)
                    # not include context lines, because they may add some changes not related to the function
                    sub_patch, old_line_start, old_line_cursor, new_line_start, new_line_cursor = extract_revert_patch(h, diff_result_begin, diff_result_end, 'old')
                    k_old = f'{path_a}{path_b}-{old_line_start},{old_line_cursor-old_line_start}+{new_line_start},{new_line_cursor-new_line_start}'
                    # check if there is a patch that has overlapped with the current patch
                    key_merged = dict()
                    if k_old not in results:
                        for k, v in results.items():
                            if f'{path_a}{path_b}' not in k:
                                # not same file, skip
                                continue
                            if 'new_signature' not in v:
                                continue
                            old_start_i, old_end_i, new_start_i, new_end_i = v['old_start_line'], v['old_end_line'], v['new_start_line'], v['new_end_line']
                            if new_start_i == new_end_i:
                                # this situation is handled in add_context()
                                continue
                            if (max(old_start_i, old_line_start) <= min(old_end_i, old_line_cursor) and
                                max(new_start_i, new_line_start) <= min(new_end_i, new_line_cursor)):
                                # update the boundaries: take min start and max end for both old and new
                                old_start = min(old_start_i, old_line_start)
                                old_end = max(old_end_i, old_line_cursor)
                                new_start = min(new_start_i, new_line_start)
                                new_end = max(new_end_i, new_line_cursor)
                                sub_patch, old_line_start, old_line_cursor, new_line_start, new_line_cursor = extract_revert_patch(h, old_start, new_end, 'both')
                                k_old = f'{path_a}{path_b}-{old_line_start},{old_line_cursor-old_line_start}+{new_line_start},{new_line_cursor-new_line_start}'
                                key_merged[k] = k_old
                                break
                        
                    patch_text = patch_header + sub_patch
                    type_set = {'Function body change'}
                    if old_line_cursor == old_line_start:
                        type_set.add('Function added')
                    if new_line_cursor == new_line_start:
                        type_set.add('Function removed')
                    
                    dependent_func = set()
                    
                    if k_old in results:
                        results[k_old]['old_signature'] = signature
                    else:
                        results[k_old] = {
                            'file_path_old':   path_a,
                            'file_path_new':   path_b,
                            'file_type':   ext,
                            'patch_text':  patch_text,
                            'old_signature':   signature,
                            'patch_type': type_set,
                            'dependent_func': dependent_func,
                            'new_start_line': int(new_line_start),
                            'new_end_line': int(new_line_cursor),
                            'old_start_line': int(old_line_start),
                            'old_end_line': int(old_line_cursor),
                            'old_function_start_line': int(node['extent']['start']['line']),
                            'old_function_end_line': int(node['extent']['end']['line']),
                        }
                    
                    for k_new, k_old in key_merged.items():
                        results[k_old]['new_signature'] = results[k_new]['new_signature']
                        results[k_old]['new_start_line'] = results[k_new]['new_start_line']
                        results[k_old]['new_end_line'] = results[k_new]['new_end_line']
                        del results[k_new]
    
    return results


def build_fuzzer(target, commit_id, sanitizer, bug_id, patch_file_path, fuzzer, build_csv, arch):
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
        return False, result.stderr+result.stdout
    
    logger.info(f"Successfully built fuzzer after reverting patch for bug {bug_id}")
    return True, ''


def rename_func(patch_text, fname, replacement_string=None):
    logger.debug(f'Renaming function {fname}')
    modified_lines = []
    regex = r'(?<![\w.])' + re.escape(fname) + r'(?!\w)'
    if not replacement_string:
        replacement_string = f"__revert_{fname}"

    for line in patch_text.splitlines():
        if line.startswith('-'):
            # Only modify lines that represent removed code
            modified_line = re.sub(regex, replacement_string, line)
            modified_lines.append(modified_line)
        else:
            modified_lines.append(line)
    return modified_lines


def remove_unnecessary_lines(diff_results, patch_to_apply, dependence_graph, trace1):
    # 1. Remove unnecessary lines from the diff results based on the trace1
    # If callee do not exist in the trace1, in caller's patch, delete the lines like 
    # " -  callee();" Because it is not used when bug is triggered.
    # 2. Also update dependence_graph to remove the callee from the graph.
    
    # Not do this in patpch_patcher, becuase it has been too complicated;
    
    trace_function_names = set()
    new_patch_to_apply = []
    for index, func in trace1:
        trace_function_names.add(func.split(' ')[0])
    
    for key in patch_to_apply:
        patch = diff_results[key]
        if 'old_signature' in patch and patch['old_signature'].split('(')[0].split(' ')[-1] in trace_function_names:
            # If the function is in the trace, do not remove any lines
            new_patch_to_apply.append(key)
            continue
        for caller_key in dependence_graph.get(key, set()):
            caller_patch = diff_results[caller_key]
            patch_text = caller_patch['patch_text']
            lines = patch_text.split('\n')
            modified_lines = []
            for line in lines:
                if line.startswith('-') and patch['old_signature'].split('(')[0].split(' ')[-1] in line:
                    # If the line is a call to the removed function, remove it
                    logger.info(f'Removing line: {line} from {caller_key} because {patch["old_signature"]} is not in the trace')
                    modified_lines.append('-')
                else:
                    # Keep all other lines (added or unchanged)
                    modified_lines.append(line)
            caller_patch['patch_text'] = '\n'.join(modified_lines)
        if key in dependence_graph:
            del dependence_graph[key]

    return new_patch_to_apply
    

def patch_patcher(diff_results, patch_to_apply : list, dependence_graph, commit, next_commit, target_repo_path):
    # Create artificial patch for function signature change or function removed
    new_patch_to_apply = []
    handle_func_signature_change = set()
    function_declarations = set() # a set of function declarations
    
    removed_old_signatures = set()
    removed_new_signatures = set()
    reserved_keys = set()
    renamed_functions = dict()
    
    for key in patch_to_apply:
        patch = diff_results[key]
        patch_text = patch['patch_text']
        lines = patch_text.split('\n')
        if 'old_signature' not in patch:
            # skip for a added function
            new_patch_to_apply.append(key)
            continue
        fname = patch['old_signature'].split('(')[0].split(' ')[-1]
        old_line_info = key.split('-')[-1].split('+')[0]
        old_line_begin = int(old_line_info.split(',')[0])
        old_line_end = int(old_line_info.split(',')[1]) + old_line_begin
        new_line_info = key.split('+')[-1]
        new_line_begin = int(new_line_info.split(',')[0])
        new_line_end = int(new_line_info.split(',')[1]) + new_line_begin
        
        if fname == 'LLVMFuzzerTestOneInput':
            # skip LLVMFuzzerTestOneInput, because it is a special function for fuzzing
            new_patch_to_apply.append(key)
            continue
        if 'Function body change' in patch['patch_type']:
            if 'Function removed' in patch['patch_type'] and not 'Function added' in patch['patch_type']:
                # add prefix to function being deleted
                modified_lines = rename_func(patch['patch_text'], fname)
                function_declarations.add(patch['old_signature'].replace(fname, f'__revert_{fname}'))
                patch['patch_text'] = '\n'.join(modified_lines)
                # iterate through the dependent functions and rename them
                for dep_key in dependence_graph.get(key, []):
                    modified_lines = rename_func(diff_results[dep_key]['patch_text'], fname)
                    diff_results[dep_key]['patch_text'] = '\n'.join(modified_lines)
                new_patch_to_apply.append(key)
                renamed_functions[patch['old_signature']] = key
            
            elif 'old_signature' in patch and 'new_signature' in patch:
                if patch['old_signature'] in handle_func_signature_change:
                    continue
                # Delete all other patches that have the same signature
                removed_old_signatures.add(patch['old_signature'])
                removed_new_signatures.add(patch['new_signature'])
                
                handle_func_signature_change.add(patch['old_signature'])
                logger.debug(f'key {key} is a function signature change, and has dependent functions')
                # Need a Artificial patch, to create the old function
                # 1. get function code from the old commit
                os.chdir(target_repo_path)
                subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["git", "checkout", '-f', commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                parsing_path = os.path.join(data_path, f'{target_repo_path.split('/')[-1]}-{commit[:6]}', f'{patch['file_path_old']}_analysis.json')
                with open(parsing_path, 'r') as f:
                    ast_nodes = json.load(f)
                for ast_node in ast_nodes:
                    if ast_node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
                        continue
                    if ast_node['extent']['start']['file'] == patch['file_path_old'] and ast_node['signature'] == patch['old_signature']:
                        with open(os.path.join(target_repo_path, patch['file_path_old']), 'r') as f:
                            file_content = f.readlines()
                            func_code = ''.join('-' + line for line in file_content[ast_node['extent']['start']['line']-1:ast_node['extent']['end']['line']])
                            func_length = func_code.count('\n')
                            break
                
                # 2. get patch insert line number from new commit for the Artificial patch
                os.chdir(target_repo_path)
                subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["git", "checkout", '-f', next_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                parsing_path = os.path.join(data_path, f'{target_repo_path.split('/')[-1]}-{next_commit[:6]}', f'{patch['file_path_new']}_analysis.json')
                with open(parsing_path, 'r') as f:
                    ast_nodes = json.load(f)
                artificial_patch_insert_point = -1
                for ast_node in ast_nodes:
                    if ast_node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
                        continue
                    if ast_node['extent']['start']['file'] == patch['file_path_new'] and ast_node['signature'] == patch['new_signature']:
                        artificial_patch_insert_point = ast_node['extent']['end']['line'] + 1
                        break
                
                # 3. create the Artificial patch
                patch_lines = patch['patch_text'].split('\n')
                patch_header = f'{patch_lines[0]}\n{patch_lines[1]}\n{patch_lines[2]}\n'
                patch_header += f'@@ -{artificial_patch_insert_point},{func_length} +{artificial_patch_insert_point},0 @@\n'
                artificial_patch = {
                    'file_path_old': patch['file_path_old'],
                    'file_path_new': patch['file_path_new'],
                    'file_type': patch['file_type'],
                    'patch_text': '\n'.join(rename_func(patch_header + func_code, fname)),
                    'old_signature': patch['old_signature'], # __revert_{fname} is not added here
                    'patch_type': {'Function removed', 'Function body change'},
                    'dependent_func': set(),
                    'new_start_line': artificial_patch_insert_point,
                    'new_end_line': artificial_patch_insert_point,
                    'old_start_line': artificial_patch_insert_point,
                    'old_end_line': artificial_patch_insert_point + func_length,
                    'old_function_start_line': artificial_patch_insert_point,
                    'old_function_end_line': artificial_patch_insert_point + func_length,
                }
                # 4. Add this new artificial patch key to patch_to_apply
                new_key = f'{patch["file_path_old"]}{patch["file_path_new"]}-{artificial_patch_insert_point},{func_length}+{artificial_patch_insert_point},0'
                diff_results[new_key] = artificial_patch
                function_declarations.add(patch['old_signature'].replace(fname, f'__revert_{fname}'))
                renamed_functions[artificial_patch['old_signature']] = new_key
                # 5. Rename the function by dependency graph
                for callee_key, caller_key_set in dependence_graph.items():
                    # rename functions in the Artificial patch
                    for caller in caller_key_set:
                        if key == caller:
                            callee_fname = diff_results[callee_key]['old_signature'].split('(')[0].split(' ')[-1]
                            modified_lines = rename_func(diff_results[new_key]['patch_text'], callee_fname)
                            diff_results[new_key]['patch_text'] = '\n'.join(modified_lines)
                    
                for caller_key in dependence_graph.get(key, []):
                    # rename functions in patches that depend on (call) this function
                    caller_key = renamed_functions.get(diff_results[caller_key]['old_signature'], caller_key)
                    modified_lines = rename_func(diff_results[caller_key]['patch_text'], fname)
                    diff_results[caller_key]['patch_text'] = '\n'.join(modified_lines)
                new_patch_to_apply.append(new_key)
                reserved_keys.add(new_key)
                
                # 6. Update the dependence graph to reflect the new key
                dependence_graph[new_key] = dependence_graph.get(key, set())
                del dependence_graph[key]
                for caller_key_set in dependence_graph.values():
                    if key in caller_key_set:
                        caller_key_set.remove(key)
                        caller_key_set.add(new_key)
        else:
            new_patch_to_apply.append(key)
            logger.debug(f"Skipping non-function body change for {key}")
            
    # Remove patches that are not needed anymore
    for key in new_patch_to_apply:
        if key in reserved_keys:
            continue
        patch = diff_results[key]
        if 'old_signature' in patch and patch['old_signature'] in removed_old_signatures:
            new_patch_to_apply.remove(key)
            continue
        if 'new_signature' in patch and patch['new_signature'] in removed_new_signatures:
            new_patch_to_apply.remove(key)
    return new_patch_to_apply, function_declarations


def normalize_signature(signature):
    """
    Parse and normalize a C-style function signature.
    Returns a tuple: (return_type, function_name, list of param types)
    """
    # Remove extra spaces
    signature = re.sub(r'\s+', ' ', signature.strip())

    # Match return type, function name, and argument list
    match = re.match(r'(.+?)\s+(\w+)\s*\((.*?)\)', signature)
    if not match:
        raise ValueError(f"Invalid function signature: {signature}")

    ret_type, func_name, args = match.groups()
    ret_type = ret_type.strip()
    func_name = func_name.strip()

    # Normalize arguments: keep only types, ignore parameter names
    arg_types = []
    args = args.strip()
    if args and args != 'void':
        for arg in args.split(','):
            # Remove default values and extract type
            parts = arg.strip().split()
            if len(parts) >= 1:
                # Keep all parts except the last (parameter name)
                arg_type = ' '.join(parts[:-1]) if len(parts) > 1 else parts[0]
                arg_types.append(arg_type.strip())

    return ret_type, func_name, tuple(arg_types)


def compare_function_signatures(sig1, sig2):
    """Returns True if two C function signatures are the same (ignoring parameter names)."""
    return normalize_signature(sig1) == normalize_signature(sig2)


def build_dependency_graph(diff_results, patch_to_apply, target_repo_path, old_commit):
    os.chdir(target_repo_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", '-f', old_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dependence_graph = dict()
    patch_list = list(patch_to_apply)
    new_patch_to_patch = []
    visited_patches = set()
    # 1. Function Call Relationship;
    # in old version of this patch, if there is a call to a fucntion, create an edge from
    # the callee definition patch to this patch(caller). specifically, do this for the patches remove
    # the function definition or change the function def.
    while patch_list:
        key = patch_list.pop()
        if key in visited_patches:
            # skip if this patch has been visited
            continue
        visited_patches.add(key)
        new_patch_to_patch.append(key)
        logger.debug(f'Analyzing patch {key}\n{diff_results[key]['patch_text']}')
        patch = diff_results[key]
        if 'Function body change' in patch['patch_type'] and patch['file_path_old']:
            patch_text = patch['patch_text']
            parsing_path = os.path.join(data_path, f'{target_repo_path.split('/')[-1]}-{old_commit[:6]}', f'{patch['file_path_old']}_analysis.json')
            with open(parsing_path, 'r') as f:
                ast_nodes = json.load(f)
            # filter for call expressions (clang cursors for function calls)
            call_kinds = {'CALL_EXPR', 'CXX_METHOD_CALL_EXPR'}
            for node in ast_nodes:
                if node.get('kind') not in call_kinds:
                    continue
                # check if the call is within the patch range
                if node['extent']['end']['line'] <= patch['old_function_end_line'] and node['extent']['start']['line'] >= patch['old_function_start_line']:
                    if 'callee' not in node:
                        # indirect call, can get the callee. skip now
                        continue
                    if 'signature' not in node['callee']:
                        # function like zalloc
                        continue
                    logger.debug(f'Found call expression in patch {key}: {node["callee"]}')
                    # find the definition of this function in the diff results
                    for key1, diff_result in diff_results.items():
                        if 'old_signature' in diff_result and compare_function_signatures(node['callee']['signature'], diff_result['old_signature']):
                            patch_list.append(key1)
                            dependence_graph.setdefault(key1, set()).add(key)
                            
    return dependence_graph, new_patch_to_patch


def add_context(diff_results, final_patches, new_commit, target_repo_path):
    new_start_line = -3
    new_end_line = -3
    old_patch_key = None
    removed_patches = set()
    
    # 1. Merge the patches that have overlap, note that the overlap here is just the simple ones
    for key in final_patches:
        patch = diff_results[key]
        patch_text = patch['patch_text']
        lines = patch_text.split('\n')
        if lines[4][0] == '-': # meaning this patch is only a remove patch, and has no context
            if old_patch_key and old_patch_key.split('-')[0] in key and new_start_line-3 <= patch['new_end_line'] <= new_end_line+3:
                # merge the patches that have overlap
                old_patch = diff_results[old_patch_key]
                old_patch['patch_text'] += '\n' + '\n'.join(lines[4:])
                old_patch_lines = old_patch['patch_text'].split('\n')
                old_patch_old_line_begin = int(old_patch_lines[3].split('@@')[-2].strip().split('-')[1].split(',')[0])
                old_patch_old_offset = int(old_patch_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
                old_patch_new_line_begin = int(old_patch_lines[3].split('@@')[-2].strip().split('+')[1].split(',')[0])
                old_patch_new_offset = int(old_patch_lines[3].split('@@')[-2].strip().split(',')[-1])
                
                patch_old_offset = int(lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
                patch_new_offset = int(lines[3].split('@@')[-2].strip().split(',')[-1])
                merged_lines = old_patch['patch_text'].split('\n')
                old_patch['patch_text'] = '\n'.join(merged_lines[:3] + [f'@@ -{old_patch_old_line_begin},{patch_old_offset+old_patch_old_offset} + {old_patch_new_line_begin},{old_patch_new_offset+patch_new_offset} @@'] + merged_lines[4:])
                removed_patches.add(key)
                continue
        new_start_line = patch['new_start_line']
        new_end_line = patch['new_end_line']
        old_patch_key = key

    for key in removed_patches:
        final_patches.remove(key)
        
    # 2. Add context lines to the patches
    for key in final_patches:
        patch = diff_results[key]
        patch_text = patch['patch_text']
        lines = patch_text.split('\n')
        if not patch['file_path_new']:
            # a patch delete a file, skip now
            continue
        context_lines1 = []
        context_lines2 = []
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', new_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        file_path = os.path.join(target_repo_path, patch['file_path_new'])
        with open(file_path, 'r') as f:
            content = [line.rstrip('\n') for line in f.readlines()]
        old_line_begin_nocontext = int(lines[3].split('@@')[-2].strip().split('-')[1].split(',')[0])
        old_offset_nocontext = int(lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
        new_line_begin_nocontext = int(lines[3].split('@@')[-2].strip().split('+')[1].split(',')[0])
        new_offset_nocontext = int(lines[3].split('@@')[-2].strip().split(',')[-1])
        new_line_begin = new_line_begin_nocontext
        new_offset = new_offset_nocontext
        old_line_begin = old_line_begin_nocontext
        old_offset = old_offset_nocontext

        # logger.info(f'{key}\npathc_text: {patch_text}')

        if lines[4] and lines[4][0] in {'-', '+'}:
            # No context lines before the patch: add context_lines1.
            new_line_begin = max(new_line_begin_nocontext - 3, 0)
            new_offset = new_offset_nocontext + (new_line_begin_nocontext - new_line_begin)
            old_line_begin = max(old_line_begin_nocontext - 3, 0)
            old_offset = old_offset_nocontext + new_offset - new_offset_nocontext
            context_lines1 = [f' {line}' for line in content[new_line_begin-1: new_line_begin_nocontext-1]]
            # Used for context_lines2
            new_line_begin_nocontext = new_line_begin
            new_offset_nocontext = new_offset
            old_line_begin_nocontext = old_line_begin
            old_offset_nocontext = old_offset
            
        if lines[-1] and lines[-1][0] in {'-', '+'}:
            # No context lines after the patch: add context_lines2.
            new_line_begin = new_line_begin_nocontext
            new_offset = new_offset_nocontext + max(0, min(3, len(content) - new_line_begin_nocontext - new_offset_nocontext))
            old_line_begin = old_line_begin_nocontext
            old_offset = old_offset_nocontext + new_offset - new_offset_nocontext
            context_lines2 = [f' {line}' for line in content[new_line_begin_nocontext+new_offset_nocontext-1: new_line_begin + new_offset-1]]
        
        lines = lines[:3] + [f'@@ -{old_line_begin},{old_offset} +{new_line_begin},{new_offset} @@']\
            + context_lines1 + lines[4:] + context_lines2
        patch['patch_text'] = '\n'.join(lines)


def handle_file_change(diff_results, patch_to_apply):
    for key in diff_results:
        patch = diff_results[key]
        # Delete and add file
        if patch['file_path_new'] == '/dev/null':
            lines = patch['patch_text'].split('\n')
            lines.insert(2, 'deleted file mode 100644')
            patch['patch_text'] = '\n'.join(lines)
        if patch['file_path_old'] == '/dev/null':
            lines = patch['patch_text'].split('\n')
            lines.insert(1, 'new file mode 100644')
            patch['patch_text'] = '\n'.join(lines)


def handle_build_error(error_log):
    pattern = r"(/src.+?):(\d+):(\d+):.*use of undeclared identifier '(\w+)'"
    matches = re.findall(pattern, error_log)
    undeclared_identifiers = {(identifier, f"{filepath}:{line}:{column}") for filepath, line, column, identifier in matches}
    
    pattern = r"(/src.+?):(\d+):(\d+):.*undeclared function '(\w+)'"
    matches = re.findall(pattern, error_log)
    undeclared_functions = {(identifier, f"{filepath}:{line}:{column}") for filepath, line, column, identifier in matches}
    return undeclared_identifiers, undeclared_functions


def find_first_code_line(file_path):
    """
    Returns the 1-based line number where actual C code starts.
    Skips blank lines, comments (both single and multi-line), and preprocessor directives.
    """
    with open(file_path, 'r') as f:
        lines = f.readlines()

    in_multiline_comment = False

    for idx, line in enumerate(lines):
        stripped = line.strip()

        # Track multi-line comment blocks
        if in_multiline_comment:
            if "*/" in stripped:
                in_multiline_comment = False
            continue

        if stripped.startswith("/*"):
            if "*/" not in stripped:
                in_multiline_comment = True
            continue

        # Skip single-line comment or blank
        if not stripped or stripped.startswith("//"):
            continue

        # Skip preprocessor directives
        if stripped.startswith("#"):
            continue

        # Found real code
        return idx + 1

    return len(lines) + 1


def get_line_context(file_path, line_number, context=3):
    """
    Returns a list of lines around the given line_number in the file.
    Includes up to `context` lines before and after, if they exist.
    
    :param file_path: Path to the C source file
    :param line_number: 1-based line number
    :param context: Number of lines before and after to include
    :return: two strings:
        - Lines before the given line_number (up to `context` lines)
        - Lines from the given line_number to the end of the context (up to `context` lines)
        - 1-based start and end indices of the context lines
    """
    with open(file_path, 'r') as f:
        lines = f.readlines()

    total_lines = len(lines)
    start = max(0, line_number - context - 1)  # zero-based index
    end = min(total_lines, line_number - 1 + context)  # one-based index

    return ''.join([f' {lines[i]}' for i in range(start, line_number-1)]), ''.join([f' {lines[i]}' for i in range(line_number-1, end)]), start+1, end


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
    
    get_patched_traces = dict()
    previous_bug = ''
    previous_trace_func_set = set()
    signature_change_list = []
    
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
        if bug_id in get_patched_traces:
            patch_path_list = get_patched_traces[bug_id]
            trace_path2 = os.path.join(data_path, f'target_trace-{next_commit['commit_id']}-testcase-{bug_id}{patch_path_list[-1].split('/')[-1].split('.diff')[0]}.txt')
        # Replace '--depth=1' in the Dockerfile
        with open(target_dockerfile_path, 'r') as dockerfile:
            dockerfile_content = dockerfile.read()
        
        dockerfile_content = dockerfile_content.replace('--depth 1', '')
        updated_content = dockerfile_content.replace('--depth=1', '')
        
        with open(target_dockerfile_path, 'w') as dockerfile:
            dockerfile.write(updated_content)
    
        if bug_id in get_patched_traces:
            collect_trace_cmd = [py3, f'{current_file_path}/fuzz_helper.py', 'collect_trace', '--commit', next_commit['commit_id'], '--sanitizer', sanitizer,
                                '--build_csv', args.build_csv, '--architecture', arch, '--patch', get_patched_traces[bug_id][-1]]
        else:
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
                
        if not os.path.exists(trace_path2):
            collect_trace_cmd[4] = next_commit['commit_id']
            # logger.info the command being executed
            logger.info(f"Running command: {" ".join(collect_trace_cmd)}")
            # Execute the command
            try:
                result = subprocess.run(collect_trace_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError as e:
                logger.info(f"Command failed with exit code {e.returncode}")
        
        # may cannot get trace, in new commit
        if not os.path.exists(trace_path2):
            logger.info(f"Trace file {trace_path2} does not exist, skipping bug {bug_id}")
            continue
        
        trace1 = extract_function_calls(trace_path1)
        trace2 = extract_function_calls(trace_path2)
        common_part, remaining_trace1, remaining_trace2 = compare_traces(trace1, trace2, signature_change_list)
        diffs = get_diff_unified(target_repo_path, commit['commit_id'], next_commit['commit_id']) # every file get a diff
        get_compile_commands(target, next_commit['commit_id'], sanitizer, bug_id, fuzzer, args.build_csv, arch)
        get_compile_commands(target, commit['commit_id'], sanitizer, bug_id, fuzzer, args.build_csv, arch)
        diff_results = analyze_diffindex(diffs, target_repo_path, next_commit['commit_id'], commit['commit_id'], target)

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
            relative_path = func_loc.split(':')[0]
            parsing_path = os.path.join(data_path, f'{target}-{commit['commit_id']}', f'{relative_path}_analysis.json')
            if os.path.exists(file_path):
                with open(parsing_path, 'r') as f:
                    ast_nodes = json.load(f)
                for node in ast_nodes:
                    if node['extent']['start']['line']+1 <= int(line_num) <= node['extent']['end']['line']:
                        func_dict[func] = node['signature']
                        break
                trace_func_set.add((func_dict[func], func_loc))
            else:
                trace_func_set.add((func.split(' ')[0], func_loc))
                
        logger.debug(f"Trace function set: {trace_func_set}")
        if not trace_func_set:
            logger.info(f'No function signatures found in trace for bug {bug_id}\n')
            continue

        if previous_bug == bug_id and previous_trace_func_set == trace_func_set:
            # Try to add trace funcs for this bug fail
            logger.info(f"Skipping bug {bug_id} as it has the same trace functions as the previous bug")
            continue
        previous_trace_func_set = trace_func_set
        previous_bug = bug_id

        # checkout target repo to the new commit, get function signature from source code using code location
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', next_commit['commit_id']], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        patch_to_apply = []
        patch_func_new = ''
        patch_func_old = ''
        patch_file_path = ''
        for key, diff_result in diff_results.items():
            if 'new_signature' in diff_result:
                logger.debug(f'newsignature{diff_result['new_signature']}')
                patch_func_new = diff_result['new_signature']
            if 'old_signature' in diff_result:
                logger.debug(f'oldsignature{diff_result['old_signature']}')
                patch_func_old = diff_result['old_signature']
            if 'file_path_old' in diff_result:
                patch_file_path = diff_result['file_path_old']
            update_type_set(diff_result)
            
            # If both bug commit's and fix commit's trace contain this patched function,
            # the patch of the function is likely related to the bug fixing. So try to
            # revert it. 
            for trace_func, func_loc in trace_func_set:
                if patch_file_path in func_loc and trace_func in patch_func_old:
                    logger.debug(f'Function {demangle_cpp_symbol(trace_func)} in both bug and fix traces, revert patch related to it')
                    patch_to_apply.append(key)
                    break

        depen_graph, patch_to_apply = build_dependency_graph(diff_results, patch_to_apply, target_repo_path, commit['commit_id'])
        patch_folder = os.path.abspath(os.path.join(current_file_path, '..', 'patch'))
        
        if not os.path.exists(patch_folder):
            os.makedirs(patch_folder, exist_ok=True)
        
        # Save all patches to a single file
        if patch_to_apply:
            patch_to_apply, function_declarations = patch_patcher(diff_results, patch_to_apply, depen_graph, commit['commit_id'], next_commit['commit_id'], target_repo_path)
            patch_to_apply = remove_unnecessary_lines(diff_results, patch_to_apply, depen_graph, trace1)
            patch_file_path = os.path.join(patch_folder, f"{bug_id}_{next_commit['commit_id']}_patches{len(get_patched_traces[bug_id]) if bug_id in get_patched_traces else ''}.diff")
            final_patches = []
            for key in patch_to_apply:
                if key not in final_patches:
                    final_patches.append(key)
        else:
            logger.error(f"No relevant patches found to revert for bug {bug_id}\n")
            continue

        # Sort final_patches by new_start_line
        final_patches = sorted(final_patches, key=lambda key: diff_results[key]['new_start_line'], reverse=True)
        add_context(diff_results, final_patches, next_commit['commit_id'], target_repo_path)
        handle_file_change(diff_results, final_patches)
        with open(patch_file_path, 'w') as patch_file:
            for key in final_patches:
                patch = diff_results[key]   
                patch_file.write(patch['patch_text'])
                patch_file.write('\n\n')  # Add separator between patches
        
        with open(patch_file_path, 'r') as patch_file:
            original_patch = patch_file.read()
        con_to_add = dict() # key: file path, value: list of enum/macro locations
        func_decl_to_add = dict() # key: file path, value: list of function declarations
        # build and test if it works, oss-fuzz version has been set in collect_trace_cmd
        error_log = 'undeclared identifier'
        while 'undeclared identifier' in error_log or 'undeclared function' in error_log:
            build_success, error_log = build_fuzzer(target, next_commit['commit_id'], sanitizer, bug_id, patch_file_path, fuzzer, args.build_csv, arch)
            undeclared_identifier, undeclared_functions = handle_build_error(error_log)
            for identifier, location in undeclared_identifier:
                parsing_path = os.path.join(data_path, f'{target}-{commit['commit_id'][:6]}', f'{location.split('/',3)[-1].split(':')[0]}_analysis.json')
                if os.path.exists(parsing_path):
                    with open(parsing_path, 'r') as f:
                        ast_nodes = json.load(f)
                    for ast_node in ast_nodes:
                        if ast_node['kind'] in {'ENUM_CONSTANT_DECL'} and ast_node['spelling'] == identifier:
                            con_to_add.setdefault(location.split('/',3)[-1].split(':')[0], []).append(f'{ast_node['extent']['start']['file']}:{ast_node['extent']['start']['line']}:{ast_node['extent']['end']['line']}')
                            break
                        if ast_node['kind'] in {'MACRO_DEFINITION'} and ast_node['spelling'] == identifier:
                            if '#include' in ast_node['extent']['start']['file']:
                                # macro defined in header file from system include paths
                                con_to_add.setdefault(location.split('/',3)[-1].split(':')[0], []).append(f'{ast_node['extent']['start']['file']}:{ast_node['extent']['start']['line']}:{ast_node['extent']['end']['line']}')
                            else:
                                # macro defined in .h file in the target repo
                                con_to_add.setdefault(location.split('/',3)[-1].split(':')[0], []).append(f'#include "{ast_node['extent']['start']['file'].split('/')[-1]}":{ast_node['extent']['start']['line']}:{ast_node['extent']['end']['line']}')
                            break

            for func_name, location in undeclared_functions:
                for func_decl in function_declarations:
                    if func_name in func_decl:
                        func_decl_to_add.setdefault(location.split('/',3)[-1].split(':')[0], []).append(f'{func_decl}')

            extra_patches = dict() # key: file path, value: patch text
            path_set = set(con_to_add.keys()) | set(func_decl_to_add.keys())

            for file_path in path_set:
                os.chdir(target_repo_path)
                subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["git", "checkout", '-f', commit['commit_id']], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                patch_header = f'diff --git a/{file_path} b/{file_path}\n--- a/{file_path}\n+++ b/{file_path}\n'
                include_text = ''
                include_len = 0
                func_decl_text = ''
                func_decl_len = 0
                
                if file_path in func_decl_to_add:
                    # function declaration patch
                    func_decls = func_decl_to_add[file_path]
                    for func_decl in func_decls:
                        func_decl_text += f'-{func_decl};\n'
                        func_decl_len += 1
                    
                if file_path in con_to_add:
                    # enum or macro patch
                    locs = con_to_add[file_path]
                    enum_len = 2
                    enum_text = '-enum {\n'
                    for log in reversed(locs):
                        path = log.split(':')[0]
                        if path.startswith('#include'):
                            # header file from system include paths
                            include_file = path.split(' ')[1]
                            include_text += f'-{path}\n'
                            include_len += 1
                            continue
                        start_line = int(log.split(':')[1])
                        end_line = int(log.split(':')[2])
                        enum_len += end_line - start_line + 1
                        with open(os.path.join(target_repo_path, path), 'r') as f:
                            file_content = f.readlines()
                            enum_text += ''.join(f'-{line}' for line in file_content[start_line-1:end_line])
                    enum_text += '-};\n'
                else:
                    enum_text = ''
                    enum_len = 0
                
                # need new version to get the context lines
                if enum_len+include_len+func_decl_len == 0:
                    # no enum or macro patch, skip this file
                    continue
                os.chdir(target_repo_path)
                subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["git", "checkout", '-f', next_commit['commit_id']], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                insert_point = find_first_code_line(os.path.join(target_repo_path, file_path))
                context1, context2, start, end = get_line_context(os.path.join(target_repo_path, file_path), insert_point, context=3)
                patch_header += f'@@ -{start},{enum_len+include_len+func_decl_len+end-start+1} +{start},{end-start+1} @@\n'
                extra_patches[file_path] = (patch_header + context1 + include_text + enum_text + func_decl_text + context2)
                
            with open(patch_file_path, 'w') as patch_file:
                patch_file.write(original_patch)
                for patch in extra_patches.values():    
                    patch_file.write(patch)
                    patch_file.write('\n\n')
            
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
                get_patched_traces.setdefault(bug_id, []).append(patch_file_path)
                transitions.append((commit, next_commit, bug_id))
                logger.info(f"Bug {bug_id} not triggered with fuzzer {fuzzer} on commit {next_commit['commit_id']}\n")
        else:
            logger.info(f"Build failed for bug {bug_id} on commit {next_commit['commit_id']}\n")

    logger.info(f"Revert and trigger set: {len(revert_and_trigger_set)} {revert_and_trigger_set}")
    logger.info(f"Revert and trigger fail set: {len(revert_and_trigger_fail_set)} {revert_and_trigger_fail_set}")


def get_compile_commands(target, commit_id, sanitizer, bug_id, fuzzer, build_csv, arch):
    cmd = [
        py3, f"{current_file_path}/fuzz_helper.py", "build_version", "--commit", commit_id, "--sanitizer", sanitizer,
        '--build_csv', build_csv, '--compile_commands', '--architecture', arch , target
    ]
    
    logger.info(' '.join(cmd))
    if not os.path.exists(os.path.join(data_path, f'{target}-{commit_id[:6]}')):
        result = subprocess.run(cmd, capture_output=True, text=True)

    
if __name__ == "__main__":
    args = parse_arguments()
    revert_patch_test(args)