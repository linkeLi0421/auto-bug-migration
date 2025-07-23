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
from typing import Tuple, Set
from collections import defaultdict

from buildAndtest import checkout_latest_commit
from run_fuzz_test import read_json_file
from run_fuzz_test import py3
from compare_trace import extract_function_calls
from compare_trace import compare_traces
from get_fix_related import demangle_cpp_symbol
from cfg_parser import parse_cfg_text, find_block_by_line
from gumtree import get_corresponding_lines

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


def get_diff_unified(repo_path, commit1, commit2, patch_path, context_lines=3):
    from git import Repo
    import os

    repo = Repo(repo_path)

    # Determine what to restore to: branch or commit
    try:
        orig_ref = repo.active_branch.name
    except TypeError:
        # Detached HEAD; fallback to current commit hash
        orig_ref = repo.head.commit.hexsha

    tmp_branch = f"tmp_patch_{os.getpid()}"

    if patch_path:
        # Create temp branch from commit2
        repo.git.checkout(commit2, b=tmp_branch)
        # Apply patch in reverse
        repo.git.apply(patch_path, reverse=True)
        # Diff with commit1
        diff_output = repo.git.diff(
            '--minimal', '--no-prefix', f'{commit1}', '.', unified=context_lines
        )
        # Clean up
        repo.git.checkout(orig_ref)
        repo.git.branch('-D', tmp_branch)
    else:
        diff_output = repo.git.diff('--minimal', '--no-prefix', commit1, commit2, unified=context_lines)

    return diff_output


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
    commit_graph = dict()
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
                if not target_line_cursor or version == 'new' and line.startswith('+') or version == 'old' and line.startswith('-'):
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
    
    # handle a case where subpatch ends with '-...\n+...'.  
    if old_line_start == old_line_cursor['num']:
        old_line_start = old_line_cursor['num'] = old_line_cursor['num'] - 1
    new_header_line = f"@@ -{old_line_start},{old_line_cursor['num']-old_line_start} +{new_line_start},{new_line_cursor['num']-new_line_start} @@"
    patch_lines.insert(0, new_header_line)
    
    if not get_sub_patch_start:
        # get nothing
        return '', 0, 0, 0, 0
    
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
    if patch['file_path_new'] == '/dev/null':
        type_set.add('Function removed')
        type_set.add('File removed')
    patch['patch_type'] = type_set

    return sig_change_list


def analyze_diffindex(diff_text, target_repo_path: str, new_commit: str, old_commit: str, target: str, signature_change_list: list):
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
            logger.debug(f'diff is too short, skipping: {diff}')
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
            logger.debug(f'Skipping non-C/C++ file: {path}')
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
            parsing_path = os.path.join(data_path, f'{target}-{new_commit}', f'{path_b}_analysis.json')
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
                    if not sub_patch:
                        # no changes in this function, skip
                        continue
                    key_new = f'{path_a}{path_b}-{old_line_start},{old_line_cursor-old_line_start}+{new_line_start},{new_line_cursor-new_line_start}'
                    patch_text = patch_header + sub_patch
                    type_set = {'Function body change'}
                    
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
            parsing_path = os.path.join(data_path, f'{target}-{old_commit}', f'{path_a}_analysis.json')

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
                            # <= because line_start and line_cursor may be the same then subpatch only contains '+' or only '-'
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
                        
                    if not sub_patch:
                        # no changes in this function, skip
                        continue
                    patch_text = patch_header + sub_patch
                    type_set = {'Function body change'}
                    
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
                        old_func_name = results[k_old]['old_signature'].split('(')[0].split(' ')[-1]
                        new_func_name = results[k_new]['new_signature'].split('(')[0].split(' ')[-1]
                        if old_func_name != new_func_name:
                            signature_change_list.append((old_func_name, new_func_name))
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
        "error: corrupt patch",
        "make: *** [Makefile:",
        "ninja: build stopped:",
        "Compilation failed",
        "failed with exit status"
        'CMake Error',
        'call to undeclared function'
    ]
    
    fuzzer_path = os.path.join(ossfuzz_path, 'build/out', target, fuzzer)
    if not os.path.exists(fuzzer_path) or any(error_pattern in result.stderr or error_pattern in result.stdout 
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
    function_declarations = set() # a set of 'recreated' function declarations
    
    removed_old_signatures = set()
    removed_new_signatures = set()
    reserved_keys = set()
    recreated_functions = set() # a set of functions that are recreated by the artificial patch, and may be called by other functions
    key_to_newkey = dict() # a mapping from old key to new key for recreated functions, used to update function name in caller patches
    
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
                function_declarations.add(patch['old_signature'].replace(fname, f'__revert_{fname}')) # do not use rename_func here, because it only change line starting with '-'
                patch['patch_text'] = '\n'.join(modified_lines)
                # iterate through the dependent functions and rename them
                for dep_key in dependence_graph.get(key, []):
                    modified_lines = rename_func(diff_results[dep_key]['patch_text'], fname)
                    diff_results[dep_key]['patch_text'] = '\n'.join(modified_lines)
                new_patch_to_apply.append(key)
                recreated_functions.add(patch['old_signature'])
                key_to_newkey[key] = key
            
            elif 'old_signature' in patch and 'new_signature' in patch:
                if patch['old_signature'] in handle_func_signature_change:
                    continue
                # Delete all other patches that have the same signature
                removed_old_signatures.add(patch['old_signature'])
                removed_new_signatures.add(patch['new_signature'])
                
                recreated_functions.add(patch['old_signature'])
                
                handle_func_signature_change.add(patch['old_signature'])
                logger.debug(f'key {key} is a function signature change, and has dependent functions')
                # Need a Artificial patch, to create the old function
                # 1. get function code from the old commit
                os.chdir(target_repo_path)
                subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["git", "checkout", '-f', commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                parsing_path = os.path.join(data_path, f'{target_repo_path.split('/')[-1]}-{commit}', f'{patch['file_path_old']}_analysis.json')
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
                            if func_code[-1] != '\n':
                                # This function is in the last line of the file, without a \n will cause the patch to fail
                                func_length += 1
                            break
                
                # 2. get patch insert line number from new commit for the Artificial patch
                os.chdir(target_repo_path)
                subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["git", "checkout", '-f', next_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                parsing_path = os.path.join(data_path, f'{target_repo_path.split('/')[-1]}-{next_commit}', f'{patch['file_path_new']}_analysis.json')
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
                    'patch_type': {'Function removed', 'Function body change', 'Recreated function'},
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
                new_patch_to_apply.append(new_key)
                reserved_keys.add(new_key)
                key_to_newkey[key] = new_key
                
        else:
            new_patch_to_apply.append(key)
            logger.debug(f"Skipping non-function body change for {key}")
            
    # 5. Rename the function by dependency graph, find the caller of the recreated function
    for key in key_to_newkey:
        patch = diff_results[key]
        fname = patch['old_signature'].split('(')[0].split(' ')[-1]
        for caller_key in dependence_graph.get(key, []):
            # rename functions in patches that depend on (call) this function
            caller_key = key_to_newkey.get(caller_key, caller_key)
            modified_lines = rename_func(diff_results[caller_key]['patch_text'], fname)
            diff_results[caller_key]['patch_text'] = '\n'.join(modified_lines)
    
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
    return new_patch_to_apply, function_declarations, recreated_functions


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


def compare_function_signatures(sig1, sig2, ignore_arg_types=False):
    """Returns True if two C function signatures are the same (ignoring parameter names)."""
    s1 = normalize_signature(sig1)
    s2 = normalize_signature(sig2)
    if ignore_arg_types:
        ret_type1, func_name1, args_types1 = s1
        ret_type2, func_name2, args_types2 = s2
        ret = (ret_type1 == ret_type2 and func_name1 == func_name2 and
               len(args_types1) == len(args_types2))
        return ret
    else:    
        return s1 == s2


def build_dependency_graph(diff_results, patch_to_apply, target_repo_path, old_commit, trace1):
    os.chdir(target_repo_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", '-f', old_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dependence_graph = dict()
    patch_list = list(patch_to_apply)
    new_patch_to_patch = []
    visited_patches = set()
    trace_function_names = set()
    for index, func in trace1:
        trace_function_names.add(func.split(' ')[0])
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
            parsing_path = os.path.join(data_path, f'{target_repo_path.split('/')[-1]}-{old_commit}', f'{patch['file_path_old']}_analysis.json')
            with open(parsing_path, 'r') as f:
                ast_nodes = json.load(f)
            # filter for call expressions (clang cursors for function calls)
            call_kinds = {'CALL_EXPR', 'CXX_METHOD_CALL_EXPR'}
            for node in ast_nodes:
                if node.get('kind') not in call_kinds:
                    continue
                if 'old_function_start_line' not in patch or 'old_function_end_line' not in patch:
                    # this patch is not related to a function in old version
                    continue
                # check if the call is within the patch range
                if node['extent']['end']['line'] <= patch['old_function_end_line'] and node['extent']['start']['line'] >= patch['old_function_start_line']:
                    if 'callee' not in node:
                        # indirect call, can get the callee. skip now
                        continue
                    if 'signature' not in node['callee']:
                        # function like zalloc
                        continue
                    if node['callee']['signature'].split('(')[0].split(' ')[-1] not in trace_function_names:
                        # if the function is not in the trace, skip it
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
    patch_prev_key = None
    removed_patches = set()
    
    os.chdir(target_repo_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", '-f', new_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # 1. Merge the patches that have overlap, note that the overlap here is just the simple ones
    for key in final_patches:
        patch = diff_results[key]
        patch_text = patch['patch_text']
        lines = patch_text.split('\n')
        if len(lines) < 5:
            logger.error(f'patch_text is too short, skip: {patch_text}')
        if lines[4][0] == '-': # meaning this patch has no context
            if patch_prev_key and patch_prev_key.split('-')[0] in key and prev_new_start_line-3 <= patch['new_end_line']-1 < prev_new_end_line+3:
                # merge the patches that have overlap
                patch_prev = diff_results[patch_prev_key]
                patch_prev_lines = patch_prev['patch_text'].split('\n')
                connect_lines_begin = patch['new_end_line']
                connect_lines_end = patch_prev['new_start_line']
                if connect_lines_begin < connect_lines_end:
                    with open(os.path.join(target_repo_path, patch['file_path_new']), 'r') as f:
                        connect_lines = [f' {line}' for line in f.readlines()[connect_lines_begin-1:connect_lines_end-1]]
                else:
                    connect_lines = []
                merged_lines = lines[4:] + connect_lines + patch_prev_lines[4:]
                
                patch_prev_old_offset = int(patch_prev_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
                patch_prev_new_offset = int(patch_prev_lines[3].split('@@')[-2].strip().split(',')[-1])
                
                patch_old_offset = int(lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
                patch_new_offset = int(lines[3].split('@@')[-2].strip().split(',')[-1])
                patch_prev['patch_text'] = '\n'.join(lines[:3] + [f'@@ -{patch['old_start_line']},{patch_old_offset+patch_prev_old_offset+connect_lines_end-connect_lines_begin} + {patch['new_start_line']},{patch_prev_new_offset+patch_new_offset+connect_lines_end-connect_lines_begin} @@'] + merged_lines)
                patch_prev['new_start_line'] = patch['new_start_line']
                patch_prev['new_end_line'] = patch_prev['new_start_line'] + patch_old_offset+patch_prev_old_offset+connect_lines_end-connect_lines_begin
                patch_prev['old_start_line'] = patch['old_start_line']
                patch_prev['old_end_line'] = patch_prev['old_start_line'] + patch_new_offset+patch_prev_new_offset+connect_lines_end-connect_lines_begin
                removed_patches.add(key)
                continue
        prev_new_start_line = patch['new_start_line']
        prev_new_end_line = patch['new_end_line']
        patch_prev_key = key

    for key in removed_patches:
        final_patches.remove(key)
        
    # 2. Add context lines to the patches
    for key in final_patches:
        patch = diff_results[key]
        patch_text = patch['patch_text']
        lines = patch_text.split('\n')
        if not patch['file_path_new'] or patch['file_path_new'] == '/dev/null':
            # a patch delete a file, skip now
            continue
        context_lines1 = []
        context_lines2 = []
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
            new_line_begin = max(new_line_begin_nocontext - 3, 1)
            new_offset = new_offset_nocontext + (new_line_begin_nocontext - new_line_begin)
            old_line_begin = max(old_line_begin_nocontext - 3, 1)
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
            new_offset = new_offset_nocontext + max(0, min(3, len(content) - new_line_begin_nocontext - new_offset_nocontext+1))
            old_line_begin = old_line_begin_nocontext
            old_offset = old_offset_nocontext + new_offset - new_offset_nocontext
            context_lines2 = [f' {line}' for line in content[new_line_begin_nocontext+new_offset_nocontext-1: new_line_begin + new_offset-1]]
            if new_offset - new_offset_nocontext < 3:
                context_lines2.append('\\ No newline at end of file')

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
    undeclared_identifiers = [(identifier, f"{filepath}:{line}:{column}") for filepath, line, column, identifier in matches]
    
    pattern = r"(/src.+?):(\d+):(\d+):.*undeclared function '(\w+)'"
    matches = re.findall(pattern, error_log)
    undeclared_functions = [(identifier, f"{filepath}:{line}:{column}") for filepath, line, column, identifier in matches]
    
    # New pattern for missing struct members
    pattern = r"(/src.+?):(\d+):(\d+):.*no member named '(\w+)' in '([^']+)'"
    matches = re.findall(pattern, error_log)
    missing_struct_members = [(member, struct_name, filepath, int(line)) for filepath, line, column, member, struct_name in matches]
    missing_struct_members.sort(key=lambda x: x[3], reverse=True)
    
    return undeclared_identifiers, undeclared_functions, missing_struct_members


def find_first_code_line(file_path):
    """
    Returns the 1-based line number where actual C code starts.
    Skips:
      - blank lines
      - single-line and multi-line comments
      - preprocessor directives
      - code inside conditional preprocessor blocks like #ifdef/#ifndef/#if ... #endif
    """
    with open(file_path, 'r') as f:
        lines = f.readlines()

    in_multiline_comment = False
    conditional_depth = 0

    for idx, line in enumerate(lines):
        stripped = line.strip()

        # Handle multi-line comments
        if in_multiline_comment:
            if "*/" in stripped:
                in_multiline_comment = False
            continue
        if stripped.startswith("/*"):
            if "*/" not in stripped:
                in_multiline_comment = True
            continue

        # Skip blank or single-line comment
        if not stripped or stripped.startswith("//"):
            continue

        # Track preprocessor conditional depth
        if stripped.startswith("#if"):
            conditional_depth += 1
            continue
        if stripped.startswith("#endif"):
            if conditional_depth > 0:
                conditional_depth -= 1
            continue
        if stripped.startswith("#else") or stripped.startswith("#elif"):
            continue

        # Skip all preprocessor lines
        if stripped.startswith("#"):
            continue

        # Skip code inside #if / #ifdef blocks
        if conditional_depth > 0:
            continue

        # Found actual code outside conditionals
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


def add_patch_for_trace_funcs(diff_results, final_patches, trace1, recreated_functions, target_repo_path, commit, next_commit, target):
    # For function do not change but appear in trace, add a patch if they should call recreated functions
    # Assume target_repo in new commit
    new_patch_to_apply = set()
    for index, func in trace1:
        fname = func.split(' ')[0]
        location = func.split(' ')[1]
        file_path = location.split(':')[0][1:]  # remove leading /
        old_line_begin = None
        old_line_end = None
        flag = False # flag to indicate if the function is changed between commit and next_commit
        for key in final_patches:
            if 'old_signature' in diff_results[key] and fname in diff_results[key]['old_signature']:
                flag = True
                break
        if flag:
            continue
        parsing_path = os.path.join(data_path, f'{target}-{next_commit}', f'{file_path}_analysis.json')
        if os.path.exists(parsing_path):
            with open(parsing_path, 'r') as f:
                ast_nodes = json.load(f)
            for node in ast_nodes:
                if node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
                    continue
                if node['extent']['start']['file'] == file_path and node['signature'].split('(')[0].split(' ')[-1] == fname:
                    # Found the function definition
                    old_line_begin = node['extent']['start']['line']
                    old_line_end = node['extent']['end']['line']
                    break
        
        if old_line_begin and old_line_end:
            # Create a patch to add the function call
            patch_header = f"diff --git a/{file_path} b/{file_path}\n"
            patch_header += f"--- {'a/'}{file_path}\n+++ {'b/'}{file_path}\n"
            with open(os.path.join(target_repo_path, file_path), 'r') as f:
                content = f.readlines()
                function_lines = content[old_line_begin-1:old_line_end]
            for func_signature in recreated_functions:
                recreated_fname = func_signature.split('(')[0].split(' ')[-1]
                function_head_flag = False
                for i, line in enumerate(function_lines):
                    if '{' in line:
                        function_head_flag = True
                    if not function_head_flag:
                        # Skip the function head
                        continue
                    if re.search(r'(?<![\w.])' + re.escape(recreated_fname) + r'(?!\w)', line) is not None:
                        # If the function is recreated, add a call to it
                        start_line = old_line_begin + i
                        end_line = start_line + 1
                        patch_text = rename_func(f'-{line}', recreated_fname)[0] + '\n+' + line[:-1]
                        patch_text = patch_header + f"@@ -{start_line},{1} +{start_line},{1} @@\n" + patch_text
                        patch = {
                            'file_path_old': file_path,
                            'file_path_new': file_path,
                            'file_type': 'c',
                            'patch_text': patch_text,
                            'old_signature': fname,
                            'new_signature': fname,
                            'patch_type': {'Function body change'},
                            'dependent_func': set(),
                            'new_start_line': start_line,
                            'new_end_line': end_line,
                            'old_start_line': start_line,
                            'old_end_line': end_line,
                            'old_function_start_line': old_line_begin,
                            'old_function_end_line': old_line_end,
                        }
                        new_key = f'{file_path}{file_path}-{start_line},{1}+{start_line},{1}'
                        
                        diff_results[new_key] = patch
                        new_patch_to_apply.add(new_key)

    final_patches.extend(list(new_patch_to_apply))


def llvm_fuzzer_test_one_input_patch_update(diff_results, patch_to_apply, recreated_functions, target_repo_path, commit, next_commit, target):
    # Assume target_repo in new commit
    fuzzer_keys = set()
    for key in patch_to_apply:
        patch = diff_results[key]
        if not ('old_signature' in patch and 'new_signature' in patch):
            # This patch is not a function body change, skip it
            continue
        if 'LLVMFuzzerTestOneInput' in patch['old_signature'] or 'LLVMFuzzerTestOneInput' in patch['new_signature']:
            # This is a patch for LLVMFuzzerTestOneInput, we need to update the function calls
            fuzzer_keys.add(key)
            fuzzer_file_path = patch['file_path_new']
            fuzzer_new_signature = patch['new_signature']
            fuzzer_old_signature = patch['old_signature']

    parsing_path = os.path.join(data_path, f'{target}-{next_commit}', f'{fuzzer_file_path}_analysis.json')
    with open(parsing_path, 'r') as f:
        ast_nodes = json.load(f)
    for node in ast_nodes:
        if node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
            continue
        if node['extent']['start']['file'] == fuzzer_file_path and node['signature'].split('(')[0].split(' ')[-1] == 'LLVMFuzzerTestOneInput':
            # Found the function definition
            fuzzer_start_line = node['extent']['start']['line']
            fuzzer_end_line = node['extent']['end']['line']
            break
    for node in ast_nodes:
        if node.get('kind') not in {'CALL_EXPR', 'CXX_METHOD_CALL_EXPR'}:
            continue
        if node['location']['file'] == fuzzer_file_path and fuzzer_start_line <= node['location']['line'] <= fuzzer_end_line and any(node['spelling'] == func_sig.split('(')[0].split(' ')[-1] for func_sig in recreated_functions):
            # This call is within the LLVMFuzzerTestOneInput function
            Inpatch_flag = False
            for key in fuzzer_keys:
                patch = diff_results[key]
                lines = patch['patch_text'].split('\n')
                new_lines = []
                new_start_line = int(lines[3].split('@@')[-2].strip().split('+')[1].split(',')[0])
                new_offset = int(lines[3].split('@@')[-2].strip().split(',')[-1])
                if new_start_line <= node['location']['line'] < new_start_line + new_offset:
                    # This call in within a patch, we need to update the patch
                    Inpatch_flag = True
                    for i, line in enumerate(lines):
                        if re.search(r'(?<![\w.])' + re.escape(node['spelling']) + r'(?!\w)', line) is not None:
                            # If the function is called in this patch, we need to update the call
                            rm_line = rename_func(f'-{line[1:]}', node['spelling'])[0]
                            add_line = f'+{line[1:]}'
                            new_lines.append(rm_line)
                            new_lines.append(add_line)
                        else:
                            new_lines.append(line)
                    patch['patch_text'] = '\n'.join(new_lines)
            
            if not Inpatch_flag:
                # This call is not in any patch, we need to create a new patch
                new_start_line = node['location']['line']
                new_offset = 1
                with open(os.path.join(target_repo_path, fuzzer_file_path), 'r') as f:
                    content = f.readlines()
                    function_line = content[node['location']['line']-1]
                    assert(node['extent']['start']['line'] == node['extent']['end']['line']), f'Function call should be in one line, but got {node["extent"]["start"]["line"]} - {node["extent"]["end"]["line"]}'

                rm_line = rename_func(f'-{function_line}', node['spelling'])[0]
                add_line = f'+{function_line}'
                patch_text = f'diff --git a/{fuzzer_file_path} b/{fuzzer_file_path}\n--- {fuzzer_file_path}\n+++ {fuzzer_file_path}\n@@ -{new_start_line},{new_offset} +{new_start_line},{new_offset} @@\n{rm_line}\n{add_line}'
                patch = {
                    'file_path_old': fuzzer_file_path,
                    'file_path_new': fuzzer_file_path,
                    'file_type': 'c',
                    'patch_text': patch_text,
                    'old_signature': fuzzer_old_signature,
                    'new_signature': fuzzer_new_signature,
                    'patch_type': {'Function body change'},
                    'dependent_func': set(),
                    'new_start_line': new_start_line,
                    'new_end_line': new_start_line + new_offset,
                    'old_start_line': new_start_line,
                    'old_end_line': new_start_line + new_offset,
                    'old_function_start_line': fuzzer_start_line,
                    'old_function_end_line': fuzzer_end_line,
                }
                new_key = f'{fuzzer_file_path}{fuzzer_file_path}-{new_start_line},{new_offset}+{new_start_line},{new_offset}'
                diff_results[new_key] = patch
                patch_to_apply.append(new_key)


def update_function_mappings(recreated_functions, signature_change_list):
    # add mapping for recreated functions
    for func_sig in recreated_functions:
        func_name = func_sig.split('(')[0].split(' ')[-1]
        signature_change_list.append((func_name, f'__revert_{func_name}'))


def get_correct_line_num(file_path, line_num, patch_key_list, diff_results):
    # This is only used for LLVMFuzzerTestOneInput, to get the correct line number in the new commit
    # transform the line number after reverting patches, to the line number before reverting patches (in new commit)
    add_num = 0 # the number of lines added by patches
    for key in reversed(patch_key_list):
        patch = diff_results[key]
        if 'file_path_new' in patch and patch['file_path_new'] == file_path:
            if patch['new_start_line'] <= line_num <= patch['new_end_line']:
                break
            patch_lines = patch['patch_text'].split('\n')
            old_offset = int(patch['patch_text'].split('@@')[1].strip().split(' ')[0].split(',')[1])
            new_offset = int(patch['patch_text'].split('@@')[1].strip().split(',')[-1])
            add_num += new_offset - old_offset
    return line_num + add_num


def get_old_line_num(file_path, line_num, patch_key_list, diff_results, extra_patches, target, commit):
    # transform the line number after reverting patches, to the line number in old commit
    add_num = 0 # the number of lines added by patches
    key_of_line_num = None
    
    if file_path in extra_patches:
        patch = extra_patches[file_path]
        add_num -= patch['old_end_line'] - patch['old_start_line'] + 1 - (patch['new_end_line'] - patch['new_start_line'] + 1)
    
    for key in reversed(patch_key_list):
        patch = diff_results[key]
        if 'file_path_new' in patch and patch['file_path_new'] == file_path:
            old_offset = int(patch['patch_text'].split('@@')[1].strip().split(' ')[0].split(',')[1])
            new_offset = int(patch['patch_text'].split('@@')[1].strip().split(',')[-1])
            old_start = int(patch['patch_text'].split('@@')[1].strip().split('-')[1].split(',')[0])
            patch_lines = patch['patch_text'].split('\n')
            add_num += new_offset - old_offset
            if line_num + add_num <= old_start:
                key_of_line_num = key
                add_num -= new_offset - old_offset
                break

    index_old_infun = 0
    front_context_num = 0 # should be less than 3
    patch_flag = False
    if key_of_line_num and 'Recreated function' in diff_results[key_of_line_num]['patch_type']:
        # for __revert_{fname} function, we need to find the line number in the old function
        for line in diff_results[key_of_line_num]['patch_text'].split('\n')[4:]:
            if line.startswith('-'):
                index_old_infun += 1
                if not patch_flag:
                    patch_flag = True
            elif line.startswith('+'):
                if not patch_flag:
                    patch_flag = True
            else:
                index_old_infun += 1
                if not patch_flag:
                    front_context_num += 1
                    assert(front_context_num <= 3), f'front_context_num should be less than 3, but got {front_context_num}'
            if line_num + add_num  == old_start + index_old_infun:
                # this is the line we are looking for, we can get this line's index in the function
                break
        index_old_infun -= front_context_num # I want the index inside the function, not the context lines
        old_function_signature = diff_results[key_of_line_num]['old_signature']
        parsing_path = os.path.join(data_path, f'{target}-{commit}', f'{diff_results[key_of_line_num]["file_path_old"]}_analysis.json')
        with open(parsing_path, 'r') as f:
            ast_nodes = json.load(f)
        for node in ast_nodes:
            if node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
                continue
            if node['signature'] == old_function_signature and node['extent']['start']['file'] == diff_results[key_of_line_num]['file_path_old']:
                # Found the function definition
                start_line = node['extent']['start']['line']
                return start_line + index_old_infun
        # should not reach here
    else:
        # must be code in LLVMFuzzerTestOneInput
        return line_num + add_num
    return 0


def corresponding_bb(cfg1, cfgs2, bb1, patch_key, diff_results):
    # return the corresponding basic blocks of bb1 from cfgs1 in cfgs2, based on their relationship in a patch
    bbs = []
    # 1. compare function name
    patch = diff_results[patch_key]
    old_signature = patch['old_signature']
    new_signature = patch['new_signature']
    cfg2 = None
    for cfg in cfgs2:
        if compare_function_signatures(cfg.function_signature, new_signature, ignore_arg_types=True):
            cfg2 = cfg
            break
    if not cfg2:
        logger.error(f'Cannot find corresponding cfg for {old_signature} and {new_signature}')
        return bbs

    # 2. iterate patch to align the basic blocks:
    #    if bb in two cfg have common lines in patch, then they are corresponding
    old_start = int(patch['patch_text'].split('@@')[1].strip().split('-')[1].split(',')[0])
    old_offset = int(patch['patch_text'].split('@@')[1].strip().split(' ')[0].split(',')[1])
    new_start = int(patch['patch_text'].split('@@')[1].strip().split('+')[1].split(',')[0])
    new_offset = int(patch['patch_text'].split('@@')[1].strip().split(',')[-1])
    ptr1 = old_start + old_offset # line number in old commit
    ptr2 = new_start + new_offset # line number in new commit
    common_unchanged_lines = []
    patch_lines = patch['patch_text'].split('\n')[4:]
    bb2_start = None
    bb2_end = None
    for line in reversed(patch_lines):
        if line.startswith('-'):
            ptr1 -= 1
        elif line.startswith('+'):
            ptr2 -= 1
        else:
            ptr1 -= 1
            ptr2 -= 1
            if ptr1 >= bb1.start_line and ptr1 <= bb1.end_line:
                common_unchanged_lines.append((ptr1, ptr2))

        if ptr1 <= bb1.end_line:
            bb2_end = ptr2
        if ptr1 <= bb1.start_line:
            bb2_start = ptr2
            break
    
    if not bb2_start:
        # this patch is inside the basic block, ptr2 is new_start
        assert ptr2 == new_start
        bb2_start = ptr2
    
    for bid in cfg2.blocks:
        bb = cfg2.blocks[bid]
        if bb.start_line and bb.end_line and bb.start_line <= bb2_end and bb.end_line >= bb2_start:
            # there is overlap, so probably they are corresponding, do not check the unchanged lines for now
            bbs.append(bb)
    return bbs


def __keep_bb_in_patch(bbstart, bbend, key, final_patches, diff_results):
    # A patch will be used to revert (git apply --reverse); but we 
    # want to keep a specific basic block from new version in the path
    patch = diff_results[key]
    ptr1 = int(patch['patch_text'].split('@@')[1].strip().split('-')[1].split(',')[0]) - 1  # line number in old commit
    ptr2 = int(patch['patch_text'].split('@@')[1].strip().split('+')[1].split(',')[0]) - 1  # line number in new commit
    bb1_start = None
    bb1_end = None
    lines = patch['patch_text'].split('\n')[4:]
    new_lines = []
    for line in lines:
        if line.startswith('-'):
            ptr1 += 1
        elif line.startswith('+'):
            ptr2 += 1
        else:
            ptr1 += 1
            ptr2 += 1

        if ptr2 == bbstart:
            bb1_start = ptr1
        if ptr2 == bbend + 1:
            bb1_end = ptr1
    if not bb1_end:
        bb1_end = ptr1
    
    ptr1 = int(patch['patch_text'].split('@@')[1].strip().split('-')[1].split(',')[0]) - 1
    ptr2 = int(patch['patch_text'].split('@@')[1].strip().split('+')[1].split(',')[0]) - 1
    removed = 0
    added = 0
    for line in lines:
        if line.startswith('-'):
            removed += 1
            ptr1 += 1

        elif line.startswith('+'):
            added += 1
            ptr2 += 1
        else:
            ptr1 += 1
            ptr2 += 1
        # remove '-' lines, and keep the '+' lines
        if bb1_start <= ptr1 <= bb1_end or bbstart <= ptr2 <= bbend:
            if line.startswith('+') or line.startswith(' '):
                if line.startswith('+'):
                    added -= 1
                new_lines.append(' ' + line[1:])
            else:
                removed -= 1
        else:
            new_lines.append(line)
        
    if removed == 0 and added == 0:
        del diff_results[key]
        final_patches.remove(key)
        return
    
    patch['patch_text'] = '\n'.join(patch['patch_text'].split('\n')[:4] + new_lines)


def get_code_from_file(target_repo_path, file_path, commit, start_line, end_line):
    if start_line > end_line:
        return [], 0
    # Get code from a file in a specific commit
    os.chdir(target_repo_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", '-f', commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(os.path.join(target_repo_path, file_path), 'r') as f:
        content = f.readlines()
    # Get the code from start_line to end_line, 1-based index
    code_lines = [line[:-1] for line in content[start_line-1:end_line]]
    code_length = len(code_lines)
    return code_lines, code_length


def blocks_overlap(bb_list_a, bb_list_b):
    for a in bb_list_a:
        for b in bb_list_b:
            if not (a.end_line < b.start_line or a.start_line > b.end_line):
                return True
    return False


def deduplicate_bb_blocks(bb_list):
    seen = set()
    unique = []
    for bb in bb_list:
        key = (bb.start_line, bb.end_line)
        if key not in seen:
            seen.add(key)
            unique.append(bb)
    return unique


def filter_and_dedup_bb_change_pairs(bb_change_pair):
    filtered = defaultdict(list)

    for file_path, change_list in bb_change_pair.items():
        kept = []

        for bb1s_i, bb2s_i, cfg_i in change_list:
            bb2s_i = deduplicate_bb_blocks(bb2s_i)

            overlap_found = False
            for idx, (bb1s_j, bb2s_j, cfg_j) in enumerate(kept):
                if blocks_overlap(bb1s_i, bb1s_j):
                    # Conflict: keep the one with more unique bb2s
                    if len(bb2s_i) > len(bb2s_j):
                        kept[idx] = (bb1s_i, bb2s_i, cfg_i)
                    # else: discard current i
                    overlap_found = True
                    break

            if not overlap_found:
                kept.append((bb1s_i, bb2s_i, cfg_i))

        filtered[file_path] = kept

    return filtered


def get_bb_change_pair(file_path, line_num, final_patches, diff_results, extra_patches, target, next_commit: str, commit: str, arch, build_csv, target_repo_path):
    line_num_after_patch = line_num
    relative_file_path = file_path.split('/', 3)[-1]
    if not os.path.exists(os.path.join(data_path, f'cfg-{target}-{next_commit}-{relative_file_path.replace('/', '-')}.txt')):
        get_cfg_cmd = [py3, f'{current_file_path}/fuzz_helper.py', 'get_cfg', '--commit', next_commit, '--build_csv', build_csv,
                    '--architecture', arch, '--target_file', relative_file_path, target]
        logger.info(f"Running command: {" ".join(get_cfg_cmd)}")
        result = subprocess.run(get_cfg_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not os.path.exists(os.path.join(data_path, f'cfg-{target}-{commit}-{relative_file_path.replace('/', '-')}.txt')):
        get_cfg_cmd = [py3, f'{current_file_path}/fuzz_helper.py', 'get_cfg', '--commit', commit, '--build_csv', build_csv,
                    '--architecture', arch, '--target_file', relative_file_path, target]
        logger.info(f"Running command: {" ".join(get_cfg_cmd)}")
        result = subprocess.run(get_cfg_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # line_num after patch -> line number in old commit
    line_num_in_old_commit = get_old_line_num(relative_file_path, line_num_after_patch, final_patches, diff_results, extra_patches, target, commit)
    with open(os.path.join(data_path, f'cfg-{target}-{commit}-{relative_file_path.replace('/', '-')}.txt'), 'r') as cfg_file:
        cfgs1 = parse_cfg_text(cfg_file.read())
    with open(os.path.join(data_path, f'cfg-{target}-{next_commit}-{relative_file_path.replace('/', '-')}.txt'), 'r') as cfg_file:
        cfgs2 = parse_cfg_text(cfg_file.read())
    cfg1, bb1s = find_block_by_line(cfgs1, file_path.split('/')[-1], [line_num_in_old_commit])
    if not bb1s:
        logger.error(f'Cannot find basic block for {file_path} at line {line_num_in_old_commit}')
        return False

    for key, patch in diff_results.items():
        if patch['file_path_new'] == relative_file_path:
            bb2_line_num_list = get_corresponding_lines(target_repo_path, patch['file_path_old'], commit, patch['file_path_old'], next_commit, bb1s)
            break
    
    cfg2, bb2s = find_block_by_line(cfgs2, file_path.split('/')[-1], bb2_line_num_list)
    # Now we get basic blocks in new commit that correspond to bb1
    if not bb2s:
        logger.error(f'Cannot find corresponding basic blocks for {cfg1.function_signature} in {relative_file_path} at line {line_num_in_old_commit}')
        return False
    
    return bb1s, bb2s, cfg1, relative_file_path
    
    
def keep_bb_in_patch(bb1s, bb2s, cfg1, diff_results, final_patches, target_repo_path, next_commit, relative_file_path):
    bb1_start_line = float('inf')
    bb1_end_line = float('-inf')
    bb2_start_line = float('inf')
    bb2_end_line = float('-inf')
    for bb1 in bb1s:
        bb1_start_line = min(bb1_start_line, bb1.start_line)
        bb1_end_line = max(bb1_end_line, bb1.end_line)
    for bb2 in bb2s:
        bb2_start_line = min(bb2_start_line, bb2.start_line)
        bb2_end_line = max(bb2_end_line, bb2.end_line)

    for key in final_patches:
        patch = diff_results[key]
        if patch['file_path_new'] == relative_file_path and 'Recreated function' in patch['patch_type'] and compare_function_signatures(patch['old_signature'], cfg1.function_signature, ignore_arg_types=True):
            logger.debug(f'bb1 {bb1_start_line} - {bb1_end_line} in patch {key}')
            logger.debug(f'bb2 {bb2_start_line} - {bb2_end_line} in new commit {next_commit}')
            old_start = int(patch['patch_text'].split('@@')[1].strip().split('-')[1].split(',')[0])
            old_offset = int(patch['patch_text'].split('@@')[1].strip().split(' ')[0].split(',')[1])
            new_start = int(patch['patch_text'].split('@@')[1].strip().split('+')[1].split(',')[0])
            new_offset = int(patch['patch_text'].split('@@')[1].strip().split(',')[-1])
            if patch['patch_text'].find('\n-') != -1:
                # find the real patch start line, usually is 3
                lines = patch['patch_text'].split('\n')
                for line in lines:
                    if line.startswith('-') and not line.startswith('---'):
                        real_patch_start_line = lines.index(line)
                        break
            else:
                raise ValueError(f'Cannot find real patch start line in {patch["patch_text"]}')
            # will change code from bb_start to bb_end in the patch, to bb2 in new commit; 4 is patch header lines
            bb_start = real_patch_start_line + bb1_start_line - cfg1.signature_line
            bb_end = real_patch_start_line + bb1_end_line - cfg1.signature_line
            bb2_code_lines, bb2_code_length = get_code_from_file(target_repo_path, relative_file_path, next_commit, bb2_start_line, bb2_end_line)
            patch_lines = patch['patch_text'].split('\n')
            patch_lines[bb_start:bb_end+1] = [f'-{line}' for line in bb2_code_lines]
            patch_lines[3] = f'@@ -{old_start},{old_offset-(bb_end-bb_start+1)+bb2_code_length} +{new_start},{new_offset} @@'
            diff_results[key]['patch_text'] = '\n'.join(patch_lines)
            break
    return True


def get_full_funsig(patch, target, commit, version:str):
    # version is either 'old' or 'new'
    patch_file_path = patch[f'file_path_{version}']
    patch_start_line = patch[f'{version}_start_line']
    parsing_path = os.path.join(data_path, f'{target}-{commit}', f'{patch_file_path}_analysis.json')
    with open(parsing_path, 'r') as f:
        ast_nodes = json.load(f)
    for node in ast_nodes:
        if node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
            continue
        if node['extent']['start']['file'] == patch_file_path and node['extent']['start']['line'] <= patch_start_line <= node['extent']['end']['line']:
            # Found the function definition
            return node['signature'], node['extent']['start']['line'], node['extent']['end']['line']
    return None, 0, 0

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
        commit['commit_id'] = commit['commit_id'][:6]  # use short commit id for trace file name
        next_commit['commit_id'] = next_commit['commit_id'][:6]  # use short commit id for trace file name
        bug_info = bug_info_dataset[bug_id]
        fuzzer = bug_info['reproduce']['fuzz_target']
        sanitizer = bug_info['reproduce']['sanitizer'].split(' ')[0]
        bug_type = bug_info['reproduce']['crash_type']
        job_type = bug_info['reproduce']['job_type']
        patch_path_list = []
        if len(job_type.split('_')) > 3:
            arch = job_type.split('_')[2]
        else:
            arch = 'x86_64'
        trace_path1 = os.path.join(data_path, f'target_trace-{commit['commit_id']}-testcase-{bug_id}.txt')
        trace_path2 = os.path.join(data_path, f'target_trace-{next_commit['commit_id']}-testcase-{bug_id}.txt')
        if bug_id in get_patched_traces:
            patch_path_list = get_patched_traces[bug_id]
            trace_path2 = os.path.join(data_path, f'target_trace-{next_commit['commit_id']}-testcase-{bug_id}{patch_path_list[-1].split('/')[-1].split('.diff')[0]}.txt')
            logger.info(f"Processing transition for bug {bug_id} from commit {commit['commit_id']} to {next_commit['commit_id']} with patch {patch_path_list[-1]}")
        else:
            logger.info(f"Processing transition for bug {bug_id} from commit {commit['commit_id']} to {next_commit['commit_id']}")
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
        diffs = get_diff_unified(target_repo_path, commit['commit_id'], next_commit['commit_id'], '') # every file get a diff
        get_compile_commands(target, next_commit['commit_id'], sanitizer, bug_id, fuzzer, args.build_csv, arch, get_patched_traces.get(bug_id, []))
        get_compile_commands(target, commit['commit_id'], sanitizer, bug_id, fuzzer, args.build_csv, arch)
        diff_results = analyze_diffindex(diffs, target_repo_path, next_commit['commit_id'], commit['commit_id'], target, signature_change_list)

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
                patch_func_new = diff_result['new_signature'].split('(')[0].split(' ')[-1]
            if 'old_signature' in diff_result:
                logger.debug(f'oldsignature{diff_result['old_signature']}')
                patch_func_old = diff_result['old_signature'].split('(')[0].split(' ')[-1]
            if 'file_path_old' in diff_result:
                patch_file_path = diff_result['file_path_old']
            else:
                patch_file_path = diff_result['file_path_new']
            update_type_set(diff_result)
            
            # If both bug commit's and fix commit's trace contain this patched function,
            # the patch of the function is likely related to the bug fixing. So try to
            # revert it. 
            for trace_func, func_loc in trace_func_set:
                if patch_file_path in func_loc and (trace_func == patch_func_old or trace_func == patch_func_new):
                    logger.info(f'Function {demangle_cpp_symbol(trace_func)} in both bug and fix traces, revert patch related to it')
                    if 'old_signature' not in diff_result:
                        diff_result['old_signature'], diff_result['old_function_start_line'], diff_result['old_function_end_line'] = get_full_funsig(diff_result, target, commit['commit_id'], 'old')
                    if 'new_signature' not in diff_result:
                        diff_result['new_signature'], _, _ = get_full_funsig(diff_result, target, next_commit['commit_id'], 'new')
                    patch_to_apply.append(key)
                    break

        depen_graph, patch_to_apply = build_dependency_graph(diff_results, patch_to_apply, target_repo_path, commit['commit_id'], trace1)
        patch_folder = os.path.abspath(os.path.join(current_file_path, '..', 'patch'))
        
        if not os.path.exists(patch_folder):
            os.makedirs(patch_folder, exist_ok=True)
        
        # Save all patches to a single file
        if patch_to_apply:
            patch_to_apply, function_declarations, recreated_functions = patch_patcher(diff_results, patch_to_apply, depen_graph, commit['commit_id'], next_commit['commit_id'], target_repo_path)
            # patch_to_apply = remove_unnecessary_lines(diff_results, patch_to_apply, depen_graph, trace1)
            patch_file_path = os.path.join(patch_folder, f"{bug_id}_{next_commit['commit_id']}_patches{len(get_patched_traces[bug_id]) if bug_id in get_patched_traces else ''}.diff")
            final_patches = []
            for key in patch_to_apply:
                if key not in final_patches:
                    final_patches.append(key)
        else:
            logger.error(f"No relevant patches found to revert for bug {bug_id}\n")
            continue

        add_patch_for_trace_funcs(diff_results, final_patches, trace1, recreated_functions, target_repo_path, commit['commit_id'], next_commit['commit_id'], target)
        llvm_fuzzer_test_one_input_patch_update(diff_results, final_patches, recreated_functions, target_repo_path, commit['commit_id'], next_commit['commit_id'], target)
        # Sort final_patches by new_start_line
        final_patches = sorted(final_patches, key=lambda key: diff_results[key]['new_start_line'], reverse=True)
        add_context(diff_results, final_patches, next_commit['commit_id'], target_repo_path)
        handle_file_change(diff_results, final_patches)
        with open(patch_file_path, 'w') as patch_file:
            for key in final_patches:
                patch = diff_results[key]   
                patch_file.write(patch['patch_text'])
                patch_file.write('\n\n')  # Add separator between patches
        
        con_to_add = dict() # key: file path, value: set of enum/macro locations (use key in dict to achieve ordered set)
        func_decl_to_add = dict() # key: file path, value: set of function declarations
        extra_patches = dict() # key: file path, value: patch; include patches for enum/macro/function declaration
        # build and test if it works, oss-fuzz version has been set in collect_trace_cmd
        error_log = 'undeclared identifier'
        while 'undeclared identifier' in error_log or 'undeclared function' in error_log:
            build_success, error_log = build_fuzzer(target, next_commit['commit_id'], sanitizer, bug_id, patch_file_path, fuzzer, args.build_csv, arch)
            if build_success:
                break
            undeclared_identifier, undeclared_functions, miss_member_structs = handle_build_error(error_log)
            logger.info(f'undeclared_identifier: {undeclared_identifier}')
            logger.info(f'undeclared_functions: {undeclared_functions}')
            logger.info(f'miss_member_structs: {miss_member_structs}')
            for identifier, location in undeclared_identifier:
                parsing_path = os.path.join(data_path, f'{target}-{commit['commit_id']}', f'{location.split('/',3)[-1].split(':')[0]}_analysis.json')
                if os.path.exists(parsing_path):
                    with open(parsing_path, 'r') as f:
                        ast_nodes = json.load(f)
                    for ast_node in ast_nodes:
                        if ast_node['kind'] in {'ENUM_CONSTANT_DECL'} and ast_node['spelling'] == identifier:
                            con_to_add.setdefault(location.split('/',3)[-1].split(':')[0], dict())[f'{ast_node['extent']['start']['file']}:{ast_node['extent']['start']['line']}:{ast_node['extent']['end']['line']}'] = identifier
                            break
                        if ast_node['kind'] in {'MACRO_DEFINITION'} and ast_node['spelling'] == identifier:
                            if '#include' in ast_node['extent']['start']['file']:
                                # macro defined in header file from system include paths
                                con_to_add.setdefault(location.split('/',3)[-1].split(':')[0], dict())[f'{ast_node['extent']['start']['file']}:{ast_node['extent']['start']['line']}:{ast_node['extent']['end']['line']}'] = None
                            else:
                                # macro defined in .h file in the target repo
                                con_to_add.setdefault(location.split('/',3)[-1].split(':')[0], dict())[f'#include "{ast_node['extent']['start']['file'].split('/')[-1]}":{ast_node['extent']['start']['line']}:{ast_node['extent']['end']['line']}'] = None
                            break

            bb_change_pair = dict() # key: relative file path, value: list of (bb1s, bb2s, cfg1), change from bb1s to bb2s
            for field_name, struct_name, file_path, line_num in miss_member_structs:
                bb1s, bb2s, cfg1, relative_file_path = get_bb_change_pair(file_path, line_num, final_patches, diff_results, extra_patches, target, next_commit['commit_id'], commit['commit_id'], arch, args.build_csv, target_repo_path)
                bb_change_pair.setdefault(relative_file_path, []).append((bb1s, bb2s, cfg1))

            bb_change_pair = filter_and_dedup_bb_change_pairs(bb_change_pair)
            for relative_file_path, bb_change_list in bb_change_pair.items():
                if not bb_change_list:
                    continue
                # bb_change_list is a list of (bb1s, bb2s, cfg1)
                for bb1s, bb2s, cfg1 in bb_change_list:
                    if not keep_bb_in_patch(bb1s, bb2s, cfg1, diff_results, final_patches, target_repo_path, next_commit['commit_id'], relative_file_path):
                        logger.error(f'Failed to keep basic block in patch for {relative_file_path}')
                        continue

            for func_name, location in undeclared_functions:
                if not func_name.startswith('__revert_'):
                    # if the function is not a reverted function, means function name change here. (And it is not in the bug trace)
                    # So compiler cannot find the function, we need to call this function in the newer way, keep that basic block new version.
                    file_path = location.split(':')[0]
                    line_num = int(location.split(':')[1])
                    relative_file_path = file_path.split('/', 3)[-1]
                    if not os.path.exists(os.path.join(data_path, f'cfg-{target}-{next_commit['commit_id']}-{relative_file_path.replace('/', '-')}.txt')):
                        get_cfg_cmd = [py3, f'{current_file_path}/fuzz_helper.py', 'get_cfg', '--commit', next_commit['commit_id'], '--build_csv', args.build_csv,
                                    '--architecture', arch, '--target_file', relative_file_path, target]
                        logger.info(f"Running command: {" ".join(get_cfg_cmd)}")
                        result = subprocess.run(get_cfg_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if not os.path.exists(os.path.join(data_path, f'cfg-{target}-{commit['commit_id']}-{relative_file_path.replace('/', '-')}.txt')):
                        get_cfg_cmd = [py3, f'{current_file_path}/fuzz_helper.py', 'get_cfg', '--commit', commit['commit_id'], '--build_csv', args.build_csv,
                                    '--architecture', arch, '--target_file', relative_file_path, target]
                        logger.info(f"Running command: {" ".join(get_cfg_cmd)}")
                        result = subprocess.run(get_cfg_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                    # line_num after patch -> line number before patch -> 
                    # find block start and end line in bug version -> get the part in patch need to be removed
                    line_num = get_correct_line_num(relative_file_path, line_num, final_patches, diff_results)
                    with open(os.path.join(data_path, f'cfg-{target}-{commit['commit_id']}-{relative_file_path.replace('/', '-')}.txt'), 'r') as cfg_file:
                        cfgs1 = parse_cfg_text(cfg_file.read())
                    with open(os.path.join(data_path, f'cfg-{target}-{next_commit['commit_id']}-{relative_file_path.replace('/', '-')}.txt'), 'r') as cfg_file:
                        cfgs2 = parse_cfg_text(cfg_file.read())
                    _, bb2s = find_block_by_line(cfgs2, file_path.split('/')[-1], [line_num])
                    if not bb2s:
                        logger.info(f'No basic block found for {file_path}:{line_num} in {next_commit['commit_id']}')
                        continue
                    
                    for key in final_patches:
                        patch = diff_results[key]
                        new_start = int(patch['patch_text'].split('@@')[1].strip().split('+')[1].split(',')[0])
                        new_offset = int(patch['patch_text'].split('@@')[1].strip().split(',')[-1])
                        if patch['file_path_new'] == relative_file_path and new_start <= bb2s[0].end_line and bb2s[0].start_line < new_start + new_offset:
                            __keep_bb_in_patch(bb2s[0].start_line, bb2s[0].end_line, key, final_patches, diff_results)

                else:
                    # Add declaration for the "__revert_*" function
                    for func_decl in function_declarations:
                        if func_name == func_decl.split('(')[0].split(' ')[-1]:
                            func_decl_to_add.setdefault(location.split('/',3)[-1].split(':')[0], set()).add(f'{func_decl}')
                            break

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
                    logger.info(f'Adding enum/macro patch for {file_path}')
                    # enum or macro patch
                    locs = list(con_to_add[file_path])
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
                patch = {
                    'file_path_old': file_path,
                    'file_path_new': file_path,
                    'patch_text': patch_header + context1 + include_text + enum_text + func_decl_text + context2,
                    'new_start_line': start,
                    'new_end_line': end,
                    'old_start_line': start,
                    'old_end_line': enum_len+include_len+func_decl_len+end,
                    'old_signature': '',
                    'new_signature': '',
                    'patch_type': {'Enum or macro change', 'Function declaration change'},
                }
                extra_patches[file_path] = patch
                
            with open(patch_file_path, 'w') as patch_file:
                for key in final_patches:
                    patch = diff_results[key]
                    patch_file.write(patch['patch_text'])
                    patch_file.write('\n\n')
                for patch in extra_patches.values():    
                    patch_file.write(patch['patch_text'])
                    patch_file.write('\n\n')
            
        if build_success:
            # Run the fuzzer to test if the bug is reproduced
            testcase_path = os.path.join(testcases_env, 'testcase-' + bug_id)
            reproduce_cmd = [
                py3, f'{current_file_path}/fuzz_helper.py', 'reproduce', target, fuzzer, testcase_path, '-e', 'ASAN_OPTIONS=detect_leaks=0'
            ]
            logger.info(f"Running reproduce command: {' '.join(reproduce_cmd)}")
            test_result = subprocess.run(reproduce_cmd, capture_output=True, text=True)
            if bug_type.lower() in test_result.stdout.lower() or bug_type.lower() in test_result.stderr.lower():
                # trigger the bug
                revert_and_trigger_set.add((bug_id, next_commit['commit_id'], fuzzer))
                if ((bug_id, next_commit['commit_id'], fuzzer) in revert_and_trigger_fail_set):
                    revert_and_trigger_fail_set.remove((bug_id, next_commit['commit_id'], fuzzer))
                logger.info(f"Bug {bug_id} triggered successfully with fuzzer {fuzzer} on commit {next_commit['commit_id']}\n")
            else:
                revert_and_trigger_fail_set.add((bug_id, next_commit['commit_id'], fuzzer))
                get_patched_traces.setdefault(bug_id, []).append(patch_file_path)
                transitions.append((commit, next_commit, bug_id))
                update_function_mappings(recreated_functions, signature_change_list)
                logger.info(f"Bug {bug_id} not triggered with fuzzer {fuzzer} on commit {next_commit['commit_id']}\n")
        else:
            logger.info(f"Build failed for bug {bug_id} on commit {next_commit['commit_id']}\n")

    logger.info(f"Revert and trigger set: {len(revert_and_trigger_set)} {revert_and_trigger_set}")
    logger.info(f"Revert and trigger fail set: {len(revert_and_trigger_fail_set)} {revert_and_trigger_fail_set}")


def get_compile_commands(target, commit_id, sanitizer, bug_id, fuzzer, build_csv, arch, patch_path_list=None):
    if not patch_path_list:
        cmd = [
            py3, f"{current_file_path}/fuzz_helper.py", "build_version", "--commit", commit_id, "--sanitizer", sanitizer,
            '--build_csv', build_csv, '--compile_commands', '--architecture', arch , target
        ]
    else:
        cmd = [
            py3, f"{current_file_path}/fuzz_helper.py", "build_version", "--commit", commit_id, "--sanitizer", sanitizer,
            '--build_csv', build_csv, '--compile_commands', '--architecture', arch, '--patch', patch_path_list[-1], target
        ]
    
    logger.info(' '.join(cmd))
    if not os.path.exists(os.path.join(data_path, f'{target}-{commit_id}{'-'+patch_path_list[-1].split('/')[-1].split('.diff')[0] if patch_path_list else ''}')):
        result = subprocess.run(cmd, capture_output=True, text=True)

    
if __name__ == "__main__":
    args = parse_arguments()
    revert_patch_test(args)