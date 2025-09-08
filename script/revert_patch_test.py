import re
import argparse
import subprocess
import json
import os
from git import Repo
import logging
from pathlib import Path
import gzip
import pickle
import copy
from collections import defaultdict
from typing import List, Dict, Set, Tuple, Any

from buildAndtest import checkout_latest_commit
from run_fuzz_test import read_json_file, py3
from compare_trace import extract_function_calls
from compare_trace import compare_traces
from cfg_parser import parse_cfg_text, find_block_by_line, compute_data_dependencies
from utils import minimize_greedy, minimize_ddmin, apply_unified_diff_to_string, split_function_parts, diff_strings
from fuzzer_correct_test import test_fuzzer_build
from gumtree import get_corresponding_lines, get_delete_lines

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

current_file_path = os.path.dirname(os.path.abspath(__file__))
ossfuzz_path = os.path.abspath(os.path.join(current_file_path, '..', 'oss-fuzz'))
data_path = os.path.abspath(os.path.join(current_file_path, '..', 'data'))


def rename_func(patch_text, fname, commit, bug_id, replacement_string=None):
    logger.debug(f'Renaming function {fname}')
    modified_lines = []
    regex = r'(?<![\w.])' + re.escape(fname) + r'(?!\w)'
    if not replacement_string:
        replacement_string = f"__revert_{commit}_{bug_id.replace('-', '_')}_{fname}"

    for line in patch_text.splitlines():
        if line.startswith('-'):
            # Only modify lines that represent removed code
            modified_line = re.sub(regex, replacement_string, line)
            modified_lines.append(modified_line)
        else:
            modified_lines.append(line)
    return modified_lines


def get_function_code_from_old_commit(target_repo_path, commit, data_path, file_path, func_sig):
    """Get function code from the old commit"""
    os.chdir(target_repo_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", '-f', commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    parsing_path = os.path.join(data_path, f'{target_repo_path.split('/')[-1]}-{commit}', f'{file_path}_analysis.json')
    parsing_path = os.path.join(
        data_path,
        f"{target_repo_path.split('/')[-1]}-{commit}",
        f"{file_path}_analysis.json",
    )
    with open(parsing_path, 'r') as f:
        ast_nodes = json.load(f)
    for ast_node in ast_nodes:
        if ast_node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
            continue
        # Use compare_function_signatures here because signature may have const keyword and can't match
        if ast_node['extent']['start']['file'] == file_path and compare_function_signatures(ast_node['signature'], func_sig, True):
            with open(os.path.join(target_repo_path, file_path), 'r') as f:
                file_content = f.readlines()
                func_code = ''.join(line for line in file_content[ast_node['extent']['start']['line']-1:ast_node['extent']['end']['line']])
                func_length = func_code.count('\n')
                if func_code[-1] != '\n':
                    # This function is in the last line of the file, without a \n will cause the patch to fail
                    func_length += 1
                return func_code, func_length, ast_node['extent']['start']['line']
    return None, 0, 0


def get_function_code_by_line(target_repo_path, commit, data_path, file_path, line_number):
    """Get function code that contains a given line number from the old commit"""
    os.chdir(target_repo_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8',
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", '-f', commit], encoding='utf-8',
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    parsing_path = os.path.join(
        data_path,
        f"{target_repo_path.split('/')[-1]}-{commit}",
        f"{file_path}_analysis.json",
    )

    if not os.path.exists(parsing_path):
        raise FileNotFoundError(f"AST analysis not found: {parsing_path}")

    with open(parsing_path, 'r') as f:
        ast_nodes = json.load(f)

    for ast_node in ast_nodes:
        if ast_node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
            continue
        if ast_node['extent']['start']['file'] != file_path:
            continue

        start_line = ast_node['extent']['start']['line']
        end_line   = ast_node['extent']['end']['line']

        if start_line <= line_number <= end_line:
            with open(os.path.join(target_repo_path, file_path), 'r') as fsrc:
                file_content = fsrc.readlines()
                func_code = ''.join(
                    file_content[start_line-1:end_line]
                )
                func_length = func_code.count('\n')
                if func_code and func_code[-1] != '\n':
                    func_length += 1
                return func_code, func_length, start_line

    return None, 0, 0


def get_patch_insert_line_number(target_repo_path, next_commit, data_path, file_path, func_sig):
    """Get patch insert line number from new commit for the Artificial patch"""
    os.chdir(target_repo_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", '-f', next_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    parsing_path = os.path.join(
        data_path,
        f"{target_repo_path.split('/')[-1]}-{next_commit}",
        f"{file_path}_analysis.json",
    )
    with open(parsing_path, 'r') as f:
        ast_nodes = json.load(f)
    artificial_patch_insert_point = -1
    for ast_node in ast_nodes:
        if ast_node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
            continue
        if ast_node['extent']['start']['file'] == file_path and compare_function_signatures(ast_node['signature'], func_sig, True):
            artificial_patch_insert_point = ast_node['extent']['end']['line'] + 1
            break
    return artificial_patch_insert_point


def get_new_funcsig(fname, next_commit, file_path_new, target_repo_path):
    parsing_path = os.path.join(
        data_path,
        f"{target_repo_path.split('/')[-1]}-{next_commit}",
        f"{file_path_new}_analysis.json",
    )
    with open(parsing_path, 'r') as f:
        ast_nodes = json.load(f)
    def_kinds = {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}
    for node in ast_nodes:
        if node['kind'] in def_kinds and node['spelling'] == fname:
            return node['signature']
    return None


def process_function_signature_changes(function_sig_changes, patch_key_list, diff_results, extra_patches, target, commit, next_commit, target_repo_path, function_declarations, file_path_pairs, depen_graph: dict, bug_id):
    # From the error_log like "too few arguments in function call" get the caller and callee info;
    # Recreate the callee function, change the callsite
    new_patch_key_list = set()
    tail_fun_info_list = []
    for code, error_type, file_path, line_range in function_sig_changes:
        def_file_path = None
        file_path_new = file_path.split('/', 3)[-1]
        if file_path_new in file_path_pairs:
            file_path_old = file_path_pairs[file_path_new]
        else:
            file_path_old = file_path_new
        old_line_list = []
        for line_num in range(line_range[0], line_range[1] + 1):
            old_line_list.append(get_old_line_num(file_path_new, line_num, patch_key_list, diff_results, extra_patches, target, commit))
        parsing_path = os.path.join(
            data_path,
            f"{target_repo_path.split('/')[-1]}-{commit}",
            f"{file_path_old}_analysis.json",
        )
        with open(parsing_path, 'r') as f:
            ast_nodes = json.load(f)
        call_kinds = {'CALL_EXPR', 'CXX_METHOD_CALL_EXPR'}
        def_kinds = {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}
        decl_kinds = {'FUNCTION_DECL'}
        callee_sig = None
        caller_sig = None
        # 1 get caller and callee
        for node in ast_nodes:
            if not callee_sig and node.get('kind') in call_kinds and file_path_old == node['location']['file'] and int(node['extent']['start']['line']) <= min(old_line_list) \
                and max(old_line_list) <= int(node['extent']['end']['line']):
                callee_sig = node['callee']['signature']
            if not caller_sig and node.get('kind') in def_kinds and file_path_old == node['location']['file'] and int(node['extent']['start']['line']) <= min(old_line_list) \
                and max(old_line_list) <= int(node['extent']['end']['line']):
                caller_sig = node['signature']
        if not callee_sig:
            logger.info(f'No callee sig found for {parsing_path}: {line_range} : {old_line_list}')
        fname = callee_sig.split('(')[0].split(' ')[-1]
        for node in ast_nodes:
            if (node.get('kind') in decl_kinds or node.get('kind') in def_kinds) and node['spelling'] == fname:
                def_file_path = node['location']['file'].replace('.h', '.c')
        
        def_file_path_new = def_file_path_old = def_file_path
        for file_path_new, file_path_old in file_path_pairs.items():
            if file_path_old == def_file_path:
                def_file_path_new = file_path_new

        if callee_sig and caller_sig:
            func_code, func_length, start_line = get_function_code_from_old_commit(target_repo_path, commit, data_path, def_file_path_old, callee_sig)
            func_code = '\n'.join([f'-{line}' for line in func_code.split('\n')][:-1]) + '\n'  # Add a \n at the end to avoid patch fail
            
            callee_sig_new = get_new_funcsig(fname, next_commit, def_file_path_new, target_repo_path)
            if not callee_sig_new:
                # Function change name, so insert at an abbitray point
                os.chdir(target_repo_path)
                subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["git", "checkout", '-f', next_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                with open(os.path.join(target_repo_path, def_file_path_new), 'r') as f:
                    lines = f.readlines()
                artificial_patch_insert_point = len(lines)+1
                # Find call in this function, check if we need to replace them with recreated functions
                parsing_path = os.path.join(
                    data_path,
                    f"{target_repo_path.split('/')[-1]}-{commit}",
                    f"{def_file_path_old}_analysis.json",
                )
                with open(parsing_path, 'r') as f:
                    ast_nodes = json.load(f)
                for node in ast_nodes:
                    if node['kind'] == 'CALL_EXPR':
                        if start_line <= node['location']['line'] <= start_line + func_length and any(
                            f"__revert_{commit}_{bug_id.replace('-', '_')}_{node['spelling']}(" in function_declaration
                            for function_declaration in function_declarations
                        ):
                            # Replace the call with the recreated function
                            func_code = '\n'.join(rename_func(func_code, node['spelling'], commit, bug_id))
                            
                tail_fun_info_list.append((func_code, artificial_patch_insert_point, func_length, def_file_path_old, def_file_path_new))
            else:
                artificial_patch_insert_point = get_patch_insert_line_number(target_repo_path, next_commit, data_path, def_file_path_new, callee_sig_new)
                # Create the Artificial patch here
                patch_header = f'diff --git a/{def_file_path_old} b/{def_file_path_new}\n--- a/{def_file_path_old}\n+++ b/{def_file_path_new}\n'
                patch_header += f'@@ -{artificial_patch_insert_point},{func_length} +{artificial_patch_insert_point},0 @@\n'
                artificial_patch = {
                    'file_path_old': def_file_path_old,
                    'file_path_new': def_file_path_new,
                    'file_type': 'c',
                    'patch_text': '\n'.join(rename_func(patch_header + func_code, fname, commit, bug_id)),
                    'old_signature': callee_sig, # __revert_{commit}_{bug_id.replace('-', '_')}_{fname} is not added here
                    'patch_type': {'Function removed', 'Function body change', 'Recreated function'},
                    'dependent_func': set(),
                    'new_start_line': artificial_patch_insert_point,
                    'new_end_line': artificial_patch_insert_point,
                    'old_start_line': artificial_patch_insert_point,
                    'old_end_line': artificial_patch_insert_point + func_length,
                }
                new_key = f'{def_file_path_old}{def_file_path_new}-{artificial_patch_insert_point},{func_length}+{artificial_patch_insert_point},0'
                diff_results[new_key] = artificial_patch
                new_patch_key_list.add(new_key)
                # change the callsite, update depen_graph
                for key in patch_key_list:
                    patch = diff_results[key]
                    if 'old_signature' in patch and patch['old_signature'] == caller_sig:
                        depen_graph.setdefault(new_key, set()).add(key)
                        patch['patch_text'] = '\n'.join(rename_func(patch['patch_text'], fname, commit, bug_id))
            function_declarations.add(callee_sig.replace(fname, f'__revert_{commit}_{bug_id.replace('-', '_')}_{fname}'))
        else:
            logger.error(f"{file_path_new}: {line_range} cannot find caller or callee in parsing files.")
            
    if len(tail_fun_info_list) > 0:
        tail_code = dict() 
        tail_code_len = dict()
        tail_insert_point = dict()
        tail_def_file_path_new = dict()
        for func_code, insert_point, func_length, def_file_path_old, def_file_path_new in tail_fun_info_list:
            tail_code[def_file_path_old] = tail_code.get(def_file_path_old, '') + func_code
            tail_code_len[def_file_path_old] = tail_code_len.get(def_file_path_old, 0) + func_length
            tail_insert_point[def_file_path_old] = insert_point
            tail_def_file_path_new[def_file_path_old] = def_file_path_new
        
        for def_file_path_old in tail_code:
            insert_point = tail_insert_point[def_file_path_old]
            def_file_path_new = tail_def_file_path_new[def_file_path_old]
            tail_key = f'{def_file_path_old}{def_file_path_new}-{insert_point},{tail_code_len[def_file_path_old]}+{insert_point},0'
            patch_header = f'diff --git a/{def_file_path_old} b/{def_file_path_new}\n--- a/{def_file_path_old}\n+++ b/{def_file_path_new}\n'
            patch_header += f'@@ -{insert_point},{tail_code_len[def_file_path_old]} +{insert_point},0 @@\n'
            diff_results[tail_key] = {
                'file_path_old': def_file_path_old,
                'file_path_new': def_file_path_new,
                'file_type': 'c',
                'patch_text': '\n'.join(rename_func(patch_header + tail_code[def_file_path_old], fname, commit)),
                'old_signature': None,
                'patch_type': {'Function removed', 'Function body change', 'Recreated function'},
                'dependent_func': set(),
                'new_start_line': insert_point,
                'new_end_line': insert_point,
                'old_start_line': insert_point,
                'old_end_line': insert_point + tail_code_len[def_file_path_old],
            }
            new_patch_key_list.add(tail_key)
            # change the callsite, update depen_graph
            for key in patch_key_list:
                patch = diff_results[key]
                if 'old_signature' in patch and patch['old_signature'] == caller_sig:
                    depen_graph.setdefault(tail_key, set()).add(key)
                    patch['patch_text'] = '\n'.join(rename_func(patch['patch_text'], fname, commit, bug_id))
            
    return new_patch_key_list, function_declarations, depen_graph


def process_undeclared_identifiers(miss_member_structs, miss_decls, final_patches, diff_results, extra_patches, target, next_commit, commit, target_repo_path, arch):
    """
    Process undeclared identifiers by analyzing and extracting basic block change pairs.
    
    This function processes the undeclared identifiers found during compilation by:
    1. Building basic block change pairs for each missing member struct and declaration
    2. Filtering and deduplicating the change pairs
    3. Analyzing def-use chains and updating block changes based on dependencies
    4. Rewriting patches based on the determined basic block changes
    
    Args:
        miss_member_structs: List of missing member structs (field_name, struct_name, file_path, line_num)
        miss_decls: List of missing declarations (identifier, file_path, line_num)
        final_patches: List of patch keys to apply
        diff_results: Dictionary of patch results
        extra_patches: Extra patches to consider
        target: The target project
        next_commit: The next commit information
        commit: The current commit information
        arch: Architecture to build for
        target_repo_path: Path to the target repository
        
    Returns:
        Dictionary of basic block change pairs by file path
    """
    bb_change_pair = dict() # key: relative file path, value: list of (bb1s, bb2s, cfg1), change from bb1s to bb2s
    
    for field_name, struct_name, file_path, line_num in miss_member_structs:
        bb1s, bb2s, cfg1, cfg2 = get_bb_change_pair_from_line(file_path, [line_num], final_patches, diff_results, extra_patches, target, next_commit['commit_id'], commit['commit_id'], arch, args.build_csv, target_repo_path)
        relative_file_path = file_path.split('/', 3)[-1]
        bb_change_pair.setdefault(relative_file_path, []).append((bb1s, bb2s, cfg1, cfg2))
        
    for identifier, file_path, line_num in miss_decls:
        bb1s, bb2s, cfg1, cfg2 = get_bb_change_pair_from_line(file_path, [line_num], final_patches, diff_results, extra_patches, target, next_commit['commit_id'], commit['commit_id'], arch, args.build_csv, target_repo_path)
        relative_file_path = file_path.split('/', 3)[-1]
        bb_change_pair.setdefault(relative_file_path, []).append((bb1s, bb2s, cfg1, cfg2))

    bb_change_pair = filter_and_dedup_bb_change_pairs(bb_change_pair)
    for relative_file_path, bb_change_list in bb_change_pair.items():
        if not bb_change_list:
            continue
        seen = set()
        # Def-use chain to solve data dependency in blocks
        bb_change_list_update = []
        for bb1s, bb2s, cfg1, cfg2 in bb_change_list:
            var_to_use_blocks_cfg1, var_to_def_blocks_cfg2 = analyze_def_use_chain(bb1s, bb2s, cfg1, cfg2)
            for var, bb_to_update_incfg1 in var_to_use_blocks_cfg1.items():
                if bb_to_update_incfg1 == []:
                    continue
                bb_to_update_incfg2 = get_corresponding_bb(target_repo_path, bb_to_update_incfg1, relative_file_path, commit['commit_id'], next_commit['commit_id'], [cfg2])
                bb_change_list_update.append((bb_to_update_incfg1, bb_to_update_incfg2, cfg1, cfg2))
            for var, bb_to_update_incfg2 in var_to_def_blocks_cfg2.items():
                if bb_to_update_incfg2 == []:
                    continue
                bb_to_update_incfg1 = get_corresponding_bb(target_repo_path, bb_to_update_incfg2, relative_file_path, next_commit['commit_id'], commit['commit_id'], [cfg1])
                bb_change_list_update.append((bb_to_update_incfg1, bb_to_update_incfg2, cfg1, cfg2))
        
        # Deduplicate bb_change_list_update based on bb1s and bb2s
        seen_pairs = set()
        deduplicated_bb_change_list_update = []
        for bb1s, bb2s, cfg1, cfg2 in bb_change_list_update:
            # Create a hashable representation of bb1s and bb2s
            bb1s_key = tuple((bb.start_line, bb.end_line) for bb in bb1s) if bb1s else ()
            bb2s_key = tuple((bb.start_line, bb.end_line) for bb in bb2s) if bb2s else ()
            pair_key = (bb1s_key, bb2s_key)
            
            if pair_key not in seen_pairs:
                seen_pairs.add(pair_key)
                deduplicated_bb_change_list_update.append((bb1s, bb2s, cfg1, cfg2))
        
        bb_change_list.extend(deduplicated_bb_change_list_update)
        
        # Rewrite the patches
        # Store all block data in a list and sort by bb1_start_line (biggest to smallest)
        block_data_list = []
        for bb1s, bb2s, cfg1, cfg2 in bb_change_list:
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
            if bb2s == []:
                # When bb2s is empty, means some blocks need to be removed from the patch, delete the whole 
                # part of code to avoid syntax error (like in if statement, need remove multiple lines)
                delete_lines = get_delete_lines(target_repo_path, relative_file_path, commit['commit_id'], relative_file_path, next_commit['commit_id'], bb1_start_line, bb1_end_line)
                for line1, line2 in delete_lines:
                    bb1_start_line = min(bb1_start_line, line1)
                    bb1_end_line = max(bb1_end_line, line2)

            block_data_list.append((bb1_start_line, bb1_end_line, bb2_start_line, bb2_end_line, bb1s, bb2s, cfg1, cfg2))

        # Sort by bb1_start_line in descending order (biggest to smallest)
        block_data_list.sort(key=lambda x: x[0], reverse=True)

        # Process blocks from biggest bb1_start_line to smallest
        for bb1_start_line, bb1_end_line, bb2_start_line, bb2_end_line, bb1s, bb2s, cfg1, cfg2 in block_data_list:
            if (bb1_start_line, bb1_end_line) in seen:
                # Skip if this bb1 range has been seen before
                continue
            seen.add((bb1_start_line, bb1_end_line))
            if bb1_start_line == float('inf'):
                logger.error(f'No basic block found for {relative_file_path} \n bb1s {bb1s} bb2s {bb2s}')
            if not keep_bb_in_patch(bb1_start_line, bb1_end_line, bb2_start_line, bb2_end_line, cfg1, diff_results, final_patches, target_repo_path, next_commit['commit_id'], relative_file_path):
                logger.error(f'Failed to keep basic block in patch for {relative_file_path}')
                continue
    
    return bb_change_pair


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
    no_merge = set() # A set of keys, means they should not be considered to merge. Because this patch is a whole function
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

            patch_header = f"diff --git a/{path_b if path_a != '/dev/null' else path_b} b/{path_b if path_b != '/dev/null' else path_a}\n"
            patch_header += f"--- {f'a/{path_b}' if path_a != '/dev/null' else '/dev/null'}\n+++ {'b/' if path_b != '/dev/null' else ''}{path_b}\n"
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
                    if node['extent']['start']['line'] == new_line_start and node['extent']['end']['line'] == new_line_cursor-1:
                        no_merge.add(key_new)
                    
                    dependent_func = set()
                    results[key_new] = {
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
            
            patch_header = f"diff --git a/{path_b if path_a != '/dev/null' else path_b} b/{path_b if path_b != '/dev/null' else path_a}\n"
            patch_header += f"--- {f'a/{path_b}' if path_a != '/dev/null' else '/dev/null'}\n+++ {'b/' if path_b != '/dev/null' else ''}{path_b}\n"
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
                            if k in no_merge:
                                continue
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


def clean_log(text: str) -> str:
    _ANSI_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')  # ANSI CSI sequences
    _BACKSPACE_RE = re.compile(r'.\x08')               # overstrike patterns

    if not text:
        return ''
    # normalize carriage returns from progress bars
    text = text.replace('\r', '\n')
    # remove backspace overstrikes
    text = _BACKSPACE_RE.sub('', text)
    # strip ANSI escape codes
    text = _ANSI_RE.sub('', text)
    # collapse duplicate newlines
    return re.sub(r'\n{3,}', '\n\n', text)


def build_fuzzer(target, commit_id, sanitizer, bug_id, patch_file_path, fuzzer, build_csv, arch):
    cmd = [
        "python3", f"{current_file_path}/fuzz_helper.py", "build_version", "--commit", commit_id, "--sanitizer", sanitizer,
        "--patch", patch_file_path, '--build_csv', build_csv, '--architecture', arch , target
    ]

    logger.info(' '.join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    stdout = clean_log(result.stdout)
    stderr = clean_log(result.stderr)
    combined = stderr + stdout

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
        "failed with exit status",
        "CMake Error",
        "call to undeclared function"
    ]

    fuzzer_path = os.path.join(ossfuzz_path, 'build/out', target, fuzzer)
    if (not os.path.exists(fuzzer_path)
        or any(p in combined for p in build_error_patterns)
        or result.returncode != 0):
        logger.info(f"Build failed after patch reversion for bug {bug_id}\n")
        return False, combined

    logger.info(f"Successfully built fuzzer after reverting patch for bug {bug_id}")
    return True, ''


def patch_patcher(diff_results, patch_to_apply : list, dependence_graph, commit, next_commit, target_repo_path, bug_id):
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
        if 'old_signature' not in patch:
            # skip for a added function
            new_patch_to_apply.append(key)
            continue
        fname = patch['old_signature'].split('(')[0].split(' ')[-1]
        
        if fname == 'LLVMFuzzerTestOneInput':
            # skip LLVMFuzzerTestOneInput, because it is a special function for fuzzing
            new_patch_to_apply.append(key)
            continue
        if 'Function body change' in patch['patch_type']:
            if 'Function removed' in patch['patch_type'] and not 'Function added' in patch['patch_type']:
                # add prefix to function being deleted
                modified_lines = rename_func(patch['patch_text'], fname, commit, bug_id)
                function_declarations.add(patch['old_signature'].replace(fname, f'__revert_{commit}_{bug_id.replace('-', '_')}_{fname}')) # do not use rename_func here, because it only change line starting with '-'
                patch['patch_text'] = '\n'.join(modified_lines)
                # iterate through the dependent functions and rename them
                for dep_key in dependence_graph.get(key, []):
                    modified_lines = rename_func(diff_results[dep_key]['patch_text'], fname, commit, bug_id)
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

                func_code, func_length, start_line = get_function_code_from_old_commit(target_repo_path, commit, data_path, patch['file_path_old'], patch['old_signature'])
                func_code = '\n'.join([f'-{line}' for line in func_code.split('\n')][:-1]) + '\n'  # Add a \n at the end to avoid patch fail

                artificial_patch_insert_point = get_patch_insert_line_number(target_repo_path, next_commit, data_path, patch['file_path_new'], patch['new_signature'])

                def create_artificial_patch_data(patch, fname, artificial_patch_insert_point, func_length, func_code):
                    """Create the Artificial patch data structure"""
                    patch_lines = patch['patch_text'].split('\n')
                    patch_header = f'{patch_lines[0]}\n{patch_lines[1]}\n{patch_lines[2]}\n'
                    patch_header += f'@@ -{artificial_patch_insert_point},{func_length} +{artificial_patch_insert_point},0 @@\n'
                    artificial_patch = {
                        'file_path_old': patch['file_path_old'],
                        'file_path_new': patch['file_path_new'],
                        'file_type': patch['file_type'],
                        'patch_text': '\n'.join(rename_func(patch_header + func_code, fname, commit, bug_id)),
                        'old_signature': patch['old_signature'], # __revert_commit_{fname} is not added here
                        'patch_type': {'Function removed', 'Function body change', 'Recreated function'},
                        'dependent_func': set(),
                        'new_start_line': artificial_patch_insert_point,
                        'new_end_line': artificial_patch_insert_point,
                        'old_start_line': artificial_patch_insert_point,
                        'old_end_line': artificial_patch_insert_point + func_length,
                        'old_function_start_line': artificial_patch_insert_point,
                        'old_function_end_line': artificial_patch_insert_point + func_length,
                    }
                    new_key = f'{patch["file_path_old"]}{patch["file_path_new"]}-{artificial_patch_insert_point},{func_length}+{artificial_patch_insert_point},0'
                    return artificial_patch, new_key
                artificial_patch, new_key = create_artificial_patch_data(patch, fname, artificial_patch_insert_point, func_length, func_code)
                
                diff_results[new_key] = artificial_patch
                function_declarations.add(patch['old_signature'].replace(fname, f'__revert_{commit}_{bug_id.replace('-', '_')}_{fname}'))
                new_patch_to_apply.append(new_key)
                reserved_keys.add(new_key)
                key_to_newkey[key] = new_key
                
        else:
            new_patch_to_apply.append(key)
            logger.debug(f"Skipping non-function body change for {key}")
            
    # Rename the function by dependency graph, find the caller of the recreated function
    for key in key_to_newkey:
        patch = diff_results[key]
        fname = patch['old_signature'].split('(')[0].split(' ')[-1]
        for caller_key in dependence_graph.get(key, []):
            # rename functions in patches that depend on (call) this function
            caller_key = key_to_newkey.get(caller_key, caller_key)
            if caller_key not in diff_results:
                # for minimal patch
                continue
            modified_lines = rename_func(diff_results[caller_key]['patch_text'], fname, commit, bug_id)
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
    # Skip error messages from AST analysis
    if not signature or 'error generated' in signature:
        raise ValueError(f"Invalid function signature: {signature}")
    
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
    # Starts with patch_to_apply are patches of common part of trace1 and trace2.
    # Find callees of patch_to_apply functions, if they are in trace1 add an edge from
    # the callee definition patch to this patch(caller). Specifically, do this for the 
    # patches remove the function definition or change the function definition.
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
    while patch_list:
        key = patch_list.pop()
        if key in visited_patches:
            # skip if this patch has been visited
            continue
        visited_patches.add(key)
        new_patch_to_patch.append(key)
        logger.debug(
            f"Analyzing patch {key}\n{diff_results[key]['patch_text']}"
        )
        patch = diff_results[key]
        if 'Function body change' in patch['patch_type'] and patch['file_path_old']:
            parsing_path = os.path.join(data_path, f'{target_repo_path.split('/')[-1]}-{old_commit}', f'{patch['file_path_old']}_analysis.json')
            with open(parsing_path, 'r') as f:
                ast_nodes = json.load(f)
            # filter for call expressions (clang cursors for function calls)
            call_kinds = {'CALL_EXPR', 'CXX_METHOD_CALL_EXPR'}
            def_kinds = {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}
            decl_kinds = {'FUNCTION_DECL'}
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
                    if node['spelling'] not in trace_function_names:
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
    patch_prev_key = None
    removed_patches = set()
    
    os.chdir(target_repo_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", '-f', new_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # 1. Merge the patches that have overlap, note that the overlap here is just the simple ones
    prev_new_start_line = dict()
    prev_new_end_line = dict()
    patch_prev_key = dict()
    for key in reversed(final_patches):
        patch = diff_results[key]
        patch_text = patch['patch_text']
        lines = patch_text.split('\n')
        if len(lines) < 5:
            logger.error(f'patch_text is too short, skip: {patch_text}')
        if lines[4][0] == '-': # meaning this patch has no context
            if patch['file_path_new'] in patch_prev_key and patch['new_start_line'] <= prev_new_end_line[patch['file_path_new']]+3:
                # merge the patches that have overlap
                patch_prev = diff_results[patch_prev_key[patch['file_path_new']]]
                patch_prev_lines = patch_prev['patch_text'].split('\n')
                connect_lines_end = patch['new_start_line']
                connect_lines_begin = patch_prev['new_end_line']
                if connect_lines_begin < connect_lines_end:
                    with open(os.path.join(target_repo_path, patch['file_path_new']), 'r') as f:
                        connect_lines = [f' {line[:-1]}' for line in f.readlines()[connect_lines_begin:connect_lines_end-1]]
                else:
                    connect_lines = []
                merged_lines = patch_prev_lines[4:] + connect_lines + lines[4:]
                
                patch_prev_old_start = int(patch_prev_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[0].split('-')[-1])
                patch_prev_old_offset = int(patch_prev_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
                patch_prev_new_start = int(patch_prev_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[0].split('-')[-1])
                patch_prev_new_offset = int(patch_prev_lines[3].split('@@')[-2].strip().split(',')[-1])
                
                patch_old_offset = int(lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
                patch_new_offset = int(lines[3].split('@@')[-2].strip().split(',')[-1])
                patch_prev['patch_text'] = '\n'.join(lines[:3] + [f'@@ -{patch_prev_old_start},{patch_old_offset+patch_prev_old_offset+max(0, connect_lines_end-connect_lines_begin-1)}\
                    + {patch_prev_new_start},{patch_prev_new_offset+patch_new_offset+max(0, connect_lines_end-connect_lines_begin-1)} @@'] + merged_lines)
                patch_prev['new_start_line'] = patch['new_start_line']
                patch_prev['new_end_line'] = patch_prev['new_start_line'] + patch_old_offset+patch_prev_old_offset+connect_lines_end-connect_lines_begin
                patch_prev['old_start_line'] = patch['old_start_line']
                patch_prev['old_end_line'] = patch_prev['old_start_line'] + patch_new_offset+patch_prev_new_offset+connect_lines_end-connect_lines_begin
                removed_patches.add(key)
        prev_new_start_line[patch['file_path_new']] = patch['new_start_line']
        prev_new_end_line[patch['file_path_new']] = patch['new_end_line']
        patch_prev_key[patch['file_path_new']] = key

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
            
        if lines[-1] and (lines[-1][0] in {'-', '+'} or lines[-2][0] in {'-', '+'} or lines[-3][0] in {'-', '+'}):
            # No context lines or context less than 3 lines after the patch: add context_lines2.
            new_line_begin = new_line_begin_nocontext
            new_offset = new_offset_nocontext + max(0, min(3, len(content) - new_line_begin_nocontext - new_offset_nocontext+1))
            old_line_begin = old_line_begin_nocontext
            old_offset = old_offset_nocontext + new_offset - new_offset_nocontext
            if new_offset == new_offset_nocontext:
                context_lines2 = []
            else:
                context_lines2 = [f' {line}' for line in content[new_line_begin_nocontext+new_offset_nocontext-1: new_line_begin + new_offset-1]]
            if new_offset - new_offset_nocontext < 3:
                context_lines2.append('\\ No newline at end of file')

        lines = lines[:3] + [f'@@ -{old_line_begin},{old_offset} +{new_line_begin},{new_offset} @@']\
            + context_lines1 + lines[4:] + context_lines2
        patch['patch_text'] = '\n'.join(lines)
        patch['old_start_line'] = old_line_begin
        patch['old_end_line'] = old_line_begin + old_offset
        patch['new_start_line'] = new_line_begin
        patch['new_end_line'] = new_line_begin + new_offset


def delete_patch_context_single_hunk(diff_results, final_patches):
    """
    Assumptions:
      - Each patch has exactly one hunk, with the header at lines[3].
      - For normal keys: remove leading & trailing ' ' context, keep '-' and '+'.
      - For keys starting with '_extra_':
          * Remove only leading front context.
          * Keep only the contiguous '-' lines right after that context.
          * Discard the following ' ' lines (and anything else).
          * new_count becomes 0.
    Updates patch['patch_text'] and line range fields.
    """
    for key in final_patches:
        patch = diff_results[key]
        text = patch.get('patch_text') or ''
        if not text:
            continue

        lines = text.splitlines()
        if len(lines) < 4 or '@@' not in lines[3]:
            # Not a valid single-hunk unified diff with header on line 4
            continue

        header = lines[3]
        header_mid = header.split('@@')[-2].strip()  # e.g. "-12,5 +12,7"
        parts = header_mid.split()
        old_start = int(parts[0].split('-')[1].split(',')[0])
        new_start = int(parts[1].split('+')[1].split(',')[0])

        # Hunk body (single hunk)
        body = lines[4:]

        # Leading context count: only until first +/- line
        leading_ctx = 0
        for ln in body:
            if ln.startswith(' '):
                leading_ctx += 1
            elif ln.startswith('-') or ln.startswith('+'):
                break
            elif ln == r'\ No newline at end of file':
                break
            else:
                break

        # Shift starts by leading context
        new_old_start = old_start + leading_ctx
        new_new_start = new_start + leading_ctx

        if key.startswith('_extra_'):
            # Keep only the contiguous '-' block immediately after leading context
            i = leading_ctx
            minus_block = []
            while i < len(body) and body[i].startswith('-'):
                minus_block.append(body[i])
                i += 1
            # Ignore anything after (spaces, '+', markers, etc.)
            old_only = len(minus_block)
            new_only = 0
            new_header = f'@@ -{new_old_start},{old_only} +{new_new_start},{new_only} @@'
            new_lines = lines[:3] + [new_header] + minus_block
        else:
            # Normal behavior: strip leading & trailing context; keep +/- lines
            trailing_ctx = 0
            for ln in reversed(body):
                if ln.startswith(' ') or ln == r'\ No newline at end of file':
                    trailing_ctx += 1
                elif ln.startswith('-') or ln.startswith('+'):
                    break
                else:
                    break

            core = body[leading_ctx : len(body) - trailing_ctx if trailing_ctx else len(body)]
            stripped = [ln for ln in core if ln and (ln[0] == '-' or ln[0] == '+')]

            old_only = sum(1 for ln in stripped if ln[0] == '-')
            new_only = sum(1 for ln in stripped if ln[0] == '+')

            new_header = f'@@ -{new_old_start},{old_only} +{new_new_start},{new_only} @@'
            new_lines = lines[:3] + [new_header] + stripped
        patch['patch_text'] = '\n'.join(new_lines)
        patch['old_start_line'] = new_old_start
        patch['new_start_line'] = new_new_start
        patch['old_end_line'] = new_old_start + old_only
        patch['new_end_line'] = new_new_start + new_only


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
    # --- Undeclared identifiers ---
    pattern = r"(/src.+?):(\d+):(\d+):.*use of undeclared identifier '(\w+)'"
    matches = re.findall(pattern, error_log)
    undeclared_identifiers = [(identifier, f"{filepath}:{line}:{column}") for filepath, line, column, identifier in matches]
    
    # --- Undeclared functions ---
    pattern = r"(/src.+?):(\d+):(\d+):.*undeclared function '(\w+)'"
    matches = re.findall(pattern, error_log)
    undeclared_functions = [(identifier, f"{filepath}:{line}:{column}") for filepath, line, column, identifier in matches]
    
    # --- Missing struct members ---
    pattern = r"(/src.+?):(\d+):(\d+):.*no member named '(\w+)' in '([^']+)'"
    matches = re.findall(pattern, error_log)
    missing_struct_members = [(member, struct_name, filepath, int(line)) for filepath, line, column, member, struct_name in matches]
    
    # --- Too few arguments ---
    pattern = r"(/src.+?):(\d+):(\d+):.*too few arguments to function call.*"
    next_error = {'note:', 'warning:', 'error:'}
    line_num_pattern = r"^\s*(\d+)\s*\|\s*(.*)"
    function_sig_changes = []
    error_lines = error_log.splitlines()

    for i, error_line in enumerate(error_lines):
        line_num_set = set()
        fun_call_code = ''
        match = re.search(pattern, error_line)
        if match:
            filepath, line_num, col_num = match.groups()
            line_num_set.add(int(line_num))
            # collect following lines, but carefully
            for j in range(i+1, len(error_lines)):
                if any(sign in error_lines[j] for sign in next_error):
                    break

                # skip caret/tilde continuation lines
                if re.match(r"^\s*\|\s*\^", error_lines[j]) or re.match(r"^\s*\|\s*~", error_lines[j]):
                    continue

                line_num_match = re.search(line_num_pattern, error_lines[j])
                if line_num_match:
                    lnum, code = line_num_match.groups()
                    # only accept lines from the SAME file region (not header notes)
                    if abs(int(lnum) - int(line_num)) > 5:
                        continue
                    line_num_set.add(int(lnum))
                    fun_call_code += code.strip() + " "
            function_sig_changes.append(
                (fun_call_code.strip(), "too_few_arguments_fun_call", filepath, (min(line_num_set), max(line_num_set)))
            )
    
    # --- Type mismatch in function calls ---
    pattern_type_mismatch = r"(/src.+?):(\d+):(\d+):.*passing '([^']+)'.*to parameter of incompatible type '([^']+)'.*"
    for i, error_line in enumerate(error_lines):
        line_num_set = set()
        fun_call_code = ''
        match = re.search(pattern_type_mismatch, error_line)
        if match:
            filepath, line_num, col_num, from_type, to_type = match.groups()
            line_num_set.add(int(line_num))
            for j in range(i+1, len(error_lines)):
                if any(sign in error_lines[j] for sign in next_error):
                    break
                if re.match(r"^\s*\|\s*\^", error_lines[j]) or re.match(r"^\s*\|\s*~", error_lines[j]):
                    continue
                line_num_match = re.search(line_num_pattern, error_lines[j])
                if line_num_match:
                    lnum, code = line_num_match.groups()
                    if abs(int(lnum) - int(line_num)) > 5:
                        continue
                    line_num_set.add(int(lnum))
                    fun_call_code += code.strip() + " "
            function_sig_changes.append(
                (fun_call_code.strip(), "type_mismatch_function_call", filepath, (min(line_num_set), max(line_num_set)))
            )
    
    # Sort results
    function_sig_changes.sort(key=lambda x: (x[2], x[3][0] if isinstance(x[3], tuple) else x[3]), reverse=True)
    
    # --- Unknown type names ---
    pattern = r"(/src.+?):(\d+):(\d+):.*unknown type name '([^']+)'"
    matches = re.findall(pattern, error_log)
    undeclared_identifiers.extend([(type_name, f"{filepath}:{line}:{column}") for filepath, line, column, type_name in matches])
    
    return undeclared_identifiers, undeclared_functions, missing_struct_members, function_sig_changes


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


def add_patch_for_trace_funcs(diff_results, final_patches, trace1, recreated_functions, target_repo_path, commit, next_commit, target, bug_id):
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
            if 'old_signature' in diff_results[key] and fname == diff_results[key]['old_signature'].split('(')[0].split(' ')[-1]:
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
            patch_header += f"--- a/{file_path}\n+++ b/{file_path}\n"
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
                        patch_text = rename_func(f'-{line}', recreated_fname, commit, bug_id)[0] + '\n+' + line[:-1]
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


def llvm_fuzzer_test_one_input_patch_update(diff_results, patch_to_apply, recreated_functions, target_repo_path, commit, next_commit, target, bug_id, trace1):
    """
    Updates patches within LLVMFuzzerTestOneInput function to handle function call replacements when reverting patches.
    
    This function ensures that function calls within the fuzzer are properly mapped from their __revert_commit prefixed 
    versions back to their original names when patches are being reverted. It handles both existing patches that 
    need updating and creates new patches for function calls that aren't covered by existing patches.
    
    Args:
        diff_results: Dictionary containing all patch information
        patch_to_apply: List of patch keys to be applied
        recreated_functions: List of function signatures that have been recreated with __revert_commit prefix
        target_repo_path: Path to the target repository
        commit: Current commit hash
        next_commit: Next commit hash
        target: Target project name
    """
    # Assume target_repo in new commit
    fuzzer_keys = set()
    
    # Step 0: Get harness file path
    for _, trace in trace1:
        if 'LLVMFuzzerTestOneInput' in trace:
            location = trace.split(' ')[1]
            fuzzer_file_path = location.split(':')[0][1:]  # remove leading /
            break
    
    # Step 1: Identify all patches that affect LLVMFuzzerTestOneInput function
    for key in patch_to_apply:
        patch = diff_results[key]
        if not ('old_signature' in patch and 'new_signature' in patch):
            # This patch is not a function body change, skip it
            continue
        if patch['file_path_new'] != fuzzer_file_path:
            continue
        if ('LLVMFuzzerTestOneInput' in patch['old_signature'] or 'LLVMFuzzerTestOneInput' in patch['new_signature']):
            # This is a patch for LLVMFuzzerTestOneInput, we need to update the function calls
            fuzzer_keys.add(key)

    # Step 2: Load AST analysis and locate LLVMFuzzerTestOneInput function boundaries
    parsing_path = os.path.join(data_path, f'{target}-{next_commit}', f'{fuzzer_file_path}_analysis.json')
    with open(parsing_path, 'r') as f:
        ast_nodes = json.load(f)
    for node in ast_nodes:
        if node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
            continue
        if node['extent']['start']['file'] == fuzzer_file_path and node['spelling'] == 'LLVMFuzzerTestOneInput':
            # Found the function definition
            fuzzer_start_line = node['extent']['start']['line']
            fuzzer_end_line = node['extent']['end']['line']
            fuzzer_new_signature = node['signature']
            fuzzer_old_signature = node['signature']
            break
    
    # Step 3: Process all function calls within LLVMFuzzerTestOneInput that reference recreated functions
    for node in ast_nodes:
        if node.get('kind') not in {'CALL_EXPR', 'CXX_METHOD_CALL_EXPR'}:
            continue
        
        # Check if this call is within the LLVMFuzzerTestOneInput function and references a recreated function
        if node['location']['file'] == fuzzer_file_path and fuzzer_start_line <= node['location']['line'] <= fuzzer_end_line and any(node['spelling'] == func_sig.split('(')[0].split(' ')[-1] for func_sig in recreated_functions):
            
            # Track whether this call is already covered by an existing patch
            Inpatch_flag = False
            
            # Step 3a: Check if this call is within any existing patch
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
                        if line[0] not in {'-', '+'} and re.search(r'(?<![\w.])' + re.escape(node['spelling']) + r'(?!\w)', line) is not None:
                            # If the function is called in this patch, we need to update the call
                            rm_line = rename_func(f'-{line[1:]}', node['spelling'], commit, bug_id)[0]
                            add_line = f'+{line[1:]}'
                            new_lines.append(rm_line)
                            new_lines.append(add_line)
                        else:
                            new_lines.append(line)
                    patch['patch_text'] = '\n'.join(new_lines)
            
            # Step 3b: Create new patch for calls not covered by existing patches
            if not Inpatch_flag:
                # This call is not in any patch, we need to create a new patch
                new_start_line = node['location']['line']
                new_offset = 1
                
                # Read the actual function call line from source file
                with open(os.path.join(target_repo_path, fuzzer_file_path), 'r') as f:
                    content = f.readlines()
                    function_line = content[node['location']['line']-1]
                    assert(node['extent']['start']['line'] == node['extent']['end']['line']), f'Function call should be in one line, but got {node["extent"]["start"]["line"]} - {node["extent"]["end"]["line"]}'

                # Create patch lines for reverting __revert_commit_ functions back to original names
                rm_line = rename_func(f'-{function_line}', node['spelling'], commit, bug_id)[0]
                add_line = f'+{function_line.replace('\n', '')}'
                
                # Construct complete patch text
                patch_text = f'diff --git a/{fuzzer_file_path} b/{fuzzer_file_path}\n--- a/{fuzzer_file_path}\n+++ b/{fuzzer_file_path}\n@@ -{new_start_line},{new_offset} +{new_start_line},{new_offset} @@\n{rm_line}\n{add_line}'
                # Create new patch entry
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
                
                # Add new patch to diff_results and patch_to_apply list
                new_key = f'{fuzzer_file_path}{fuzzer_file_path}-{new_start_line},{new_offset}+{new_start_line},{new_offset}'
                diff_results[new_key] = patch
                patch_to_apply.append(new_key)


def update_function_mappings(recreated_functions, signature_change_list, commit: str, bug_id: str):
    # add mapping for recreated functions
    for func_sig in recreated_functions:
        func_name = func_sig.split('(')[0].split(' ')[-1]
        signature_change_list.append((func_name, f'__revert_{commit}_{bug_id.replace('-', '_')}_{func_name}'))


def get_correct_line_num(file_path, line_num, patch_key_list, diff_results, extra_patches):
    # This is only used for LLVMFuzzerTestOneInput, to get the correct line number in the new commit
    # transform the line number after reverting patches, to the line number before reverting patches (in new commit)
    # extra_patches is not considered directly because it is not applied yet
    add_num = 0 # the number of lines added by patches
    patch = None
    for key in reversed(patch_key_list):
        patch = diff_results[key]
        if 'file_path_new' in patch and patch['file_path_new'] == file_path or patch['file_path_new'].endswith(file_path):
            new_start_line = int(patch['patch_text'].split('@@')[1].strip().split('+')[1].split(',')[0])
            old_offset = int(patch['patch_text'].split('@@')[1].strip().split(' ')[0].split(',')[1])
            new_offset = int(patch['patch_text'].split('@@')[1].strip().split(',')[-1])
            if new_start_line <= line_num < new_start_line + new_offset:
                # TODO: check again
                # logger.info(f'here:\n{new_start_line} {new_start_line + new_offset}\n {patch['patch_text']}')
                break
            add_num += new_offset - old_offset
        
    if patch:
        lines = patch['patch_text'].split('\n')
    elif file_path in extra_patches:
        lines = extra_patches[file_path]['patch_text'].split('\n')
    else:
        logger.error(f'Cannot find patch of the line. file_path: {file_path}, line_num: {line_num}')
        
    start_line = int(lines[3].split('@@')[-2].strip().split('+')[1].split(',')[0])
    for i, line in enumerate(lines):
        if i < 4:
            continue
        if start_line == line_num:
            break
        if line.startswith('+'):
            add_num += 1
        elif line.startswith('-'):
            add_num -= 1
            start_line += 1
        else:
            start_line += 1
    
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
        if 'file_path_new' in patch and patch['file_path_new'] == file_path or patch['file_path_new'].endswith(file_path):
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
        # for __revert_{commit}_{bug_id}_{fname} function, we need to find the line number in the old function
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


def check_if_in_fuzzer(line_num, cfgs):
    """
    Check if the given line number falls within the scope of LLVMFuzzerTestOneInput function.
    
    Args:
        line_num: The line number to check
        cfgs: List of CFG objects parsed from cfg files
    
    Returns:
        bool: True if line_num is within LLVMFuzzerTestOneInput, False otherwise
    """
    for cfg in cfgs:
        start_line, end_line = cfg.get_line_range()
        if cfg.function_signature.split('(')[0].split(' ')[-1] == 'LLVMFuzzerTestOneInput' and start_line <= line_num <= end_line:
            return True
    return False


def corresponding_bb(cfg1, cfgs2, bb1, patch_key, diff_results):
    # return the corresponding basic blocks of bb1 from cfgs1 in cfgs2, based on their relationship in a patch
    bbs = []
    # 1. compare function name
    patch = diff_results[patch_key]
    old_signature = patch['old_signature']
    new_signature = patch['new_signature']
    cfg2 = None
    for cfg in cfgs2:
        try:
            if compare_function_signatures(cfg.function_signature, new_signature, ignore_arg_types=True):
                cfg2 = cfg
                break
        except (ValueError, AttributeError):
            # Skip invalid signatures or missing attributes
            continue
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
    seen = set()
    
    for file_path, change_list in bb_change_pair.items():
        kept = []

        new_change_list = []
        for bb1s_i, bb2s_i, cfg1, cfg2 in change_list:
            if not cfg1 or not cfg2:
                # Find nothing from get_bb_change_pair_from_line, ignore it.
                continue
            bb1_start_line = min(bb.start_line for bb in bb1s_i)
            bb1_end_line = max(bb.end_line for bb in bb1s_i)
            if (bb1_start_line, bb1_end_line) in seen:
                # Skip if this bb1 range has been seen before
                continue
            seen.add((bb1_start_line, bb1_end_line))
            new_change_list.append((bb1s_i, bb2s_i, cfg1, cfg2))
        for bb1s_i, bb2s_i, cfg1_i, cfg2_i in new_change_list:
            bb2s_i = deduplicate_bb_blocks(bb2s_i)

            overlap_found = False
            for idx, (bb1s_j, bb2s_j, cfg1_j, cfg2_j) in enumerate(kept):
                if blocks_overlap(bb1s_i, bb1s_j):
                    # Conflict: keep the one with more unique bb2s
                    if len(bb2s_i) > len(bb2s_j):
                        kept[idx] = (bb1s_i, bb2s_i, cfg1_i, cfg2_i)
                    # else: discard current i
                    overlap_found = True
                    break

            if not overlap_found:
                kept.append((bb1s_i, bb2s_i, cfg1_i, cfg2_i))

        filtered[file_path] = kept

    return filtered


def get_corresponding_bb(target_repo_path, bb1s, file_path, commit, next_commit, cfgs2):
    bb2_line_num_list = get_corresponding_lines(target_repo_path, file_path, commit, file_path, next_commit, bb1s)
    cfg2, bb2s = find_block_by_line(cfgs2, file_path.split('/')[-1], bb2_line_num_list)
    return bb2s


def get_bb_change_pair_from_line(file_path, line_num_list, final_patches, diff_results, extra_patches, target, next_commit: str, commit: str, arch, build_csv, target_repo_path):
    relative_file_path = file_path.split('/', 3)[-1]
    line_num_after_patch_list = line_num_list
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
    line_num_in_old_commit_list = []
    for line_num_after_patch in line_num_after_patch_list:
        line_num_in_old_commit_list.append(get_old_line_num(relative_file_path, line_num_after_patch, final_patches, diff_results, extra_patches, target, commit))
    
    with open(os.path.join(data_path, f'cfg-{target}-{commit}-{relative_file_path.replace('/', '-')}.txt'), 'r') as cfg_file:
        cfgs1 = parse_cfg_text(cfg_file.read())
    with open(os.path.join(data_path, f'cfg-{target}-{next_commit}-{relative_file_path.replace('/', '-')}.txt'), 'r') as cfg_file:
        cfgs2 = parse_cfg_text(cfg_file.read())
    cfg1, bb1s = find_block_by_line(cfgs1, file_path.split('/')[-1], line_num_in_old_commit_list)
    if not bb1s:
        logger.error(f'Cannot find basic block for {file_path} at line {line_num_in_old_commit_list} line after patch {line_num_after_patch_list}')
        return None, None, None, None

    for key, patch in diff_results.items():
        if patch['file_path_new'] == relative_file_path:
            bb2_line_num_list = get_corresponding_lines(target_repo_path, patch['file_path_old'], commit, patch['file_path_new'], next_commit, bb1s)
            break
    
    # Now we get basic blocks in new commit that correspond to bb1
    cfg2, bb2s = find_block_by_line(cfgs2, file_path.split('/')[-1], bb2_line_num_list)
    
    return bb1s, bb2s, cfg1, cfg2
    
    
def keep_bb_in_patch(bb1_start_line, bb1_end_line, bb2_start_line, bb2_end_line, cfg1, diff_results, final_patches, target_repo_path, next_commit, relative_file_path):
    for key in final_patches:
        patch = diff_results[key]
        real_patch_start_line = 0
        try:
            signature_match = compare_function_signatures(patch['old_signature'], cfg1.function_signature, ignore_arg_types=True)
        except (ValueError, AttributeError):
            signature_match = False
        if patch['file_path_new'] == relative_file_path and 'Recreated function' in patch['patch_type'] and signature_match:
            logger.debug(f'bb1 {bb1_start_line} - {bb1_end_line} in patch {key}')
            logger.debug(f'bb2 {bb2_start_line} - {bb2_end_line} in new commit {next_commit}')
            old_start = int(patch['patch_text'].split('@@')[1].strip().split('-')[1].split(',')[0])
            old_offset = int(patch['patch_text'].split('@@')[1].strip().split(' ')[0].split(',')[1])
            new_start = int(patch['patch_text'].split('@@')[1].strip().split('+')[1].split(',')[0])
            new_offset = int(patch['patch_text'].split('@@')[1].strip().split(',')[-1])
            if patch['patch_text'].find('\n-') != -1:
                # find the real patch start line, usually is 7
                lines = patch['patch_text'].split('\n')
                for line in lines:
                    if line.startswith('-') and not line.startswith('---'):
                        real_patch_start_line = lines.index(line)
                        break
            if not real_patch_start_line:
                raise ValueError(f'Cannot find real patch start line in {key}\n{patch["patch_text"]}')
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
    patch_end_line = patch[f'{version}_end_line']
    parsing_path = os.path.join(data_path, f'{target}-{commit}', f'{patch_file_path}_analysis.json')
    with open(parsing_path, 'r') as f:
        ast_nodes = json.load(f)
    for node in ast_nodes:
        if node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
            continue
        if node['extent']['start']['file'] == patch_file_path and node['extent']['start']['line'] <= (patch_start_line + patch_end_line)/2 <= node['extent']['end']['line']:
            # Found the function definition
            return node['signature'], node['extent']['start']['line'], node['extent']['end']['line']
    return None, 0, 0


def analyze_def_use_chain(bb1s, bb2s, cfg1, cfg2):
    compute_data_dependencies(cfg1)
    if cfg2:
        # Sometimes corresponding block does not exist
        compute_data_dependencies(cfg2)
    # Get all defs and uses variables in bb1s and bb2s
    bb1_defs = set()
    bb1_uses = set()
    for bb in bb1s:
        bb1_defs.update(getattr(bb, "defs", set()))
        bb1_uses.update(getattr(bb, "uses", set()))
    bb2_defs = set()
    bb2_uses = set()
    for bb in bb2s:
        bb2_defs.update(getattr(bb, "defs", set()))
        bb2_uses.update(getattr(bb, "uses", set()))
    # Now bb1_defs, bb1_uses, bb2_defs, bb2_uses contain all defs/uses in the respective block lists

    # Compare bb1_defs and bb2_defs, for variable in bb1_defs but not in bb2_defs, get the blocks that use it in cfg1
    unique_bb1_defs = bb1_defs - bb2_defs
    var_to_use_blocks_cfg1 = {}
    for var in unique_bb1_defs:
        blocks_using = []
        for block in cfg1.blocks.values():
            if var in getattr(block, "uses", set()):
                blocks_using.append(block)
        var_to_use_blocks_cfg1[var] = blocks_using
    # var_to_use_blocks_cfg1 now maps each unique variable to the list of blocks in cfg1 that use it

    # Compare bb1_uses and bb2_uses, for variable in bb2_uses but not in bb1_uses, find the definition block in cfg2
    unique_bb2_uses = bb2_uses - bb1_uses
    var_to_def_blocks_cfg2 = {}
    for var in unique_bb2_uses:
        def_blocks = []
        for block in cfg2.blocks.values():
            if var in getattr(block, "defs", set()):
                def_blocks.append(block)
        var_to_def_blocks_cfg2[var] = def_blocks
    # var_to_def_blocks_cfg2 now maps each unique variable to the list of blocks in cfg2 that define it
    return var_to_use_blocks_cfg1, var_to_def_blocks_cfg2


def get_file_path_pairs(diff_results):
    file_path_pairs = dict() # key: new file path; value: old file path
    for key, patch in diff_results.items():
        if patch['file_path_old'] != patch['file_path_new'] and patch['file_path_new'] != '/dev/null' and patch['file_path_old'] != '/dev/null':
            file_path_pairs[patch['file_path_new']] = patch['file_path_old']
    return file_path_pairs


def apply_and_test_patches(
    patch_pair_list,
    patches_without_context,
    diff_results,
    trace1,
    target_repo_path,
    commit,
    next_commit,
    target,
    sanitizer,
    bug_id,
    fuzzer,
    args,
    arch,
    file_path_pairs,
    data_path,
    bug_type,
    get_patched_traces,
    transitions,
    revert_and_trigger_set,
    revert_and_trigger_fail_set,
    depen_graph,
    ):
    signature_change_list = []
    patch_key_list = [key for keys in patch_pair_list for key in keys]
    patch_folder = os.path.abspath(os.path.join(current_file_path, '..', 'patch'))
    if not os.path.exists(patch_folder):
        os.makedirs(patch_folder, exist_ok=True)
    logger.info(f'Applying and testing {len(patch_pair_list)} {patch_pair_list}')
    
    patch_to_apply, function_declarations, recreated_functions = patch_patcher(diff_results, patch_key_list, depen_graph, commit['commit_id'], next_commit['commit_id'], target_repo_path, bug_id)
    update_function_mappings(recreated_functions, signature_change_list, commit['commit_id'], bug_id)
    patch_file_path = os.path.join(patch_folder, f"{bug_id}_{next_commit['commit_id']}_patches{len(get_patched_traces[bug_id]) if bug_id in get_patched_traces else ''}.diff")
    patch_key_list = list(set(patch_to_apply))
    add_patch_for_trace_funcs(diff_results, patch_key_list, trace1, recreated_functions, target_repo_path, commit['commit_id'], next_commit['commit_id'], target, bug_id)
    llvm_fuzzer_test_one_input_patch_update(diff_results, patch_key_list, recreated_functions, target_repo_path, commit['commit_id'], next_commit['commit_id'], target, bug_id, trace1)
    # Sort patch_key_list by new_start_line
    patch_key_list = sorted(patch_key_list, key=lambda key: diff_results[key]['new_start_line'], reverse=True)
    add_context(diff_results, patch_key_list, next_commit['commit_id'], target_repo_path)
    handle_file_change(diff_results, patch_key_list)
    with open(patch_file_path, 'w') as patch_file:
        for key in patch_key_list:
            patch = diff_results[key]   
            patch_file.write(patch['patch_text'])
            patch_file.write('\n\n')  # Add separator between patches
    
    con_to_add = dict() # key: file path, value: set of enum/macro locations (use key in dict to achieve ordered set)
    func_decl_to_add = dict() # key: file path, value: set of function declarations
    extra_patches = dict() # key: file path, value: patch; include patches for enum/macro/function declaration
    var_del_to_add = dict() # key: file path, value: set of variable declarations
    union_to_add = dict() # key: file path, value: set of union declarations
    type_def_to_add = dict() # key: file path, value: set of type definitions
    con_to_add_len = 0
    var_del_to_add_len = 0
    union_to_add_len = 0
    type_def_to_add_len = 0
    # build and test if it works, oss-fuzz version has been set in collect_trace_cmd
    error_log = 'undeclared identifier'
    count = 0
    while ('undeclared identifier' in error_log or 'undeclared function' in error_log or 
           'too few arguments to function call' in error_log or 'member named' or 'unknown type name'
           in error_log):
        count += 1
        if count > 10:
            break
        build_success, error_log = build_fuzzer(target, next_commit['commit_id'], sanitizer, bug_id, patch_file_path, fuzzer, args.build_csv, arch)
        if build_success:
            break
        with open('/home/user/oss-fuzz-for-select/tmp3', 'w') as f:
            f.write(error_log)
        undeclared_identifier, undeclared_functions, miss_member_structs, function_sig_changes = handle_build_error(error_log)
        logger.info(f'undeclared_identifier: {undeclared_identifier}')
        logger.info(f'undeclared_functions: {undeclared_functions}')
        logger.info(f'miss_member_structs: {miss_member_structs}')
        miss_decls = []
        for identifier, location in undeclared_identifier:
            file_path_new = location.split('/',3)[-1].split(':')[0]
            if file_path_new in file_path_pairs:
                file_path_old = file_path_pairs[file_path_new]
            else:
                file_path_old = file_path_new
            if identifier.startswith(f'__revert_{commit["commit_id"]}_{bug_id.replace('-', '_')}_'):
                # Assign a recreated function to a function pointer
                undeclared_functions.append((identifier, location))
                continue
            parsing_path = os.path.join(data_path, f'{target}-{commit['commit_id']}', f'{file_path_old}_analysis.json')
            if os.path.exists(parsing_path):
                with open(parsing_path, 'r') as f:
                    ast_nodes = json.load(f)
                found = False
                for ast_node in ast_nodes:
                    if ast_node['kind'] in {'ENUM_CONSTANT_DECL'} and ast_node['spelling'] == identifier:
                        found = True
                        con_to_add.setdefault(file_path_new, dict())[f'__revert_cons_{commit["commit_id"]}_{bug_id.replace('-', '_')}_{next_commit["commit_id"]}_{ast_node['spelling']} = {ast_node['enum_value']},\n'] = identifier
                        # Change the name where use this enum
                        for key in patch_key_list:
                            patch = diff_results[key]
                            if patch['file_path_new'] == file_path_new:
                                patch['patch_text'] = '\n'.join(rename_func(patch['patch_text'], identifier, None, None, f'__revert_cons_{commit["commit_id"]}_{bug_id.replace('-', '_')}_{next_commit["commit_id"]}_{ast_node["spelling"]}'))
                        break
                    if ast_node['kind'] in {'MACRO_DEFINITION'} and ast_node['spelling'] == identifier:
                        found = True
                        if '#include' in ast_node['extent']['start']['file']:
                            # macro defined in header file from system include paths
                            var_del_to_add.setdefault(file_path_new, dict())[f'{ast_node['extent']['start']['file']}:{ast_node['extent']['start']['line']}:{ast_node['extent']['end']['line']}'] = None
                        else:
                            # macro defined in .h file in the target repo
                            var_del_to_add.setdefault(file_path_new, dict())[f'#include "{ast_node['extent']['start']['file'].split('/')[-1]}":{ast_node['extent']['start']['line']}:{ast_node['extent']['end']['line']}'] = None
                        break
                    if ast_node['kind'] in {'DECL_REF_EXPR'} and ast_node['spelling'] == identifier:
                        found = True
                        miss_decls.append((ast_node['spelling'], location.split(':')[0], int(location.split(':')[1])))
                        break
                    if ast_node['kind'] in {'UNION_DECL', 'ENUM_DECL'} and ast_node['spelling'] == identifier:
                        # typedef union{...}...; typedef enum{...}...;
                        found = True
                        union_to_add.setdefault(file_path_new, dict())[f'{ast_node['extent']['start']['file']}:{ast_node['extent']['start']['line']}:{ast_node['extent']['end']['line']}'] = identifier
                        break
                    if ast_node['kind'] in {'TYPEDEF_DECL'} and ast_node['spelling'] == identifier:
                        found = True
                        type_def_to_add.setdefault(file_path_new, dict())[f'{ast_node['extent']['start']['file']}:{ast_node['extent']['start']['line']}:{ast_node['extent']['end']['line']}'] = identifier
                        break
                if not found:
                    logger.info(f'Cannot find {identifier} in {parsing_path}')
                    exit(0)
            else:
                logger.error(f'Cannot find {identifier} in parsing_path: {parsing_path}!')

        for func_name, location in undeclared_functions:
            file_path = location.split(':')[0]
            line_num_after_patch = int(location.split(':')[1])
            relative_file_path = file_path.split('/', 3)[-1]
            if not func_name.startswith(f'__revert_{commit["commit_id"]}_{bug_id.replace('-', '_')}_'):
                # if the function is not a reverted function, means function name change here. (And it is not in the bug trace)
                # So compiler cannot find the function, we need to call this function in the newer way, keep that basic block new version.
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
                
                with open(os.path.join(data_path, f'cfg-{target}-{commit['commit_id']}-{relative_file_path.replace('/', '-')}.txt'), 'r') as cfg_file:
                    cfgs1 = parse_cfg_text(cfg_file.read())
                with open(os.path.join(data_path, f'cfg-{target}-{next_commit['commit_id']}-{relative_file_path.replace('/', '-')}.txt'), 'r') as cfg_file:
                    cfgs2 = parse_cfg_text(cfg_file.read())
                # line_num after patch -> line number before patch -> 
                # find block start and end line in bug version -> get the part in patch need to be removed
                line_num = get_correct_line_num(relative_file_path, line_num_after_patch, patch_key_list, diff_results, extra_patches)
                if not check_if_in_fuzzer(line_num, cfgs2):
                    # Treat as a signature/name change at call site; feed into process_function_signature_changes
                    function_sig_changes.append(("", "undeclared_function", file_path, (line_num_after_patch, line_num_after_patch)))
                    continue
                _, bb2s = find_block_by_line(cfgs2, file_path.split('/')[-1], [line_num])
                if not bb2s:
                    logger.info(f'No basic block2 found for {file_path}:{line_num} in {next_commit['commit_id']}')
                    continue
                
                for key in patch_key_list:
                    patch = diff_results[key]
                    new_start = int(patch['patch_text'].split('@@')[1].strip().split('+')[1].split(',')[0])
                    new_offset = int(patch['patch_text'].split('@@')[1].strip().split(',')[-1])
                    if patch['file_path_new'] == relative_file_path and new_start <= bb2s[0].end_line and bb2s[0].start_line < new_start + new_offset:
                        __keep_bb_in_patch(bb2s[0].start_line, bb2s[0].end_line, key, patch_key_list, diff_results)

            else:
                # Add declaration for the "__revert_commit_bug_id_*" function
                func_decl_line = dict()
                for func_decl in function_declarations:
                    if func_name == func_decl.split('(')[0].split(' ')[-1]:
                        old_line_num = get_old_line_num(relative_file_path, line_num_after_patch, patch_key_list, diff_results, extra_patches, target, commit['commit_id'])
                        func_decl_to_add.setdefault(relative_file_path, set()).add(f'{func_decl}')
                        if relative_file_path in func_decl_line:
                            func_decl_line[relative_file_path] = min(old_line_num, func_decl_line[relative_file_path])
                        else:
                            func_decl_line[relative_file_path] = old_line_num
                        break
        logger.info(f'function_sig_changes: {function_sig_changes}')
        new_patch_key_list, function_declarations, depen_graph = process_function_signature_changes(function_sig_changes, patch_key_list, diff_results, extra_patches, target, commit['commit_id'], next_commit['commit_id'], target_repo_path, function_declarations, file_path_pairs, depen_graph, bug_id)
        for key in new_patch_key_list:
            if key not in patch_key_list:
                patch_key_list.append(key)
        patch_key_list = sorted(patch_key_list, key=lambda key: diff_results[key]['new_start_line'], reverse=True)
        add_context(diff_results, patch_key_list, next_commit['commit_id'], target_repo_path)
        handle_file_change(diff_results, patch_key_list)
        
        if con_to_add_len == len(con_to_add) and var_del_to_add_len == len(var_del_to_add) and union_to_add_len == len(union_to_add) and type_def_to_add_len == len(type_def_to_add):
            # Solve other declarations and definitions first; Because they may lead to miss_decls here
            # Process miss_decls and miss_member_structs; replace them with corresponding block in new version
            bb_change_pair = process_undeclared_identifiers(miss_member_structs, miss_decls, patch_key_list, diff_results, extra_patches, target, next_commit, commit, target_repo_path, arch)

        path_set = set(con_to_add.keys()) | set(func_decl_to_add.keys()) | set(var_del_to_add.keys()) | set(union_to_add.keys())

        not_write_patches = set()
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
                
            if file_path in union_to_add:
                if file_path in con_to_add and union_to_add_len != len(union_to_add):
                    del con_to_add[file_path]
                # union patch
                locs = list(union_to_add[file_path])
                union_len = 0
                union_text = ''
                for log in reversed(locs):
                    path = log.split(':')[0]
                    start_line = int(log.split(':')[1])
                    end_line = int(log.split(':')[2])
                    union_len += end_line - start_line + 1
                    with open(os.path.join(target_repo_path, path), 'r') as f:
                        file_content = f.readlines()
                        union_text += ''.join(f'-{line}' for line in file_content[start_line-1:end_line])
            else:
                union_text = ''
                union_len = 0
            
            if file_path in con_to_add:
                # enum or macro patch
                locs = list(con_to_add[file_path])
                enum_len = 2
                enum_text = '-enum {\n'
                for log in reversed(locs):
                    enum_len += 1
                    enum_text += f'-{log}'
                enum_text += '-};\n'
            else:
                enum_text = ''
                enum_len = 0
            
            var_len = 0
            var_text = ''
            if file_path in var_del_to_add:
                # variable declaration patch
                locs = list(var_del_to_add[file_path])
                for log in reversed(locs):
                    path = log.split(':')[0]
                    if path.startswith('#include'):
                        # macro defined in header file from system include paths
                        include_file = path.split(' ')[1]
                        include_text += f'-{path}\n'
                        include_len += 1
                        continue
                    start_line = int(log.split(':')[1])
                    end_line = int(log.split(':')[2])
                    var_len += end_line - start_line + 1
                    with open(os.path.join(target_repo_path, path), 'r') as f:
                        file_content = f.readlines()
                        var_text += ''.join(f'-{line}' for line in file_content[start_line-1:end_line])
            
            if file_path in type_def_to_add:
                locs = list(type_def_to_add[file_path])
                for log in reversed(locs):
                    path = log.split(':')[0]
                    start_line = int(log.split(':')[1])
                    end_line = int(log.split(':')[2])
                    var_len += end_line - start_line + 1
                    with open(os.path.join(target_repo_path, path), 'r') as f:
                        file_content = f.readlines()
                        var_text += ''.join(f'-{line}' for line in file_content[start_line-1:end_line])

            # need new version to get the context lines
            if enum_len+include_len+func_decl_len+var_len+union_len == 0:
                # no enum or macro patch, skip this file
                continue
            os.chdir(target_repo_path)
            subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["git", "checkout", '-f', next_commit['commit_id']], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            insert_point = find_first_code_line(os.path.join(target_repo_path, file_path))
            context1, context2, start, end = get_line_context(os.path.join(target_repo_path, file_path), insert_point, context=3)
            merge_flag = 0
            
            for key_f in patch_key_list:
                patch_f = diff_results[key_f]
                if patch_f['file_path_new'] != file_path:
                    continue
                lines = patch_f['patch_text'].split('\n')
                new_start_f = int(lines[3].strip().split('@@')[-2].strip().split('+')[1].split(',')[0])
                new_offset_f = int(lines[3].strip().split('@@')[-2].strip().split('+')[1].split(',')[1])
                old_start_f = int(lines[3].strip().split('@@')[-2].strip().split(',')[-1])
                old_offset_f = int(lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
                if end >= new_start_f:
                    # There is overlap, merge them
                    merge_flag = 1
                    gap_len = (new_start_f + 3) - (end - 3) - 1
                    _, gap_text, _, _ = get_line_context(os.path.join(target_repo_path, file_path), insert_point, context=gap_len)
                    f_text = patch_f['patch_text'].split('\n', 7)[-1] # Remove the patch header and the front context
                    patch_header += f'@@ -{start},{enum_len+include_len+func_decl_len+var_len+union_len+insert_point-start+gap_len+old_offset_f-3} +{start},{insert_point-start+gap_len+new_offset_f-3} @@\n'
                    patch = {
                        'file_path_old': file_path,
                        'file_path_new': file_path,
                        'patch_text': patch_header + context1 + include_text + var_text + enum_text + func_decl_text + union_text + gap_text + f_text,
                        'new_start_line': start,
                        'new_end_line': patch_f['new_end_line'],
                        'old_start_line': start,
                        'old_end_line': start+enum_len+include_len+func_decl_len+var_len+union_len+insert_point-start+1+gap_len+old_offset_f-3-1,
                        'old_signature': patch_f['old_signature'],
                        'new_signature': patch_f['new_signature'],
                        'patch_type': {'Enum or macro change', 'Function declaration change'},
                        'extra_length': enum_len+include_len+func_decl_len+var_len+union_len,
                    }
                    not_write_patches.add(key_f)
                    break
                
            if not merge_flag:
                patch_header += f'@@ -{start},{enum_len+include_len+func_decl_len+var_len+union_len+end-start+1} +{start},{end-start+1} @@\n'
                patch = {
                    'file_path_old': file_path,
                    'file_path_new': file_path,
                    'patch_text': patch_header + context1 + include_text + var_text + enum_text + func_decl_text + union_text + context2,
                    'new_start_line': start,
                    'new_end_line': end,
                    'old_start_line': start,
                    'old_end_line': enum_len+include_len+func_decl_len+var_len+union_len+end,
                    'old_signature': '',
                    'new_signature': '',
                    'patch_type': {'Enum or macro change', 'Function declaration change'},
                    'extra_length': enum_len+include_len+func_decl_len+var_len+union_len,
                }
            extra_patches[file_path] = patch
            
        with open(patch_file_path, 'w') as patch_file:
            for key in patch_key_list:
                # not_write_patches means the patch is merged with the extra patches
                patch = diff_results[key]
                patches_without_context.update({key: patch})
                if key in not_write_patches:
                    continue
                patch_file.write(patch['patch_text'])
                patch_file.write('\n\n')
            for patch in extra_patches.values():
                patch_file.write(patch['patch_text'])
                patch_file.write('\n\n')
                patches_without_context[f'_extra_{patch['file_path_new']}'] = patch
        # update length of con_to_add, var_del_to_add, union_to_add
        con_to_add_len = len(con_to_add)
        var_del_to_add_len = len(var_del_to_add)
        union_to_add_len = len(union_to_add)
        type_def_to_add_len = len(type_def_to_add)
        
    testcases_env = os.getenv('TESTCASES', '')
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
            if test_fuzzer_build(target, sanitizer, arch):
                logger.info(f"Fuzzer build success after applying patch for bug {bug_id} on commit {next_commit['commit_id']}\n")
                return 'trigger_and_fuzzer_build'
            else:
                logger.info(f"Fuzzer build fail after applying patch for bug {bug_id} on commit {next_commit['commit_id']}\n")
                return 'trigger_but_fuzzer_build_fail'
        else:
            revert_and_trigger_fail_set.add((bug_id, next_commit['commit_id'], fuzzer))
            get_patched_traces.setdefault(bug_id, []).append(patch_file_path)
            transitions.append((commit, next_commit, bug_id))
            logger.info(f"Bug {bug_id} not triggered with fuzzer {fuzzer} on commit {next_commit['commit_id']}\n")
            return 'not_trigger'
    else:
        logger.info(f"Build failed for bug {bug_id} on commit {next_commit['commit_id']}\n")
        return 'build_fail'


def revert_patch_test(args):
    csv_file_path = args.target_test_result
    bug_info_dataset = read_json_file(args.bug_info)
    checkout_latest_commit(ossfuzz_path)
    revert_and_trigger_set = set()
    patches_without_contexts = dict()
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
    previous_trace_func_list = []
    signature_change_list = []
    
    for commit, next_commit, bug_id in transitions:
        if bug_id not in {'OSV-2021-485'}:
            continue
        next_commit['commit_id'] = '83d00f2316e8c1dc9a2d5fa2c89de7d94f9ac00e'
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
        get_compile_commands(target, next_commit['commit_id'], sanitizer, bug_id, fuzzer, args.build_csv, arch)
        get_compile_commands(target, commit['commit_id'], sanitizer, bug_id, fuzzer, args.build_csv, arch)
        diff_results = analyze_diffindex(diffs, target_repo_path, next_commit['commit_id'], commit['commit_id'], target, signature_change_list)
        file_path_pairs = get_file_path_pairs(diff_results)

        trace_func_list = []
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
                trace_func_list.append((func_dict[func], func_loc))
            else:
                trace_func_list.append((func.split(' ')[0], func_loc))
                
        logger.info(f"Trace function set: {len(trace_func_list)} {trace_func_list}")
        if not trace_func_list:
            logger.info(f'No function signatures found in trace for bug {bug_id}\n')
            continue

        if previous_bug == bug_id and previous_trace_func_list == trace_func_list:
            # Try to add trace funcs for this bug fail
            logger.info(f"Skipping bug {bug_id} as it has the same trace functions as the previous bug")
            continue
        previous_trace_func_list = trace_func_list
        previous_bug = bug_id

        # checkout target repo to the new commit, get function signature from source code using code location
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', next_commit['commit_id']], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        patch_to_apply = []
        for key, diff_result in diff_results.items():
            patch_func_new = ''
            patch_func_old = ''
            patch_file_path = ''
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
            for trace_func, func_loc in trace_func_list:
                if patch_file_path in func_loc and (trace_func == patch_func_old or trace_func == patch_func_new):
                    if 'old_signature' not in diff_result:
                        diff_result['old_signature'], diff_result['old_function_start_line'], diff_result['old_function_end_line'] = get_full_funsig(diff_result, target, commit['commit_id'], 'old')
                    if 'new_signature' not in diff_result:
                        diff_result['new_signature'], _, _ = get_full_funsig(diff_result, target, next_commit['commit_id'], 'new')
                    patch_to_apply.append(key)
                    break

        depen_graph, patch_to_apply = build_dependency_graph(diff_results, patch_to_apply, target_repo_path, commit['commit_id'], trace1)

        context = (diff_results, trace1, target_repo_path, commit, next_commit, target,
            sanitizer, bug_id, fuzzer, args, arch, file_path_pairs, data_path, bug_type,
            get_patched_traces, transitions, revert_and_trigger_set, revert_and_trigger_fail_set,
            depen_graph,)
        patch_by_func = dict()
        for key in patch_to_apply:
            if 'new_signature' in diff_results[key]:
                patch_by_func.setdefault(diff_results[key]['new_signature'], []).append(key)
            else:
                patch_by_func.setdefault(diff_results[key]['old_signature'], []).append(key)
        patch_pair_list = [tuple(v) for v in patch_by_func.values()]
        if bug_id == 'OSV-2021-485':
            minimal_fast = [('blosc/frame.cblosc/frame.c-2021,18+2298,27', 'blosc/frame.cblosc/frame.c-1977,17+2252,19', 'blosc/frame.cblosc/frame.c-1950,21+2197,49', 'blosc/frame.cblosc/frame.c-1877,62+2110,76'), ('blosc/schunk.cblosc/schunk.c-446,8+558,14',), ('blosc/frame.cblosc/frame.c-1659,15+1849,30', 'blosc/frame.cblosc/frame.c-1646,3+1837,2', 'blosc/frame.cblosc/frame.c-1572,67+1753,77', 'blosc/frame.cblosc/frame.c-1553,4+1734,4', 'blosc/frame.cblosc/frame.c-1538,7+1718,8', 'blosc/frame.cblosc/frame.c-1526,5+1707,4', 'blosc/frame.cblosc/frame.c-1497,18+1676,20'), ('blosc/frame.cblosc/frame.c-1428,19+1587,27', 'blosc/frame.cblosc/frame.c-1406,12+1564,13'), ('blosc/frame.cblosc/frame.c-1257,15+1408,23', 'blosc/frame.cblosc/frame.c-1243,5+1393,6')]
            # minimal_fast = [('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-50,2+46,2', 'tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-12,21+12,17'), ('blosc/schunk.cblosc/schunk.c-774,5+1067,6', 'blosc/schunk.cblosc/schunk.c-766,2+1059,2'), ('blosc/frame.cblosc/frame.c-2763,34+3458,34', 'blosc/frame.cblosc/frame.c-2753,2+3448,2'), ('blosc/frame.cblosc/frame.c-2021,18+2298,27', 'blosc/frame.cblosc/frame.c-1977,17+2252,19', 'blosc/frame.cblosc/frame.c-1950,21+2197,49', 'blosc/frame.cblosc/frame.c-1877,62+2110,76'), ('blosc/schunk.cblosc/schunk.c-446,8+558,14',), ('blosc/frame.cblosc/frame.c-1659,15+1849,30', 'blosc/frame.cblosc/frame.c-1646,3+1837,2', 'blosc/frame.cblosc/frame.c-1572,67+1753,77', 'blosc/frame.cblosc/frame.c-1553,4+1734,4', 'blosc/frame.cblosc/frame.c-1538,7+1718,8', 'blosc/frame.cblosc/frame.c-1526,5+1707,4', 'blosc/frame.cblosc/frame.c-1497,18+1676,20'), ('blosc/frame.cblosc/frame.c-1428,19+1587,27', 'blosc/frame.cblosc/frame.c-1406,12+1564,13'), ('blosc/frame.cblosc/frame.c-1257,15+1408,23', 'blosc/frame.cblosc/frame.c-1243,5+1393,6'), ('blosc/blosc2.cblosc/blosc2.c-2905,10+3371,10',), ('blosc/blosc2.cblosc/blosc2.c-3166,5+3626,14',)]
        if bug_id == 'OSV-2021-496':
            minimal_fast = [('blosc/frame.cblosc/frame.c-2037,7+2317,8', 'blosc/frame.cblosc/frame.c-1974,17+2252,19', 'blosc/frame.cblosc/frame.c-1947,21+2197,49', 'blosc/frame.cblosc/frame.c-1874,62+2110,76'), ('blosc/schunk.cblosc/schunk.c-461,8+558,14',), ('blosc/frame.cblosc/frame.c-1656,15+1849,30', 'blosc/frame.cblosc/frame.c-1643,3+1837,2', 'blosc/frame.cblosc/frame.c-1569,67+1753,77', 'blosc/frame.cblosc/frame.c-1550,4+1734,4', 'blosc/frame.cblosc/frame.c-1535,7+1718,8', 'blosc/frame.cblosc/frame.c-1523,5+1707,4', 'blosc/frame.cblosc/frame.c-1494,18+1676,20'), ('blosc/frame.cblosc/frame.c-1425,19+1587,27', 'blosc/frame.cblosc/frame.c-1403,12+1564,13'), ('blosc/frame.cblosc/frame.c-1254,15+1408,23', 'blosc/frame.cblosc/frame.c-1240,5+1393,6')]
        
        patches_without_context = dict()
        # tmp_context = copy.deepcopy(context)
        # if not apply_and_test_patches(patch_pair_list, dict(), *tmp_context):
        #     revert_and_trigger_fail_set.add((bug_id, next_commit['commit_id'], fuzzer))
        # else:
        #     revert_and_trigger_set.add((bug_id, next_commit['commit_id'], fuzzer))
        #     logger.info(f'Initial revert patch set: {len(patch_pair_list)} {patch_pair_list}')
        #     minimal_fast = minimize_greedy(patch_pair_list, apply_and_test_patches, dict(), context)
        #     logger.info(f'Minimal revert patch set after fast minimization: {len(minimal_fast)} {minimal_fast}')
        #     # make sure we have a correct minimal patch
        apply_and_test_patches(minimal_fast, patches_without_context, *context)

        patches_without_contexts[(bug_id, commit['commit_id'], fuzzer)] = patches_without_context

    logger.info(f"Revert and trigger set: {len(revert_and_trigger_set)} {revert_and_trigger_set}")
    logger.info(f"Revert and trigger fail set: {len(revert_and_trigger_fail_set)} {revert_and_trigger_fail_set}")
    
    return patches_without_contexts


def merge_patches(args, patches_without_contexts: Dict[Tuple, Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Merge patches that come from different bugs
    harness_patches = dict()
    patches = dict()
    csv_file_path = args.target_test_result
    target = csv_file_path.split('/')[-1].split('.')[0]
    repo_path = os.getenv('REPO_PATH')
    target_repo_path = os.path.join(repo_path, target)
    target_commit_id = '83d00f2316e8c1dc9a2d5fa2c89de7d94f9ac00e'[:6]
    patch_folder = os.path.abspath(os.path.join(current_file_path, '..', 'patch'))
    patch_file_path = os.path.join(patch_folder, f"all_{target_commit_id}_patches.diff")

    for (bug_id, commit_id, fuzzer), patch_dict in patches_without_contexts.items():
        patches_for_one_harness = []
        for key, patch in patch_dict.items():
            if key.startswith('_extra_'):
                # auxiliary patches
                patches[f'{key}_{bug_id}_{commit_id}_{patch['file_path_new']}'] = patch
            elif 'new_signature' in patch and 'LLVMFuzzerTestOneInput' in patch['new_signature']:
                # harness function
                fun_sig, _, _ = get_full_funsig(patch, target, target_commit_id, 'new')
                patch['new_signature'] = fun_sig
                patches_for_one_harness.append(patch)
            else:
                # recreated functions
                patches[f'{key}_{bug_id}_{commit_id}_{patch['file_path_new']}'] = patch
        harness_patches.setdefault(fuzzer, []).append(patches_for_one_harness)

    key_list = list(patches.keys())
    delete_patch_context_single_hunk(patches, key_list)
    key_list = sorted(key_list, key=lambda key: patches[key]['new_start_line'], reverse=True)
    for k in key_list:
        patch = patches[k]
        # logger.info(f'k: {k}')
        # logger.info(f'patch: {patch['patch_text']}')
    add_context(patches, key_list, target_commit_id, target_repo_path)
    with open(patch_file_path, 'w') as f:
        for key in key_list:
            patch = patches[key]
            f.write(patch['patch_text'])
            f.write('\n\n')


def get_compile_commands(target, commit_id, sanitizer, bug_id, fuzzer, build_csv, arch):
    # use libclang to parse, and save results to files
    cmd = [
        py3, f"{current_file_path}/fuzz_helper.py", "build_version", "--commit", commit_id, "--sanitizer", sanitizer,
        '--build_csv', build_csv, '--compile_commands', '--architecture', arch , target
    ]
    
    if not os.path.exists(os.path.join(data_path, f'{target}-{commit_id}')):
        logger.info(' '.join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)


def save_patches_pickle(patches: Dict[str, Dict[str, Any]], path: str | Path) -> None:
    path = Path(path)
    logger.info(path)
    with gzip.open(path, "wb") if str(path).endswith(".gz") else open(path, "wb") as f:
        pickle.dump(patches, f, protocol=pickle.HIGHEST_PROTOCOL)


def load_patches_pickle(path: str | Path) -> Dict[str, Dict[str, Any]]:
    path = Path(path)
    with gzip.open(path, "rb") if str(path).endswith(".gz") else open(path, "rb") as f:
        return pickle.load(f)


if __name__ == "__main__":
    args = parse_arguments()
    patches_without_contexts = revert_patch_test(args)
    # Use absolute path for the cache file
    cache_file = os.path.join(current_file_path, "patches.pkl.gz")
    
    # Save the patches to cache file
    save_patches_pickle(patches_without_contexts, cache_file)
    
    # Load the patches from cache file (only if it exists)
    if os.path.exists(cache_file):
        patches_without_contexts = load_patches_pickle(cache_file)
    else:
        logger.warning(f"Cache file {cache_file} not found, using original data")
    merge_patches(args, patches_without_contexts)