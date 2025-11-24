import re
import argparse
import subprocess
import json
import os
import tempfile
from git import Repo, GitCommandError
import logging
from pathlib import Path
import gzip
import pickle
import copy
import sys
import hashlib
from collections import defaultdict
from typing import List, Dict, Set, Tuple, Any, Optional
from dataclasses import dataclass, field

from buildAndtest import checkout_latest_commit
from run_fuzz_test import read_json_file, py3
from compare_trace import extract_function_calls
from compare_trace import compare_traces
from cfg_parser import CFGBlock, parse_cfg_text, find_block_by_line, compute_data_dependencies
from monitor_crash import (
    extract_function_stack,
    build_stack_patterns,
    _stack_matches_patterns,
    _clean_function_name,
)
from utils import (
    minimize_greedy,
    minimize_func_list_greedy,
    apply_unified_diff_to_string,
    split_function_parts,
    diff_strings,
    save_patches_pickle,
    load_patches_pickle,
)
from fuzzer_correct_test import test_fuzzer_build
from gumtree import get_corresponding_lines, get_delete_lines

HERE = os.path.dirname(__file__)               # script/
OPENAI_DIR = os.path.join(HERE, "openai")     # script/openai
sys.path.insert(0, OPENAI_DIR)
from handle_struct_use import solve_code_migration
from handle_func_sig_change import handle_func_sig_change, handle_renaming_patch_sig_change

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

current_file_path = os.path.dirname(os.path.abspath(__file__))
ossfuzz_path = os.path.abspath(os.path.join(current_file_path, '..', 'oss-fuzz'))
data_path = os.path.abspath(os.path.join(current_file_path, '..', 'data'))


@dataclass(frozen=True)
class FunctionLocation:
    """
    Represents the location of a function in source code.
    """
    file_path: str
    start_line: int
    end_line: int
    
    def __post_init__(self):
        """Validate that start_line <= end_line."""
        if self.start_line > self.end_line:
            raise ValueError(f"start_line ({self.start_line}) must be <= end_line ({self.end_line})")


@dataclass(frozen=True)
class FunctionInfo:
    """
    A hashable dataclass to store function metadata including signature, name, and special keywords.
    """
    name: str
    signature: str
    file_path_old: str
    func_used_file: str
    keywords: tuple[str, ...] = ()
    
    def __post_init__(self):
        """Ensure keywords is always a tuple (for immutability)."""
        if not isinstance(self.keywords, tuple):
            # Use object.__setattr__ because the dataclass is frozen
            object.__setattr__(self, 'keywords', tuple(self.keywords))
    
    def has_keyword(self, keyword: str) -> bool:
        """Check if a specific keyword is present."""
        return keyword in self.keywords
    
    def is_static(self) -> bool:
        """Check if function is static."""
        return 'static' in self.keywords
    
    def is_classmethod(self) -> bool:
        """Check if function is a classmethod."""
        return 'classmethod' in self.keywords
    
    def is_async(self) -> bool:
        """Check if function is async."""
        return 'async' in self.keywords


@dataclass
class PatchInfo:
    """
    Represents a single code patch, encapsulating its metadata and content.
    """
    # Core patch information
    file_path_old: str
    file_path_new: str
    patch_text: str
    file_type: str

    # Line number information for the patch hunk
    old_start_line: int
    old_end_line: int
    new_start_line: int
    new_end_line: int

    # Metadata about the patch content and type, initialized with a default
    patch_type: Set[str] = field(default_factory=set)

    # Optional: Information about the function this patch modifies
    old_signature: Optional[str] = None
    new_signature: Optional[str] = None
    old_function_start_line: Optional[int] = None
    old_function_end_line: Optional[int] = None
    new_function_start_line: Optional[int] = None
    new_function_end_line: Optional[int] = None

    # Optional: For dependency tracking and complex patch generation
    dependent_func: Set[str] = field(default_factory=set)
    hiden_func_dict: Dict[str, int] = field(default_factory=dict)
    # Stores original source locations for functions recreated in this patch
    # Maps function signature to FunctionLocation containing file_path, start_line, end_line
    recreated_function_locations: Dict[str, FunctionLocation] = field(default_factory=dict)

    def has_type(self, patch_type: str) -> bool:
        """Checks if the patch has a specific type."""
        return patch_type in self.patch_type

    @property
    def is_function_modification(self) -> bool:
        """Returns True if the patch modifies a function."""
        return bool(self.old_signature or self.new_signature)

    def _get_function_name_from_sig(self, signature: Optional[str]) -> Optional[str]:
        """Helper to extract function name from a signature string."""
        if not signature:
            return None
        try:
            # Extracts the last word before the first parenthesis, e.g., "int my_func(int)" -> "my_func"
            return signature.split('(')[0].split()[-1]
        except IndexError:
            return None

    @property
    def old_function_name(self) -> Optional[str]:
        """Returns the name of the function from the old signature."""
        return self._get_function_name_from_sig(self.old_signature)

    @property
    def new_function_name(self) -> Optional[str]:
        """Returns the name of the function from the new signature."""
        return self._get_function_name_from_sig(self.new_signature)

    @property
    def is_file_deletion(self) -> bool:
        """Returns True if the patch represents a file deletion."""
        return self.file_path_new == '/dev/null'

    @property
    def is_file_addition(self) -> bool:
        """Returns True if the patch represents a file addition."""
        return self.file_path_old == '/dev/null'

    def __str__(self) -> str:
        """Human-friendly representation used when printing the object."""
        patch_types = ", ".join(sorted(self.patch_type)) if self.patch_type else "none"
        dependent_funcs = ", ".join(sorted(self.dependent_func)) if self.dependent_func else "none"
        preview_lines = [line.strip() for line in self.patch_text.strip().splitlines() if line.strip()]
        if preview_lines:
            preview = preview_lines[0]
            if len(preview_lines) > 1:
                preview += " ..."
            if len(preview) > 80:
                preview = f"{preview[:77]}..."
        else:
            preview = "<empty>"
        return (
            "PatchInfo("
            f"{self.file_path_old} -> {self.file_path_new}, "
            f"type={self.file_type}, "
            f"old_lines={self.old_start_line}-{self.old_end_line}, "
            f"new_lines={self.new_start_line}-{self.new_end_line}, "
            f"patch_types={patch_types}, "
            f"dependent_funcs={dependent_funcs}, "
            f"old_sig={self.old_signature}, "
            f"new_sig={self.new_signature}, "
            f"preview='{preview}'"
            ")"
        )


def stable_hash(s: str) -> int:
    # Convert the string to bytes
    data = s.encode('utf-8')
    # Use SHA-256 to generate a deterministic hash
    digest = hashlib.sha256(data).hexdigest()
    # Optionally, convert part of it to an integer
    return int(digest, 16) % (10 ** 12)  # shorter integer form


def is_function_static(source_code: str) -> bool:
    # source_code should be a c function source code
    for line in source_code.split('\n'):
        if 'static ' in line:
            return True
        if '{' in line:
            return False


def rename_func(patch_text, fname, commit, replacement_string=None):
    logger.debug(f'Renaming function {fname}')
    modified_lines = []
    regex = r'(?<![\w.])' + re.escape(fname) + r'(?!\w)'
    if not replacement_string:
        replacement_string = f"__revert_{commit}_{fname}"

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
    with open(parsing_path, 'r') as f:
        ast_nodes = json.load(f)
    for ast_node in ast_nodes:
        if ast_node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
            continue
        # Use compare_function_signatures here because signature may have const keyword and can't match
        if ast_node['extent']['start']['file'] == file_path and compare_function_signatures(ast_node['signature'], func_sig, True):
            with open(os.path.join(target_repo_path, file_path), 'r', encoding="latin-1") as f:
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


def handle_func_deled(func_deled, patch_key_list, diff_results, extra_patches, target, commit, next_commit, target_repo_path, function_declarations, file_path_pairs, depen_graph: dict, type_def_to_add: dict, recreated_functions, func_list):
    # Recreate the callee function, change the callsite
    new_patch_key_list = set()
    tail_fun_info_list = []
    for func_name, file_path, line_range in func_deled:
        def_file_path = None
        file_path_new = file_path.split('/', 3)[-1]
        if file_path_new in file_path_pairs:
            file_path_old = file_path_pairs[file_path_new]
        else:
            file_path_old = file_path_new
        
        key_of_error_patch, caller_sig, func_start_index, func_end_index = get_error_patch(file_path_new, line_range[0], patch_key_list, diff_results, extra_patches)
        
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
        # 1 get caller and callee
        if not func_start_index:
            # not inside a recreated function, in harness function, get caller_loc here
            for node in ast_nodes:
                if node['kind'] in def_kinds and file_path_old == node['location']['file'] and node['signature'] == caller_sig:
                    caller_loc = FunctionLocation(
                        file_path=file_path_old,
                        start_line=node['extent']['start']['line'],
                        end_line=node['extent']['end']['line'],
                    )
                    break
        else:
            caller_loc = diff_results[key_of_error_patch].recreated_function_locations[caller_sig]

        parsing_path = os.path.join(
            data_path,
            f"{target_repo_path.split('/')[-1]}-{commit}",
            f"{caller_loc.file_path}_analysis.json",
        )
        with open(parsing_path, 'r') as f:
            ast_nodes = json.load(f)
        for node in ast_nodes:
            if node['spelling'] == func_name and \
                node['kind'] in call_kinds and 'callee' in node and\
                node['location']['file'] == caller_loc.file_path and\
                caller_loc.start_line <= node['location']['line'] <= caller_loc.end_line:
                callee_sig = node['callee']['signature']
                break
        if not callee_sig:
            logger.info(f'No callee sig found for {parsing_path}: {func_name} {caller_loc}')
        fname = callee_sig.split('(')[0].split(' ')[-1]
        for node in ast_nodes:
            if (node.get('kind') in decl_kinds or node.get('kind') in def_kinds) and node['spelling'] == fname:
                def_file_path = node['location']['file'].replace('.h', '.c')
                if not os.path.exists(os.path.join(data_path, f'{target_repo_path.split('/')[-1]}-{commit}', f'{def_file_path}_analysis.json')):
                    def_file_path = node['location']['file']
        def_file_path_new = def_file_path_old = def_file_path
        for file_path_new_, file_path_old_ in file_path_pairs.items():
            if file_path_old_ == def_file_path:
                def_file_path_new = file_path_new_

        if callee_sig and caller_sig:
            if callee_sig in func_list:
                callee_commit = next_commit
            else:
                callee_commit = commit
            function_declarations.add(callee_sig.replace(fname, f'__revert_{callee_commit}_{fname}'))
            func_code, func_length, start_line = get_function_code_from_old_commit(target_repo_path, callee_commit, data_path, def_file_path_old, callee_sig)
            cur_fun_info = FunctionInfo(name=fname, signature=callee_sig, file_path_old=def_file_path_old, func_used_file=file_path_new, keywords=['static'])
            if cur_fun_info in recreated_functions:
                continue
            else:
                recreated_functions.add(cur_fun_info)
            def_loc = FunctionLocation(file_path=def_file_path_old, start_line=start_line, end_line=start_line + func_length - 1)
            if not func_code:
                logger.error(f'No func code found for {def_file_path_old}: {callee_sig}')
                for recreate_func, recreate_func_loc in diff_results[key_of_error_patch].recreated_function_locations.items():
                    func_code, func_length, start_line = get_function_code_by_line(target_repo_path, callee_commit, data_path, recreate_func_loc.file_path, recreate_func_loc.start_line)
                    if func_code:
                        logger.info(f'Found func code for {def_file_path_old}: {callee_sig} in recreated function {recreate_func} at {recreate_func_loc}')
                        break
            func_code = '\n'.join([f'-{line}' for line in func_code.split('\n')][:-1]) + '\n'  # Add a \n at the end to avoid patch fail

            if file_path_new == def_file_path_new:
                callee_sig_new = get_new_funcsig(fname, next_commit, def_file_path_new, target_repo_path)
            if file_path_new != def_file_path_new or not callee_sig_new:
                # Function change name, so insert at an abbitray point
                os.chdir(target_repo_path)
                subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["git", "checkout", '-f', next_commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                with open(os.path.join(target_repo_path, file_path_new), 'r', encoding="latin-1") as f:
                    lines = f.readlines()
                artificial_patch_insert_point = len(lines)+1

                func_code = '\n'.join(rename_func(func_code, fname, commit))
                tail_fun_info_list.append((func_code, artificial_patch_insert_point, func_length, def_file_path_old, file_path_old, file_path_new, caller_sig, callee_sig, def_loc))
            else:
                artificial_patch_insert_point = get_patch_insert_line_number(target_repo_path, next_commit, data_path, def_file_path_new, callee_sig_new)
                # Create the Artificial patch here
                patch_header = f'diff --git a/{def_file_path_new} b/{def_file_path_new}\n--- a/{def_file_path_new}\n+++ b/{def_file_path_new}\n'
                patch_header += f'@@ -{artificial_patch_insert_point},{func_length} +{artificial_patch_insert_point},0 @@\n'
                artificial_patch = PatchInfo(
                    file_path_old=def_file_path_old,
                    file_path_new=def_file_path_new,
                    file_type='c',
                    patch_text='\n'.join(rename_func(patch_header + func_code, fname, commit)),
                    old_signature=callee_sig, # __revert_{commit}_{fname} is not added here
                    patch_type={'Function removed', 'Function body change', 'Recreated function'},
                    dependent_func=set(),
                    new_start_line=artificial_patch_insert_point,
                    new_end_line=artificial_patch_insert_point,
                    old_start_line=artificial_patch_insert_point,
                    old_end_line=artificial_patch_insert_point + func_length,
                    recreated_function_locations={callee_sig: FunctionLocation(file_path=def_file_path_old, start_line=start_line, end_line=start_line + func_length - 1)},
                )
                new_key = f'{def_file_path_old}{def_file_path_new}-{artificial_patch_insert_point},{func_length}+{artificial_patch_insert_point},0'
                artificial_patch.patch_type.add('Static Function')
                diff_results[new_key] = artificial_patch
                new_patch_key_list.add(new_key)
                # change the callsite, update depen_graph
                for key in patch_key_list:
                    patch = diff_results[key]
                    if patch.file_path_old != def_file_path_old:
                        continue
                    if patch.old_signature and patch.old_signature == caller_sig:
                        depen_graph.setdefault(new_key, set()).add(key)
                        modified_lines = rename_func(diff_results[key].patch_text, fname, commit)
                        diff_results[key].patch_text = '\n'.join(modified_lines)
        else:
            logger.error(f"-{file_path_old}+{file_path_new}: {line_range} cannot find caller or callee in parsing files.")
            
    if len(tail_fun_info_list) > 0:
        tail_code = dict() 
        tail_code_len = dict()
        tail_insert_point = dict()
        tail_file_path_new = dict()
        tail_details = dict()
        tail_hiden_func_dict = dict()
        tail_recreated_function_locations = dict()
        func_names = dict()
        for func_code, insert_point, func_length, def_file_path_old, file_path_old, file_path_new, caller_sig, callee_sig, def_loc in tail_fun_info_list:
            tail_hiden_func_dict.setdefault(file_path_old, dict())[callee_sig] = tail_code.get(file_path_old, '').count('\n')
            tail_code[file_path_old] = tail_code.get(file_path_old, '') + func_code + '\n'
            tail_code_len[file_path_old] = tail_code_len.get(file_path_old, 0) + func_length
            tail_insert_point[file_path_old] = insert_point
            tail_file_path_new[file_path_old] = file_path_new
            tail_recreated_function_locations.setdefault(file_path_old, dict())[callee_sig] = def_loc
            tail_details.setdefault(file_path_old, set()).add((caller_sig, callee_sig))
            func_names[file_path_old] = func_names.setdefault(file_path_old, '') + f'{callee_sig.split("(")[0].split(" ")[-1]}_'

        for file_path_old in tail_code:
            insert_point = tail_insert_point[file_path_old]
            file_path_new = tail_file_path_new[file_path_old]
            tail_key = f'tail-{file_path_new}-{func_names[file_path_old]}'
            patch_header = f'diff --git a/{file_path_new} b/{file_path_new}\n--- a/{file_path_new}\n+++ b/{file_path_new}\n'
            patch_header += f'@@ -{insert_point},{tail_code_len[file_path_old]} +{insert_point},0 @@\n'
            diff_results[tail_key] = PatchInfo(
                file_path_old=file_path_old,
                file_path_new=file_path_new,
                file_type='c',
                patch_text=patch_header + tail_code[file_path_old],
                old_signature=list(tail_hiden_func_dict[file_path_old].keys())[0],
                patch_type={'Function removed', 'Function body change', 'Recreated function', 'Tail function'},
                dependent_func=set(),
                new_start_line=insert_point,
                new_end_line=insert_point,
                old_start_line=insert_point,
                old_end_line=insert_point + tail_code_len[file_path_old],
                hiden_func_dict=tail_hiden_func_dict[file_path_old],
                recreated_function_locations=tail_recreated_function_locations[file_path_old],
            )
            new_patch_key_list.add(tail_key)
            # change the callsite, update depen_graph
            for caller_sig, callee_sig in tail_details[file_path_old]:
                fname = callee_sig.split('(')[0].split(' ')[-1]
                for key in patch_key_list:
                    patch = diff_results[key]
                    if file_path_new != patch.file_path_new:
                        continue
                    if patch.old_signature and patch.old_signature == caller_sig:
                        depen_graph.setdefault(tail_key, set()).add(key)
                        modified_lines = rename_func(diff_results[key].patch_text, fname, commit)
                        diff_results[key].patch_text = '\n'.join(modified_lines)
            
    return new_patch_key_list, function_declarations, depen_graph, type_def_to_add


def process_undeclared_identifiers(miss_member_structs, miss_decls, last_round, final_patches, diff_results, extra_patches, target, next_commit, commit, target_repo_path, arch, signature_change_list):
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
    
    diff_results_last_round, final_patches_last_round, extra_patches_last_round = last_round
    
    for field_name, struct_name, file_path, line_num in miss_member_structs:
        bb1s, bb2s, cfg1, cfg2 = get_bb_change_pair_from_line(file_path, [line_num], final_patches_last_round, diff_results_last_round, extra_patches_last_round, target, next_commit['commit_id'], commit['commit_id'], arch, args.build_csv, target_repo_path, signature_change_list)
        relative_file_path = file_path.split('/', 3)[-1]
        bb_change_pair.setdefault(relative_file_path, []).append((bb1s, bb2s, cfg1, cfg2))
        
    for identifier, file_path, line_num in miss_decls:
        bb1s, bb2s, cfg1, cfg2 = get_bb_change_pair_from_line(file_path, [line_num], final_patches_last_round, diff_results_last_round, extra_patches_last_round, target, next_commit['commit_id'], commit['commit_id'], arch, args.build_csv, target_repo_path, signature_change_list)
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
                if not bb_to_update_incfg1:
                    pseudo_bb1 = CFGBlock(-1) # Create an empty block, suggest should 
                    pseudo_bb1.start_line = bb1_start_line
                    pseudo_bb1.end_line = bb1_start_line-1
                    bb_to_update_incfg1 = [pseudo_bb1]
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
            if bb1_start_line > bb1_end_line:
                # When bb1s is the pseudo block, means we are going to insert a block. We want a larger syntactic construct
                # (like the body of an if)
                # TODO: relative_file_path is not accurate here
                delete_lines = get_delete_lines(target_repo_path, relative_file_path, next_commit['commit_id'], relative_file_path, commit['commit_id'], bb2_start_line, bb2_end_line)
                for line1, line2 in delete_lines:
                    bb2_start_line = min(bb2_start_line, line1)
                    bb2_end_line = max(bb2_end_line, line2)
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
    parser.add_argument('--target', required=True,
                        help='target project name')
    parser.add_argument('--bug_id', 
                        help='Optional: specific bug ID to process')
    parser.add_argument('--buggy_commit', 
                        help='Optional: specific buggy commit to process')
    
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
                'poc_count': 0
            }
            
            # Process all OSV columns (skipping first and last columns)
            for i in range(1, len(headers)):
                bug_id = headers[i]
                row['osv_statuses'][bug_id] = values[i] if values[i] else None
                if values[i] and values[i] == '1|1':
                    row['poc_count'] += 1
            
            data.append(row)
    
    return data


def select_crash_test_input(bug_id: str, testcases_dir: str) -> str:
    """Return preferred testcase filename for crash collection."""
    base_name = f'testcase-{bug_id}'
    if not testcases_dir:
        return base_name
    original_candidate = f'{base_name}-original'
    original_path = os.path.join(testcases_dir, original_candidate)
    if os.path.exists(original_path):
        return original_candidate
    return base_name


def get_crash_stack(
    bug_id: str,
    commit_id: str,
    crash_test_input: str,
    sanitizer: str,
    build_csv: str,
    arch: str,
    testcases_env: str,
    target: str,
    fuzzer: str,
) -> str:
    """
    Ensure the crash log for the given commit/input exists, invoking the helper script if needed.
    Returns the path to the crash log (exists or best-effort generated).
    """
    crash_dir = os.path.join(data_path, 'crash')
    os.makedirs(crash_dir, exist_ok=True)
    crash_log_path = os.path.join(
        crash_dir,
        f'target_crash-{commit_id[:6]}-{crash_test_input}.txt',
    )
    if os.path.exists(crash_log_path):
        return crash_log_path

    collect_crash_cmd = [
        py3,
        f'{current_file_path}/fuzz_helper.py',
        'collect_crash',
        '--commit',
        commit_id,
        '--sanitizer',
        sanitizer,
        '--build_csv',
        build_csv,
        '--architecture',
        arch,
        '--testcases',
        testcases_env,
        '--test_input',
        crash_test_input,
        target,
        fuzzer,
    ]
    logger.info(
        "Collecting crash log for bug %s using input %s: %s",
        bug_id,
        crash_test_input,
        " ".join(collect_crash_cmd),
    )
    try:
        subprocess.run(
            collect_crash_cmd,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as e:
        logger.info("Collect crash command failed with exit code %s", e.returncode)
    return crash_log_path


def crashes_match(test_output: str, baseline_path: str, signature_file: Optional[str]) -> bool:
    """Compare crash logs using stack traces and optional signature mapping."""
    if not os.path.exists(baseline_path):
        logger.warning("Baseline crash log %s not found; skipping comparison.", baseline_path)
        return True
    signature_arg = signature_file if signature_file and os.path.exists(signature_file) else None
    try:
        baseline_stack, signature_map = extract_function_stack(
            baseline_path,
            signature_file=signature_arg,
            apply_signatures=False,
            return_signature_map=True,
        )
    except Exception:
        logger.exception("Failed to parse baseline crash log %s", baseline_path)
        return True
    if not baseline_stack:
        logger.warning("Baseline crash stack empty for %s; skipping comparison.", baseline_path)
        return True

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
            tmp.write(test_output.encode('utf-8', errors='ignore'))
            tmp_path = tmp.name
        current_stack = extract_function_stack(
            tmp_path,
            signature_file=signature_arg,
            apply_signatures=False,
        )
    except Exception:
        logger.exception("Failed to parse reproduced crash output.")
        return False
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)

    signature_map = signature_map or {}
    alias_adj: Dict[str, Set[str]] = defaultdict(set)
    for base, mapped_list in signature_map.items():
        base_clean = _clean_function_name(base)
        alias_adj[base_clean].add(base_clean)
        for mapped in mapped_list:
            mapped_clean = _clean_function_name(mapped)
            alias_adj[base_clean].add(mapped_clean)
            alias_adj[mapped_clean].add(mapped_clean)
            alias_adj[mapped_clean].add(base_clean)

    def resolve_aliases(name: str) -> Set[str]:
        clean = _clean_function_name(name)
        visited: Set[str] = set()
        stack = [clean]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            stack.extend(alias_adj.get(current, []))
        if not visited:
            visited.add(clean)
        return visited

    baseline_clean = [_clean_function_name(func) for func in baseline_stack]
    current_clean = [_clean_function_name(func) for func in current_stack]

    if not baseline_clean or not current_clean:
        logger.info(
            "Crash stack missing frames (baseline %d, current %d). Treating as mismatch.\nBaseline: %s\nCurrent: %s",
            len(baseline_clean),
            len(current_clean),
            baseline_stack,
            current_stack,
        )
        return False

    def frames_match(base_frame: str, current_frame: str) -> bool:
        allowed = resolve_aliases(base_frame)
        if current_frame in allowed:
            return True
        reverse_allowed = resolve_aliases(current_frame)
        return base_frame in reverse_allowed

    logger.info(f'signature_map: {signature_map}')
    top_match = frames_match(baseline_clean[0], current_clean[0])
    if not top_match:
        logger.info(
            "Crash stack top frame mismatch: baseline '%s' vs current '%s'.\nBaseline: %s\nCurrent: %s",
            baseline_clean[0],
            current_clean[0],
            baseline_stack,
            current_stack,
        )
        return False

    matches = 0
    current_idx = 0
    for base_frame in baseline_clean:
        while current_idx < len(current_clean) and not frames_match(base_frame, current_clean[current_idx]):
            current_idx += 1
        if current_idx == len(current_clean):
            continue
        matches += 1
        current_idx += 1

    baseline_len = max(len(baseline_clean), 1)
    match_ratio = matches / baseline_len
    STACK_MATCH_THRESHOLD = 0.6
    if match_ratio >= STACK_MATCH_THRESHOLD:
        return True

    logger.info(
        "Crash stack mismatch (ratio %.2f < %.2f).\nBaseline: %s\nCurrent: %s",
        match_ratio,
        STACK_MATCH_THRESHOLD,
        baseline_stack,
        current_stack,
    )
    return False


def is_ancestor(repo_path: str, older_commit: str, newer_commit: str) -> bool:
    """
    Return True if `older_commit` is an ancestor of `newer_commit`,
    False otherwise.
    """
    repo = Repo(repo_path)
    try:
        repo.git.merge_base('--is-ancestor', older_commit, newer_commit)
        return True
    except GitCommandError:
        return False


def prepare_transplant(data, repo_path):
    # Build commit graph for easy parent/child lookup, and commits stored ordered by time
    max_poc_count = 0
    max_poc_row = None
    
    # Initialize the graph with all commits
    for row in data:
        row['poc_count'] = 0
        for bug_id in row['osv_statuses'].keys():
            if row['osv_statuses'][bug_id] in {'1|1', '0.5|1'}:
                row['poc_count'] += 1
        if row['poc_count'] >= max_poc_count:
            max_poc_count = row['poc_count']
            max_poc_row = row
    
    bug_ids_trigger = set() # do not need to change
    bug_ids_other = set()
    
    for bug_id in max_poc_row['osv_statuses'].keys():
        if max_poc_row['osv_statuses'][bug_id] in {'1|1', '0.5|1'}:
            bug_ids_trigger.add(bug_id)
        else:
            bug_ids_other.add(bug_id)
    bugs_need_transplant = dict() # key: bug_id; value: a commit that a poc trigger this bug, this commit should be closest to max_poc_row['commit_id']
    bugs_cant_use = set()
    for row in data:
        for bug_id in bug_ids_other:
            if row['osv_statuses'][bug_id] in {'1|1', '0.5|1'}:
                if bug_id in bugs_need_transplant:
                    if is_ancestor(repo_path, bugs_need_transplant[bug_id], row['commit_id']) == is_ancestor(repo_path, max_poc_row['commit_id'], row['commit_id']):
                        bugs_need_transplant[bug_id] = row
                else:
                    bugs_need_transplant[bug_id] = row
    for bug_id in bug_ids_other:
        if bug_id not in bugs_need_transplant:
            bugs_cant_use.add(bug_id)
    logger.info(f'all bugs count: {len(max_poc_row["osv_statuses"])}')
    logger.info(f'bug_ids_trigger: {len(bug_ids_trigger)} {bug_ids_trigger}')
    logger.info(f'bugs need transplant count: {len(bugs_need_transplant)} {bugs_need_transplant.keys()}')
    logger.info(f'bugs cant use count: {len(bugs_cant_use)} {bugs_cant_use}\n')
    
    return bug_ids_trigger, bugs_need_transplant, max_poc_row


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
        if ext not in ['c']:
            # Skip non-C files
            logger.debug(f'Skipping non-C file: {path}')
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
                new_line_num = '1,0' if new_line_num == '1' else new_line_num
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
                    
                    results[key_new] = PatchInfo(
                        file_path_old=path_a,
                        file_path_new=path_b,
                        file_type=ext,
                        patch_text=patch_text,
                        new_signature=signature,
                        patch_type=type_set,
                        new_start_line=int(new_line_start),
                        new_end_line=int(new_line_cursor),
                        old_start_line=int(old_line_start),
                        old_end_line=int(old_line_cursor),
                        new_function_start_line=int(node['extent']['start']['line']),
                        new_function_end_line=int(node['extent']['end']['line']),
                    )
                    break
        
        # checkout target repo to the old commit, and parse the code from that
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
                            if v.new_signature is None:
                                continue
                            old_start_i, old_end_i, new_start_i, new_end_i = v.old_start_line, v.old_end_line, v.new_start_line, v.new_end_line
                            if new_start_i == new_end_i:
                                # this situation is handled in add_context()
                                continue
                            if sub_patch == '':
                                # patch only add lines, no lines removed
                                old_line_start = old_line_cursor = diff_result_begin-1
                                new_line_start = new_line_cursor = new_end_i
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
                    
                    if k_old in results:
                        results[k_old].old_signature = signature
                    else:
                        results[k_old] = PatchInfo(
                            file_path_old=path_a,
                            file_path_new=path_b,
                            file_type=ext,
                            patch_text=patch_text,
                            old_signature=signature,
                            patch_type=type_set,
                            new_start_line=int(new_line_start),
                            new_end_line=int(new_line_cursor),
                            old_start_line=int(old_line_start),
                            old_end_line=int(old_line_cursor),
                            old_function_start_line=int(node['extent']['start']['line']),
                            old_function_end_line=int(node['extent']['end']['line']),
                        )
                    
                    for k_new, k_old in key_merged.items():
                        patch_old = results[k_old]
                        patch_new = results[k_new]
                        if patch_old.old_function_name != patch_new.new_function_name:
                            signature_change_list.append((patch_old.old_function_name, patch_new.new_function_name))
                        patch_old.new_signature = patch_new.new_signature
                        patch_old.new_start_line = patch_new.new_start_line
                        patch_old.new_end_line = patch_new.new_end_line
                        del results[k_new]

    for patch in results.values():
        if patch.old_signature and patch.new_signature and patch.old_signature != patch.new_signature:
            patch.patch_type.add('Function added')
            patch.patch_type.add('Function removed')
            patch.patch_type.add('Function signature change')
        if patch.is_file_deletion:
            patch.patch_type.add('Function removed')
            patch.patch_type.add('File removed')

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

    cmd = [str(x) for x in cmd]
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
        "error: 'struct",
        "error: conflicting types",
        "error: invalid conversion",
        "error: patch failed:",
        "error: git",
        "error: corrupt patch",
        "make: *** [Makefile:",
        "ninja: build stopped:",
        "Compilation failed",
        "failed with exit status",
        "CMake Error",
        "call to undeclared function"
    ]

    pattern = r"ERROR:.*Sanitizer"
    fuzzer_path = os.path.join(ossfuzz_path, 'build/out', target, fuzzer)
    if not re.search(pattern, combined) \
        and (not os.path.exists(fuzzer_path) \
        or any(p in combined for p in build_error_patterns) \
        or result.returncode != 0):
        logger.info(f"Build failed after patch reversion for bug {bug_id}\n")
        return False, combined

    logger.info(f"Successfully built fuzzer after reverting patch for bug {bug_id}")
    return True, ''


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
        if not patch.old_signature:
            # skip for a added function
            new_patch_to_apply.append(key)
            continue
        fname = patch.old_function_name
        
        if fname == 'LLVMFuzzerTestOneInput':
            # skip LLVMFuzzerTestOneInput, because it is a special function for fuzzing
            patch_lines = patch.patch_text.split('\n')
            old_start = int(patch_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[0].split('-')[-1])
            old_offset = int(patch_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
            new_start = int(patch_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[0].split('-')[-1])
            new_offset = int(patch_lines[3].split('@@')[-2].strip().split(',')[-1])
            patch_lines[3] = f'@@ -{new_start},{old_offset} +{new_start},{new_offset} @@'
            patch.patch_text = '\n'.join(patch_lines)
            new_patch_to_apply.append(key)
            continue
        if 'Function body change' in patch.patch_type:
            if 'Function removed' in patch.patch_type and 'Function added' not in patch.patch_type:
                # TODO: remove this part
                # add prefix to function being deleted
                modified_lines = rename_func(patch.patch_text, fname, commit)
                if patch.file_path_new == '/dev/null':
                    # This file is deleted, can't handle now
                    continue
                function_declarations.add(patch.old_signature.replace(fname, f'__revert_{commit}_{fname}')) # do not use rename_func here, because it only change line starting with '-'
                patch.patch_text = '\n'.join(modified_lines)
                # iterate through the dependent functions and rename them
                for dep_key in dependence_graph.get(key, []):
                    modified_lines = rename_func(diff_results[dep_key].patch_text, fname, commit)
                    diff_results[dep_key].patch_text = '\n'.join(modified_lines)
                new_patch_to_apply.append(key)
                recreated_functions.add(FunctionInfo(name=fname, signature=patch.old_signature, func_used_file=patch.file_path_new, file_path_old=patch.file_path_old, keywords=['static'] if is_function_static(patch.patch_text) else []))
                key_to_newkey[key] = key
            
            elif patch.old_signature and patch.new_signature:
                if (patch.old_signature, patch.file_path_old) in handle_func_signature_change:
                    continue
                # Delete all other patches that have the same signature
                removed_old_signatures.add(patch.old_signature)
                removed_new_signatures.add(patch.new_signature)
                                
                handle_func_signature_change.add((patch.old_signature, patch.file_path_old))
                # Need a Artificial patch, to create the old function

                func_code, func_length, start_line = get_function_code_from_old_commit(target_repo_path, commit, data_path, patch.file_path_old, patch.old_signature)
                func_code = '\n'.join([f'-{line}' for line in func_code.split('\n')][:-1]) + '\n'  # Add a \n at the end to avoid patch fail
                func_loc = FunctionLocation(file_path=patch.file_path_old, start_line=start_line, end_line=start_line + func_length - 1)

                artificial_patch_insert_point = get_patch_insert_line_number(target_repo_path, next_commit, data_path, patch.file_path_new, patch.new_signature)

                def create_artificial_patch_data(patch, fname, artificial_patch_insert_point, func_length, func_code, func_loc):
                    """Create the Artificial patch data structure"""
                    patch_header = f'diff --git a/{patch.file_path_new} b/{patch.file_path_new}\n--- a/{patch.file_path_new}\n+++ b/{patch.file_path_new}\n'
                    patch_header += f'@@ -{artificial_patch_insert_point},{func_length} +{artificial_patch_insert_point},0 @@\n'
                    artificial_patch = PatchInfo(
                        file_path_old=patch.file_path_old,
                        file_path_new=patch.file_path_new,
                        file_type=patch.file_type,
                        patch_text='\n'.join(rename_func(patch_header + func_code, fname, commit)),
                        old_signature=patch.old_signature, # __revert_commit_{fname} is not added here
                        patch_type={'Function removed', 'Function body change', 'Recreated function'},
                        dependent_func=set(),
                        new_start_line=artificial_patch_insert_point,
                        new_end_line=artificial_patch_insert_point,
                        old_start_line=artificial_patch_insert_point,
                        old_end_line=artificial_patch_insert_point + func_length,
                        old_function_start_line=artificial_patch_insert_point,
                        old_function_end_line=artificial_patch_insert_point + func_length,
                        recreated_function_locations={patch.old_signature: func_loc},
                    )
                    new_key = f'{patch.file_path_old}{patch.file_path_new}-{artificial_patch_insert_point},{func_length}+{artificial_patch_insert_point},0'
                    return artificial_patch, new_key
                artificial_patch, new_key = create_artificial_patch_data(patch, fname, artificial_patch_insert_point, func_length, func_code, func_loc)
                recreated_functions.add(FunctionInfo(name=fname, signature=artificial_patch.old_signature, file_path_old=artificial_patch.file_path_old, func_used_file=patch.file_path_new, keywords=['static'] if is_function_static(func_code) else []))
                diff_results[new_key] = artificial_patch
                function_declarations.add(patch.old_signature.replace(fname, f'__revert_{commit}_{fname}'))
                new_patch_to_apply.append(new_key)
                reserved_keys.add(new_key)
                key_to_newkey[key] = new_key
                
        else:
            new_patch_to_apply.append(key)
            logger.debug(f"Skipping non-function body change for {key}")
            
    # Rename the function by dependency graph, find the caller of the recreated function
    for key in key_to_newkey:
        patch = diff_results[key]
        artificial_patch = diff_results[key_to_newkey[key]]
        fname = patch.old_function_name
        for caller_key in dependence_graph.get(key, []):
            # rename functions in patches that depend on (call) this function
            caller_key = key_to_newkey.get(caller_key, caller_key)
            if caller_key not in diff_results:
                # for minimal patch
                continue
            if 'Static Function' in artificial_patch.patch_type and artificial_patch.file_path_old != diff_results[caller_key].file_path_old:
                # If recreate function is static, it is only seen to that file
                continue
            modified_lines = rename_func(diff_results[caller_key].patch_text, fname, commit)
            diff_results[caller_key].patch_text = '\n'.join(modified_lines)
    
    # Remove patches that are not needed anymore
    for key in new_patch_to_apply:
        if key in reserved_keys:
            continue
        patch = diff_results[key]
        if patch.old_signature and patch.old_signature in removed_old_signatures:
            new_patch_to_apply.remove(key)
            continue
        if patch.new_signature and patch.new_signature in removed_new_signatures:
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
            f"Analyzing patch {key}\n{diff_results[key].patch_text}"
        )
        patch = diff_results[key]
        if 'Function body change' in patch.patch_type and patch.file_path_old:
            parsing_path = os.path.join(data_path, f'{target_repo_path.split('/')[-1]}-{old_commit}', f'{patch.file_path_old}_analysis.json')
            with open(parsing_path, 'r') as f:
                ast_nodes = json.load(f)
            # filter for call expressions (clang cursors for function calls)
            call_kinds = {'CALL_EXPR', 'CXX_METHOD_CALL_EXPR'}
            def_kinds = {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}
            decl_kinds = {'FUNCTION_DECL'}
            for node in ast_nodes:
                if node.get('kind') not in call_kinds:
                    continue
                if not patch.old_function_start_line or not patch.old_function_end_line:
                    # this patch is not related to a function in old version
                    continue
                # check if the call is within the patch range
                if node['extent']['end']['line'] <= patch.old_function_end_line and node['extent']['start']['line'] >= patch.old_function_start_line:
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
                        if diff_result.old_signature and compare_function_signatures(node['callee']['signature'], diff_result.old_signature):
                            patch_list.append(key1)
                            dependence_graph.setdefault(key1, set()).add(key)
                            
    return dependence_graph, new_patch_to_patch


def remove_context(patches: Dict[str, PatchInfo]) -> Dict[str, PatchInfo]:
    """
    Remove context lines from every hunk while keeping the original structure
    intact by splitting each hunk into the minimal set of context-free hunks.
    The returned patches only contain +/- lines and updated headers that point
    precisely to the affected ranges so that they can be reapplied without
    relying on extra context.
    """
    header_pattern = re.compile(
        r'@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? '
        r'\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?P<suffix>.*)'
    )

    def _flush_block(block_lines: List[str], block_old_start: int, block_new_start: int,
                     block_old_count: int, block_new_count: int, suffix: str,
                     output: List[str],
                     span_tracker: Dict[str, Tuple[Optional[int], Optional[int]]]):
        if not block_lines:
            return
        header = (
            f'@@ -{block_old_start},{block_old_count} '
            f'+{block_new_start},{block_new_count} @@{suffix}'
        )
        output.append(header)
        output.extend(block_lines)
        old_start, old_end = span_tracker['old']
        new_start, new_end = span_tracker['new']
        block_old_end = block_old_start + block_old_count
        block_new_end = block_new_start + block_new_count
        span_tracker['old'] = (
            block_old_start if old_start is None else min(old_start, block_old_start),
            block_old_end if old_end is None else max(old_end, block_old_end),
        )
        span_tracker['new'] = (
            block_new_start if new_start is None else min(new_start, block_new_start),
            block_new_end if new_end is None else max(new_end, block_new_end),
        )

    stripped_patches: Dict[str, PatchInfo] = {}
    for key, patch in patches.items():
        patch_copy = copy.deepcopy(patch)
        lines = patch_copy.patch_text.split('\n')
        output_lines: List[str] = []
        span_tracker = {
            'old': (None, None),
            'new': (None, None),
        }
        i = 0
        while i < len(lines):
            line = lines[i]
            if not line.startswith('@@'):
                output_lines.append(line)
                i += 1
                continue

            match = header_pattern.match(line)
            if not match:
                output_lines.append(line)
                i += 1
                continue

            suffix = match.group('suffix') or ''
            old_start = int(match.group('old_start'))
            new_start = int(match.group('new_start'))

            body_lines: List[str] = []
            i += 1
            hunk_terminators = ('@@', 'diff --', 'Index: ', 'index ', '+++ ', '--- ')
            while i < len(lines):
                next_line = lines[i]
                if any(next_line.startswith(prefix) for prefix in hunk_terminators):
                    break
                body_lines.append(next_line)
                i += 1

            while body_lines and body_lines[0] == '':
                body_lines.pop(0)
            while body_lines and body_lines[-1] == '':
                body_lines.pop()

            def _is_context_line(hunk_line: str) -> bool:
                """Context lines in unified diffs start with a single space."""
                return hunk_line.startswith(' ')

            # Remove all leading context lines.
            while body_lines and _is_context_line(body_lines[0]):
                body_lines.pop(0)
                old_start += 1
                new_start += 1

            # Remove all trailing context lines.
            while body_lines and _is_context_line(body_lines[-1]):
                body_lines.pop()

            if not body_lines:
                continue

            old_count = 0
            new_count = 0
            for body_line in body_lines:
                if body_line.startswith('-'):
                    old_count += 1
                elif body_line.startswith('+'):
                    new_count += 1
                elif body_line.startswith('\\'):
                    # Metadata line; does not affect line counters.
                    continue
                else:
                    # Context line affects both old and new positions.
                    old_count += 1
                    new_count += 1

            _flush_block(
                body_lines,
                old_start,
                new_start,
                old_count,
                new_count,
                suffix,
                output_lines,
                span_tracker,
            )

        patch_copy.patch_text = '\n'.join(output_lines)
        old_span_start, old_span_end = span_tracker['old']
        new_span_start, new_span_end = span_tracker['new']
        if old_span_start is not None:
            patch_copy.old_start_line = old_span_start
        if old_span_end is not None:
            patch_copy.old_end_line = old_span_end
        if new_span_start is not None:
            patch_copy.new_start_line = new_span_start
        if new_span_end is not None:
            patch_copy.new_end_line = new_span_end
        stripped_patches[key] = patch_copy

    return stripped_patches


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
        patch_text = patch.patch_text
        # logger.info(f'Processing patch for add_context: {key}\n{patch_text}')
        lines = patch_text.split('\n')
        if len(lines) < 5:
            logger.error(f'patch_text is too short, skip: {patch_text}')
        if lines[4][0] == '-': # meaning this patch has no context
            if patch.file_path_new in patch_prev_key and patch.new_start_line <= prev_new_end_line[patch.file_path_new]+3:
                # merge the patches that have overlap
                patch_prev = diff_results[patch_prev_key[patch.file_path_new]]
                patch_prev_lines = patch_prev.patch_text.split('\n')
                connect_lines_end = int(lines[3].split('@@')[-2].strip().split('+')[1].split(',')[0])
                # In most cases, patch_prev.new_end_line is the actually line number+1, except patch_prev.new_end_line = patch_prev.new_start_line
                connect_lines_begin = int(patch_prev_lines[3].split('@@')[-2].strip().split('+')[1].split(',')[0]) + int(patch_prev_lines[3].split('@@')[-2].strip().split(',')[-1])
                if connect_lines_begin < connect_lines_end:
                    with open(os.path.join(target_repo_path, patch.file_path_new), 'r', encoding="latin-1") as f:
                        connect_lines = [f' {line[:-1]}' for line in f.readlines()[connect_lines_begin-1:connect_lines_end-1]]
                else:
                    connect_lines = []
                if patch_prev_lines[-1] == '\\ No newline at end of file':
                    patch_prev_lines = patch_prev_lines[:-1]
                merged_lines = patch_prev_lines[4:] + connect_lines + lines[4:]
                
                patch_prev_old_start = int(patch_prev_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[0].split('-')[-1])
                patch_prev_old_offset = int(patch_prev_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
                patch_prev_new_start = int(patch_prev_lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[0].split('-')[-1])
                patch_prev_new_offset = int(patch_prev_lines[3].split('@@')[-2].strip().split(',')[-1])
                
                prev_front_context_len = 0
                for line in patch_prev_lines[4:]:
                    if line.startswith('+') or line.startswith('-'):
                        break
                    prev_front_context_len += 1
                
                patch_old_offset = int(lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
                patch_new_offset = int(lines[3].split('@@')[-2].strip().split(',')[-1])
                patch_prev.patch_type = {'Merged functions'}.union(patch.patch_type).union(patch_prev.patch_type)
                if not patch.hiden_func_dict:
                    patch_front_context_len = 0
                    for line in lines[4:]:
                        if line.startswith('+') or line.startswith('-'):
                            break
                        patch_front_context_len += 1
                    patch.hiden_func_dict.setdefault(patch.old_signature, patch_front_context_len)
                patch_prev.hiden_func_dict.update({key: offset+patch_prev_old_offset for key, offset in patch.hiden_func_dict.items()})
                patch_prev.hiden_func_dict[patch_prev.old_signature] = prev_front_context_len
                patch_prev.hiden_func_dict = dict(
                    sorted(patch_prev.hiden_func_dict.items(), key=lambda x: x[1])  # ascending by offset
                )
                patch_prev.patch_text = '\n'.join(lines[:3] + [f'@@ -{patch_prev_old_start},{patch_old_offset+patch_prev_old_offset+max(0, connect_lines_end-connect_lines_begin)} +{patch_prev_new_start},{patch_prev_new_offset+patch_new_offset+max(0, connect_lines_end-connect_lines_begin)} @@'] + merged_lines)
                patch_prev.new_start_line = patch_prev_new_start
                patch_prev.new_end_line = patch_prev_new_start + patch_prev_new_offset + patch_new_offset + max(0, connect_lines_end-connect_lines_begin)
                patch_prev.old_start_line = patch_prev_old_start
                patch_prev.old_end_line = patch_prev_old_start + patch_old_offset + patch_prev_old_offset + max(0, connect_lines_end-connect_lines_begin)
                patch_prev.recreated_function_locations.update(patch.recreated_function_locations)
                # Use the merged patch, remove the previous patch
                diff_results[key] = patch_prev
                removed_patches.add(patch_prev_key[patch.file_path_new])
        prev_new_start_line[diff_results[key].file_path_new] = diff_results[key].new_start_line
        prev_new_end_line[diff_results[key].file_path_new] = diff_results[key].new_end_line
        patch_prev_key[diff_results[key].file_path_new] = key

    for key in removed_patches:
        final_patches.remove(key)
        
    # 2. Add context lines to the patches
    for key in final_patches:
        patch = diff_results[key]
        patch_text = patch.patch_text
        lines = patch_text.split('\n')
        if lines[-1] == '':
            lines = lines[:-1]
        if not patch.file_path_new or patch.file_path_new == '/dev/null':
            # a patch delete a file, skip now
            continue
        context_lines1 = []
        context_lines2 = []
        file_path = os.path.join(target_repo_path, patch.file_path_new)
        with open(file_path, 'r', encoding="latin-1") as f:
            content = [line.rstrip('\n') for line in f.readlines()]
        try:
            old_line_begin_nocontext = int(lines[3].split('@@')[-2].strip().split('-')[1].split(',')[0])
        except (ValueError, IndexError):
            logger.error(f'Failed to parse patch hunk header: {lines[3]} in patch {patch_text}')
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
            new_offset = new_offset_nocontext + max(0, min(3, len(content) - new_line_begin_nocontext - new_offset_nocontext + 1))
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
        for func_sig in patch.hiden_func_dict:
            patch.hiden_func_dict[func_sig] += len(context_lines1)
        patch.patch_text = '\n'.join(lines)
        patch.old_start_line = old_line_begin
        patch.old_end_line = old_line_begin + old_offset
        patch.new_start_line = new_line_begin
        patch.new_end_line = new_line_begin + new_offset


def handle_file_change(diff_results, patch_to_apply):
    for key in diff_results:
        patch = diff_results[key]
        # Delete and add file
        if patch.file_path_new == '/dev/null':
            lines = patch.patch_text.split('\n')
            lines.insert(2, 'deleted file mode 100644')
            patch.patch_text = '\n'.join(lines)
        if patch.file_path_old == '/dev/null':
            lines = patch.patch_text.split('\n')
            lines.insert(1, 'new file mode 100644')
            patch.patch_text = '\n'.join(lines)


def handle_build_error(error_log):
    # --- Undeclared identifiers ---
    pattern = r"(/src.+?):(\d+):(\d+):.*use of undeclared identifier '(\w+)'"
    matches = re.findall(pattern, error_log)
    undeclared_identifiers = [(identifier, f"{filepath}:{line}:{column}") for filepath, line, column, identifier in matches]
    
    # --- Undeclared functions ---
    pattern = r"(/src.+?):(\d+):(\d+):.*undeclared function '(\w+)'"
    matches = re.findall(pattern, error_log)
    undeclared_functions = [(identifier, f"{filepath}:{line}:{column}") for filepath, line, column, identifier in matches]
    
    # --- Conflicting types (treat like undeclared) ---
    pattern = r"(/src.+?):(\d+):(\d+):.*conflicting types for '(\w+)'"
    matches = re.findall(pattern, error_log)
    undeclared_functions.extend((identifier, f"{filepath}:{line}:{column}") for filepath, line, column, identifier in matches)
    
    # --- Missing struct members ---
    pattern = r"(/src.+?):(\d+):(\d+):.*no member named '(\w+)' in '([^']+)'"
    missing_struct_members = dict()

    lines = error_log.splitlines()
    for i, line in enumerate(lines):
        match = re.search(pattern, line)
        if match:
            filepath, line_num, column, member, struct_name = match.groups()
            # Grab this line + the next 2 lines (if they exist)
            context_lines = lines[i : i + 3]
            full_message = "\n".join(context_lines).strip()
            missing_struct_members[(member, struct_name, filepath, int(line_num))] = full_message
    
    # --- Too few / many arguments ---
    pattern = r"(/src.+?):(\d+):(\d+):.*too (?:few|many) arguments to function call.*"
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
            
            # --- Capture the full error block ---
            context_lines = [error_line]
            for j in range(i + 1, len(error_lines)):
                if any(sign in error_lines[j] for sign in next_error):
                    break
                context_lines.append(error_lines[j])

                # skip caret/tilde continuation lines
                if re.match(r"^\s*\|\s*\^", error_lines[j]) or re.match(r"^\s*\|\s*~", error_lines[j]):
                    continue

                line_num_match = re.search(line_num_pattern, error_lines[j])
                if line_num_match:
                    lnum, code = line_num_match.groups()
                    if abs(int(lnum) - int(line_num)) > 5:
                        continue
                    line_num_set.add(int(lnum))
                    fun_call_code += code.strip() + " "
            
            full_message = "\n".join(context_lines).strip()
            function_sig_changes.append(
                (fun_call_code.strip(), "too_few_or_many_arguments_fun_call", filepath, (min(line_num_set), max(line_num_set)), full_message)
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

            # --- Capture the full error block ---
            context_lines = [error_line]
            for j in range(i + 1, len(error_lines)):
                if any(sign in error_lines[j] for sign in next_error):
                    break
                context_lines.append(error_lines[j])

                if re.match(r"^\s*\|\s*\^", error_lines[j]) or re.match(r"^\s*\|\s*~", error_lines[j]):
                    continue
                line_num_match = re.search(line_num_pattern, error_lines[j])
                if line_num_match:
                    lnum, code = line_num_match.groups()
                    if abs(int(lnum) - int(line_num)) > 5:
                        continue
                    line_num_set.add(int(lnum))
                    fun_call_code += code.strip() + " "
            
            full_message = "\n".join(context_lines).strip()
            function_sig_changes.append(
                (fun_call_code.strip(), "type_mismatch_function_call", filepath, (min(line_num_set), max(line_num_set)), full_message)
            )
    
    # --- Unknown type names ---
    pattern = r"(/src.+?):(\d+):(\d+):.*unknown type name '([^']+)'"
    matches = re.findall(pattern, error_log)
    undeclared_identifiers.extend([(type_name, f"{filepath}:{line}:{column}") for filepath, line, column, type_name in matches])
    
    # --- Incomplete type definitions ---
    incomplete_types = []
    pattern = r"(/src.+?):(\d+):(\d+):.*incomplete definition of type '([^']+)'"
    for i, error_line in enumerate(error_lines):
        match = re.search(pattern, error_line)
        if match:
            error_filepath, error_line_num, error_column, type_name = match.groups()
            error_location = f"{error_filepath}:{error_line_num}:{error_column}"
            
            # Look for the corresponding "note: forward declaration" in following lines
            forward_decl_location = None
            
            for j in range(i + 1, len(error_lines)):
                current_line = error_lines[j]
                
                # Stop if we hit another error/warning (but allow notes)
                if any(sign in current_line for sign in {'warning:', 'error:'}):
                    break
                
                # Look for the note about forward declaration
                note_pattern = r"(/src.+?):(\d+):(\d+):.*note:.*forward declaration of '([^']+)'"
                note_match = re.search(note_pattern, current_line)
                
                if note_match:
                    note_filepath, note_line, note_column, note_type = note_match.groups()
                    # Match the type name (handle both "struct blosc2_frame_s" and "blosc2_frame_s")
                    clean_type_name = type_name.replace('struct ', '')
                    if note_type == clean_type_name or note_type == type_name:
                        forward_decl_location = f"{note_filepath}:{note_line}:{note_column}"
                        break
            
            incomplete_types.append((type_name, error_location, forward_decl_location))
    
    return undeclared_identifiers, undeclared_functions, missing_struct_members, function_sig_changes, incomplete_types


def get_insert_line(file_path):
    """
    Returns the 0-based index of the last line that is actual code
    (not empty, not a comment).
    Returns -1 if no code line is found.
    Searches backwards from the end of the file.
    """
    in_multiline_comment = False
    idx = find_first_code_line(file_path)
    with open(file_path, 'r', encoding="latin-1") as f:
        lines = f.readlines()[:idx-1]
    for idx in range(len(lines) - 1, -1, -1):
        stripped = lines[idx].strip()
        
        # Handle multi-line comments (going backwards, so check for /* first)
        if in_multiline_comment:
            if "/*" in stripped:
                in_multiline_comment = False
                # Check if there's code before the /*
                before_comment = stripped.split("/*", 1)[0].strip()
                if before_comment and not before_comment.startswith("//"):
                    return idx
            continue
        
        # Check for */ (start of multi-line comment when going backwards)
        if "*/" in stripped:
            # Check if /* is also on the same line (single-line comment)
            if "/*" in stripped:
                # Find the positions to handle comment blocks on one line
                comment_start = stripped.find("/*")
                comment_end = stripped.rfind("*/")
                
                # Extract parts before and after the comment
                before_comment = stripped[:comment_start].strip()
                after_comment = stripped[comment_end + 2:].strip()
                combined = (before_comment + " " + after_comment).strip()
                
                if combined and not combined.startswith("//"):
                    return idx
                continue
            else:
                # This is the end of a multi-line comment block
                in_multiline_comment = True
                after_comment = stripped.split("*/", 1)[-1].strip()
                if after_comment and not after_comment.startswith("//"):
                    return idx
                continue
        
        # Skip empty lines and single-line comments
        if not stripped or stripped.startswith("//"):
            continue
        
        # Found actual code (including preprocessor directives)
        return idx
    
    return -1  # No code found


def find_first_code_line(file_path, skip_conditionals=False):
    """
    Returns the 1-based line number where actual C code starts.
    Skips:
      - blank lines
      - single-line and multi-line comments
      - preprocessor directives (including multi-line #define macros)
      - (optionally) code inside conditional preprocessor blocks like #ifdef/#ifndef/#if ... #endif

    Set skip_conditionals=True to also skip code inside #ifdef blocks.
    """
    with open(file_path, 'r', encoding="latin-1") as f:
        lines = f.readlines()

    in_multiline_comment = False
    in_multiline_preprocessor = False  # Track multi-line macros / continued preprocessor lines
    conditional_stack = []  # store 1-based line numbers of #if/#ifdef/#ifndef entries

    for idx, line in enumerate(lines):
        stripped = line.strip()

        # If previous line started a multi-line preprocessor directive, handle continuation
        if in_multiline_preprocessor:
            if stripped.endswith('\\'):
                continue  # still in a continued preprocessor
            else:
                in_multiline_preprocessor = False
                continue  # this was the last continued preprocessor line

        # Handle multi-line comments
        if in_multiline_comment:
            if "*/" in stripped:
                in_multiline_comment = False
                after_comment = stripped.split("*/", 1)[1].strip()
                if after_comment and not after_comment.startswith("//"):
                    if not after_comment.startswith("#"):
                        # Found code after a closing comment: determine appropriate insertion point
                        if not skip_conditionals and conditional_stack:
                            # prefer to insert before outermost conditional
                            return conditional_stack[0]
                        return idx + 1
            continue

        # Check for /* - handle inline closing
        if "/*" in stripped:
            before_comment = stripped.split("/*", 1)[0].strip()

            if "*/" in stripped:
                after_comment = stripped.split("*/", 1)[-1].strip()
                combined = (before_comment + " " + after_comment).strip()
                stripped = combined
            else:
                in_multiline_comment = True
                if before_comment:
                    stripped = before_comment
                else:
                    continue

        # Skip blank or single-line comment
        if not stripped or stripped.startswith("//"):
            continue

        # Track preprocessor conditional depth / stack
        is_if = (
            stripped.startswith("#if ") or
            stripped.startswith("#ifdef ") or
            stripped.startswith("#ifndef ") or
            stripped == "#if" or
            stripped == "#ifdef" or
            stripped == "#ifndef"
        )
        if is_if:
            # record the 1-based line number where this conditional starts
            conditional_stack.append(idx + 1)
            # check for continued preprocessor line
            if stripped.endswith('\\'):
                in_multiline_preprocessor = True
            continue

        if stripped.startswith("#endif"):
            if conditional_stack:
                conditional_stack.pop()
            continue

        if stripped.startswith("#else") or stripped.startswith("#elif"):
            # keep conditional stack as-is; we don't change stack height
            continue

        # Skip ALL other preprocessor lines (including #define, #include, etc.)
        if stripped.startswith("#"):
            if stripped.endswith('\\'):
                in_multiline_preprocessor = True
            continue

        # If we reach here, we've found an actual code line.
        # If it's inside a conditional and the caller did NOT request skipping conditionals,
        # prefer to insert before the outermost conditional start so we don't end up inside.
        if not skip_conditionals and conditional_stack:
            return conditional_stack[0]

        # Otherwise return this line (1-based)
        return idx + 1

    # No code found -> return line after last line
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
    with open(file_path, 'r', encoding="latin-1") as f:
        lines = f.readlines()

    total_lines = len(lines)
    start = max(0, line_number - context - 1)  # zero-based index
    end = min(total_lines, line_number - 1 + context)  # one-based index

    return ''.join([f' {lines[i]}' for i in range(start, line_number-1)]), ''.join([f' {lines[i]}' for i in range(line_number-1, end)]), start+1, end


def add_patch_for_trace_funcs(diff_results, final_patches, trace1, recreated_functions, target_repo_path, commit, next_commit, target):
    # For function do not change but appear in trace, add a patch if they should call recreated functions
    # Assume target_repo in new commit
    new_patch_to_apply = set()
    trace_set = set() # avoid duplicate functions in loop
    for index, func in trace1:
        fname = func.split(' ')[0]
        location = func.split(' ')[1]
        file_path = location.split(':')[0][1:]  # remove leading /
        trace_set.add((fname, file_path))
    for fname, file_path in trace_set:
        old_line_begin = None
        old_line_end = None
        flag = False # flag to indicate if the function is changed between commit and next_commit
        for key in final_patches:
            if diff_results[key].old_signature and fname == diff_results[key].old_function_name:
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
            with open(os.path.join(target_repo_path, file_path), 'r', encoding="latin-1") as f:
                content = f.readlines()
                function_lines = content[old_line_begin-1:old_line_end]
            for func_info in recreated_functions:
                recreated_fname = func_info.name
                function_head_flag = False
                for i, line in enumerate(function_lines):
                    if '{' in line:
                        function_head_flag = True
                    if not function_head_flag:
                        # Skip the function head
                        continue
                    if re.search(r'(?<![\w.])' + re.escape(recreated_fname) + r'(?!\w)', line) is not None:
                        # If the function is recreated, add a call to it
                        start_line = old_line_begin  + i
                        end_line = start_line + 1
                        patch_text = rename_func(f'-{line}', recreated_fname, commit)[0] + '\n+' + line[:-1]
                        patch_text = patch_header + f"@@ -{start_line},{1} +{start_line},{1} @@\n" + patch_text
                        patch = PatchInfo(
                            file_path_old=file_path,
                            file_path_new=file_path,
                            file_type='c',
                            patch_text=patch_text,
                            old_signature=f'no change trace function {recreated_fname}',
                            new_signature=f'no change trace function {recreated_fname}',
                            patch_type={'Function body change'},
                            dependent_func=set(),
                            new_start_line=start_line,
                            new_end_line=end_line,
                            old_start_line=start_line,
                            old_end_line=end_line,
                            new_function_start_line=old_line_begin,
                            new_function_end_line=old_line_end,
                        )
                        new_key = f'{file_path}{file_path}-{start_line},{1}+{start_line},{1}'
                        
                        diff_results[new_key] = patch
                        new_patch_to_apply.add(new_key)

    final_patches.extend(list(new_patch_to_apply))


def llvm_fuzzer_test_one_input_patch_update(diff_results, patch_to_apply, recreated_functions, target_repo_path, commit, next_commit, target, trace1):
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
        if not (patch.old_signature and patch.new_signature):
            # This patch is not a function body change, skip it
            continue
        if patch.file_path_new != fuzzer_file_path:
            continue
        if ('LLVMFuzzerTestOneInput' in patch.old_signature or 'LLVMFuzzerTestOneInput' in patch.new_signature):
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
        if 'type_ref' not in node:
            continue
        
        # Check if this call is within the LLVMFuzzerTestOneInput function and references a recreated function
        if node['location']['file'] == fuzzer_file_path and fuzzer_start_line <= node['location']['line'] <= fuzzer_end_line and any(node['spelling'] == func_info.name for func_info in recreated_functions):
            
            # Track whether this call is already covered by an existing patch
            Inpatch_flag = False
            
            # Step 3a: Check if this call is within any existing patch
            for key in fuzzer_keys:
                patch = diff_results[key]
                lines = patch.patch_text.split('\n')
                new_lines = []
                new_start_line = int(lines[3].split('@@')[-2].strip().split('+')[1].split(',')[0])
                new_offset = int(lines[3].split('@@')[-2].strip().split(',')[-1])
                if new_start_line <= node['location']['line'] < new_start_line + new_offset:
                    # This call in within a patch, we need to update the patch
                    Inpatch_flag = True
                    for i, line in enumerate(lines):
                        if line[0] not in {'-', '+'} and re.search(r'(?<![\w.])' + re.escape(node['spelling']) + r'(?!\w)', line) is not None:
                            # If the function is called in this patch, we need to update the call
                            rm_line = rename_func(f'-{line[1:]}', node['spelling'], commit)[0]
                            add_line = f'+{line[1:]}'
                            new_lines.append(rm_line)
                            new_lines.append(add_line)
                        else:
                            new_lines.append(line)
                    patch.patch_text = '\n'.join(new_lines)
            
            # Step 3b: Create new patch for calls not covered by existing patches
            if not Inpatch_flag:
                # This call is not in any patch, we need to create a new patch
                new_start_line = node['location']['line']
                new_offset = 1
                
                # Read the actual function call line from source file
                with open(os.path.join(target_repo_path, fuzzer_file_path), 'r', encoding="latin-1") as f:
                    content = f.readlines()
                    function_line = content[node['location']['line']-1]
                    assert(node['extent']['start']['line'] == node['extent']['end']['line']), f'Function call should be in one line, but got {node["extent"]["start"]["line"]} - {node["extent"]["end"]["line"]}'

                # Create patch lines for reverting __revert_commit_ functions back to original names
                rm_line = rename_func(f'-{function_line}', node['spelling'], commit)[0]
                add_line = f'+{function_line.replace('\n', '')}'
                
                # Construct complete patch text
                patch_text = f'diff --git a/{fuzzer_file_path} b/{fuzzer_file_path}\n--- a/{fuzzer_file_path}\n+++ b/{fuzzer_file_path}\n@@ -{new_start_line},{new_offset} +{new_start_line},{new_offset} @@\n{rm_line}\n{add_line}'
                # Create new patch entry
                patch = PatchInfo(
                    file_path_old=fuzzer_file_path,
                    file_path_new=fuzzer_file_path,
                    file_type='c',
                    patch_text=patch_text,
                    old_signature=fuzzer_old_signature,
                    new_signature=fuzzer_new_signature,
                    patch_type={'Function body change'},
                    dependent_func=set(),
                    new_start_line=new_start_line,
                    new_end_line=new_start_line + new_offset,
                    old_start_line=new_start_line,
                    old_end_line=new_start_line + new_offset,
                    old_function_start_line=fuzzer_start_line,
                    old_function_end_line=fuzzer_end_line,
                )
                
                # Add new patch to diff_results and patch_to_apply list
                new_key = f'{fuzzer_file_path}{fuzzer_file_path}-{new_start_line},{new_offset}+{new_start_line},{new_offset}'
                diff_results[new_key] = patch
                patch_to_apply.append(new_key)


def update_function_mappings(recreated_functions, signature_change_list, commit: str):
    # add mapping for recreated functions
    for func_info in recreated_functions:
        signature_change_list.append((func_info.name, f'__revert_{commit}_{func_info.name}'))


def handle_function_signature_changes(function_sig_changes, patch_key_list, diff_results, extra_patches, target, commit, next_commit, target_repo_path, data_path, bug_id, file_path_pairs):
    """
    Handle function signature changes by using OpenAI API to fix caller functions.
    
    Args:
        function_sig_changes: List of tuples containing (function_call_code, error_type, filepath, line_range_tuple, full_error_message)
        patch_key_list: List of patch keys currently being applied
        diff_results: Dictionary containing all patch information
        extra_patches: Dictionary of extra patches
        target: Target project name
        commit_info: Dictionary with commit information (containing 'commit_id')
        next_commit_info: Dictionary with next commit information (containing 'commit_id')
        target_repo_path: Path to the target repository
        data_path: Path to data directory
        
    Returns:
        List of new patches created to fix function signature issues
    """
    callee_per_caller_dict = dict()  # caller_function_name -> list of (callee_name, error_message)
    renaming_patch_dict = dict()  # for API Renaming Patches; caller function location -> list of (callee_name, error_message)

    # 1. Divide errors by caller functions
    for callee_line, _, file_path, line_range, error_message in function_sig_changes:
        relative_file_path = file_path.split('/', 3)[-1]
        start_line, end_line = line_range
        key_of_line_num, caller_sig, func_start_index, func_end_index = get_error_patch(relative_file_path, start_line, patch_key_list, diff_results, extra_patches)
        if 'no change trace function' in caller_sig:
            # For API Renaming Patches; 
            func_loc = FunctionLocation(diff_results[key_of_line_num].file_path_new, diff_results[key_of_line_num].new_function_start_line, diff_results[key_of_line_num].new_function_end_line)
            renaming_patch_dict.setdefault((key_of_line_num, func_loc), set()).add((caller_sig.split(' ')[-1], error_message))
        else:
            # For recreate function patches
            callee_name = callee_line.split('(')[0].split(' ')[-1]
            callee_per_caller_dict.setdefault((key_of_line_num, caller_sig, func_start_index, func_end_index), []).append((callee_name, error_message))
        
    # 2. For each caller function, prepare arguments and call OpenAI API to get the fixed function code
    for (caller_key, caller_sig, func_start_index, func_end_index), callee_list in callee_per_caller_dict.items():
        caller_patch = diff_results[caller_key]
        function_lines = []
        in_function = False
        full_error_message = ''.join([error_message for _, error_message in callee_list])
        callee_defA = dict()
        callee_defB = dict()
        caller_code = '\n'.join(line[1:] for line in diff_results[caller_key].patch_text.split('\n')[4:][func_start_index:func_end_index] if line.startswith('-'))
        caller_loc = caller_patch.recreated_function_locations[caller_sig]
        # 2.1 visit ast nodes in version A
        parsing_path = os.path.join(data_path, f'{target}-{commit}', f'{caller_loc.file_path}_analysis.json')
        with open(parsing_path, 'r') as f:
            ast_nodes = json.load(f)
        for node in ast_nodes:
            if node.get('kind') not in {'CALL_EXPR', 'CXX_METHOD_CALL_EXPR'}:
                continue
            if "type_ref" in node and node['location']['file'] == caller_loc.file_path and caller_loc.start_line <= node['location']['line'] <= caller_loc.end_line and any(node['spelling'] == callee_name for callee_name, _ in callee_list):
                callee_loc = FunctionLocation(node['type_ref']['typedef_extent']['start']['file'],
                                             node['type_ref']['typedef_extent']['start']['line'],
                                             node['type_ref']['typedef_extent']['end']['line'])
                if node['callee']['name'] not in callee_defA:
                    callee_defA[node['callee']['name']] = get_code_from_file(target_repo_path, callee_loc.file_path, commit, callee_loc.start_line, callee_loc.end_line)

        # 2.2 visit ast nodes in version B
        caller_file_path_in_B = caller_loc.file_path
        for file_path_new, file_path_old in file_path_pairs.items():
            if file_path_old == caller_loc.file_path:
                caller_file_path_in_B = file_path_new
        parsing_path = os.path.join(data_path, f'{target}-{next_commit}', f'{caller_file_path_in_B}_analysis.json')
        with open(parsing_path, 'r') as f:
            ast_nodes = json.load(f)
        for node in ast_nodes:
            if node.get('kind') == 'FUNCTION_DEFI':
                if node['spelling'] not in callee_defB and\
                    node['spelling'] in [callee_name for callee_name, _ in callee_list]:
                    callee_defB[node['spelling']] = get_code_from_file(target_repo_path, node['extent']['start']['file'], next_commit, node['extent']['start']['line'], node['extent']['end']['line'])
        for node in ast_nodes:
            if node['spelling'] not in callee_defB and\
                node['kind'] == 'FUNCTION_DECL' and\
                node['spelling'] in [callee_name for callee_name, _ in callee_list]:
                # Define in other file, find out the definition
                def_parsing_path = os.path.join(data_path, f'{target}-{next_commit}', f'{node['location']['file']}_analysis.json')
                with open(def_parsing_path, 'r') as f:
                    def_ast_nodes = json.load(f)
                for def_ast_node in def_ast_nodes:
                    if def_ast_node['kind'] == 'FUNCTION_DEFI' and def_ast_node['spelling'] == node['spelling']:
                        callee_defB[node['spelling']] = get_code_from_file(target_repo_path, def_ast_node['extent']['start']['file'], next_commit, def_ast_node['extent']['start']['line'], def_ast_node['extent']['end']['line'])
        assert len(callee_defA) == len(callee_defB), f'callee_defA and callee_defB should have same length, but got {callee_defA} and {callee_defB} in {caller_loc.file_path},{caller_file_path_in_B}'
        callee_defA_text = '\n'.join('\n'.join(code_lines) for code_lines, _ in callee_defA.values())
        callee_defB_text = '\n'.join('\n'.join(code_lines) for code_lines, _ in callee_defB.values())

        # 2.3 call OpenAI API to get the fixed function code
        caller_name = caller_sig.split('(')[0].split(' ')[-1]
        callee_str = caller_loc.file_path + ', '.join(sorted([name for name, _ in callee_list]))
        solution_path = os.path.join(data_path, 'openai', str(bug_id), f'{bug_id}-{next_commit}-{stable_hash(caller_code)}-{stable_hash(callee_str)}-sigchange.txt')
        logger.info(f'Solution path: {solution_path}')
        if not os.path.exists(solution_path):
            logger.info(f'Create patch using open ai api for {caller_name}')
            logger.info(f'solution_path: {solution_path}')
            logger.info(f'Error message: {full_error_message}')
            logger.info(f'caller_code: {caller_code}')
            logger.info(f'callee_defA_text: {callee_defA_text}')
            logger.info(f'callee_defB_text: {callee_defB_text}')
            solution_code = handle_func_sig_change(full_error_message, caller_code, callee_defA_text, callee_defB_text)
            os.makedirs(os.path.dirname(solution_path), exist_ok=True)
            with open(solution_path, 'w', encoding='utf-8') as f:
                f.write(solution_code)
        else:
            with open(solution_path, 'r', encoding='utf-8') as f:
                solution_code = f.read()
        patch_text_lines = caller_patch.patch_text.split('\n')
        patch_text_lines[4+func_start_index:4+func_end_index] = [f'-{line}' for line in solution_code.split('\n')]  # remove old function code
        # update hiden_func_dict
        func_length_change = len(solution_code.split('\n')) - (func_end_index - func_start_index)
        if hasattr(caller_patch, "hiden_func_dict"):
            for fun_sig in caller_patch.hiden_func_dict:
                if caller_patch.hiden_func_dict[fun_sig] > caller_patch.hiden_func_dict[caller_sig]:
                    caller_patch.hiden_func_dict[fun_sig] += func_length_change
        old_offset = len([line for line in patch_text_lines if line[0] in {'-', ' '} and not line.startswith('--')])
        new_offset = len([line for line in patch_text_lines if line[0] in {'+', ' '} and not line.startswith('++')])
        patch_text_lines[3] = f'@@ -{caller_patch.old_start_line},{old_offset} +{caller_patch.new_start_line},{new_offset} @@'
        diff_results[caller_key].patch_text = '\n'.join(patch_text_lines)

    # 3. For API Renaming Patches
    for (key_of_line_num, func_loc), callee_set in renaming_patch_dict.items():
        caller_code_original_lines = get_code_from_file(target_repo_path, func_loc.file_path, next_commit, func_loc.start_line, func_loc.end_line)[0]
        caller_code = '\n'.join([f'-{line}' for line in caller_code_original_lines])
        callee_codes = '' # May be several callees
        full_error_message = ''
        solution_path = os.path.join(data_path, 'openai', str(bug_id), f'{bug_id}-{next_commit}-{stable_hash(key_of_line_num)}-apirenaming.txt')
        logger.info(f'Solution path: {solution_path}')
        if os.path.exists(solution_path):
            with open(solution_path, 'r', encoding='utf-8') as f:
                solution_code = f.read()
        else:
            for callee_name, error_message in callee_set:
                # Search callee code in the patches, because it is a recreating function patch
                caller_code = '\n'.join([line[1:] for line in rename_func(caller_code, callee_name, commit)])
                for key in patch_key_list:
                    patch = diff_results[key]
                    if 'Recreated function' in patch.patch_type:
                        if patch.old_signature and callee_name == patch.old_function_name:
                            callee_code = '\n'.join(line[1:] for line in patch.patch_text.split('\n')[4:] if line.startswith('-'))
                            break
                        for func_sig in patch.hiden_func_dict:
                            if callee_name == func_sig.split('(')[0].split(' ')[-1]:
                                callee_code = '\n'.join(line[1:] for line in patch.patch_text.split('\n')[4:] if line.startswith('-'))
                                break
 
                new_name = f'__revert_{commit}_{callee_name}'
                callee_codes += f'\n// Definition of {new_name}:\n{callee_code}\n'
                full_error_message += error_message
            solution_code = handle_renaming_patch_sig_change(full_error_message, caller_code, callee_codes)
            solution_code = '\n'.join(diff_strings(solution_code, func_loc.file_path, '\n'.join(caller_code_original_lines), func_loc.file_path, 3, func_loc.start_line)) + '\n'
            os.makedirs(os.path.dirname(solution_path), exist_ok=True)
            with open(solution_path, 'w', encoding='utf-8') as f:
                f.write(solution_code)
        diff_results[key_of_line_num].patch_text = solution_code


def get_correct_line_num(file_path, line_num, patch_key_list, diff_results, extra_patches):
    # This is only used for LLVMFuzzerTestOneInput, to get the correct line number in the new commit
    # transform the line number after reverting patches, to the line number before reverting patches (in new commit)
    # extra_patches is not considered directly because it is not applied yet
    add_num = 0 # the number of lines added by patches
    patch = None
    for key in reversed(patch_key_list):
        patch = diff_results[key]
        if patch.file_path_new and (patch.file_path_new == file_path or patch.file_path_new.endswith(file_path)):
            new_start_line = int(patch.patch_text.split('@@')[1].strip().split('+')[1].split(',')[0])
            old_offset = int(patch.patch_text.split('@@')[1].strip().split(' ')[0].split(',')[1])
            new_offset = int(patch.patch_text.split('@@')[1].strip().split(',')[-1])
            if new_start_line <= line_num < new_start_line + new_offset:
                # TODO: check again
                # logger.info(f'here:\n{new_start_line} {new_start_line + new_offset}\n {patch.patch_text}')
                break
            add_num += new_offset - old_offset
        
    if patch:
        lines = patch.patch_text.split('\n')
    elif file_path in extra_patches:
        lines = extra_patches[file_path].patch_text.split('\n')
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


def get_error_patch(relative_file_path, line_num, patch_key_list, diff_results, extra_patches):
    add_num = 0 # the number of lines added by patches
    key_of_line_num = None
    
    if relative_file_path in extra_patches:
        patch = extra_patches[relative_file_path]
        add_num -= patch.old_end_line - patch.old_start_line + 1 - (patch.new_end_line - patch.new_start_line + 1)
        key_of_line_num = f'extra-{relative_file_path}'
        diff_results[key_of_line_num] = patch
    for key in reversed(patch_key_list):
        patch = diff_results[key]
        if patch.file_path_new and (patch.file_path_new == relative_file_path or patch.file_path_new.endswith(relative_file_path)):
            old_offset = int(patch.patch_text.split('@@')[1].strip().split(' ')[0].split(',')[1])
            new_offset = int(patch.patch_text.split('@@')[1].strip().split(',')[-1])
            old_start = int(patch.patch_text.split('@@')[1].strip().split('-')[1].split(',')[0])
            new_start = int(patch.patch_text.split('@@')[1].strip().split('+')[1].split(',')[0])
            if new_start <= line_num + add_num <= new_start + old_offset - 1:
                key_of_line_num = key
                break
            add_num += new_offset - old_offset

    index_old_infun = 0
    patch_flag = False
    front_context_num = next((i for i, x in enumerate(diff_results[key_of_line_num].patch_text.split('\n')[4:]) if x[0] == '-'), -1)
    old_function_signature = diff_results[key_of_line_num].old_signature
    if key_of_line_num and 'Recreated function' in diff_results[key_of_line_num].patch_type:
        for line in diff_results[key_of_line_num].patch_text.split('\n')[front_context_num+4:]:
            if line.startswith('-'):
                index_old_infun += 1
                if not patch_flag:
                    patch_flag = True
            elif line.startswith('+'):
                if not patch_flag:
                    patch_flag = True
            else:
                index_old_infun += 1
            if line_num + add_num  == old_start + index_old_infun:
                # this is the line we are looking for, we can get this line's index in the function
                break
        func_start_index = front_context_num
        patch_lines = diff_results[key_of_line_num].patch_text.split('\n')
        func_end_index = len(patch_lines) - next((i for i, x in enumerate(reversed(patch_lines)) if x[0] == '-'), -1) - 4
        if 'Merged functions' in diff_results[key_of_line_num].patch_type or 'Tail function' in diff_results[key_of_line_num].patch_type:
            last_offset = front_context_num
            last_func_sig = old_function_signature
            flag = False
            for func_sig, offset in diff_results[key_of_line_num].hiden_func_dict.items():
                if offset > index_old_infun:
                    flag = True
                    func_start_index = last_offset
                    func_end_index = offset
                    old_function_signature = last_func_sig
                    break
                last_offset = offset
                last_func_sig = func_sig
            if not flag:
                # The code we want to find is in the last function
                func_start_index = last_offset
                old_function_signature = last_func_sig
                func_end_index = len(patch_lines) - next((i for i, x in enumerate(reversed(patch_lines)) if x[0] == '-'), -1) - 4

    if not 'Recreated function' in diff_results[key_of_line_num].patch_type:
        return key_of_line_num, old_function_signature, None, None

    return key_of_line_num, old_function_signature, func_start_index, func_end_index


def handle_miss_member_structs(miss_member_structs, patch_key_list, diff_results, extra_patches, target, next_commit, commit, target_repo_path, bug_id):
    logger.info(f'enter handle miss member structs {len(miss_member_structs)}')
    struct_error_dict = dict()
    struct_per_fuc_dict = dict()
    solutions_per_patch = dict()
    
    # 1. Divide error into groups based on their function signature
    for (field_name, struct_name, file_path, line_num), full_message in miss_member_structs.items():
        relative_file_path = file_path.split('/', 3)[-1]
        key_of_line_num, old_function_signature, func_start_index, func_end_index = get_error_patch(relative_file_path, line_num, patch_key_list, diff_results, extra_patches)
        struct_error_dict.setdefault((key_of_line_num, old_function_signature, func_start_index, func_end_index), []).append((field_name, struct_name.split(' ')[-1], relative_file_path, line_num, full_message))
        struct_per_fuc_dict.setdefault((key_of_line_num, old_function_signature, func_start_index, func_end_index), set()).add(struct_name.split(' ')[-1])
    # 2. Handle each group of errors, prepare function source code and struct defination
    for (key_of_line_num, old_function_signature, func_start_index, func_end_index), field_struct_list in struct_error_dict.items():
        relative_file_path = field_struct_list[0][2]
        fname = old_function_signature.split('(')[0].split(' ')[-1]
        # 2.1. get source code of the function
        func_code = '\n'.join(line[1:] for line in diff_results[key_of_line_num].patch_text.split('\n')[4:][func_start_index:func_end_index] if line.startswith('-'))
        # 2.2. get struct defination
        struct_defs_v1 = ''
        struct_defs_v2 = ''
        struct_set = struct_per_fuc_dict[(key_of_line_num, old_function_signature, func_start_index, func_end_index)]
        patch = diff_results[key_of_line_num]
        file_path_v1 = patch.file_path_old
        parsing_path = os.path.join(data_path, f'{target}-{commit["commit_id"]}', f'{file_path_v1}_analysis.json')
        deduplicate_struct = set()
        with open(parsing_path, 'r') as f:
            ast_nodes = json.load(f)
        for node in ast_nodes:
            if node.get('kind') not in {'STRUCT_DECL', 'TYPEDEF_DECL', 'TYPE_REF'}:
                continue
            if node['spelling'] in struct_set:
                # Found the struct definition
                struct_file_path = node['extent']['start']['file']
                start_line = node['extent']['start']['line']
                end_line = node['extent']['end']['line']
            
                if node.get('kind') == 'TYPE_REF':
                    if node['type_ref']['underlying']['kind'] == 'NO_DECL_FOUND':
                        struct_file_path = node['type_ref']['typedef_extent']['start']['file']
                        start_line = node['type_ref']['typedef_extent']['start']['line']
                        end_line = node['type_ref']['typedef_extent']['end']['line']
                    else:
                        struct_file_path = node['type_ref']['underlying']['extent']['start']['file']
                        start_line = node['type_ref']['underlying']['extent']['start']['line']
                        end_line = node['type_ref']['underlying']['extent']['end']['line']

                os.chdir(target_repo_path)
                subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["git", "checkout", '-f', commit['commit_id']], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                with open(os.path.join(target_repo_path, struct_file_path), 'r', encoding="latin-1") as f:
                    file_content = f.readlines()
                    struct_code = ''.join(line for line in file_content[start_line-1:end_line])
                    if struct_code not in deduplicate_struct:
                        deduplicate_struct.add(struct_code)
                        struct_defs_v1 += struct_code
        
        for key in patch_key_list:
            patch = diff_results[key]
            if 'Incomplete type' not in patch.patch_type:
                continue
            if patch.new_signature[11:] not in struct_set:
                # f'incomplete {incomplete_type}'
                continue
            patch_text_lines = patch.patch_text.split('\n')
            struct_defs_v2 += '\n'.join([line[1:] for line in patch_text_lines if line.startswith('-') and not line.startswith('---')]) + '\n'
            struct_set.remove(patch.new_signature[11:])
            
        parsing_path = os.path.join(data_path, f'{target}-{next_commit["commit_id"]}', f'{relative_file_path}_analysis.json')
        with open(parsing_path, 'r') as f:
            ast_nodes = json.load(f)
        deduplicate_struct = set()
        for node in ast_nodes:
            if node.get('kind') not in {'STRUCT_DECL', 'TYPEDEF_DECL', 'TYPE_REF'}:
                continue
            if node['spelling'] in struct_set:
                # Found the struct definition
                struct_file_path = node['extent']['start']['file']
                start_line = node['extent']['start']['line']
                end_line = node['extent']['end']['line']
            
                if node.get('kind') == 'TYPE_REF':
                    if node['type_ref']['underlying']['kind'] == 'NO_DECL_FOUND':
                        struct_file_path = node['type_ref']['typedef_extent']['start']['file']
                        start_line = node['type_ref']['typedef_extent']['start']['line']
                        end_line = node['type_ref']['typedef_extent']['end']['line']
                    else:
                        struct_file_path = node['type_ref']['underlying']['extent']['start']['file']
                        start_line = node['type_ref']['underlying']['extent']['start']['line']
                        end_line = node['type_ref']['underlying']['extent']['end']['line']

                os.chdir(target_repo_path)
                subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["git", "checkout", '-f', next_commit['commit_id']], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                with open(os.path.join(target_repo_path, struct_file_path), 'r', encoding="latin-1") as f:
                    file_content = f.readlines()
                    struct_code = ''.join(line for line in file_content[start_line-1:end_line])
                    if struct_code not in deduplicate_struct:
                        deduplicate_struct.add(struct_code)
                        struct_defs_v2 += struct_code
        # 2.3. get the error message
        error_message = ''
        for field_name, struct_name, relative_file_path, line_num, full_message in field_struct_list:
            error_message += full_message
        
        # 2.4. get the solution code
        field_struct_list_str = relative_file_path + ', '.join(sorted([f'{field_name} in {struct_name}' for field_name, struct_name, _, _, _ in field_struct_list]))
        solution_path = os.path.join(data_path, 'openai', str(bug_id), f'{bug_id}-{next_commit["commit_id"]}-{stable_hash(func_code)}-{stable_hash(field_struct_list_str)}.txt')
        logger.info(f'Solution path: {solution_path}')
        if not os.path.exists(solution_path):
            logger.info(f'Create patch using open ai api for {fname}')
            logger.info(f'solution_path: {solution_path}')
            logger.info(f'Error message: {error_message}')
            logger.info(f'struct_defs_v1: {struct_defs_v1}')
            logger.info(f'struct_defs_v2: {struct_defs_v2}')
            logger.info(f'func_code: {func_code}')
            solution_code = solve_code_migration(error_message, struct_defs_v1, struct_defs_v2, func_code)
            os.makedirs(os.path.dirname(solution_path), exist_ok=True)
            with open(solution_path, 'w', encoding='utf-8') as f:
                f.write(solution_code)
        else:
            with open(solution_path, 'r', encoding='utf-8') as f:
                solution_code = f.read()
        # logger.info(f'solution_code for {fname}:\n{solution_code}')
        solutions_per_patch.setdefault(key_of_line_num, dict())[old_function_signature] = solution_code
        
    # 3. change patch in diff_results
    for key_of_line_num, solution_code_dict in solutions_per_patch.items():
        patch_text = diff_results[key_of_line_num].patch_text
        start_line = int(patch_text.split('@@')[1].strip().split('-')[1].split(',')[0])
        patch_text_lines = patch_text.split('\n')
        patch_text_lines = [line for line in patch_text_lines if not line.startswith('\\')]
        front_context_len = len([line for line in patch_text_lines[4:7] if not line.startswith('-')]) # 6 in most cases
        end_context_len = len([line for line in patch_text_lines[-3:] if line.startswith(' ')]) # 3 in most cases
        if 'Merged functions' in diff_results[key_of_line_num].patch_type or 'Tail function' in diff_results[key_of_line_num].patch_type:
            last_offset = len(patch_text_lines)-end_context_len
            hiden_func_dict = dict(sorted(diff_results[key_of_line_num].hiden_func_dict.items(), key=lambda x: x[1], reverse=True)) # descending by offset
            for func_sig in hiden_func_dict:
                if func_sig not in solution_code_dict:
                    last_offset = 4 + hiden_func_dict[func_sig]
                    continue
                solution_code = solution_code_dict[func_sig]
                patch_text_lines[4+hiden_func_dict[func_sig]:last_offset] = [f'-{line}' for line in solution_code.split('\n')]
                func_length_change = len(solution_code.split('\n')) - (last_offset - (4 + hiden_func_dict[func_sig]))
                last_offset = 4 + hiden_func_dict[func_sig]
                # update hiden_func_dict
                for fun_sig, index in diff_results[key_of_line_num].hiden_func_dict.items():
                    if index > hiden_func_dict[func_sig]:
                        diff_results[key_of_line_num].hiden_func_dict[fun_sig] += func_length_change
        else:
            # There should be only one func_sig here
            assert(len(solution_code_dict) == 1)
            for func_sig in solution_code_dict:
                solution_code = solution_code_dict[func_sig]
            patch_text_lines[4+front_context_len:len(patch_text_lines)-end_context_len] = [f'-{line}' for line in solution_code.split('\n')]
            func_length_change = len(solution_code.split('\n')) - (len(patch_text_lines)-end_context_len - (4+front_context_len))
            # update hiden_func_dict
            for fun_sig, index in diff_results[key_of_line_num].hiden_func_dict.items():
                if index > hiden_func_dict[func_sig]:
                    diff_results[key_of_line_num].hiden_func_dict[fun_sig] += func_length_change
        
        old_offset = len([line for line in patch_text_lines if line[0] in {'-', ' '} and not line.startswith('--')])
        new_offset = len([line for line in patch_text_lines if line[0] in {'+', ' '} and not line.startswith('++')])
        patch_text_lines[3] = f'@@ -{start_line},{old_offset} +{start_line},{new_offset} @@'
        diff_results[key_of_line_num].patch_text = '\n'.join(patch_text_lines)


def insert_func_def_before_error(file_path, func_sig, def_loc, error_line_num, patch_key_list, diff_results, extra_patches, target_repo_path, commit, recreated_functions, function_declarations):
    # insert function definition before the error line
    add_num = 0 # the number of lines added by patches
    key_of_line_num = None
    
    # 1. get the patch where error occurs
    if file_path in extra_patches:
        patch = extra_patches[file_path]
        add_num -= patch.old_end_line - patch.old_start_line + 1 - (patch.new_end_line - patch.new_start_line + 1)
        key_of_line_num = f'extra-{file_path}'
        diff_results[key_of_line_num] = patch
    for key in reversed(patch_key_list):
        patch = diff_results[key]
        if patch.file_path_new and (patch.file_path_new == file_path or patch.file_path_new.endswith(file_path)):
            old_offset = int(patch.patch_text.split('@@')[1].strip().split(' ')[0].split(',')[1])
            new_offset = int(patch.patch_text.split('@@')[1].strip().split(',')[-1])
            old_start = int(patch.patch_text.split('@@')[1].strip().split('-')[1].split(',')[0])
            new_start = int(patch.patch_text.split('@@')[1].strip().split('+')[1].split(',')[0])
            if new_start <= error_line_num + add_num <= new_start + old_offset - 1:
                key_of_line_num = key
                break
            add_num += new_offset - old_offset

    # 2. read the definition
    fname = func_sig.split('(')[0].split(' ')[-1]
    def_file_path = def_loc.split(':')[0]
    def_func_start = int(def_loc.split(':')[1])
    def_func_end = int(def_loc.split(':')[2])
    def_loc = FunctionLocation(file_path=def_file_path, start_line=def_func_start, end_line=def_func_end)
    os.chdir(target_repo_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", '-f', commit['commit_id']], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(os.path.join(target_repo_path, def_loc.file_path), 'r', encoding='utf-8') as f:
        func_def = f.readlines()[int(def_loc.start_line)-1:int(def_loc.end_line)]
        func_def = [f'-{line[:-1]}' for line in func_def]
    
    # 3. insert def into patch
    patch = diff_results[key_of_line_num]
    patch_lines = patch.patch_text.split('\n')
    front_context_len = 0
    back_context_len = next((i for i, x in enumerate(reversed(patch_lines)) if x[0] == '-' or x[0] == '+'), -1)
    for line in patch_lines[4:]:
        if line.startswith('+') or line.startswith('-'):
            break
        front_context_len += 1
        
    patch.recreated_function_locations[func_sig] = def_loc
    old_start = int(patch_lines[3].split('-')[1].split(',')[0])
    old_offset = int(patch_lines[3].split(',')[1].split(' ')[0])
    new_start = int(patch_lines[3].split('+')[1].split(',')[0])
    new_offset = int(patch_lines[3].split(',')[-1].split(' ')[0])
    patch_lines[3] = f'@@ -{old_start},{old_offset+len(func_def)} +{new_start},{new_offset} @@'
    if key_of_line_num.startswith('extra-'):
        patch.patch_text = '\n'.join(patch_lines[:-back_context_len] + func_def + patch_lines[-back_context_len:])
        patch.hiden_func_dict[func_sig] = len(patch_lines) - back_context_len - 4
    else:
        patch.patch_text = '\n'.join(patch_lines[:4+front_context_len] + func_def + patch_lines[4+front_context_len:])
        for key in patch.hiden_func_dict:
            patch.hiden_func_dict[key] += len(func_def)
        patch.hiden_func_dict[func_sig] = front_context_len
    patch.patch_type.add('Merged functions')
    patch.patch_type.add('Recreated function')
    patch.old_signature = patch.new_signature = func_sig
    patch.old_end_line += len(func_def)
    recreated_functions.add(FunctionInfo(name=fname, signature=func_sig, file_path_old=file_path, func_used_file=patch.file_path_new, keywords=['static']))
    function_declarations.add(func_sig.replace(fname, f'__revert_{commit["commit_id"]}_{fname}'))


def get_old_line_num(file_path, line_num, patch_key_list, diff_results, extra_patches, target, commit):
    # transform the line number after reverting patches, to the line number in old commit
    add_num = 0 # the number of lines added by patches
    key_of_line_num = None
    
    if file_path in extra_patches:
        patch = extra_patches[file_path]
        add_num -= patch.old_end_line - patch.old_start_line + 1 - (patch.new_end_line - patch.new_start_line + 1)
    for key in reversed(patch_key_list):
        patch = diff_results[key]
        if patch.file_path_new and (patch.file_path_new == file_path or patch.file_path_new.endswith(file_path)):
            old_offset = int(patch.patch_text.split('@@')[1].strip().split(' ')[0].split(',')[1])
            new_offset = int(patch.patch_text.split('@@')[1].strip().split(',')[-1])
            old_start = int(patch.patch_text.split('@@')[1].strip().split('-')[1].split(',')[0])
            new_start = int(patch.patch_text.split('@@')[1].strip().split('+')[1].split(',')[0])
            if new_start <= line_num + add_num <= new_start + old_offset - 1:
                key_of_line_num = key
                break
            add_num += new_offset - old_offset

    index_old_infun = 0
    front_context_num = 0 # should be less than 3
    patch_flag = False
    if key_of_line_num and 'Recreated function' in diff_results[key_of_line_num].patch_type:
        # for __revert_{commit}_{fname} function, we need to find the line number in the old function
        for line in diff_results[key_of_line_num].patch_text.split('\n')[4:]:
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
        old_function_signature = diff_results[key_of_line_num].old_signature
        if 'Merged functions' in diff_results[key_of_line_num].patch_type or 'Tail function' in diff_results[key_of_line_num].patch_type:
            last_offset = front_context_num
            last_func_sig = old_function_signature
            flag = False
            for func_sig, offset in diff_results[key_of_line_num].hiden_func_dict.items():
                if offset > index_old_infun:
                    index_old_infun -= last_offset
                    old_function_signature = last_func_sig
                    flag = True
                    break
                last_offset = offset
                last_func_sig = func_sig
            if not flag:
                # The code we want to find is in the last function
                index_old_infun -= last_offset
                old_function_signature = last_func_sig
        else:
            index_old_infun -= front_context_num # I want the index inside the function, not the context lines
        parsing_path = os.path.join(data_path, f'{target}-{commit}', f'{diff_results[key_of_line_num].file_path_old}_analysis.json')
        with open(parsing_path, 'r') as f:
            ast_nodes = json.load(f)
        for node in ast_nodes:
            if node.get('kind') not in {'FUNCTION_DEFI', 'CXX_METHOD', 'FUNCTION_TEMPLATE'}:
                continue
            if node['spelling'] == old_function_signature.split('(')[0].split(' ')[-1] and node['extent']['start']['file'] == diff_results[key_of_line_num].file_path_old:
                # Found the function definition
                start_line = node['extent']['start']['line']
                return start_line + index_old_infun
        # should not reach here
    else:
        # must be code in LLVMFuzzerTestOneInput
        return line_num + add_num - new_start + old_start


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
    old_signature = patch.old_signature
    new_signature = patch.new_signature
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
    old_start = int(patch.patch_text.split('@@')[1].strip().split('-')[1].split(',')[0])
    old_offset = int(patch.patch_text.split('@@')[1].strip().split(' ')[0].split(',')[1])
    new_start = int(patch.patch_text.split('@@')[1].strip().split('+')[1].split(',')[0])
    new_offset = int(patch.patch_text.split('@@')[1].strip().split(',')[-1])
    ptr1 = old_start + old_offset # line number in old commit
    ptr2 = new_start + new_offset # line number in new commit
    common_unchanged_lines = []
    patch_lines = patch.patch_text.split('\n')[4:]
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


def get_code_from_file(target_repo_path, file_path, commit, start_line, end_line):
    if start_line > end_line:
        return [], 0
    # Get code from a file in a specific commit
    os.chdir(target_repo_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", '-f', commit], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(os.path.join(target_repo_path, file_path), 'r', encoding="latin-1") as f:
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
            if not cfg1:
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
    if None in cfgs2:
        # There is no corresponding block in another commit;
        return []
    cfg2, bb2s = find_block_by_line(cfgs2, file_path.split('/')[-1], bb2_line_num_list)
    return bb2s


def get_bb_change_pair_from_line(file_path, line_num_list, final_patches, diff_results, extra_patches, target, next_commit: str, commit: str, arch, build_csv, target_repo_path, signature_change_list):
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
    if not cfgs1:
        logger.error(f'Cannot find cfg for {file_path} at line {line_num_in_old_commit_list} line after patch {line_num_after_patch_list}')
        exit(1)
    if not cfgs2:
        logger.error(f'Cannot find cfg for {file_path} at line {line_num_in_old_commit_list} line after patch {line_num_after_patch_list} in new commit {next_commit}')
        exit(1)
    
    pseudo_blosks = []
    for line_in_old in line_num_in_old_commit_list:
        pseudo_block = CFGBlock(-1)
        pseudo_block.start_line = line_in_old
        pseudo_block.end_line = line_in_old
        pseudo_blosks.append(pseudo_block)
    for key, patch in diff_results.items():
        if patch.file_path_new == relative_file_path:
            bb2_line_num_list = get_corresponding_lines(target_repo_path, patch.file_path_old, commit, patch.file_path_new, next_commit, pseudo_blosks)
            break
    
    cfg1, bb1s = find_block_by_line(cfgs1, file_path.split('/')[-1], line_num_in_old_commit_list)
    if bb2_line_num_list:
        if not bb1s:
            logger.error(f'Cannot find basic block for {file_path} at line {line_num_in_old_commit_list} line after patch {line_num_after_patch_list}')
            return None, None, None, None

        for key, patch in diff_results.items():
            if patch.file_path_new == relative_file_path:
                bb2_line_num_list = get_corresponding_lines(target_repo_path, patch.file_path_old, commit, patch.file_path_new, next_commit, bb1s)
                break
    else:
        bb1s = pseudo_blosks
    
    # Now we get basic blocks in new commit that correspond to bb1
    bb2s = []
    cfg2 = None
    fname1 = cfg1.function_signature.split('(')[0].split(' ')[-1]
    for bb2_line_num in bb2_line_num_list:
        cfg, bbs = find_block_by_line(cfgs2, file_path.split('/')[-1], [bb2_line_num])
        fname = cfg.function_signature.split('(')[0].split(' ')[-1]
        if not fname1 == fname and (fname1, fname) not in signature_change_list:
            # Filter those error matching from gumtree
            continue
        bb2s.extend(bbs)
        cfg2 = cfg
    
    return bb1s, bb2s, cfg1, cfg2
    
    
def keep_bb_in_patch(bb1_start_line, bb1_end_line, bb2_start_line, bb2_end_line, cfg1, diff_results, final_patches, target_repo_path, next_commit, relative_file_path):
    for key in final_patches:
        patch = diff_results[key]
        real_patch_start_line = 0
        try:
            signature_match = compare_function_signatures(patch.old_signature, cfg1.function_signature, ignore_arg_types=True)
        except (ValueError, AttributeError):
            signature_match = False
        if patch.file_path_new == relative_file_path and 'Recreated function' in patch.patch_type and signature_match:
            logger.debug(f'bb1 {bb1_start_line} - {bb1_end_line} in patch {key}')
            logger.debug(f'bb2 {bb2_start_line} - {bb2_end_line} in new commit {next_commit}')
            old_start = int(patch.patch_text.split('@@')[1].strip().split('-')[1].split(',')[0])
            old_offset = int(patch.patch_text.split('@@')[1].strip().split(' ')[0].split(',')[1])
            new_start = int(patch.patch_text.split('@@')[1].strip().split('+')[1].split(',')[0])
            new_offset = int(patch.patch_text.split('@@')[1].strip().split(',')[-1])
            if patch.patch_text.find('\n-') != -1:
                # find the real patch start line, usually is 7
                lines = patch.patch_text.split('\n')
                for line in lines:
                    if line.startswith('-') and not line.startswith('---'):
                        real_patch_start_line = lines.index(line)
                        break
            if not real_patch_start_line:
                raise ValueError(f'Cannot find real patch start line in {key}\n{patch.patch_text}')
            # will change code from bb_start to bb_end in the patch, to bb2 in new commit; 4 is patch header lines
            bb_start = real_patch_start_line + bb1_start_line - cfg1.signature_line
            bb_end = real_patch_start_line + bb1_end_line - cfg1.signature_line
            bb2_code_lines, bb2_code_length = get_code_from_file(target_repo_path, relative_file_path, next_commit, bb2_start_line, bb2_end_line)
            patch_lines = patch.patch_text.split('\n')
            patch_lines[bb_start:bb_end+1] = [f'-{line}' for line in bb2_code_lines]
            patch_lines[3] = f'@@ -{old_start},{old_offset-(bb_end-bb_start+1)+bb2_code_length} +{new_start},{new_offset} @@'
            patch.patch_text = '\n'.join(patch_lines)
            break
    return True


def get_full_funsig(patch, target, commit, version:str):
    # version is either 'old' or 'new'
    patch_file_path = getattr(patch, f'file_path_{version}')
    patch_start_line = getattr(patch, f'{version}_start_line')
    patch_end_line = getattr(patch, f'{version}_end_line')
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
        if patch.file_path_old != patch.file_path_new and patch.file_path_new != '/dev/null' and patch.file_path_old != '/dev/null':
            file_path_pairs[patch.file_path_new] = patch.file_path_old
    return file_path_pairs


def apply_and_test_patches(
    patch_pair_list,
    func_list, # list of function signatures, use source code from next_commit
    patches_without_context,
    get_patched_traces,
    transitions,
    signature_change_list,
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
    depen_graph,
    ):
    if not patch_pair_list:
        return
    
    patch_key_list = [key for keys in patch_pair_list for key in keys]
    patch_folder = os.path.abspath(os.path.join(current_file_path, '..', 'patch'))
    if not os.path.exists(patch_folder):
        os.makedirs(patch_folder, exist_ok=True)
    logger.info(f'Patch_pair_list: {patch_pair_list}')
    logger.info(f'Applying and testing {len(patch_pair_list)} {[diff_results[key].old_signature for key in patch_key_list]} ')
    
    patch_to_apply, function_declarations, recreated_functions = patch_patcher(diff_results, patch_key_list, depen_graph, commit['commit_id'], next_commit['commit_id'], target_repo_path)
    update_function_mappings(recreated_functions, signature_change_list, commit['commit_id'])
    patch_file_path = os.path.join(patch_folder, f"{bug_id}_{next_commit['commit_id']}_patches{len(get_patched_traces[bug_id]) if bug_id in get_patched_traces else ''}.diff")
    patch_key_list = list(set(patch_to_apply))
    add_patch_for_trace_funcs(diff_results, patch_key_list, trace1, recreated_functions, target_repo_path, commit['commit_id'], next_commit['commit_id'], target)
    llvm_fuzzer_test_one_input_patch_update(diff_results, patch_key_list, recreated_functions, target_repo_path, commit['commit_id'], next_commit['commit_id'], target, trace1)
    # Sort patch_key_list by new_start_line
    patch_key_list = list(set(patch_key_list))
    patch_key_list = sorted(patch_key_list, key=lambda key: diff_results[key].new_start_line, reverse=True)
    add_context(diff_results, patch_key_list, next_commit['commit_id'], target_repo_path)
    handle_file_change(diff_results, patch_key_list)
    with open(patch_file_path, 'w') as patch_file:
        for key in patch_key_list:
            patch = diff_results[key]   
            patches_without_context.update({key: patch})
            patch_file.write(patch.patch_text)
            patch_file.write('\n\n')  # Add separator between patches
    
    #TODO: update the comments
    con_to_add = dict() # key: file path, value: set of enum/macro locations (use key in dict to achieve ordered set)
    func_decl_to_add = dict() # key: file path, value: set of function declarations
    func_decl_to_add_moveforward = dict() # key: file path, value: set of function declarations that need to be added before function use in the extra patch
    extra_patches = dict() # key: file path, value: patch; include patches for enum/macro/function declaration
    var_del_to_add = dict() # key: file path, value: set of variable declarations
    union_to_add = dict() # key: file path, value: set of union declarations
    type_def_to_add = dict() # key: file path, value: set of type definitions
    incomplete_type_to_add = dict() # key: file path, value: set of incomplete types
    func_def_to_add = dict() # key: (file path, function def location), value: insert line number
    last_type_def_to_add = dict()
    recreated_cons = set()
    recreated_var = set()
    # build and test if it works, oss-fuzz version has been set in collect_trace_cmd
    error_log = 'undeclared identifier'
    count = 0
    while ('undeclared identifier' in error_log or 'undeclared function' in error_log or 
           'too few arguments to function call' in error_log or 'member named' or 'unknown type name'
           in error_log):
        count += 1
        if count > 20:
            break
        build_success, error_log = build_fuzzer(target, next_commit['commit_id'], sanitizer, bug_id, patch_file_path, fuzzer, args.build_csv, arch)
        if build_success:
            break
        with open('/home/user/oss-fuzz-for-select/tmp3', 'w') as f:
            f.write(error_log)
        undeclared_identifier, undeclared_functions, miss_member_structs, function_sig_changes, incomplete_types = handle_build_error(error_log)
        logger.info(f'undeclared_identifier: {len(undeclared_identifier)} {undeclared_identifier}')
        logger.info(f'undeclared_functions: {undeclared_functions}')
        logger.info(f'miss_member_structs: {len(miss_member_structs)} {[item for item in miss_member_structs]}')
        logger.info(f'incomplete_types: {incomplete_types}')
        
        if len(undeclared_identifier) == 0 and len(undeclared_functions) == 0 and len(miss_member_structs) == 0 and len(incomplete_types) == 0 and len(function_sig_changes) == 0:
            break
        
        diff_results_last_round = copy.deepcopy(diff_results) # Read-only, used for querying, because I will change these objects in this round
        patch_key_list_last_round = copy.deepcopy(patch_key_list)
        extra_patches_last_round = copy.deepcopy(extra_patches)
        last_round = (diff_results_last_round, patch_key_list_last_round, extra_patches_last_round)
        un_dec_vars_to_add = dict() # key: file path, value: set of undeclared variables
        
        for type_name, error_location, forward_decl_location in incomplete_types:
            add_file_path = None
            add_start_line = None
            add_end_line = None
            delete_file_path = None
            delete_start = None
            delete_end = None
            type_used = None
            pure_type = type_name.split(' ')[-1]
            error_file_path_new = error_location.split(':')[0].split('/', 3)[-1]
            parsing_path = os.path.join(
                data_path,
                f"{target_repo_path.split('/')[-1]}-{next_commit['commit_id']}",
                f"{error_file_path_new}_analysis.json",
            )
            with open(parsing_path, 'r') as f:
                ast_nodes = json.load(f)
            for node in ast_nodes:
                if node.get('kind') == 'TYPEDEF_DECL' and node.get('spelling') == pure_type:
                    add_file_path = node['extent']['start']['file']
                    add_start_line = node['extent']['start']['line']
                    add_end_line = node['extent']['end']['line']
                if node.get('kind') == 'TYPEDEF_DECL' and node.get('typedef') == type_name and node.get('spelling') != pure_type:
                    type_used = node['spelling']
                    delete_file_path = node['extent']['start']['file']
                    delete_start = node['extent']['start']['line']
                    delete_end = node['extent']['end']['line']
            if add_file_path is None:
                ast_file_folder = os.path.join(data_path, f"{target_repo_path.split('/')[-1]}-{next_commit['commit_id']}")
                if os.path.isdir(ast_file_folder):
                    for dirpath, _, filenames in os.walk(ast_file_folder):
                        for filename in filenames:
                            if not filename.endswith('_analysis.json'):
                                continue
                            ast_file = os.path.join(dirpath, filename)
                            if ast_file == parsing_path:
                                continue
                            with open(ast_file, 'r') as ast_file_handle:
                                candidate_nodes = json.load(ast_file_handle)
                            for candidate in candidate_nodes:
                                if candidate.get('kind') == 'TYPEDEF_DECL' and candidate.get('spelling') == pure_type:
                                    add_file_path = candidate['extent']['start']['file']
                                    add_start_line = candidate['extent']['start']['line']
                                    add_end_line = candidate['extent']['end']['line']
                                    break
                            if add_file_path is not None:
                                break
                        if add_file_path is not None:
                            break
                
            if add_file_path is None or delete_file_path is None:
                logger.info(f'Cannot find type {type_name} in {parsing_path}')
                continue
            incomplete_type_to_add[(delete_file_path, delete_start, delete_end)] = (add_file_path, add_start_line, add_end_line, pure_type, type_used)
        
        miss_decls = []
        for identifier, location in undeclared_identifier:
            file_path_new = location.split('/',3)[-1].split(':')[0]
            if file_path_new in file_path_pairs:
                file_path_old = file_path_pairs[file_path_new]
            else:
                file_path_old = file_path_new
            if identifier.startswith(f'__revert_{commit["commit_id"]}_'):
                # Assign a recreated function to a function pointer
                undeclared_functions.append((identifier, location))
                continue
            if identifier.startswith(f'__revert_cons_{commit["commit_id"]}_'):
                identifier = identifier.split(f'__revert_cons_{commit["commit_id"]}_')[-1]
            parsing_path = os.path.join(data_path, f'{target}-{commit['commit_id']}', f'{file_path_old}_analysis.json')
            def search_ids_in_ast_nodes(con_to_add, var_del_to_add, un_dec_vars_to_add, union_to_add, type_def_to_add, func_def_to_add, miss_decls, file_path_new, recreated_cons):
                if os.path.exists(parsing_path):
                    with open(parsing_path, 'r') as f:
                        ast_nodes = json.load(f)
                    found = False
                    for ast_node in ast_nodes:
                        if ast_node['kind'] in {'ENUM_CONSTANT_DECL'} and ast_node['spelling'] == identifier:
                            found = True
                            con_to_add.setdefault(file_path_new, dict())[f'__revert_cons_{commit["commit_id"]}_{ast_node['spelling']} = {ast_node['enum_value']},\n'] = identifier
                            recreated_cons.add(identifier)
                            break
                        if ast_node['kind'] in {'MACRO_DEFINITION'} and ast_node['spelling'] == identifier:
                            found = True
                            var_del_to_add.setdefault(file_path_new, dict())[f'{ast_node['extent']['start']['file']}:{ast_node['extent']['start']['line']}:{ast_node['extent']['end']['line']}'] = identifier
                            break
                        if ast_node['kind'] in {'DECL_REF_EXPR'} and ast_node['spelling'] == identifier:
                            # A reference (use) of a declared entity such as a variable, function, or enum constant.
                            found = True
                            if 'type_ref' in ast_node and ast_node['type_ref']['target_kind'] == 'VAR_DECL':
                                # use type def here, because they are similiar
                                un_dec_vars_to_add.setdefault(file_path_new, dict())[f'{ast_node['type_ref']['typedef_extent']['start']['file']}:{ast_node['type_ref']['typedef_extent']['start']['line']}:{ast_node['type_ref']['typedef_extent']['end']['line']}'] = identifier
                            else: 
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
                        if ast_node['kind'] in {'TYPE_REF'} and ast_node['spelling'] == identifier:
                            found = True
                            type_def_to_add.setdefault(file_path_new, dict())[f'{ast_node['type_ref']['typedef_extent']['start']['file']}:{ast_node['type_ref']['typedef_extent']['start']['line']}:{ast_node['type_ref']['typedef_extent']['end']['line']}'] = identifier
                            break
                    if not found:
                        # 1. Functions added by DECL_REF_EXPR branch above, search FUNCTION_DECL and FUNCTION_DEFI
                        for ast_node in ast_nodes:
                            if ast_node['kind'] == 'FUNCTION_DEFI' and ast_node['spelling'] == identifier:
                                found = True
                                key = (file_path_new, f'{ast_node['extent']['start']['file']}:{ast_node['extent']['start']['line']}:{ast_node['extent']['end']['line']}', f'{ast_node['signature']}')
                                if key not in func_def_to_add or (key in func_def_to_add and func_def_to_add[key] > int(location.split(':')[1])):
                                    func_def_to_add[key] = int(location.split(':')[1])
                                break
                    if not found:
                        for ast_node in ast_nodes:
                            if ast_node['kind'] == 'FUNCTION_DECL' and ast_node['spelling'] == identifier:
                                # Define in other file, find out the definition
                                def_parsing_path = os.path.join(data_path, f'{target}-{commit['commit_id']}', f'{ast_node['location']['file']}_analysis.json')
                                with open(def_parsing_path, 'r') as f:
                                    def_ast_nodes = json.load(f)
                                for def_ast_node in def_ast_nodes:
                                    if def_ast_node['kind'] == 'FUNCTION_DEFI' and def_ast_node['spelling'] == identifier:
                                        found = True
                                        key = (file_path_new, f'{def_ast_node['extent']['start']['file']}:{def_ast_node['extent']['start']['line']}:{def_ast_node['extent']['end']['line']}', f'{def_ast_node['signature']}')
                                        if key not in func_def_to_add or (key in func_def_to_add and func_def_to_add[key] > int(location.split(':')[1])):
                                            func_def_to_add[key] = int(location.split(':')[1])
                                        break
                                break
                    if not found:
                        return False
                else:
                    return False
                return True
            if not search_ids_in_ast_nodes(con_to_add, var_del_to_add, un_dec_vars_to_add, union_to_add, type_def_to_add, func_def_to_add, miss_decls, file_path_new, recreated_cons):
                logger.debug(f'Cannot find {identifier} in {parsing_path}')
                key_of_line_num, caller_sig, func_start_index, func_end_index = get_error_patch(file_path_new, int(location.split(':')[1]), patch_key_list, diff_results, extra_patches)
                for func_sig, func_loc in diff_results[key_of_line_num].recreated_function_locations.items():
                    parsing_path = os.path.join(data_path, f'{target}-{commit['commit_id']}', f'{func_loc.file_path}_analysis.json')
                    logger.debug(f'Searching {identifier} in recreated function {func_sig} at {parsing_path}')
                    if search_ids_in_ast_nodes(con_to_add, var_del_to_add, un_dec_vars_to_add, union_to_add, type_def_to_add, func_def_to_add, miss_decls, file_path_new, recreated_cons):
                        logger.debug(f'Found {identifier} in recreated function {func_sig} at {parsing_path}')
                        break
        
        func_deled = [] # list of (function name, file path, start line, end line)
        for func_name, location in undeclared_functions:
            file_path = location.split(':')[0]
            line_num_after_patch = int(location.split(':')[1])
            file_path_new = file_path.split('/', 3)[-1]
            if file_path_new in file_path_pairs:
                file_path_old = file_path_pairs[file_path_new]
            else:
                file_path_old = file_path_new
            if not func_name.startswith(f'__revert_{commit["commit_id"]}_'):
                # Check if this function is a 'macro' function
                parsing_path = os.path.join(data_path, f'{target}-{commit['commit_id']}', f'{file_path_old}_analysis.json')
                with open(parsing_path, 'r') as f:
                    ast_nodes = json.load(f)
                is_macro = False
                for ast_node in ast_nodes:
                    if ast_node['kind'] in {'MACRO_DEFINITION'} and ast_node['spelling'] == func_name:
                        type_def_to_add.setdefault(file_path_new, dict())[f'{ast_node['extent']['start']['file']}:{ast_node['extent']['start']['line']}:{ast_node['extent']['end']['line']}'] = func_name
                        is_macro = True
                        break
                if is_macro:
                    continue
                func_deled.append((func_name, file_path, (line_num_after_patch, line_num_after_patch)))
            else:
                # Add declaration for the "__revert_commit_bug_id_*" function
                for func_decl in function_declarations:
                    if func_name == func_decl.split('(')[0].split(' ')[-1]:
                        if file_path_new in extra_patches and func_decl in extra_patches[file_path_new].patch_text:
                            # Suggest that we need to reorder function declarations
                            func_decl_to_add_moveforward.setdefault(file_path_new, set()).add(f'{func_decl}')
                        else:
                            func_decl_to_add.setdefault(file_path_new, set()).add(f'{func_decl}')
                        break

        new_patch_key_list, function_declarations, depen_graph, type_def_to_add = handle_func_deled(func_deled, patch_key_list, diff_results, extra_patches, target, commit['commit_id'], next_commit['commit_id'], target_repo_path, function_declarations, file_path_pairs, depen_graph, type_def_to_add, recreated_functions, func_list)
        logger.info(f'function_sig_changes: {[change[:-1] for change in function_sig_changes]}')
        if function_sig_changes and len(func_deled) == 0:
            handle_function_signature_changes(function_sig_changes, patch_key_list, diff_results, extra_patches, target, commit['commit_id'], next_commit['commit_id'], target_repo_path, data_path, bug_id, file_path_pairs)
            
        update_function_mappings(recreated_functions, signature_change_list, commit['commit_id'])
        for key in new_patch_key_list:
            if key not in patch_key_list:
                patch_key_list.append(key)
        patch_key_list = sorted(patch_key_list, key=lambda key: diff_results[key].new_start_line, reverse=True)
        add_context(diff_results, patch_key_list, next_commit['commit_id'], target_repo_path)
        handle_file_change(diff_results, patch_key_list)
        
        if len(undeclared_identifier) == 0 and len(undeclared_functions) == 0 and len(incomplete_types) == 0 and len(function_sig_changes) == 0:
            # Solve other declarations and definitions first; Because they may lead to miss_decls here
            handle_miss_member_structs(miss_member_structs, patch_key_list, diff_results, extra_patches, target, next_commit, commit, target_repo_path, bug_id)
            bb_change_pair = process_undeclared_identifiers([], miss_decls, last_round, patch_key_list, diff_results, extra_patches, target, next_commit, commit, target_repo_path, arch, signature_change_list)

        if type_def_to_add == last_type_def_to_add:
            for file_path in type_def_to_add:
                type_def_to_add[file_path] = {**un_dec_vars_to_add.get(file_path, dict()), **type_def_to_add.get(file_path, dict())}

        # front patch part
        path_set = set(con_to_add.keys()) | set(func_decl_to_add.keys()) | set(var_del_to_add.keys()) | set(union_to_add.keys()) | set(type_def_to_add.keys())

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
            func_decl_text_moveforward = ''
            func_decl_len_moveforward = 0
            
            if file_path in func_decl_to_add:
                # function declaration patch
                func_decls = func_decl_to_add[file_path]
                for func_decl in func_decls:
                    flag = False
                    prefix = f"__revert_{commit['commit_id']}_"
                    for func_info in recreated_functions:
                        if func_info.signature == func_decl.replace(prefix, "") and func_info.func_used_file == file_path:
                            flag = True
                            func_decl_text += f'-{' '.join(func_info.keywords)} {func_decl};\n'
                    if not flag:
                        func_decl_text += f'-static {func_decl};\n'
                    func_decl_len += 1
            
            if file_path in func_decl_to_add_moveforward:
                # function declaration patch that need to be added before function use in the extra patch
                func_decls = func_decl_to_add_moveforward[file_path]
                for func_decl in func_decls:
                    flag = False
                    prefix = f"__revert_{commit['commit_id']}_"
                    for func_info in recreated_functions:
                        if func_info.signature == func_decl.replace(prefix, "") and func_info.func_used_file == file_path:
                            flag = True
                            func_decl_text_moveforward += f'-{' '.join(func_info.keywords)} {func_decl};\n'
                    if not flag:
                        func_decl_text_moveforward += f'-static {func_decl};\n'
                    func_decl_len_moveforward += 1

            if file_path in union_to_add:
                if file_path in con_to_add and union_to_add_len != len(union_to_add):
                    del con_to_add[file_path]
                # union patch
                locs = list(union_to_add[file_path])
                union_len = 0
                union_text = ''
                for loc in reversed(locs):
                    path = loc.split(':')[0]
                    start_line = int(loc.split(':')[1])
                    end_line = int(loc.split(':')[2])
                    union_len += end_line - start_line + 1
                    with open(os.path.join(target_repo_path, path), 'r', encoding="latin-1") as f:
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
                for loc in reversed(locs):
                    enum_len += 1
                    enum_text += f'-{loc}'
                enum_text += '-};\n'
            else:
                enum_text = ''
                enum_len = 0
            
            var_len = 0
            var_text = ''
            ids = set()
                        
            if file_path in type_def_to_add:
                locs = list(type_def_to_add[file_path])
                for loc in reversed(locs):
                    path = loc.split(':')[0]
                    start_line = int(loc.split(':')[1])
                    end_line = int(loc.split(':')[2])
                    var_len += end_line - start_line + 1
                    with open(os.path.join(target_repo_path, path), 'r', encoding="latin-1") as f:
                        file_content = f.readlines()
                        var_text += ''.join(f'-{line}' for line in file_content[start_line-1:end_line])
            
            if file_path in var_del_to_add:
                # variable declaration patch
                locs = list(var_del_to_add[file_path])
                for loc in reversed(locs):
                    path = loc.split(':')[0]
                    identifier = var_del_to_add[file_path][loc]
                    ids.add(identifier)
                    if path.startswith('#include'):
                        # macro defined in header file from system include paths
                        include_file = path.split(' ')[1]
                        include_text += f'-{path}\n'
                        include_len += 1
                        continue
                    start_line = int(loc.split(':')[1])
                    end_line = int(loc.split(':')[2])
                    var_len += end_line - start_line + 1
                    with open(os.path.join(target_repo_path, path), 'r', encoding="latin-1") as f:
                        file_content = f.readlines()
                        new_identifier = f'__rervert_var_{commit['commit_id']}_{identifier}'
                        var_text += ''.join(f'-{line.replace(identifier, new_identifier)}' for line in file_content[start_line-1:end_line])
                for key in patch_key_list:
                    patch = diff_results[key]
                    if patch.file_path_new == file_path:
                        for identifier in ids:
                            patch.patch_text = '\n'.join(rename_func(patch.patch_text, identifier, None, f'__rervert_var_{commit['commit_id']}_{identifier}'))
                            var_text = '\n'.join(rename_func(var_text, identifier, None, f'__rervert_var_{commit['commit_id']}_{identifier}')) + '\n'

            # need new version to get the context lines
            if enum_len+include_len+func_decl_len+var_len+union_len+func_decl_len_moveforward == 0:
                # no enum or macro patch, skip this file
                continue
            os.chdir(target_repo_path)
            subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["git", "checkout", '-f', next_commit['commit_id']], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            insert_point = get_insert_line(os.path.join(target_repo_path, file_path)) + 2
            context1, context2, start, end = get_line_context(os.path.join(target_repo_path, file_path), insert_point, context=3)
            merge_flag = 0
            
            for key_f in patch_key_list:
                patch_f = diff_results[key_f]
                if patch_f.file_path_new != file_path:
                    continue
                lines = patch_f.patch_text.split('\n')
                new_start_f = int(lines[3].strip().split('@@')[-2].strip().split('+')[1].split(',')[0])
                new_offset_f = int(lines[3].strip().split('@@')[-2].strip().split('+')[1].split(',')[1])
                old_start_f = int(lines[3].strip().split('@@')[-2].strip().split(',')[-1])
                old_offset_f = int(lines[3].split('@@')[-2].strip().split(' ')[0].split(',')[1])
                if end >= new_start_f:
                    # There is overlap, merge them
                    merge_flag = 1
                    gap_len = (new_start_f + 3) - (end - 3) - 1
                    _, gap_text, _, _ = get_line_context(os.path.join(target_repo_path, file_path), insert_point, context=gap_len)
                    f_text = patch_f.patch_text.split('\n', 7)[-1] # Remove the patch header and the front context
                    patch_header += f'@@ -{start},{enum_len+include_len+func_decl_len+func_decl_len_moveforward+var_len+union_len+insert_point-start+gap_len+old_offset_f-3} +{start},{insert_point-start+gap_len+new_offset_f-3} @@\n'
                    patch = PatchInfo(
                        file_path_old=file_path,
                        file_path_new=file_path,
                        patch_text=patch_header + context1 + include_text + func_decl_text_moveforward + enum_text + union_text + var_text + func_decl_text + gap_text + f_text,
                        file_type='c',
                        new_start_line=start,
                        new_end_line=patch_f.new_end_line,
                        old_start_line=start,
                        old_end_line=start+enum_len+include_len+func_decl_len+func_decl_len_moveforward+var_len+union_len+insert_point-start+1+gap_len+old_offset_f-3-1,
                        old_signature=patch_f.old_signature,
                        new_signature=patch_f.new_signature,
                        patch_type={'Enum or macro change', 'Function declaration change'},
                    )
                    not_write_patches.add(key_f)
                    break
                
            if not merge_flag:
                patch_header += f'@@ -{start},{enum_len+include_len+func_decl_len+func_decl_len_moveforward+var_len+union_len+end-start+1} +{start},{end-start+1} @@\n'
                patch = PatchInfo(
                    file_path_old=file_path,
                    file_path_new=file_path,
                    patch_text=patch_header + context1 + include_text + func_decl_text_moveforward + enum_text + union_text + var_text + func_decl_text + context2,
                    file_type='c',
                    new_start_line=start,
                    new_end_line=end,
                    old_start_line=start,
                    old_end_line=enum_len+include_len+func_decl_len+func_decl_len_moveforward+var_len+union_len+end,
                    old_signature='',
                    new_signature='',
                    patch_type={'Enum or macro change', 'Function declaration change'},
                )
            extra_patches[file_path] = patch
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', next_commit['commit_id']], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for key, details in incomplete_type_to_add.items():
            delete_file_path, delete_start, delete_end = key
            add_file_path, add_start_line, add_end_line, incomplete_type, type_used = details
            with open(os.path.join(target_repo_path, add_file_path), 'r', encoding="latin-1") as f:
                file_lines = f.readlines()
                add_code_lines = [f'-{line[:-1]}' for line in file_lines[add_start_line-1:add_end_line]]
                add_code_lines[-1] = add_code_lines[-1].replace(incomplete_type, type_used) + '\n'
            
            with open(os.path.join(target_repo_path, delete_file_path), 'r', encoding="latin-1") as f:
                file_lines = f.readlines()
                delete_code_lines = [f'+{line[:-1]}' for line in file_lines[delete_start-1:delete_end]]
            
            patch_header = f"diff --git a/{delete_file_path} b/{delete_file_path}\n"
            patch_header += f"--- a/{delete_file_path}\n"
            patch_header += f"+++ b/{delete_file_path}\n"
            patch_text = patch_header + f"@@ -{delete_start},{add_end_line-add_start_line+1} +{delete_start},{delete_end-delete_start+1} @@\n"
            patch_text += "\n".join(add_code_lines) + "\n".join(delete_code_lines)
            patch = PatchInfo(
                file_path_old=delete_file_path,
                file_path_new=delete_file_path,
                patch_text=patch_text,
                file_type='c',
                old_start_line=delete_start,
                old_end_line=delete_start + (add_end_line-add_start_line),
                new_start_line=delete_start,
                new_end_line=delete_end,
                old_signature=f'incomplete {incomplete_type}',
                new_signature=f'incomplete {type_used}',
                patch_type={'Incomplete type'},
            )
            key = f'{delete_file_path}-{delete_start}-{delete_end}'
            diff_results[key] = patch
            if key not in patch_key_list:
                patch_key_list.append(key)
            add_context(diff_results, [key], next_commit['commit_id'], target_repo_path)
        
        for identifier in recreated_cons:
            for key in patch_key_list:
                patch = diff_results[key]
                patch.patch_text = '\n'.join(rename_func(patch.patch_text, identifier, None, f'__revert_cons_{commit["commit_id"]}_{identifier}'))
            for patch in extra_patches.values():
                patch.patch_text = '\n'.join(rename_func(patch.patch_text, identifier, None, f'__revert_cons_{commit["commit_id"]}_{identifier}'))
        for identifier in recreated_var:
            for key in patch_key_list:
                patch = diff_results[key]
                patch.patch_text = '\n'.join(rename_func(patch.patch_text, identifier, None, f'__revert_var_{commit["commit_id"]}_{identifier}'))
            for patch in extra_patches.values():
                patch.patch_text = '\n'.join(rename_func(patch.patch_text, identifier, None, f'__revert_var_{commit["commit_id"]}_{identifier}'))
        
        # insert function directly from version A before the error shows
        for (file_path_new, def_loc, func_sig), error_line_num in func_def_to_add.items():
            insert_func_def_before_error(file_path_new, func_sig, def_loc, error_line_num, patch_key_list, diff_results, extra_patches, target_repo_path, commit, recreated_functions, function_declarations)

        # Sometimes, recreated function here call other recreate functions
        for fun_info in recreated_functions:
            for key in patch_key_list:
                patch = diff_results[key]
                if fun_info.func_used_file == patch.file_path_new:
                    patch.patch_text = '\n'.join(rename_func(patch.patch_text, fun_info.name, commit['commit_id']))
            if fun_info.func_used_file in extra_patches:
                patch = extra_patches[fun_info.func_used_file]
                patch.patch_text = '\n'.join(rename_func(patch.patch_text, fun_info.name, commit['commit_id']))

        patches_without_context.clear() # empty the dict before updating
        with open(patch_file_path, 'w') as patch_file:
            for key in patch_key_list:
                # not_write_patches means the patch is merged with the extra patches
                patch = diff_results[key]
                patches_without_context.update({key: patch})
                if key in not_write_patches:
                    continue
                patch_file.write(patch.patch_text)
                patch_file.write('\n\n')
            for patch in extra_patches.values():
                patch_file.write(patch.patch_text)
                patch_file.write('\n\n')
                patches_without_context.update({f'_extra_{patch.file_path_new}': patch})

        # update length of con_to_add, var_del_to_add, union_to_add
        last_type_def_to_add = copy.deepcopy(type_def_to_add)
        
    testcases_env = os.getenv('TESTCASES', '')
    if not testcases_env:
        logger.info("TESTCASES environment variable not set. Exiting.")
        exit(1)
    crash_test_input = select_crash_test_input(bug_id, testcases_env)
    baseline_crash_path = os.path.join(
        data_path,
        'crash',
        f'target_crash-{commit["commit_id"][:6]}-{crash_test_input}.txt',
    )
    signature_file = os.path.join(
        data_path,
        'signature_change_list',
        f'{bug_id}_{next_commit["commit_id"]}.json',
    )
    if build_success:
        # Run the fuzzer to test if the bug is reproduced
        testcase_path = os.path.join(testcases_env, 'testcase-' + bug_id)
        reproduce_cmd = [
            py3, f'{current_file_path}/fuzz_helper.py', 'reproduce', target, fuzzer, testcase_path, '-e', 'ASAN_OPTIONS=detect_leaks=0'
        ]
        logger.info(f"Running reproduce command: {' '.join(reproduce_cmd)}")
        test_result = subprocess.run(reproduce_cmd, capture_output=True, text=True)
        get_patched_traces.setdefault(bug_id, []).append(patch_file_path)
        if 'sanitizer' in test_result.stderr.lower()+test_result.stdout.lower() and sanitizer in test_result.stderr.lower()+test_result.stdout.lower():
            # trigger the bug
            combined_output = (test_result.stderr or '') + (test_result.stdout or '')
            if not crashes_match(combined_output, baseline_crash_path, signature_file):
                logger.info(
                    "Crash for bug %s on commit %s does not match baseline stack; skipping.",
                    bug_id,
                    next_commit['commit_id'],
                )
                return 'crash_mismatch'
            if test_fuzzer_build(target, sanitizer, arch):
                logger.info(f"Fuzzer build success after applying patch for bug {bug_id} on commit {next_commit['commit_id']}\n")
                return 'trigger_and_fuzzer_build'
            else:
                logger.info(f"Fuzzer build fail after applying patch for bug {bug_id} on commit {next_commit['commit_id']}\n")
                return 'trigger_but_fuzzer_build_fail'
        else:
            logger.info(f"Bug {bug_id} not triggered with fuzzer {fuzzer} on commit {next_commit['commit_id']}\n")
            return 'not_trigger'
    else:
        logger.info(f"Build failed for bug {bug_id} on commit {next_commit['commit_id']}\n")
        return 'build_fail'


def test_fuzzer(args, bug_id, target, commit_id, patch_path, need_build = True):
    # Run the fuzzer to test if the bug is reproduced
    bug_info_path = args.bug_info
    testcases_env = os.getenv('TESTCASES', '')
    bug_info_dataset = read_json_file(bug_info_path)
    bug_info = bug_info_dataset[bug_id]
    crash_type = bug_info['reproduce']['crash_type'].split(' ')[0]
    fuzzer = bug_info['reproduce']['fuzz_target']
    sanitizer = bug_info['reproduce']['sanitizer'].split(' ')[0]
    arch = 'i386' if 'i386' in bug_info['reproduce']['job_type'] else 'x86_64'
    
    if need_build:
        build_fuzzer(target, commit_id, sanitizer, bug_id, patch_path, fuzzer, args.build_csv, arch)
    
    testcase_path = os.path.join(testcases_env, 'testcase-' + bug_id)
    reproduce_cmd = [
        py3, f'{current_file_path}/fuzz_helper.py', 'reproduce', target, fuzzer, testcase_path, '-e', 'ASAN_OPTIONS=detect_leaks=0'
    ]
    logger.info(f"Running reproduce command: {' '.join(reproduce_cmd)}")
    test_result = subprocess.run(reproduce_cmd, capture_output=True, text=True)
    combined_output = (test_result.stderr or '') + (test_result.stdout or '')
    lowered = combined_output.lower()
    sanitizer_lower = sanitizer.lower()
    if 'sanitizer' in lowered and sanitizer_lower in lowered:
        # trigger the bug
        confidence_level = '0.5'
        if crash_type.lower() in lowered:
            confidence_level = '1'
        return f'trigger with confidence level: {confidence_level}', combined_output
    else:
        return 'not trigger', combined_output


def update_type_set(patch_info):
    """Update the patch_type set based on the patch content."""
    if patch_info.old_signature and patch_info.new_signature and patch_info.old_signature != patch_info.new_signature:
        patch_info.patch_type.add('Function signature change')
    if patch_info.is_file_deletion:
        patch_info.patch_type.add('File removed')
    if patch_info.is_file_addition:
        patch_info.patch_type.add('File added')


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
    testcases_env = os.getenv('TESTCASES', '')
    if not testcases_env:
        logger.info("TESTCASES environment variable not set. Exiting.")
        exit(1)

    parsed_data = parse_csv_file(csv_file_path)
    target = args.target
    target_repo_path = os.path.join(repo_path, target)
    target_dockerfile_path = f'{ossfuzz_path}/projects/{target}/Dockerfile'
    bug_ids_trigger, bugs_need_transplant, max_poc_row = prepare_transplant(parsed_data, target_repo_path)
    
    get_patched_traces = dict()
    previous_bug = ''
    previous_trace_func_list = []
    signature_change_list = []
    transitions = []
    
    for bug_id, row in bugs_need_transplant.items():
        commit = dict()
        next_commit = dict()
        commit['commit_id'] = row['commit_id'][:6]  # use short commit id for trace file name
        next_commit['commit_id'] = max_poc_row['commit_id'][:6]  # use short commit id for trace file name
        transitions.append((commit, next_commit, bug_id))
    
    flag = False
    test_local_bug_after_patch = dict() # key: bug_id, value: test result, whether the local bug is triggered after applying the patch
    for commit, next_commit, bug_id in transitions:
        if bug_id in {'OSV-2023-51', 'OSV-2021-897', 'OSV-2021-639', 'OSV-2022-1242', 'OSV-2022-511'}:
            continue
        if bug_id in {'OSV-2021-22', 'OSV-2020-2184'}:
            continue
        if args.bug_id and bug_id != args.bug_id:
            continue
        if args.buggy_commit:
            commit['commit_id'] = args.buggy_commit[:6]
        if bug_id == 'OSV-2021-21':
            commit["commit_id"] = '3055a0'
        logger.info(f'bug trigger commit: {commit["commit_id"]}')
        logger.info(f'target commit id: {next_commit["commit_id"]}')
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
        crash_test_input = select_crash_test_input(bug_id, testcases_env)
        trace_path1 = os.path.join(data_path, f'target_trace-{commit['commit_id']}-{crash_test_input}.txt')
        trace_path2 = os.path.join(data_path, f'target_trace-{next_commit['commit_id']}-{crash_test_input}.txt')
        if bug_id in get_patched_traces:
            patch_path_list = get_patched_traces[bug_id]
            trace_path2 = os.path.join(data_path, f'target_trace-{next_commit['commit_id']}-{crash_test_input}{patch_path_list[-1].split('/')[-1].split('.diff')[0]}.txt')
            logger.info(f"Processing transition for bug {bug_id} from commit {commit['commit_id']} to {next_commit['commit_id']} with patch {patch_path_list[-1]}")
        else:
            logger.info(f"Processing transition for bug {bug_id} from commit {commit['commit_id']} to {next_commit['commit_id']}")
    
        if bug_id in get_patched_traces:
            collect_trace_cmd = [py3, f'{current_file_path}/fuzz_helper.py', 'collect_trace', '--commit', next_commit['commit_id'], '--sanitizer', sanitizer,
                                '--build_csv', args.build_csv, '--architecture', arch, '--patch', get_patched_traces[bug_id][-1]]
        else:
            collect_trace_cmd = [py3, f'{current_file_path}/fuzz_helper.py', 'collect_trace', '--commit', commit['commit_id'], '--sanitizer', sanitizer,
                                '--build_csv', args.build_csv, '--architecture', arch]
        collect_trace_cmd.extend(['--testcases', testcases_env])

        collect_trace_cmd.extend(['--build_csv', args.build_csv])

        collect_trace_cmd.extend(['--test_input', crash_test_input])

        collect_trace_cmd.append(target)

        collect_trace_cmd.append(fuzzer)

        collect_trace_cmd.extend(['-e', 'ASAN_OPTIONS=detect_leaks=0'])

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
        crash_log_path = get_crash_stack(
            bug_id=bug_id,
            commit_id=commit['commit_id'],
            crash_test_input=crash_test_input,
            sanitizer=sanitizer,
            build_csv=args.build_csv,
            arch=arch,
            testcases_env=testcases_env,
            target=target,
            fuzzer=fuzzer,
        )
        
        trace1 = extract_function_calls(trace_path1)
        trace2 = extract_function_calls(trace_path2)
        common_part = compare_traces(trace1, trace2, signature_change_list)
        diffs = get_diff_unified(target_repo_path, commit['commit_id'], next_commit['commit_id'], '') # every file get a diff
        get_compile_commands(target, next_commit['commit_id'], sanitizer, args.build_csv, arch)
        get_compile_commands(target, commit['commit_id'], sanitizer, args.build_csv, arch)
        diff_path = os.path.join(data_path, 'diff', f'revert_patch_{bug_id}_{commit["commit_id"]}_to_{next_commit["commit_id"]}.diff')
        os.makedirs(os.path.dirname(diff_path), exist_ok=True)
        diff_results = None
        if os.path.exists(diff_path):
            try:
                diff_results = load_patches_pickle(diff_path)
                logger.info(f"Loaded cached diff analysis from {diff_path}")
            except (pickle.UnpicklingError, EOFError, OSError, gzip.BadGzipFile) as exc:
                logger.warning(f"Failed to load cached diff from {diff_path}: {exc}")
                diff_results = None
        if diff_results is None:
            diff_results = analyze_diffindex(diffs, target_repo_path, next_commit['commit_id'], commit['commit_id'], target, signature_change_list)
            try:
                save_patches_pickle(diff_results, diff_path)
                logger.info(f"Saved diff analysis cache to {diff_path}")
            except OSError as exc:
                logger.warning(f"Failed to save diff analysis cache to {diff_path}: {exc}")
        file_path_pairs = get_file_path_pairs(diff_results)

        trace_func_list = []
        # checkout target repo to the bug commit, get function signature from source code using code location
        os.chdir(target_repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", '-f', commit['commit_id']], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        func_dict = dict()
        for _, func in trace1:
            if func in func_dict:
                continue
            func_loc = func.split(' ')[-1]
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
                func_dict[func] = func.split(' ')[0]
                trace_func_list.append((func_dict[func], func_loc))
                
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
            if diff_result.new_signature:
                logger.debug(f'newsignature{diff_result.new_signature}')
                patch_func_new = diff_result.new_function_name
            if diff_result.old_signature:
                logger.debug(f'oldsignature{diff_result.old_signature}')
                patch_func_old = diff_result.old_function_name
            else:
                continue
            if diff_result.file_path_old:
                patch_file_path = diff_result.file_path_old
            else:
                patch_file_path = diff_result.file_path_new
            update_type_set(diff_result)
            
            # If both bug commit's and fix commit's trace contain this patched function,
            # the patch of the function is likely related to the bug fixing. So try to
            # revert it. 
            for trace_func, func_loc in trace_func_list:
                if patch_file_path in func_loc and (trace_func == patch_func_old or trace_func == patch_func_new):
                    if not diff_result.old_signature:
                        diff_result.old_signature, diff_result.old_function_start_line, diff_result.old_function_end_line = get_full_funsig(diff_result, target, commit['commit_id'], 'old')
                    if not diff_result.new_signature and diff_result.file_path_new != '/dev/null':
                        diff_result.new_signature, _, _ = get_full_funsig(diff_result, target, next_commit['commit_id'], 'new')
                    patch_to_apply.append(key)
                    break

        depen_graph, patch_to_apply = build_dependency_graph(diff_results, patch_to_apply, target_repo_path, commit['commit_id'], trace1)

        inmutable_args = (diff_results, trace1, target_repo_path, commit, next_commit, target,
            sanitizer, bug_id, fuzzer, args, arch, file_path_pairs, data_path, depen_graph)
        signature_change_list = []
        mutable_args = (get_patched_traces, transitions, signature_change_list)
        patch_by_func = dict()
        for key in patch_to_apply[:]:
            if diff_results[key].new_signature:
                if not diff_results[key].new_signature:
                    # Some special cases, dont know why now
                    patch_to_apply.remove(key)
                    continue
                patch_by_func.setdefault(diff_results[key].new_signature, []).append(key)
            else:
                patch_by_func.setdefault(diff_results[key].old_signature, []).append(key)
        patch_pair_list = [tuple(v) for v in patch_by_func.values()]
        
        if bug_id == 'OSV-2021-27':
        #     # ['int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)', 'blosc2_schunk * blosc2_schunk_open_sframe(uint8_t * sframe, int64_t len)']
            # patch_pair_list = [('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,7+23,12',), ('blosc/schunk.cblosc/schunk.c-285,10+440,11',)]
            patch_pair_list = [('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,7+23,12',)]
        # if bug_id == 'OSV-2020-2184':1
        #     # ['int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)', 'blosc2_schunk * blosc2_schunk_open_sframe(uint8_t * sframe, int64_t len)'] 
        #     patch_pair_list = [('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,7+23,12',), ('blosc/schunk.cblosc/schunk.c-258,10+440,11',)]
        # if bug_id == 'OSV-2021-22':1
        #     patch_pair_list = [('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,7+23,12',), ('blosc/schunk.cblosc/schunk.c-285,10+440,11',)]
        # # if bug_id == 'OSV-2021-21':
        # #     patch_pair_list = [('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,7+23,12',), ('blosc/blosc2.cblosc/blosc2.c-2201,22+2331,30',), ('blosc/blosc2.cblosc/blosc2.c-1693,16+1800,18', 'blosc/blosc2.cblosc/blosc2.c-1573,18+1748,0', 'blosc/blosc2.cblosc/blosc2.c-1607,75+1760,29', 'blosc/blosc2.cblosc/blosc2.c-1593,4+1748,0'), ('blosc/frame.cblosc/frame.c-1690,3+2021,20', 'blosc/frame.cblosc/frame.c-1651,3+1976,9', 'blosc/frame.cblosc/frame.c-1618,27+1938,32', 'blosc/frame.cblosc/frame.c-1570,42+1877,55'), ('blosc/frame.cblosc/frame.c-1470,18+1706,58',), ('blosc/schunk.cblosc/schunk.c-285,10+440,11',), ('blosc/frame.cblosc/frame.c-1367,86+1612,77', 'blosc/frame.cblosc/frame.c-1312,46+1554,49', 'blosc/frame.cblosc/frame.c-1301,4+1545,2', 'blosc/frame.cblosc/frame.c-1280,5+1522,7', 'blosc/frame.cblosc/frame.c-1257,12+1497,13')]
        # if bug_id == 'OSV-2021-274':
        #     # ['blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy)', 'int frame_get_metalayers(blosc2_frame_s * frame, blosc2_schunk * schunk)', 'int frame_get_metalayers(blosc2_frame_s * frame, blosc2_schunk * schunk)', 'int frame_get_metalayers(blosc2_frame_s * frame, blosc2_schunk * schunk)', 'int get_header_info(blosc2_frame_s * frame, int32_t * header_len, int64_t * frame_len, int64_t * nbytes, int64_t * cbytes, int32_t * chunksize, int32_t * nchunks, int32_t * typesize, uint8_t * compcode, uint8_t * clevel, uint8_t * filters, uint8_t * filters_meta)', 'int get_header_info(blosc2_frame_s * frame, int32_t * header_len, int64_t * frame_len, int64_t * nbytes, int64_t * cbytes, int32_t * chunksize, int32_t * nchunks, int32_t * typesize, uint8_t * compcode, uint8_t * clevel, uint8_t * filters, uint8_t * filters_meta)', 'int get_header_info(blosc2_frame_s * frame, int32_t * header_len, int64_t * frame_len, int64_t * nbytes, int64_t * cbytes, int32_t * chunksize, int32_t * nchunks, int32_t * typesize, uint8_t * compcode, uint8_t * clevel, uint8_t * filters, uint8_t * filters_meta)', 'blosc2_frame_s * frame_from_cframe(uint8_t * cframe, int64_t len, _Bool copy)', 'blosc2_frame_s * frame_from_cframe(uint8_t * cframe, int64_t len, _Bool copy)'] 
        #     patch_pair_list = [('blosc/frame.cblosc/frame.c-1473,9+1682,7', 'blosc/frame.cblosc/frame.c-1461,4+1674,0', 'blosc/frame.cblosc/frame.c-1432,11+1641,15', 'blosc/frame.cblosc/frame.c-1416,10+1622,13', 'blosc/frame.cblosc/frame.c-1389,8+1592,11', 'blosc/frame.cblosc/frame.c-1368,4+1569,6', 'blosc/frame.cblosc/frame.c-1301,8+1500,10'), ('blosc/frame.cblosc/frame.c-1247,8+1271,8', 'blosc/frame.cblosc/frame.c-1234,5+1261,2', 'blosc/frame.cblosc/frame.c-1216,4+1241,6'), ('blosc/frame.cblosc/frame.c-419,9+396,22', 'blosc/frame.cblosc/frame.c-400,5+380,2', 'blosc/frame.cblosc/frame.c-387,2+366,0'), ('blosc/frame.cblosc/frame.c-720,2+816,2', 'blosc/frame.cblosc/frame.c-704,2+799,3')]
        # if bug_id == 'OSV-2021-246':
        #     patch_pair_list = [('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,2+23,2',), ('blosc/schunk.cblosc/schunk.c-285,10+440,11',), ('blosc/frame.cblosc/frame.c-1453,86+1612,77', 'blosc/frame.cblosc/frame.c-1402,42+1559,44', 'blosc/frame.cblosc/frame.c-1386,4+1545,2', 'blosc/frame.cblosc/frame.c-1365,5+1522,7', 'blosc/frame.cblosc/frame.c-1342,12+1497,13'), ('blosc/frame.cblosc/frame.c-1055,86+1125,110',), ('blosc/frame.cblosc/frame.c-469,2+462,2', 'blosc/frame.cblosc/frame.c-461,2+454,2', 'blosc/frame.cblosc/frame.c-445,2+438,2', 'blosc/frame.cblosc/frame.c-411,19+391,32', 'blosc/frame.cblosc/frame.c-383,18+365,14'), ('blosc/frame.cblosc/frame.c-1180,72+1271,68', 'blosc/frame.cblosc/frame.c-1143,28+1236,24')]
        # if bug_id == 'OSV-2021-213':
        #     # ['int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)', 'blosc2_schunk * blosc2_schunk_open_sframe(uint8_t * sframe, int64_t len)', 'blosc2_schunk * blosc2_frame_to_schunk(blosc2_frame * frame, _Bool copy)', 'blosc2_schunk * blosc2_frame_to_schunk(blosc2_frame * frame, _Bool copy)', 'blosc2_schunk * blosc2_frame_to_schunk(blosc2_frame * frame, _Bool copy)', 'blosc2_schunk * blosc2_frame_to_schunk(blosc2_frame * frame, _Bool copy)', 'blosc2_schunk * blosc2_frame_to_schunk(blosc2_frame * frame, _Bool copy)', 'int frame_get_metalayers(blosc2_frame * frame, blosc2_schunk * schunk)', 'int frame_get_metalayers(blosc2_frame * frame, blosc2_schunk * schunk)'] 
        #     patch_pair_list = [('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,7+23,12',), ('blosc/blosc2.cblosc/blosc2.c-2201,22+2331,30',), ('blosc/blosc2.cblosc/blosc2.c-1693,16+1800,18', 'blosc/blosc2.cblosc/blosc2.c-1573,18+1748,0', 'blosc/blosc2.cblosc/blosc2.c-1607,75+1760,29', 'blosc/blosc2.cblosc/blosc2.c-1593,4+1748,0'), ('blosc/schunk.cblosc/schunk.c-285,10+440,11',)]
        # if bug_id == 'OSV-2021-247':
        #     # ['int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)', 'blosc2_schunk * blosc2_schunk_open_sframe(uint8_t * sframe, int64_t len)']
        #     patch_pair_list = [('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,2+23,2',), ('blosc/frame.cblosc/frame.c-1782,8+2021,24', 'blosc/frame.cblosc/frame.c-1743,3+1976,9', 'blosc/frame.cblosc/frame.c-1724,13+1955,15', 'blosc/frame.cblosc/frame.c-1710,6+1938,9', 'blosc/frame.cblosc/frame.c-1650,54+1877,55'), ('blosc/frame.cblosc/frame.c-1506,17+1706,20',), ('blosc/frame.cblosc/frame.c-963,2+1037,2', 'blosc/frame.cblosc/frame.c-912,43+964,65'), ('blosc/frame.cblosc/frame.c-472,2+462,2', 'blosc/frame.cblosc/frame.c-464,2+454,2', 'blosc/frame.cblosc/frame.c-448,2+438,2', 'blosc/frame.cblosc/frame.c-414,19+391,32', 'blosc/frame.cblosc/frame.c-386,18+365,14'), ('blosc/schunk.cblosc/schunk.c-291,9+440,11',), ('blosc/frame.cblosc/frame.c-1289,15+1271,15', 'blosc/frame.cblosc/frame.c-1253,28+1236,27')]
        # if bug_id == 'OSV-2021-404':
        #     # ['int frame_get_metalayers(blosc2_frame_s * frame, blosc2_schunk * schunk)']
        #     patch_pair_list = [('blosc/frame.cblosc/frame.c-2018,5+2022,21', 'blosc/frame.cblosc/frame.c-1978,3+1976,9', 'blosc/frame.cblosc/frame.c-1966,6+1963,7', 'blosc/frame.cblosc/frame.c-1958,2+1954,3', 'blosc/frame.cblosc/frame.c-1946,5+1939,8', 'blosc/frame.cblosc/frame.c-1910,26+1907,22', 'blosc/frame.cblosc/frame.c-1888,14+1882,17'), ('blosc/frame.cblosc/frame.c-1057,10+1014,11', 'blosc/frame.cblosc/frame.c-1043,2+992,10', 'blosc/frame.cblosc/frame.c-1026,11+965,21'), ('blosc/frame.cblosc/frame.c-479,8+409,9', 'blosc/frame.cblosc/frame.c-437,2+366,0'), ('blosc/frame.cblosc/frame.c-1698,1+1674,0', 'blosc/frame.cblosc/frame.c-1669,11+1641,15', 'blosc/frame.cblosc/frame.c-1653,10+1622,13', 'blosc/frame.cblosc/frame.c-1626,8+1592,11', 'blosc/frame.cblosc/frame.c-1605,4+1569,6', 'blosc/frame.cblosc/frame.c-1538,8+1500,10'), ('blosc/frame.cblosc/frame.c-1444,4+1404,6',), ('blosc/frame.cblosc/frame.c-1283,4+1241,6',)]
        # if bug_id == 'OSV-2021-221':
        #     # ['int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)', 'int frame_get_lazychunk(blosc2_frame * frame, int nchunk, uint8_t ** chunk, _Bool * needs_free)', 'int frame_get_lazychunk(blosc2_frame * frame, int nchunk, uint8_t ** chunk, _Bool * needs_free)', 'int frame_get_lazychunk(blosc2_frame * frame, int nchunk, uint8_t ** chunk, _Bool * needs_free)', 'int frame_get_lazychunk(blosc2_frame * frame, int nchunk, uint8_t ** chunk, _Bool * needs_free)', 'int64_t get_coffset(blosc2_frame * frame, int32_t header_len, int64_t cbytes, int32_t nchunk)', 'int blosc_getitem(const void * src, int start, int nitems, void * dest)', 'uint8_t get_filter_flags(const uint8_t header_flags, const int32_t typesize)', 'int get_header_info(blosc2_frame * frame, int32_t * header_len, int64_t * frame_len, int64_t * nbytes, int64_t * cbytes, int32_t * chunksize, int32_t * nchunks, int32_t * typesize, uint8_t * compcode, uint8_t * clevel, uint8_t * filters, uint8_t * filters_meta)', 'int get_header_info(blosc2_frame * frame, int32_t * header_len, int64_t * frame_len, int64_t * nbytes, int64_t * cbytes, int32_t * chunksize, int32_t * nchunks, int32_t * typesize, uint8_t * compcode, uint8_t * clevel, uint8_t * filters, uint8_t * filters_meta)', 'int get_header_info(blosc2_frame * frame, int32_t * header_len, int64_t * frame_len, int64_t * nbytes, int64_t * cbytes, int32_t * chunksize, int32_t * nchunks, int32_t * typesize, uint8_t * compcode, uint8_t * clevel, uint8_t * filters, uint8_t * filters_meta)', 'int get_header_info(blosc2_frame * frame, int32_t * header_len, int64_t * frame_len, int64_t * nbytes, int64_t * cbytes, int32_t * chunksize, int32_t * nchunks, int32_t * typesize, uint8_t * compcode, uint8_t * clevel, uint8_t * filters, uint8_t * filters_meta)', 'int get_header_info(blosc2_frame * frame, int32_t * header_len, int64_t * frame_len, int64_t * nbytes, int64_t * cbytes, int32_t * chunksize, int32_t * nchunks, int32_t * typesize, uint8_t * compcode, uint8_t * clevel, uint8_t * filters, uint8_t * filters_meta)', 'blosc2_schunk * blosc2_schunk_open_sframe(uint8_t * sframe, int64_t len)']
        #     patch_pair_list = [('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,7+23,12',), ('blosc/frame.cblosc/frame.c-1816,8+2021,24', 'blosc/frame.cblosc/frame.c-1777,3+1976,9', 'blosc/frame.cblosc/frame.c-1744,27+1938,32', 'blosc/frame.cblosc/frame.c-1684,54+1877,55'), ('blosc/frame.cblosc/frame.c-1540,17+1706,20',), ('blosc/blosc2.cblosc/blosc2.c-2617,43+2561,19',), ('blosc/blosc2.cblosc/blosc2.c-1576,18+1748,0',), ('blosc/frame.cblosc/frame.c-469,2+462,2', 'blosc/frame.cblosc/frame.c-461,2+454,2', 'blosc/frame.cblosc/frame.c-445,2+438,2', 'blosc/frame.cblosc/frame.c-411,19+391,32', 'blosc/frame.cblosc/frame.c-383,18+365,14'), ('blosc/schunk.cblosc/schunk.c-285,10+440,11',), ('blosc/frame.cblosc/frame.c-1172,72+1271,68', 'blosc/frame.cblosc/frame.c-1135,28+1236,24')]
        # if bug_id == 'OSV-2021-369':
        #     # ['int frame_get_lazychunk(blosc2_frame_s * frame, int nchunk, uint8_t ** chunk, _Bool * needs_free)', 'int frame_get_lazychunk(blosc2_frame_s * frame, int nchunk, uint8_t ** chunk, _Bool * needs_free)', 'int frame_get_lazychunk(blosc2_frame_s * frame, int nchunk, uint8_t ** chunk, _Bool * needs_free)', 'int frame_get_lazychunk(blosc2_frame_s * frame, int nchunk, uint8_t ** chunk, _Bool * needs_free)', 'int frame_get_lazychunk(blosc2_frame_s * frame, int nchunk, uint8_t ** chunk, _Bool * needs_free)', 'int frame_get_lazychunk(blosc2_frame_s * frame, int nchunk, uint8_t ** chunk, _Bool * needs_free)', 'int frame_get_lazychunk(blosc2_frame_s * frame, int nchunk, uint8_t ** chunk, _Bool * needs_free)', 'uint8_t * get_coffsets(blosc2_frame_s * frame, int32_t header_len, int64_t cbytes, int32_t * off_cbytes)', 'uint8_t * get_coffsets(blosc2_frame_s * frame, int32_t header_len, int64_t cbytes, int32_t * off_cbytes)', 'int get_header_info(blosc2_frame_s * frame, int32_t * header_len, int64_t * frame_len, int64_t * nbytes, int64_t * cbytes, int32_t * chunksize, int32_t * nchunks, int32_t * typesize, uint8_t * compcode, uint8_t * clevel, uint8_t * filters, uint8_t * filters_meta)', 'int get_header_info(blosc2_frame_s * frame, int32_t * header_len, int64_t * frame_len, int64_t * nbytes, int64_t * cbytes, int32_t * chunksize, int32_t * nchunks, int32_t * typesize, uint8_t * compcode, uint8_t * clevel, uint8_t * filters, uint8_t * filters_meta)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy)', 'int frame_get_metalayers(blosc2_frame_s * frame, blosc2_schunk * schunk)', 'int frame_get_metalayers(blosc2_frame_s * frame, blosc2_schunk * schunk)', 'blosc2_frame_s * frame_from_cframe(uint8_t * cframe, int64_t len, _Bool copy)', 'blosc2_frame_s * frame_from_cframe(uint8_t * cframe, int64_t len, _Bool copy)'] 
        #     patch_pair_list = [('blosc/frame.cblosc/frame.c-1770,5+2022,21', 'blosc/frame.cblosc/frame.c-1730,3+1976,9', 'blosc/frame.cblosc/frame.c-1718,6+1963,7', 'blosc/frame.cblosc/frame.c-1710,2+1954,3', 'blosc/frame.cblosc/frame.c-1698,5+1939,8', 'blosc/frame.cblosc/frame.c-1662,26+1907,22', 'blosc/frame.cblosc/frame.c-1640,14+1882,17'), ('blosc/frame.cblosc/frame.c-884,17+992,33', 'blosc/frame.cblosc/frame.c-867,11+965,21'), ('blosc/frame.cblosc/frame.c-431,8+409,9', 'blosc/frame.cblosc/frame.c-389,2+366,0'), ('blosc/frame.cblosc/frame.c-1457,9+1682,7', 'blosc/frame.cblosc/frame.c-1445,4+1674,0', 'blosc/frame.cblosc/frame.c-1416,11+1641,15', 'blosc/frame.cblosc/frame.c-1400,10+1622,13', 'blosc/frame.cblosc/frame.c-1373,8+1592,11', 'blosc/frame.cblosc/frame.c-1352,4+1569,6', 'blosc/frame.cblosc/frame.c-1285,8+1500,10'), ('blosc/frame.cblosc/frame.c-1237,2+1277,2', 'blosc/frame.cblosc/frame.c-1203,4+1241,6'), ('blosc/frame.cblosc/frame.c-722,2+816,2', 'blosc/frame.cblosc/frame.c-706,2+799,3')]
        # if bug_id == 'OSV-2021-429':
        #     # ['int get_coffset(blosc2_frame_s * frame, int32_t header_len, int64_t cbytes, int32_t nchunk, int64_t * offset)']
        #     patch_pair_list = [('blosc/frame.cblosc/frame.c-1673,10+1707,11',)]
        # if bug_id == 'OSV-2022-4':
        #     # ['int initialize_context_decompression(blosc2_context * context, blosc_header * header, const void * src, int32_t srcsize, void * dest, int32_t destsize)']
        #     patch_pair_list = [('blosc/blosc2.cblosc/blosc2.c-1969,24+1777,6',)]
        # if bug_id == 'OSV-2022-34':
        #     # ['int initialize_context_decompression(blosc2_context * context, blosc_header * header, const void * src, int32_t srcsize, void * dest, int32_t destsize)']
        #     patch_pair_list = [('blosc/blosc2.cblosc/blosc2.c-2719,2+2554,3', 'blosc/blosc2.cblosc/blosc2.c-2699,13+2521,26', 'blosc/blosc2.cblosc/blosc2.c-2608,64+2487,7', 'blosc/blosc2.cblosc/blosc2.c-2594,2+2463,12', 'blosc/blosc2.cblosc/blosc2.c-2578,1+2448,0')]
        # if bug_id == 'OSV-2021-1589':
        #     # ['int _blosc_getitem(blosc2_context * context, blosc_header * header, const void * src, int32_t srcsize, int start, int nitems, void * dest, int32_t destsize)', 'int _blosc_getitem(blosc2_context * context, blosc_header * header, const void * src, int32_t srcsize, int start, int nitems, void * dest, int32_t destsize)', 'int _blosc_getitem(blosc2_context * context, blosc_header * header, const void * src, int32_t srcsize, int start, int nitems, void * dest, int32_t destsize)', 'int _blosc_getitem(blosc2_context * context, blosc_header * header, const void * src, int32_t srcsize, int start, int nitems, void * dest, int32_t destsize)', 'int _blosc_getitem(blosc2_context * context, blosc_header * header, const void * src, int32_t srcsize, int start, int nitems, void * dest, int32_t destsize)']
        #     patch_pair_list = [('blosc/blosc2.cblosc/blosc2.c-2719,2+2554,3', 'blosc/blosc2.cblosc/blosc2.c-2699,13+2521,26', 'blosc/blosc2.cblosc/blosc2.c-2608,64+2487,7', 'blosc/blosc2.cblosc/blosc2.c-2594,2+2463,12', 'blosc/blosc2.cblosc/blosc2.c-2578,1+2448,0')]
        # if bug_id == 'OSV-2022-486':
        #     # ['blosc2_schunk * blosc2_schunk_from_buffer(uint8_t * cframe, int64_t len, _Bool copy)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy, const blosc2_io * udio)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy, const blosc2_io * udio)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy, const blosc2_io * udio)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy, const blosc2_io * udio)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy, const blosc2_io * udio)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy, const blosc2_io * udio)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy, const blosc2_io * udio)', 'blosc2_schunk * frame_to_schunk(blosc2_frame_s * frame, _Bool copy, const blosc2_io * udio)', 'int frame_get_vlmetalayers(blosc2_frame_s * frame, blosc2_schunk * schunk)', 'int frame_get_vlmetalayers(blosc2_frame_s * frame, blosc2_schunk * schunk)', 'int get_header_info(blosc2_frame_s * frame, int32_t * header_len, int64_t * frame_len, int64_t * nbytes, int64_t * cbytes, int32_t * blocksize, int32_t * chunksize, int32_t * nchunks, int32_t * typesize, uint8_t * compcode, uint8_t * compcode_meta, uint8_t * clevel, uint8_t * filters, uint8_t * filters_meta, const blosc2_io * io)', 'int get_header_info(blosc2_frame_s * frame, int32_t * header_len, int64_t * frame_len, int64_t * nbytes, int64_t * cbytes, int32_t * blocksize, int32_t * chunksize, int32_t * nchunks, int32_t * typesize, uint8_t * compcode, uint8_t * compcode_meta, uint8_t * clevel, uint8_t * filters, uint8_t * filters_meta, const blosc2_io * io)', 'int get_header_info(blosc2_frame_s * frame, int32_t * header_len, int64_t * frame_len, int64_t * nbytes, int64_t * cbytes, int32_t * blocksize, int32_t * chunksize, int32_t * nchunks, int32_t * typesize, uint8_t * compcode, uint8_t * compcode_meta, uint8_t * clevel, uint8_t * filters, uint8_t * filters_meta, const blosc2_io * io)', 'int frame_get_metalayers(blosc2_frame_s * frame, blosc2_schunk * schunk)', 'int frame_get_metalayers(blosc2_frame_s * frame, blosc2_schunk * schunk)']
        #     patch_pair_list = [('blosc/schunk.cblosc/schunk.c-476,2+446,2',), ('blosc/frame.cblosc/frame.c-1761,2+1664,2', 'blosc/frame.cblosc/frame.c-1728,5+1631,5', 'blosc/frame.cblosc/frame.c-1695,20+1598,20', 'blosc/frame.cblosc/frame.c-1663,15+1572,9', 'blosc/frame.cblosc/frame.c-1644,2+1553,2', 'blosc/frame.cblosc/frame.c-1634,2+1543,2', 'blosc/frame.cblosc/frame.c-1617,11+1526,11', 'blosc/frame.cblosc/frame.c-1586,14+1497,12'), ('blosc/frame.cblosc/frame.c-1498,24+1428,17', 'blosc/frame.cblosc/frame.c-1478,3+1409,2'), ('blosc/frame.cblosc/frame.c-434,8+431,0', 'blosc/frame.cblosc/frame.c-415,9+414,7', 'blosc/frame.cblosc/frame.c-360,30+365,24'), ('blosc/frame.cblosc/frame.c-1321,20+1257,13', 'blosc/frame.cblosc/frame.c-1309,3+1246,2')]
        
        patches_without_context = dict()
        tmp = copy.deepcopy(inmutable_args)
        if not apply_and_test_patches(patch_pair_list, [], patches_without_context, *mutable_args, *tmp) in {'trigger_but_fuzzer_build_fail', 'trigger_and_fuzzer_build'}:
            revert_and_trigger_fail_set.add((bug_id, next_commit['commit_id'], fuzzer))
        else:
            revert_and_trigger_set.add((bug_id, next_commit['commit_id'], fuzzer))
            logger.info(f'Initial revert patch set: {len(patch_pair_list)} {patch_pair_list}')
            # try to minimize the patch set
            minimal_fast = minimize_greedy(patch_pair_list, apply_and_test_patches, patches_without_context, mutable_args, inmutable_args)
            logger.info(f'Minimal revert patch set after fast minimization {bug_id}: {len(minimal_fast)} {minimal_fast}')

        patches_without_contexts[
            (bug_id, commit['commit_id'], fuzzer,
            tuple(diff_results[key].old_function_name for keys in patch_pair_list for key in keys))
        ] = patches_without_context

        get_patched_traces, transitions, signature_change_list = mutable_args

        if not os.path.exists(os.path.join(data_path, 'signature_change_list')):
            os.makedirs(os.path.join(data_path, 'signature_change_list'))
        with open(os.path.join(data_path, 'signature_change_list', f'{bug_id}_{next_commit['commit_id']}.json'), 'w') as f:
            json.dump(signature_change_list, f, indent=4)

        get_patched_traces, transitions, signature_change_list = mutable_args
        # test if the local bugs is still there using crash stack comparison
        # for bug_id_trigger in bug_ids_trigger:
        #     result, crash_output = test_fuzzer(
        #         args,
        #         bug_id_trigger,
        #         target,
        #         next_commit['commit_id'],
        #         get_patched_traces[bug_id][-1],
        #     )
        #     if result == 'not trigger':
        #         logger.info(f'\t{bug_id} not trigger local bug {bug_id_trigger}')
        #         continue

        #     trigger_info = bug_info_dataset[bug_id_trigger]
        #     trigger_fuzzer = trigger_info['reproduce']['fuzz_target']
        #     trigger_sanitizer = trigger_info['reproduce']['sanitizer'].split(' ')[0]
        #     trigger_job_type = trigger_info['reproduce']['job_type']
        #     trigger_arch = trigger_job_type.split('_')[2] if len(trigger_job_type.split('_')) > 3 else 'x86_64'
        #     trigger_input = select_crash_test_input(bug_id_trigger, testcases_env)
        #     baseline_crash_path = get_crash_stack(
        #         bug_id=bug_id_trigger,
        #         commit_id=next_commit['commit_id'],
        #         crash_test_input=trigger_input,
        #         sanitizer=trigger_sanitizer,
        #         build_csv=args.build_csv,
        #         arch=trigger_arch,
        #         testcases_env=testcases_env,
        #         target=target,
        #         fuzzer=trigger_fuzzer,
        #     )
        #     signature_file_trigger = os.path.join(
        #         data_path,
        #         'signature_change_list',
        #         f'{bug_id}_{next_commit["commit_id"]}.json',
        #     )
        #     if crashes_match(crash_output, baseline_crash_path, signature_file_trigger):
        #         logger.info(f'\t{bug_id} trigger local bug {bug_id_trigger} (stack match)\n')
        #         test_local_bug_after_patch.setdefault(bug_id_trigger, set()).add(bug_id)
        #     else:
        #         logger.info(f'\t{bug_id} trigger local bug {bug_id_trigger} but stack mismatch\n')

        
    logger.info(f"Revert and trigger set: {len(revert_and_trigger_set)} {revert_and_trigger_set}")
    logger.info(f"Revert and trigger fail set: {len(revert_and_trigger_fail_set)} {revert_and_trigger_fail_set}")
    
    return patches_without_contexts, test_local_bug_after_patch


def get_compile_commands(target, commit_id, sanitizer, build_csv, arch):
    # use libclang to parse, and save results to files
    cmd = [
        py3, f"{current_file_path}/fuzz_helper.py", "build_version", "--commit", commit_id, "--sanitizer", sanitizer,
        '--build_csv', build_csv, '--compile_commands', '--architecture', arch , target
    ]
    
    if not os.path.exists(os.path.join(data_path, f'{target}-{commit_id}')):
        logger.info(' '.join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        

if __name__ == "__main__":
    args = parse_arguments()
    # Use absolute path for the cache file
    cache_file = os.path.join(data_path, "patches", f"{args.target}_patches.pkl.gz")
    # Create cache_file's folder if it doesn't exist
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
    if os.path.exists(cache_file):
        patches_without_contexts = load_patches_pickle(cache_file)
    else:
        patches_without_contexts, test_local_bug_after_patch = revert_patch_test(args)
        # Save the patches to cache file
        save_patches_pickle(patches_without_contexts, cache_file)
    
        for bug_id, affected_bugs in test_local_bug_after_patch.items():
            logger.info(f'local bug {bug_id} is compatible with: {len(affected_bugs)} {affected_bugs}')

    # for (bug_id, commit_id, fuzzer, input_functions), patch_dict in patches_without_contexts.items():
    #     logger.info(f'bug_id {bug_id}')
    #     for key in patch_dict:
    #         patch = patch_dict[key]
    #         if patch.hiden_func_dict:
    #             for func_sig in patch.hiden_func_dict:
    #                 logger.info(f'-->{func_sig}\n')
    #         else:
    #             if patch.new_signature:
    #                 logger.info(f'-->{patch.new_signature}')
    #             elif patch.old_signature:
    #                 logger.info(f'-->{patch.old_signature}')
    #     patch_not_context = remove_context(patch_dict)
    #     for key in patch_not_context:
    #         patch = patch_not_context[key]
        # patches_without_contexts[(bug_id, commit_id, fuzzer, input_functions)] = patch_not_context
