"""Utilities for combining patch sets produced by `revert_patch_test`."""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, Tuple, Any, DefaultDict, Set, Callable, Iterable, Optional, List, Sequence
from contextlib import redirect_stdout, redirect_stderr
from types import SimpleNamespace

from utils import load_patches_pickle, save_patches_pickle
from revert_patch_test import (
    PatchInfo,
    FunctionLocation,
    revert_patch_test as execute_revert_patch_test,
    add_context,
    remove_context,
    build_fuzzer,
    select_crash_test_input,
    crashes_match,
)
from run_fuzz_test import read_json_file, py3
from tabulate import tabulate as _tabulate

local_bug_compatibility: Dict[str, Set[str]] = {}

LOCAL_BUG_NODE_PREFIX = "__local_bug__"
PendingRefreshInfo = Dict[str, Any]
pending_patch_refreshes: Dict[str, PendingRefreshInfo] = {}
REVERT_PATCH_CONFIG: Optional[Dict[str, Any]] = None
REFRESH_ATTEMPTS: Set[Tuple[str, str]] = set()
MAIN_CACHE_PATH: Optional[Path] = None
CURRENT_PATCHES: Optional[Dict[PatchSetKey, PatchSet]] = None
REANALYZE_PENDING = False


def _integrate_refreshed_patches(bug_id: str, new_patches: Optional[Dict[PatchSetKey, PatchSet]]) -> None:
    """Replace cached patches for a bug with refreshed patches and mark for reanalysis."""
    global CURRENT_PATCHES, MAIN_CACHE_PATH, REANALYZE_PENDING
    if CURRENT_PATCHES is None or MAIN_CACHE_PATH is None or not new_patches:
        return

    removed_any = False
    for key, patch in list(CURRENT_PATCHES.items()):
        owner: Optional[str] = None
        if isinstance(key, tuple) and key:
            candidate = key[0]
            if isinstance(candidate, str):
                owner = candidate
        if owner is None and isinstance(patch, dict):
            candidate = patch.get("bug_id")
            if isinstance(candidate, str):
                owner = candidate
        if owner == bug_id:
            del CURRENT_PATCHES[key]
            removed_any = True

    CURRENT_PATCHES.update(new_patches)
    REANALYZE_PENDING = True
    logger.info(
        "Integrated refreshed patches for %s into %s%s",
        bug_id,
        MAIN_CACHE_PATH,
        " (replaced prior entries)" if removed_any else "",
    )
current_file_path = os.path.dirname(os.path.abspath(__file__))
ossfuzz_path = os.path.abspath(os.path.join(current_file_path, '..', 'oss-fuzz'))
data_path = os.path.abspath(os.path.join(current_file_path, '..', 'data'))
patch_path = os.path.join(os.path.join(current_file_path, '..', 'patch'))


logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)


PatchSetKey = Tuple[Any, ...] # (e.g., (bug_id, commit_id, fuzzer, (func_a, func_b, ...)))
PatchSet = Dict[str, Any]


def configure_revert_patch(config: Optional[Dict[str, Any]]) -> None:
    """Register configuration used to invoke revert_patch_test when needed."""
    global REVERT_PATCH_CONFIG
    REVERT_PATCH_CONFIG = config


def _trigger_revert_patch_for_bug(bug_id: str, required_commit: Optional[str]) -> bool:
    """Invoke revert_patch_test for the given bug if configuration is present."""
    if not REVERT_PATCH_CONFIG or not required_commit:
        return False

    attempt_key = (bug_id, required_commit[:6])
    if attempt_key in REFRESH_ATTEMPTS:
        return False
    REFRESH_ATTEMPTS.add(attempt_key)

    config = REVERT_PATCH_CONFIG
    args = SimpleNamespace(
        target_test_result=str(config["target_test_result"]),
        bug_info=str(config["bug_info"]),
        build_csv=str(config["build_csv"]),
        target=str(config["target"]),
        bug_id=bug_id,
        buggy_commit=required_commit,
    )

    log_path: Optional[Path] = None
    output_dir: Optional[Path] = config.get("output_dir")
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        log_path = output_dir / f"revert_{config['target']}_{bug_id}_{required_commit[:6]}.log"

    patches: Optional[Dict[str, Any]] = None
    local_tests: Optional[Dict[str, Any]] = None
    if log_path:
        with log_path.open("w", encoding="utf-8") as handle, redirect_stdout(handle), redirect_stderr(handle):
            patches, local_tests = execute_revert_patch_test(args)
    else:
        patches, local_tests = execute_revert_patch_test(args)
    logger.info("Triggered revert_patch_test for bug %s at commit %s", bug_id, required_commit[:6])
    return {"patches": patches, "local_tests": local_tests}


class PatchCompatibilityGraph:
    """Undirected graph describing compatibility relationships between patch sets."""

    def __init__(self) -> None:
        self._nodes: Dict[PatchSetKey, PatchSet] = {}
        self._edges: DefaultDict[PatchSetKey, Set[PatchSetKey]] = defaultdict(set)

    def add_patch(self, identifier: PatchSetKey, patch: PatchSet) -> None:
        """Register a patch node."""
        self._nodes[identifier] = patch

    def add_compatibility(self, lhs: PatchSetKey, rhs: PatchSetKey) -> None:
        """Record that two patches are compatible."""
        self._edges[lhs].add(rhs)
        self._edges[rhs].add(lhs)

    def connect_compatibilities(self, predicate: Callable[[PatchSetKey, PatchSetKey], bool]) -> None:
        """Evaluate all node pairs and add compatibility edges."""
        identifiers: Iterable[PatchSetKey] = list(self._nodes.keys())
        for idx, lhs in enumerate(identifiers):
            for rhs in identifiers[idx + 1 :]:
                if predicate(lhs, rhs):
                    self.add_compatibility(lhs, rhs)

    @property
    def nodes(self) -> Dict[PatchSetKey, PatchSet]:
        """Return mapping of node identifier to patch payload."""
        return self._nodes

    @property
    def edges(self) -> Dict[PatchSetKey, Set[PatchSetKey]]:
        """Return adjacency list representing compatibility edges."""
        return self._edges

    def edge_count(self) -> int:
        """Return the total number of undirected edges."""
        return sum(len(neighbors) for neighbors in self._edges.values()) // 2

    def fully_compatible_groups(self, min_size: int = 2) -> List[List[PatchSetKey]]:
        """
        Return groups where every node is compatible with every other node (cliques).

        min_size controls the minimum number of nodes required for a group to be considered.
        """

        if min_size <= 0:
            min_size = 1

        nodes: Set[PatchSetKey] = set(self._nodes.keys())
        adjacency: Dict[PatchSetKey, Set[PatchSetKey]] = {
            node: set(self._edges.get(node, set())) & nodes for node in nodes
        }
        cliques: List[List[PatchSetKey]] = []

        def bron_kerbosch(r: Set[PatchSetKey], p: Set[PatchSetKey], x: Set[PatchSetKey]) -> None:
            if not p and not x:
                if len(r) >= min_size:
                    cliques.append(sorted(r, key=str))
                return
            for node in list(p):
                bron_kerbosch(r | {node}, p & adjacency[node], x & adjacency[node])
                p.remove(node)
                x.add(node)

        bron_kerbosch(set(), set(nodes), set())

        cliques.sort(key=lambda group: (-len(group), [str(node) for node in group]))
        return cliques


def _format_node_label(identifier: PatchSetKey) -> str:
    """
    Produce a human-friendly label for Graphviz nodes.

    identifier is expected to be shaped like
      (bug_id, commit_id, fuzzer, (func_a, func_b, ...))
    but the implementation is defensive and will tolerate divergent tuples.
    """

    def safe_get(index: int) -> str:
        if len(identifier) > index and identifier[index] is not None:
            return str(identifier[index])
        return ""

    bug_id = safe_get(0) or "unknown-bug"
    commit_id = safe_get(1)
    fuzzer = safe_get(2)
    functions = identifier[3] if len(identifier) > 3 else ()
    func_names = [str(func) for func in functions if func]
    if not bug_id:
        bug_id = "unknown-bug"

    return bug_id.replace("\\", "\\\\").replace("\"", "\\\"")


def _format_local_node_label(bug_id: str) -> str:
    """Return the label used for synthetic local bug nodes."""
    safe_id = bug_id.replace("\\", "\\\\").replace("\"", "\\\"")
    return f"{safe_id} (local)"


def _is_local_bug_identifier(identifier: PatchSetKey) -> bool:
    """True when the identifier represents a synthetic local bug node."""
    return (
        isinstance(identifier, tuple)
        and len(identifier) >= 2
        and identifier[0] == LOCAL_BUG_NODE_PREFIX
        and isinstance(identifier[1], str)
    )


def _extract_commit_id(identifier: PatchSetKey) -> Optional[str]:
    """Return commit id embedded in the identifier tuple, if available."""
    if len(identifier) > 1 and isinstance(identifier[1], str):
        return identifier[1]
    return None


def _commit_prefix(commit_id: Optional[str], length: int = 6) -> Optional[str]:
    """Return the first `length` characters of a commit id, if available."""
    if commit_id:
        return commit_id[:length]
    return None


def _build_commit_index(parsed_data: Optional[List[Dict[str, Any]]]) -> Dict[str, int]:
    """Return mapping from commit id to its order index in the CSV."""
    if not parsed_data:
        return {}
    return {row.get("commit_id"): idx for idx, row in enumerate(parsed_data) if row.get("commit_id")}


def _select_best_shared_commit(
    shared_commits: Set[str], reference_commit: Optional[str], commit_index: Dict[str, int]
) -> Optional[str]:
    """Choose the shared commit closest to the reference commit in the CSV ordering."""
    if not shared_commits:
        return None
    if not commit_index:
        return next(iter(shared_commits))

    def idx(commit: str) -> int:
        return commit_index.get(commit, float("inf"))

    if reference_commit and reference_commit in commit_index:
        ref_idx = commit_index[reference_commit]
        best_commit = min(shared_commits, key=lambda commit: abs(idx(commit) - ref_idx))
        if idx(best_commit) != float("inf"):
            return best_commit

    best_commit = min(shared_commits, key=lambda commit: idx(commit))
    if idx(best_commit) == float("inf"):
        return next(iter(shared_commits))
    return best_commit


def _record_pending_refresh(
    bug_id: str, required_commit: Optional[str], current_commit: Optional[str], partner_bug_id: str
) -> Dict[str, Any]:
    info = pending_patch_refreshes.setdefault(
        bug_id,
        {
            "required_commit": required_commit,
            "current_commit": current_commit,
            "partners": set(),
            "partner_requirements": {},
            "attempted": False,
            "attempt_success": None,
        },
    )
    if required_commit:
        info["required_commit"] = required_commit
    info["current_commit"] = current_commit
    partners: Set[str] = info.setdefault("partners", set())
    partners.add(partner_bug_id)
    partner_requirements: Dict[str, Optional[str]] = info.setdefault("partner_requirements", {})
    partner_requirements[partner_bug_id] = required_commit
    return info


def request_new_patch_for_bug(
    bug_id: str, required_commit: Optional[str], current_commit: Optional[str], partner_bug_id: str
) -> None:
    """Invoke revert_patch_test for the given bug, recording attempt status."""
    info = _record_pending_refresh(bug_id, required_commit, current_commit, partner_bug_id)
    cache_dir = Path(data_path) / "patches"
    target_name = (
        REVERT_PATCH_CONFIG.get("target") if REVERT_PATCH_CONFIG and "target" in REVERT_PATCH_CONFIG else "target"
    )
    commit_fragment = (required_commit or "unknown")[:6]
    cache_file = cache_dir / f"{target_name}_{bug_id}_{commit_fragment}_patches.pkl.gz"
    logger.info("Checking for cached refreshed patches for %s at %s", bug_id, cache_file)
    cache_dir.mkdir(parents=True, exist_ok=True)
    if cache_file.exists():
        info["cached_patch"] = cache_file
        patches = load_patches_pickle(cache_file)
        _integrate_refreshed_patches(bug_id, patches)
        return
    else:
        if info.get("attempted"):
            return
        result = _trigger_revert_patch_for_bug(bug_id, required_commit)
        local_tests = result.get("local_tests")
        compatible_locals = set()
        for local_bug in local_tests:
            compatible_locals.add(local_bug)
        local_bug_compatibility[bug_id] = compatible_locals

        info["attempted"] = True
        info["attempt_success"] = bool(result)
        if result and result.get("patches"):
            info["refresh_result"] = result
            save_patches_pickle(result["patches"], cache_file)
            _integrate_refreshed_patches(bug_id, result["patches"])


def attach_local_bug_nodes(graph: PatchCompatibilityGraph) -> Tuple[int, int]:
    """
    Add synthetic local bug nodes to the compatibility graph and connect edges.

    Returns (nodes_added, edges_added).
    """

    bug_to_nodes: DefaultDict[str, List[PatchSetKey]] = defaultdict(list)
    for identifier in list(graph.nodes.keys()):
        if _is_local_bug_identifier(identifier):
            continue
        if isinstance(identifier, tuple) and identifier:
            bug_id = identifier[0]
            if isinstance(bug_id, str):
                bug_to_nodes[bug_id].append(identifier)

    nodes_added = 0
    edges_added = 0
    for bug_id, compatible_locals in local_bug_compatibility.items():
        patch_nodes = bug_to_nodes.get(bug_id)
        if not patch_nodes:
            continue
        for local_bug in sorted(compatible_locals):
            local_identifier: PatchSetKey = (LOCAL_BUG_NODE_PREFIX, local_bug)
            if local_identifier not in graph.nodes:
                graph.add_patch(local_identifier, {"local_bug_id": local_bug, "remote_bug_id": bug_id})
                nodes_added += 1
            for patch_identifier in patch_nodes:
                neighbors = graph.edges.get(local_identifier)
                if neighbors is None:
                    neighbors = set()
                if patch_identifier not in neighbors:
                    edges_added += 1
                graph.add_compatibility(local_identifier, patch_identifier)

    local_identifiers = [identifier for identifier in graph.nodes if _is_local_bug_identifier(identifier)]
    for idx, lhs in enumerate(local_identifiers):
        for rhs in local_identifiers[idx + 1 :]:
            neighbors = graph.edges.get(lhs)
            if neighbors is None:
                neighbors = set()
            if rhs not in neighbors:
                edges_added += 1
            graph.add_compatibility(lhs, rhs)

    return nodes_added, edges_added


def write_graphviz(graph: PatchCompatibilityGraph, output_path: Path) -> None:
    """Serialize the compatibility graph into a Graphviz DOT file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    node_identifiers = list(graph.nodes.keys())
    node_names: Dict[PatchSetKey, str] = {identifier: f"n{idx}" for idx, identifier in enumerate(node_identifiers)}

    unique_edges: Set[Tuple[str, str]] = set()
    for lhs, neighbors in graph.edges.items():
        for rhs in neighbors:
            lhs_name = node_names[lhs]
            rhs_name = node_names[rhs]
            normalized = tuple(sorted((lhs_name, rhs_name)))
            unique_edges.add(normalized)

    with output_path.open("w", encoding="utf-8") as graph_file:
        graph_file.write("graph PatchCompatibility {\n")
        graph_file.write("  graph [splines=true, overlap=false];\n")
        graph_file.write("  node [shape=box, style=filled, fillcolor=\"#f0f5ff\", fontsize=10];\n")

        local_node_count = 0
        for identifier, node_name in node_names.items():
            if _is_local_bug_identifier(identifier):
                local_node_count += 1
                bug_id = identifier[1]
                label = _format_local_node_label(bug_id)
                graph_file.write(
                    f"  {node_name} [label=\"{label}\", style=filled, fillcolor=\"#ffd6d6\", color=\"#b30000\", fontcolor=\"#660000\"];\n"
                )
            else:
                label = _format_node_label(identifier)
                graph_file.write(f"  {node_name} [label=\"{label}\"];\n")

        for lhs_name, rhs_name in sorted(unique_edges):
            graph_file.write(f"  {lhs_name} -- {rhs_name};\n")

        graph_file.write("}\n")

    logger.info(
        "Wrote Graphviz representation with %d nodes (%d local) and %d edges to %s",
        len(node_identifiers),
        local_node_count,
        len(unique_edges),
        output_path,
    )


def _expand_function_set(funcs: Set[str], commit: str,signature_map: Optional[Dict[str, Set[str]]]) -> Set[str]:
    """Return function names plus any equivalents defined in the signature map."""
    if not signature_map:
        return funcs
    expanded: Set[str] = set()
    for func in funcs:
        revert_func = f"revert_{commit}_{func}"
        expanded.add(func)
        equivalents = signature_map.get(revert_func)
        if equivalents:
            expanded.update(equivalents)
    return expanded


def is_compatiable(
    key_a: PatchSetKey,
    key_b: PatchSetKey,
    bug_distribution: Optional[List[Dict[str, Any]]] = None,
    commit_index: Optional[Dict[str, int]] = None,
    signature_map: Optional[Dict[str, Set[str]]] = None,
) -> bool:
    """Return True when two patch sets are compatible based on touched functions and shared triggers."""

    def extract_functions(key: PatchSetKey) -> Set[str]:
        if len(key) < 4:
            return set()
        commit = key[1]
        funcs = key[3]
        if isinstance(funcs, (list, tuple, set)):
            return {str(name) for name in funcs}, commit
        logger.debug("Unexpected function list type for key %s: %s", key, type(funcs).__name__)
        return set(), commit

    funcs_a = _expand_function_set(*extract_functions(key_a), signature_map)
    funcs_b = _expand_function_set(*extract_functions(key_b), signature_map)

    if funcs_a.isdisjoint(funcs_b):
        return True

    if not bug_distribution:
        return False

    bug1 = key_a[0] if len(key_a) > 0 else None
    bug2 = key_b[0] if len(key_b) > 0 else None
    if not isinstance(bug1, str) or not isinstance(bug2, str):
        logger.debug("Cannot determine bug ids for keys %s and %s", key_a, key_b)
        return False

    shared_commits = have_joint_triggers(bug_distribution, bug1, bug2)
    if shared_commits:
        commit_a = _extract_commit_id(key_a)
        commit_b = _extract_commit_id(key_b)
        shared_prefixes = {_commit_prefix(commit) for commit in shared_commits if commit}
        prefix_a = _commit_prefix(commit_a)
        prefix_b = _commit_prefix(commit_b)
        needs_refresh_a = prefix_a not in shared_prefixes
        needs_refresh_b = prefix_b not in shared_prefixes
        commit_map = commit_index or {}
        if not needs_refresh_b:
            required_commit_a = prefix_b
        else:
            required_commit_a = _select_best_shared_commit(shared_commits, commit_a, commit_map)
        if not needs_refresh_a:
            required_commit_b = prefix_a
        else:
            required_commit_b = _select_best_shared_commit(shared_commits, commit_b, commit_map)
        if needs_refresh_a:
            _record_pending_refresh(bug1, required_commit_a or "", commit_a, bug2)
        if needs_refresh_b:
            _record_pending_refresh(bug2, required_commit_b or "", commit_b, bug1)
        if not needs_refresh_a and not needs_refresh_b:
            logger.info(
                "Bugs %s and %s share at least one triggering commit with aligned patches; treating as compatible",
                bug1,
                bug2,
            )
        else:
            refresh_notes = []
            if needs_refresh_a:
                refresh_notes.append(f"{bug1} needs {required_commit_a or 'unknown'}")
            if needs_refresh_b:
                refresh_notes.append(f"{bug2} needs {required_commit_b or 'unknown'}")
            logger.info(
                "Bugs %s and %s share at least one triggering commit but require refresh before alignment (%s)",
                bug1,
                bug2,
                ", ".join(refresh_notes),
            )
        return True

    return False


def merge_patches(
    patches_without_contexts: Dict[PatchSetKey, PatchSet],
    bug_distribution: Optional[List[Dict[str, Any]]] = None,
    signature_map: Optional[Dict[str, Set[str]]] = None,
) -> PatchCompatibilityGraph:
    """Build a compatibility graph where each node represents an entire patch dictionary."""

    pending_patch_refreshes.clear()
    REFRESH_ATTEMPTS.clear()
    graph = PatchCompatibilityGraph()

    for key_tuple, patch_dict in patches_without_contexts.items():
        if not isinstance(patch_dict, dict):
            logger.warning("Expected dict for patch set %s, got %s", key_tuple, type(patch_dict).__name__)
            continue
        graph.add_patch(key_tuple, patch_dict)

    commit_index = _build_commit_index(bug_distribution)
    graph.connect_compatibilities(
        lambda a, b: is_compatiable(a, b, bug_distribution, commit_index, signature_map)
    )
    local_nodes_added, local_edges_added = attach_local_bug_nodes(graph)

    total_edges = graph.edge_count()
    logger.info(
        "Constructed compatibility graph: %d nodes (%d local), %d edges (+%d local edges)",
        len(graph.nodes),
        sum(1 for identifier in graph.nodes if _is_local_bug_identifier(identifier)),
        total_edges,
        local_edges_added,
    )

    return graph


def report_compatible_groups(graph: PatchCompatibilityGraph, min_size: int = 2) -> List[List[PatchSetKey]]:
    """Log all fully compatible bug groups with at least min_size members, and return them."""

    def describe_identifier(identifier: PatchSetKey) -> str:
        if _is_local_bug_identifier(identifier):
            return f"{identifier[1]} (local)"
        if isinstance(identifier, tuple) and identifier:
            bug_id = identifier[0]
            if isinstance(bug_id, str):
                return bug_id
        return str(identifier)

    groups = graph.fully_compatible_groups(min_size=min_size)
    if not groups:
        logger.info("No fully compatible bug groups of size >= %d found.", min_size)
        return []

    def group_sort_key(group: List[PatchSetKey]) -> Tuple[int, int, Tuple[str, ...]]:
        local_bug_count = sum(1 for identifier in group if _is_local_bug_identifier(identifier))
        identifier_strings = tuple(str(identifier) for identifier in group)
        # Sort primarily by group size (descending), then by local bug count (descending),
        # and finally by identifier strings to keep ordering stable.
        return (-len(group), -local_bug_count, identifier_strings)

    groups.sort(key=group_sort_key)

    logger.info("Detected %d fully compatible bug groups (size >= %d):", len(groups), min_size)
    for idx, group in enumerate(groups, start=1):
        identifiers = [describe_identifier(identifier) for identifier in group]
        logger.info("  Group %d (%d bugs): %s", idx, len(group), "; ".join(identifiers))
    return groups


def _render_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    """Return a formatted ASCII table using tabulate when available."""

    if _tabulate:
        column_alignments = ["left"] + ["center"] * (len(headers) - 1)
        return _tabulate(
            rows,
            headers=headers,
            tablefmt="psql",
            colalign=column_alignments,
            stralign="center",
            disable_numparse=True,
        )

    return _render_ascii_table(headers, rows)


def _render_ascii_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    """Fallback pure-Python table formatter that keeps separators aligned."""

    data = [list(map(str, headers))] + [list(map(str, row)) for row in rows]
    column_widths: List[int] = []
    for column_values in zip(*data):
        column_widths.append(max(len(value) for value in column_values))

    def format_row(row: Sequence[str]) -> str:
        padded_cells: List[str] = []
        for idx, (value, width) in enumerate(zip(row, column_widths)):
            if idx == 0:
                cell = value.ljust(width)
            else:
                pad = width - len(value)
                left = pad // 2
                right = pad - left
                cell = f"{' ' * left}{value}{' ' * right}"
            padded_cells.append(f" {cell} ")
        return "|" + "|".join(padded_cells) + "|"

    divider = "+" + "+".join("-" * (width + 2) for width in column_widths) + "+"
    lines = [divider, format_row(headers), divider]
    for row in rows:
        lines.append(format_row(row))
    lines.append(divider)
    return "\n".join(lines)


def log_patch_function_table(graph: PatchCompatibilityGraph) -> None:
    """Emit a readable table outlining which bugs touch which functions."""

    bug_to_functions: DefaultDict[str, Set[str]] = defaultdict(set)
    all_functions: Set[str] = set()

    for identifier in graph.nodes:
        if _is_local_bug_identifier(identifier):
            continue
        if not isinstance(identifier, tuple) or not identifier:
            continue
        bug_id = identifier[0]
        if not isinstance(bug_id, str):
            continue
        raw_functions = identifier[3] if len(identifier) > 3 else ()
        if isinstance(raw_functions, (list, tuple, set)):
            functions = raw_functions
        elif raw_functions:
            functions = (raw_functions,)
        else:
            functions = ()
        for func in functions:
            if not func:
                continue
            func_name = str(func)
            bug_to_functions[bug_id].add(func_name)
            all_functions.add(func_name)

    if not bug_to_functions or not all_functions:
        logger.info("Function coverage table: no function metadata available.")
        return

    bug_ids = sorted(bug_to_functions.keys())
    function_list = sorted(all_functions)

    def _shorten_bug_id(bug_id: str) -> str:
        if bug_id.startswith("OSV-"):
            return bug_id[4:]
        return bug_id

    display_bug_ids = [_shorten_bug_id(bug_id) for bug_id in bug_ids]
    headers = ["Function"] + display_bug_ids
    rows: List[List[str]] = []
    for func_name in function_list:
        row = [func_name]
        for bug_id in bug_ids:
            marker = "✓" if func_name in bug_to_functions.get(bug_id, set()) else ""
            row.append(marker)
        rows.append(row)

    table = _render_table(headers, rows)
    logger.info("Function coverage table (✓ indicates the bug touches the function):")
    for line in table.splitlines():
        logger.info(line)
    if not _tabulate:
        logger.info("  (Install 'tabulate' for enhanced table formatting.)")
    if any(bug_id.startswith("OSV-") for bug_id in bug_ids):
        logger.info("  (Bug headers omit the shared 'OSV-' prefix for readability.)")


def report_pending_patch_refreshes(group: Optional[List[PatchSetKey]], idx: int) -> None:
    """
    Emit recorded patch refresh requirements scoped to the provided group (typically Group 1).
    """

    if not group:
        return

    relevant_bug_ids: Set[str] = set()
    for identifier in group:
        if _is_local_bug_identifier(identifier):
            continue
        if isinstance(identifier, tuple) and identifier:
            bug_id = identifier[0]
            if isinstance(bug_id, str):
                relevant_bug_ids.add(bug_id)

    if not relevant_bug_ids:
        return

    filtered = {bug: info for bug, info in pending_patch_refreshes.items() if bug in relevant_bug_ids}
    if not filtered:
        return

    report_entries: List[Dict[str, Any]] = []
    for bug_id in sorted(filtered):
        info = filtered[bug_id]
        partners = sorted(info.get("partners", []))
        partners_in_group = [partner for partner in partners if partner in relevant_bug_ids]
        if not partners_in_group:
            continue
        partner_requirements: Dict[str, Optional[str]] = info.get("partner_requirements", {})
        partner_details = [
            {
                "partner": partner,
                "commit": partner_requirements.get(partner),
            }
            for partner in partners_in_group
        ]
        report_entries.append(
            {
                "bug_id": bug_id,
                "info": info,
                "partner_details": partner_details,
            }
        )

    if not report_entries:
        logger.info("Pending patch refreshes impacting Group %d: none", idx)
        return

    logger.info("Pending patch refreshes impacting Group %d (%d bugs):", idx, len(report_entries))
    for entry in report_entries:
        bug_id = entry["bug_id"]
        info = entry["info"]
        partner_details = entry["partner_details"]
        first_partner = partner_details[0]["partner"] if partner_details else None
        required_full = partner_details[0]["commit"] if partner_details else None
        if not required_full:
            required_full = info.get("required_commit")
        current_full = info.get("current_commit")
        required_fragment = (required_full or "unknown")[:6]
        current_fragment = (current_full or "unknown")[:6]
        partner_text = ", ".join(
            f"{detail['partner']}@{(detail['commit'] or 'unknown')[:6]}"
            if detail.get("commit")
            else detail["partner"]
            for detail in partner_details
        )
        attempt_note = ""
        if info.get("attempted"):
            attempt_status = "success" if info.get("attempt_success") else "failed"
            attempt_note = f"; revert attempt {attempt_status}"
        logger.info(
            "  %s: requires %s (current %s) [shares commit with %s]%s",
            bug_id,
            required_fragment,
            current_fragment,
            partner_text,
            attempt_note,
        )
        if first_partner:
            request_new_patch_for_bug(bug_id, required_full, current_full, first_partner)


def finalize_patch_group(
    group: Optional[List[PatchSetKey]],
    patches: Optional[Dict[PatchSetKey, PatchSet]],
    target_repo_path: Optional[str],
    target_commit: Optional[str],
) -> Optional[str]:
    """Restore context lines for the selected group's patches by invoking add_context."""

    if not group:
        logger.info("No compatible group selected for finalization; skipping context restoration.")
        return
    if not patches:
        logger.info("Patch cache is empty; nothing to finalize.")
        return
    if not target_repo_path:
        logger.warning(
            "Unable to finalize patches because target repository path is unknown; "
            "set REPO_PATH and provide --revert_target."
        )
        return
    if not os.path.isdir(target_repo_path):
        logger.warning("Target repository path %s does not exist; skipping finalization.", target_repo_path)
        return
    if not target_commit:
        logger.warning("target_commit not provided; cannot finalize merged patches.")
        return

    merged_patches: Dict[str, PatchInfo] = {}
    key_list: List[str] = []

    for identifier in group:
        if _is_local_bug_identifier(identifier):
            continue
        patch_dict = patches.get(identifier)
        patch_not_context = remove_context(patch_dict)
        for patch_key, patch in patch_not_context.items():
            function_names = []
            if patch.hiden_func_dict:
                function_names = list(patch.hiden_func_dict.keys())
            elif patch.old_signature:
                function_names = [patch.old_signature]
            else:
                function_names = ["extra patch", patch.file_path_old, identifier[0]]

            merged_key = f"{identifier[1]}::{','.join(function_names)}"
            merged_patches[merged_key] = patch
            if merged_key not in key_list:
                key_list.append(merged_key)

    if not merged_patches:
        logger.info("No PatchInfo entries found for the selected group; skipping finalization.")
        return

    sorted_keys = sorted(
        key_list,
        key=lambda key: getattr(merged_patches[key], "new_start_line", 0) or 0,
        reverse=True,
    )
    
    try:
        add_context(merged_patches, sorted_keys, target_commit, target_repo_path)
        logger.info(
            "Restored context for commit %s using %d patches from %d identifiers.",
            target_commit[:6],
            len(sorted_keys),
            len(group),
        )
    except Exception:
        logger.exception("Failed to add context for commit %s.", target_commit)

    final_path = os.path.join(
        patch_path,
        f"group_{target_commit[:6]}_final.diff",
    )
    os.makedirs(os.path.dirname(final_path), exist_ok=True)
    with open(final_path, "w", encoding="utf-8") as handle:
        for key in sorted_keys:
            patch = merged_patches[key]
            handle.write(patch.patch_text)
            if not patch.patch_text.endswith("\n"):
                handle.write("\n")
    logger.info("Wrote merged finalized patches to %s", final_path)
    return final_path


def have_joint_triggers(parsed_data: list[dict[str, Any]], bug1: str, bug2: str) -> Set[str]:
    """
    Return the set of commit ids where both bugs are marked '1|1' or '0.5|1'.

    parsed_data follows the structure produced by prepare_transplant/parse_csv_file:
      [{'commit_id': 'abc123', 'osv_statuses': {'OSV-1': '1|1', ...}}, ...]
    """

    def is_trigger(value: str | None) -> bool:
        return value in {'1|1', '0.5|1'}

    commits: Set[str] = set()
    for row in parsed_data:
        statuses = row.get('osv_statuses', {})
        if is_trigger(statuses.get(bug1)) and is_trigger(statuses.get(bug2)):
            commit_id = row.get('commit_id')
            if commit_id:
                commits.add(commit_id)
    return commits


def parse_csv_data(csv_content: str) -> list[dict[str, Any]]:
    """Parse the CSV payload used for bug distribution metadata."""
    lines = [line for line in csv_content.strip().splitlines() if line.strip()]
    if not lines:
        return []

    headers = lines[0].split(",")
    parsed_rows: list[dict[str, Any]] = []

    for line in lines[1:]:
        values = line.split(",")
        if not values or len(values) < 2:
            continue

        row: dict[str, Any] = {
            "commit_id": values[0],
            "osv_statuses": {},
            "poc_count": 0,
        }

        for idx in range(1, min(len(headers), len(values))):
            bug_id = headers[idx]
            value = values[idx] or None
            row["osv_statuses"][bug_id] = value
            if value == "1|1" or value == "0.5|1":
                row["poc_count"] += 1

        parsed_rows.append(row)

    return parsed_rows


def parse_csv_file(file_path: str) -> list[dict[str, Any]]:
    """Load a CSV file and return the structured bug distribution data."""
    with open(file_path, "r", encoding="utf-8") as handle:
        return parse_csv_data(handle.read())


def parse_bug_distribution_csv(csv_path: Path) -> list[dict[str, Any]]:
    """Parse the bug distribution CSV into the structure expected by have_joint_trigger."""
    return parse_csv_file(str(csv_path))


def load_signature_change_map(file_path: Path) -> Dict[str, Set[str]]:
    """Load signature equivalence mappings from JSON file containing [new, old] pairs."""
    with open(file_path, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    equivalence: DefaultDict[str, Set[str]] = defaultdict(set)
    if isinstance(data, list):
        for pair in data:
            if not isinstance(pair, list) or len(pair) != 2:
                continue
            new_name, old_name = pair
            if not isinstance(new_name, str) or not isinstance(old_name, str):
                continue
            equivalence[old_name].add(new_name)

    return {key: set(values) for key, values in equivalence.items()}


def load_local_bug_compatibility(target: Optional[str]) -> None:
    """Populate local_bug_compatibility from data/local_compatibility/{target}.json."""
    global local_bug_compatibility
    local_bug_compatibility = {}
    if not target:
        return

    compatibility_file = Path(data_path) / "local_compatibility" / f"{target}.json"
    try:
        with compatibility_file.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        logger.info("Local compatibility file %s not found; continuing without local bugs.", compatibility_file)
        return
    except json.JSONDecodeError:
        logger.warning("Local compatibility file %s is not valid JSON; ignoring.", compatibility_file)
        return

    if not isinstance(data, dict):
        logger.warning("Local compatibility file %s must contain an object mapping.", compatibility_file)
        return

    parsed: Dict[str, Set[str]] = {}
    for bug_id, compatibles in data.items():
        if not isinstance(bug_id, str):
            continue
        if not isinstance(compatibles, (list, tuple, set)):
            continue
        compat_set = {item for item in compatibles if isinstance(item, str)}
        if compat_set:
            parsed[bug_id] = compat_set
    local_bug_compatibility = parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge patches generated by revert_patch_test.")
    parser.add_argument(
        "cache_file",
        type=Path,
        help="Path to the pickle file storing patches_without_contexts.",
    )
    parser.add_argument(
        "--bug_distribution_csv",
        type=Path,
        help="CSV file describing bug-trigger distribution (same format as prepare_transplant input).",
    )
    parser.add_argument(
        "--graphviz_output",
        type=Path,
        help="Write the compatibility graph to this Graphviz DOT file for visualization.",
    )
    parser.add_argument(
        "--fuzz_target",
        help="Name of the fuzz target to build and verify after merging patches.",
    )
    parser.add_argument(
        "--revert_bug_info",
        type=Path,
        help="JSON metadata passed as --bug_info to revert_patch_test.",
    )
    parser.add_argument(
        "--revert_build_csv",
        type=Path,
        help="CSV with build mapping passed as --build_csv to revert_patch_test.",
    )
    parser.add_argument(
        "--revert_target",
        help="Target project name passed as --target to revert_patch_test.",
    )
    parser.add_argument(
        "--revert_output_dir",
        type=Path,
        help="Directory where revert_patch_test stdout/stderr should be captured.",
    )
    parser.add_argument(
        "--target_commit",
        help="Commit hash to use as the base when re-adding context to merged patches.",
    )
    parser.add_argument(
        "--signature_change_file",
        type=Path,
        help="JSON file containing signature mappings [[version2, version1], ...] used for compatibility checks.",
    )
    return parser.parse_args()


def _stack_verification_for_bug(
    bug_id: str,
    bug_commit: str,
    bug_info_dataset: Dict[str, Any],
    target: str,
    target_commit: str,
) -> str:
    """Run reproduce helper for `bug_id` and compare stack traces with the baseline."""
    if not target_commit:
        return "missing target commit"
    bug_info = bug_info_dataset.get(bug_id)
    if not bug_info:
        return "bug info missing"
    testcases_env = os.getenv("TESTCASES", "")
    if not testcases_env:
        return "TESTCASES not set"

    reproduce_cfg = bug_info.get("reproduce", {})
    fuzzer = reproduce_cfg.get("fuzz_target")
    sanitizer = (reproduce_cfg.get("sanitizer") or "").split(" ")[0]
    if not fuzzer or not sanitizer:
        return "reproduce config incomplete"

    testcase_path = os.path.join(testcases_env, f"testcase-{bug_id}")
    reproduce_cmd = [
        py3,
        f"{current_file_path}/fuzz_helper.py",
        "reproduce",
        target,
        fuzzer,
        testcase_path,
        "-e",
        "ASAN_OPTIONS=detect_leaks=0",
    ]
    logger.info("Running reproduce command for %s: %s", bug_id, " ".join(reproduce_cmd))
    test_result = subprocess.run(reproduce_cmd, capture_output=True, text=True)
    combined_output = (test_result.stderr or "") + (test_result.stdout or "")
    lowered = combined_output.lower()
    if "sanitizer" not in lowered or sanitizer.lower() not in lowered:
        return "not triggered"

    crash_input = select_crash_test_input(bug_id, testcases_env)
    baseline_crash_path = os.path.join(
        data_path,
        "crash",
        f"target_crash-{bug_commit[:6]}-{crash_input}.txt",
    )
    signature_file = os.path.join(
        data_path,
        "signature_change_list",
        f"{bug_id}_{target_commit}.json",
    )
    if crashes_match(combined_output, baseline_crash_path, signature_file):
        return "triggered (stack matches)"
    return "triggered (stack mismatch)"


def main() -> None:
    args = parse_args()
    global MAIN_CACHE_PATH, CURRENT_PATCHES
    cache_file = args.cache_file
    patches_without_contexts = load_patches_pickle(cache_file)
    MAIN_CACHE_PATH = cache_file
    CURRENT_PATCHES = patches_without_contexts
    revert_config: Optional[Dict[str, Any]] = None
    revert_args_provided = [
        args.bug_distribution_csv,
        args.revert_bug_info,
        args.revert_build_csv,
        args.revert_target,
    ]
    if all(revert_args_provided):
        revert_config = {
            "target_test_result": args.bug_distribution_csv,
            "bug_info": args.revert_bug_info,
            "build_csv": args.revert_build_csv,
            "target": args.revert_target,
        }
        if args.revert_output_dir:
            revert_config["output_dir"] = args.revert_output_dir
    elif any(revert_args_provided):
        logger.warning(
            "Incomplete revert_patch_test configuration supplied; automatic patch refresh disabled. "
            "Provide --bug_distribution_csv and all --revert_* flags to enable it."
        )
    configure_revert_patch(revert_config)
    load_local_bug_compatibility(args.revert_target)
    signature_change_map: Optional[Dict[str, Set[str]]] = None
    if args.signature_change_file:
        try:
            signature_change_map = load_signature_change_map(args.signature_change_file)
            logger.info(
                "Loaded %d signature mapping entries from %s",
                len(signature_change_map),
                args.signature_change_file,
            )
        except FileNotFoundError:
            logger.warning("Signature change file %s not found; ignoring.", args.signature_change_file)
        except json.JSONDecodeError:
            logger.warning("Failed to parse signature change file %s; ignoring.", args.signature_change_file)
    bug_distribution = None
    bug_info_dataset: Optional[Dict[str, Any]] = None
    if args.revert_bug_info:
        try:
            bug_info_dataset = read_json_file(str(args.revert_bug_info))
        except FileNotFoundError:
            logger.warning("Bug info file %s not found; stack verification disabled.", args.revert_bug_info)
        except json.JSONDecodeError:
            logger.warning("Failed to parse bug info file %s; stack verification disabled.", args.revert_bug_info)
    if args.bug_distribution_csv:
        bug_distribution = parse_bug_distribution_csv(args.bug_distribution_csv)
    global REANALYZE_PENDING
    while True:
        graph = merge_patches(CURRENT_PATCHES or {}, bug_distribution, signature_change_map)
        log_patch_function_table(graph)
        groups = report_compatible_groups(graph)
        group_one = groups[0] if groups else None
        for idx, candidate in enumerate(groups):
            if len(groups[0]) == len(candidate):
                report_pending_patch_refreshes(candidate, idx+1)
            break
        if REANALYZE_PENDING:
            logger.info("Detected refreshed patches; re-running compatibility analysis.\n")
            REANALYZE_PENDING = False
            continue
        if args.graphviz_output:
            write_graphviz(graph, args.graphviz_output)
        break

    # Merge and finalize patches for Group 1
    repo_base = os.getenv("REPO_PATH")
    target_repo_path = (
        os.path.join(repo_base, args.revert_target) if repo_base and args.revert_target else None
    )
    patch_file_path = finalize_patch_group(group_one, CURRENT_PATCHES, target_repo_path, args.target_commit)
    build_success = False
    error_log = ""
    if patch_file_path and args.revert_target and args.target_commit and args.revert_build_csv and args.fuzz_target:
        build_success, error_log = build_fuzzer(
            args.revert_target,
            args.target_commit,
            "address",
            "",
            str(patch_file_path),
            args.fuzz_target,
            str(args.revert_build_csv),
            "x86_64",
        )
        if build_success:
            logger.info("Successfully built fuzzer with merged patches applied.")
        else:
            logger.error("Failed to build fuzzer with merged patches. See log:\n%s", error_log)
    else:
        logger.info(
            "Skipping post-merge build step due to missing patch path or required arguments "
            "(requires --revert_target, --target_commit, --revert_build_csv, and --fuzz_target)."
        )

    if build_success and patch_file_path:
        if not group_one:
            logger.info("No compatible group to fuzz test after build.")
        elif not (args.revert_bug_info and args.revert_target and args.target_commit):
            logger.info(
                "Missing --revert_bug_info/--revert_target/--target_commit; "
                "skipping stack verification."
            )
        elif not bug_info_dataset:
            logger.info("Bug info unavailable; skipping stack verification.")
        else:
            verification_results: List[Tuple[str, str, bool]] = []
            for identifier in group_one:
                if not isinstance(identifier, tuple) or not identifier:
                    continue
                if _is_local_bug_identifier(identifier):
                    bug_id = identifier[1]
                    buggy_commit = args.target_commit
                else:
                    bug_id = identifier[0]
                    buggy_commit = identifier[1]
                if not isinstance(bug_id, str):
                    continue
                try:
                    result = _stack_verification_for_bug(
                        bug_id,
                        buggy_commit,
                        bug_info_dataset,
                        args.revert_target,
                        args.target_commit,
                    )
                    logger.info("Stack verification result for %s: %s", bug_id, result)
                    success = result == "triggered (stack matches)"
                    verification_results.append((bug_id, result, success))
                except Exception:
                    logger.exception("Stack verification failed for %s.", bug_id)
                    verification_results.append((bug_id, "verification failed", False))

            if verification_results:
                headers = ["Bug", "Post-merge status", "Success"]
                rows = [[bug, status, "True" if success else "False"] for bug, status, success in verification_results]
                table = _render_table(headers, rows)
                logger.info("Post-merge trigger summary:")
                for line in table.splitlines():
                    logger.info(line)
                if not _tabulate:
                    logger.info("  (Install 'tabulate' for enhanced table formatting.)")
            else:
                logger.info("No stack verification results collected.")

if __name__ == "__main__":
    main()
