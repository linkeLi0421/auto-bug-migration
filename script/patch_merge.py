"""Utilities for combining patch sets produced by `revert_patch_test`."""

from __future__ import annotations

import argparse
import logging
from collections import defaultdict
from pathlib import Path
from typing import Dict, Tuple, Any, DefaultDict, Set, Callable, Iterable, Optional, List

from utils import load_patches_pickle
from revert_patch_test import PatchInfo, FunctionLocation

patch_pair_dict = {
    'OSV-2021-27': [
        ('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,7+23,12',),
        ('blosc/schunk.cblosc/schunk.c-285,10+440,11',)
    ],
    'OSV-2020-2184': [
        ('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,7+23,12',),
        ('blosc/schunk.cblosc/schunk.c-258,10+440,11',)
    ],
    'OSV-2021-22': [
        ('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,7+23,12',),
        ('blosc/schunk.cblosc/schunk.c-285,10+440,11',)
    ],
    'OSV-2021-21': [
        ('blosc/blosc2.cblosc/blosc2.c-2201,22+2331,30',),
        ('blosc/blosc2.cblosc/blosc2.c-1693,16+1800,18', 'blosc/blosc2.cblosc/blosc2.c-1573,18+1748,0', 'blosc/blosc2.cblosc/blosc2.c-1607,75+1760,29', 'blosc/blosc2.cblosc/blosc2.c-1593,4+1748,0'),
        ('blosc/frame.cblosc/frame.c-1690,3+2021,20', 'blosc/frame.cblosc/frame.c-1651,3+1976,9', 'blosc/frame.cblosc/frame.c-1618,27+1938,32', 'blosc/frame.cblosc/frame.c-1570,42+1877,55'),
        ('blosc/schunk.cblosc/schunk.c-285,10+440,11',),
        ('blosc/frame.cblosc/frame.c-1367,86+1612,77', 'blosc/frame.cblosc/frame.c-1312,46+1554,49', 'blosc/frame.cblosc/frame.c-1301,4+1545,2', 'blosc/frame.cblosc/frame.c-1280,5+1522,7', 'blosc/frame.cblosc/frame.c-1257,12+1497,13'),
        ('blosc/blosc2.cblosc/blosc2.c-1272,2+1501,3', 'blosc/blosc2.cblosc/blosc2.c-1253,4+1483,3')
    ],
    'OSV-2021-274': [
        ('blosc/frame.cblosc/frame.c-1473,9+1682,7', 'blosc/frame.cblosc/frame.c-1461,4+1674,0', 'blosc/frame.cblosc/frame.c-1432,11+1641,15', 'blosc/frame.cblosc/frame.c-1416,10+1622,13', 'blosc/frame.cblosc/frame.c-1389,8+1592,11', 'blosc/frame.cblosc/frame.c-1368,4+1569,6', 'blosc/frame.cblosc/frame.c-1301,8+1500,10'),
        ('blosc/frame.cblosc/frame.c-1247,8+1271,8', 'blosc/frame.cblosc/frame.c-1234,5+1261,2', 'blosc/frame.cblosc/frame.c-1216,4+1241,6'),
        ('blosc/frame.cblosc/frame.c-419,9+396,22', 'blosc/frame.cblosc/frame.c-400,5+380,2', 'blosc/frame.cblosc/frame.c-387,2+366,0'),
        ('blosc/frame.cblosc/frame.c-720,2+816,2', 'blosc/frame.cblosc/frame.c-704,2+799,3')
    ],
    'OSV-2021-246': [
        ('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,2+23,2',),
        ('blosc/schunk.cblosc/schunk.c-285,10+440,11',)
    ],
    'OSV-2021-213': [
        ('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,7+23,12',),
        ('blosc/schunk.cblosc/schunk.c-285,10+440,11',),
        ('blosc/frame.cblosc/frame.c-1367,86+1612,77', 'blosc/frame.cblosc/frame.c-1312,46+1554,49', 'blosc/frame.cblosc/frame.c-1301,4+1545,2', 'blosc/frame.cblosc/frame.c-1280,5+1522,7', 'blosc/frame.cblosc/frame.c-1257,12+1497,13'),
        ('blosc/frame.cblosc/frame.c-1148,51+1271,68', 'blosc/frame.cblosc/frame.c-1111,28+1236,24')
    ],
    'OSV-2021-247': [
        ('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,2+23,2',),
        ('blosc/schunk.cblosc/schunk.c-291,9+440,11',)
    ],
    'OSV-2021-404': [
        ('blosc/frame.cblosc/frame.c-1283,4+1241,6',)
    ],
    'OSV-2021-221': [
        ('tests/fuzz/fuzz_decompress_frame.ctests/fuzz/fuzz_decompress_frame.c-23,7+23,12',),
        ('blosc/frame.cblosc/frame.c-1816,8+2021,24', 'blosc/frame.cblosc/frame.c-1777,3+1976,9', 'blosc/frame.cblosc/frame.c-1744,27+1938,32', 'blosc/frame.cblosc/frame.c-1684,54+1877,55'),
        ('blosc/frame.cblosc/frame.c-1540,17+1706,20',),
        ('blosc/blosc2.cblosc/blosc2.c-2617,43+2561,19',),
        ('blosc/blosc2.cblosc/blosc2.c-1576,18+1748,0',),
        ('blosc/frame.cblosc/frame.c-469,2+462,2', 'blosc/frame.cblosc/frame.c-461,2+454,2', 'blosc/frame.cblosc/frame.c-445,2+438,2', 'blosc/frame.cblosc/frame.c-411,19+391,32', 'blosc/frame.cblosc/frame.c-383,18+365,14'),
        ('blosc/schunk.cblosc/schunk.c-285,10+440,11',),
        ('blosc/frame.cblosc/frame.c-1172,72+1271,68', 'blosc/frame.cblosc/frame.c-1135,28+1236,24')
    ],
    'OSV-2021-369': [
        ('blosc/frame.cblosc/frame.c-1770,5+2022,21', 'blosc/frame.cblosc/frame.c-1730,3+1976,9', 'blosc/frame.cblosc/frame.c-1718,6+1963,7', 'blosc/frame.cblosc/frame.c-1710,2+1954,3', 'blosc/frame.cblosc/frame.c-1698,5+1939,8', 'blosc/frame.cblosc/frame.c-1662,26+1907,22', 'blosc/frame.cblosc/frame.c-1640,14+1882,17'),
        ('blosc/frame.cblosc/frame.c-884,17+992,33', 'blosc/frame.cblosc/frame.c-867,11+965,21'),
        ('blosc/frame.cblosc/frame.c-431,8+409,9', 'blosc/frame.cblosc/frame.c-389,2+366,0'),
        ('blosc/frame.cblosc/frame.c-1457,9+1682,7', 'blosc/frame.cblosc/frame.c-1445,4+1674,0', 'blosc/frame.cblosc/frame.c-1416,11+1641,15', 'blosc/frame.cblosc/frame.c-1400,10+1622,13', 'blosc/frame.cblosc/frame.c-1373,8+1592,11', 'blosc/frame.cblosc/frame.c-1352,4+1569,6', 'blosc/frame.cblosc/frame.c-1285,8+1500,10'),
        ('blosc/frame.cblosc/frame.c-1237,2+1277,2', 'blosc/frame.cblosc/frame.c-1203,4+1241,6'),
        ('blosc/frame.cblosc/frame.c-722,2+816,2', 'blosc/frame.cblosc/frame.c-706,2+799,3')
    ],
    'OSV-2021-429': [
        ('blosc/frame.cblosc/frame.c-1673,10+1707,11',)
    ],
    'OSV-2023-51': [
        ('blosc/blosc2.cblosc/blosc2.c-771,1+771,0',),
        ('blosc/blosc2.cblosc/blosc2.c-2436,2+2342,12',)
    ],
    'OSV-2022-4': [
        ('blosc/blosc2.cblosc/blosc2.c-1969,24+1777,6',)
    ],
    'OSV-2021-897': [
        ('blosc/blosc2.cblosc/blosc2.c-2466,2+2342,12',),
        ('blosc/blosc2.cblosc/blosc2.c-1888,9+1697,8', 'blosc/blosc2.cblosc/blosc2.c-1864,4+1675,2')
    ],
    'OSV-2022-34': [
        ('blosc/blosc2.cblosc/blosc2.c-1969,24+1777,6',)
    ],
    'OSV-2021-1589': [
        ('blosc/blosc2.cblosc/blosc2.c-2719,2+2554,3', 'blosc/blosc2.cblosc/blosc2.c-2699,13+2521,26', 'blosc/blosc2.cblosc/blosc2.c-2608,64+2487,7', 'blosc/blosc2.cblosc/blosc2.c-2594,2+2463,12', 'blosc/blosc2.cblosc/blosc2.c-2578,1+2448,0')
    ],
    'OSV-2022-486': [
        ('blosc/schunk.cblosc/schunk.c-476,2+446,2',),
        ('blosc/frame.cblosc/frame.c-1761,2+1664,2', 'blosc/frame.cblosc/frame.c-1728,5+1631,5', 'blosc/frame.cblosc/frame.c-1695,20+1598,20', 'blosc/frame.cblosc/frame.c-1663,15+1572,9', 'blosc/frame.cblosc/frame.c-1644,2+1553,2', 'blosc/frame.cblosc/frame.c-1634,2+1543,2', 'blosc/frame.cblosc/frame.c-1617,11+1526,11', 'blosc/frame.cblosc/frame.c-1586,14+1497,12'),
        ('blosc/frame.cblosc/frame.c-1498,24+1428,17', 'blosc/frame.cblosc/frame.c-1478,3+1409,2'),
        ('blosc/frame.cblosc/frame.c-434,8+431,0', 'blosc/frame.cblosc/frame.c-415,9+414,7', 'blosc/frame.cblosc/frame.c-360,30+365,24'),
        ('blosc/frame.cblosc/frame.c-1321,20+1257,13', 'blosc/frame.cblosc/frame.c-1309,3+1246,2')
    ],
    'OSV-2022-1242': [
        ('blosc/schunk.cblosc/schunk.c-468,8+446,8',),
        ('blosc/frame.cblosc/frame.c-1787,2+1664,2', 'blosc/frame.cblosc/frame.c-1754,5+1631,5', 'blosc/frame.cblosc/frame.c-1746,1+1624,0', 'blosc/frame.cblosc/frame.c-1714,26+1594,24', 'blosc/frame.cblosc/frame.c-1685,16+1572,9', 'blosc/frame.cblosc/frame.c-1666,2+1553,2', 'blosc/frame.cblosc/frame.c-1656,2+1543,2', 'blosc/frame.cblosc/frame.c-1639,11+1526,11', 'blosc/frame.cblosc/frame.c-1608,14+1497,12')
    ],
    'OSV-2022-511': [
        ('blosc/frame.cblosc/frame.c-2250,27+2021,18', 'blosc/frame.cblosc/frame.c-2214,9+1987,7', 'blosc/frame.cblosc/frame.c-2204,2+1977,2', 'blosc/frame.cblosc/frame.c-2149,49+1950,21', 'blosc/frame.cblosc/frame.c-2102,36+1916,23', 'blosc/frame.cblosc/frame.c-2093,2+1907,2', 'blosc/frame.cblosc/frame.c-2073,9+1888,8'),
        ('blosc/frame.cblosc/frame.c-443,8+431,0', 'blosc/frame.cblosc/frame.c-413,22+410,13', 'blosc/frame.cblosc/frame.c-362,30+365,24'),
        ('blosc/schunk.cblosc/schunk.c-477,8+446,8',),
        ('blosc/frame.cblosc/frame.c-1817,20+1659,16', 'blosc/frame.cblosc/frame.c-1805,2+1646,3', 'blosc/frame.cblosc/frame.c-1761,37+1592,47', 'blosc/frame.cblosc/frame.c-1734,21+1572,14', 'blosc/frame.cblosc/frame.c-1715,2+1553,2', 'blosc/frame.cblosc/frame.c-1705,2+1543,2', 'blosc/frame.cblosc/frame.c-1688,11+1526,11', 'blosc/frame.cblosc/frame.c-1657,14+1497,12'),
        ('blosc/frame.cblosc/frame.c-1569,24+1428,17', 'blosc/frame.cblosc/frame.c-1549,3+1409,2'),
        ('blosc/frame.cblosc/frame.c-1392,20+1257,13', 'blosc/frame.cblosc/frame.c-1380,3+1246,2')
    ],
}

local_bug_compatibility = {
 'OSV-2022-34': {'OSV-2021-496', 'OSV-2021-485', 'OSV-2021-997', 'OSV-2021-1791', 'OSV-2021-622', 'OSV-2021-464', 'OSV-2021-498', 'OSV-2021-487', 'OSV-2021-481', 'OSV-2021-526'},
 'OSV-2023-51': {'OSV-2021-496', 'OSV-2021-485', 'OSV-2021-997', 'OSV-2021-1791', 'OSV-2021-622', 'OSV-2021-464', 'OSV-2021-498', 'OSV-2021-487', 'OSV-2021-481', 'OSV-2021-526'},
 'OSV-2021-897': {'OSV-2021-496', 'OSV-2021-485', 'OSV-2021-997', 'OSV-2021-1791', 'OSV-2021-622', 'OSV-2021-464', 'OSV-2021-498', 'OSV-2021-487', 'OSV-2021-481', 'OSV-2021-526'},
 'OSV-2021-213': {'OSV-2021-496', 'OSV-2021-485', 'OSV-2021-997', 'OSV-2021-1791', 'OSV-2021-622', 'OSV-2021-464', 'OSV-2021-498', 'OSV-2021-487', 'OSV-2021-481', 'OSV-2021-526'},
 'OSV-2022-511': {'OSV-2021-496', 'OSV-2021-485', 'OSV-2021-997', 'OSV-2021-1791', 'OSV-2021-487', 'OSV-2021-481'},
 'OSV-2021-404': {'OSV-2021-496', 'OSV-2021-485', 'OSV-2021-997', 'OSV-2021-1791', 'OSV-2021-622', 'OSV-2021-464', 'OSV-2021-498', 'OSV-2021-487', 'OSV-2021-481', 'OSV-2021-526'},
 'OSV-2021-429': {'OSV-2021-496', 'OSV-2021-485', 'OSV-2021-997', 'OSV-2021-1791', 'OSV-2021-622', 'OSV-2021-464', 'OSV-2021-498', 'OSV-2021-487', 'OSV-2021-481', 'OSV-2021-526'},
 'OSV-2022-4': {'OSV-2021-496', 'OSV-2021-485', 'OSV-2021-997', 'OSV-2021-1791', 'OSV-2021-622', 'OSV-2021-464', 'OSV-2021-498', 'OSV-2021-481', 'OSV-2021-526'},
 'OSV-2022-1242': {'OSV-2021-496', 'OSV-2021-485', 'OSV-2021-997', 'OSV-2021-1791', 'OSV-2021-622', 'OSV-2021-464', 'OSV-2021-498', 'OSV-2021-487', 'OSV-2021-481', 'OSV-2021-526'},
 'OSV-2021-27': {'OSV-2021-496', 'OSV-2021-485', 'OSV-2021-997', 'OSV-2021-1791', 'OSV-2021-622', 'OSV-2021-498', 'OSV-2021-487', 'OSV-2021-481', 'OSV-2021-526'},
 'OSV-2021-21': {'OSV-2021-496', 'OSV-2021-485', 'OSV-2021-997', 'OSV-2021-1791', 'OSV-2021-622', 'OSV-2021-464', 'OSV-2021-498', 'OSV-2021-487', 'OSV-2021-481', 'OSV-2021-526'},
 'OSV-2022-486': {'OSV-2021-1791', 'OSV-2021-997', 'OSV-2021-526'},
 'OSV-2021-1589': {'OSV-2021-622', 'OSV-2021-526'},
 'OSV-2021-22': {'OSV-2021-622'},
 'OSV-2020-2184': {'OSV-2021-622'},
}

LOCAL_BUG_NODE_PREFIX = "__local_bug__"
PendingRefreshInfo = Dict[str, Any]
pending_patch_refreshes: Dict[str, PendingRefreshInfo] = {}


logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)


PatchSetKey = Tuple[Any, ...]
PatchSet = Dict[str, Any]


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


def request_new_patch_for_bug(bug_id: str, required_commit: str, current_commit: Optional[str], partner_bug_id: str) -> None:
    """
    Placeholder hook for refreshing a patch using required_commit.

    Implementers should replace this with repo-specific logic that regenerates the patch.
    """
    info = pending_patch_refreshes.setdefault(
        bug_id,
        {
            "required_commit": required_commit,
            "current_commit": current_commit,
            "partners": set(),
        },
    )
    info["required_commit"] = required_commit
    info["current_commit"] = current_commit
    partners: Set[str] = info.setdefault("partners", set())
    partners.add(partner_bug_id)


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


def is_compatiable(key_a: PatchSetKey, key_b: PatchSetKey, bug_distribution: Optional[List[Dict[str, Any]]] = None) -> bool:
    """Return True when two patch sets are compatible based on touched functions and shared triggers."""

    def extract_functions(key: PatchSetKey) -> Set[str]:
        if len(key) < 4:
            return set()
        funcs = key[3]
        if isinstance(funcs, (list, tuple, set)):
            return {str(name) for name in funcs}
        logger.debug("Unexpected function list type for key %s: %s", key, type(funcs).__name__)
        return set()

    funcs_a = extract_functions(key_a)
    funcs_b = extract_functions(key_b)

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
        representative_commit = next(iter(sorted(shared_commits))) if shared_commits else None
        if needs_refresh_a:
            request_new_patch_for_bug(bug1, representative_commit or "", commit_a, bug2)
        if needs_refresh_b:
            request_new_patch_for_bug(bug2, representative_commit or "", commit_b, bug1)
        if not needs_refresh_a and not needs_refresh_b:
            logger.info(
                "Bugs %s and %s share at least one triggering commit with aligned patches; treating as compatible",
                bug1,
                bug2,
            )
        return True

    return False


def merge_patches(patches_without_contexts: Dict[PatchSetKey, PatchSet], bug_distribution: Optional[List[Dict[str, Any]]] = None) -> PatchCompatibilityGraph:
    """Build a compatibility graph where each node represents an entire patch dictionary."""

    pending_patch_refreshes.clear()
    graph = PatchCompatibilityGraph()

    for key_tuple, patch_dict in patches_without_contexts.items():
        if not isinstance(patch_dict, dict):
            logger.warning("Expected dict for patch set %s, got %s", key_tuple, type(patch_dict).__name__)
            continue
        graph.add_patch(key_tuple, patch_dict)

    graph.connect_compatibilities(lambda a, b: is_compatiable(a, b, bug_distribution))
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

    logger.info("Detected %d fully compatible bug groups (size >= %d):", len(groups), min_size)
    for idx, group in enumerate(groups, start=1):
        identifiers = [describe_identifier(identifier) for identifier in group]
        logger.info("  Group %d (%d bugs): %s", idx, len(group), "; ".join(identifiers))
    return groups


def report_pending_patch_refreshes(group: Optional[List[PatchSetKey]]) -> None:
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

    report_entries: List[Tuple[str, str, str, List[str]]] = []
    for bug_id in sorted(filtered):
        info = filtered[bug_id]
        partners = sorted(info.get("partners", []))
        partners_in_group = [partner for partner in partners if partner in relevant_bug_ids]
        if not partners_in_group:
            continue
        required = (info.get("required_commit") or "unknown")[:6]
        current = (info.get("current_commit") or "unknown")[:6]
        report_entries.append((bug_id, required, current, partners_in_group))

    if not report_entries:
        logger.info("Pending patch refreshes impacting Group 1: none")
        return

    logger.info("Pending patch refreshes impacting Group 1 (%d bugs):", len(report_entries))
    for bug_id, required, current, partners_in_group in report_entries:
        partner_text = ", ".join(partners_in_group)
        logger.info("  %s: requires %s (current %s) [shares commit with %s]", bug_id, required, current, partner_text)


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
            if value == "1|1":
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
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cache_file = args.cache_file
    patches_without_contexts = load_patches_pickle(cache_file)
    bug_distribution = None
    if args.bug_distribution_csv:
        bug_distribution = parse_bug_distribution_csv(args.bug_distribution_csv)
    graph = merge_patches(patches_without_contexts, bug_distribution)
    groups = report_compatible_groups(graph)
    group_one = groups[0] if groups else None
    report_pending_patch_refreshes(group_one)
    if args.graphviz_output:
        write_graphviz(graph, args.graphviz_output)


if __name__ == "__main__":
    main()
