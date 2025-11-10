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
        ('blosc/schunk.cblosc/schunk.c-285,10+440,11',)
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

        for identifier, node_name in node_names.items():
            label = _format_node_label(identifier)
            graph_file.write(f"  {node_name} [label=\"{label}\"];\n")

        for lhs_name, rhs_name in sorted(unique_edges):
            graph_file.write(f"  {lhs_name} -- {rhs_name};\n")

        graph_file.write("}\n")

    logger.info("Wrote Graphviz representation with %d nodes and %d edges to %s", len(node_identifiers), len(unique_edges), output_path)


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

    shared_commit = have_joint_trigger(bug_distribution, bug1, bug2)
    if shared_commit:
        logger.info("Bugs %s and %s share triggering commit %s; treating as compatible", bug1, bug2, shared_commit)
        return True

    return False


def merge_patches(patches_without_contexts: Dict[PatchSetKey, PatchSet], bug_distribution: Optional[List[Dict[str, Any]]] = None) -> PatchCompatibilityGraph:
    """Build a compatibility graph where each node represents an entire patch dictionary."""

    graph = PatchCompatibilityGraph()

    for key_tuple, patch_dict in patches_without_contexts.items():
        if not isinstance(patch_dict, dict):
            logger.warning("Expected dict for patch set %s, got %s", key_tuple, type(patch_dict).__name__)
            continue
        graph.add_patch(key_tuple, patch_dict)

    graph.connect_compatibilities(lambda a, b: is_compatiable(a, b, bug_distribution))

    total_edges = graph.edge_count()
    logger.info("Constructed compatibility graph: %d patch sets, %d edges", len(graph.nodes), total_edges)

    return graph


def have_joint_trigger(parsed_data: list[dict[str, Any]], bug1: str, bug2: str) -> str | None:
    """
    Return the commit id where both bugs are marked '1|1' or '0.5|1'.

    parsed_data follows the structure produced by prepare_transplant/parse_csv_file:
      [{'commit_id': 'abc123', 'osv_statuses': {'OSV-1': '1|1', ...}}, ...]
    """

    def is_trigger(value: str | None) -> bool:
        return value in {'1|1', '0.5|1'}

    for row in parsed_data:
        statuses = row.get('osv_statuses', {})
        if is_trigger(statuses.get(bug1)) and is_trigger(statuses.get(bug2)):
            return row.get('commit_id')
    return None


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
    if args.graphviz_output:
        write_graphviz(graph, args.graphviz_output)


if __name__ == "__main__":
    main()
