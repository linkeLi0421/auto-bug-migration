from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Generic, Mapping, MutableMapping, Optional, TypeVar


END = object()

StateT = TypeVar("StateT")
GraphStateT = TypeVar("GraphStateT", bound=MutableMapping[str, Any])
NodeFn = Callable[[GraphStateT], GraphStateT]
RouteFn = Callable[[GraphStateT], str]


@dataclass(frozen=True)
class _CompiledGraph(Generic[GraphStateT]):
    entry: str
    nodes: Dict[str, NodeFn]
    edges: Dict[str, Any]
    cond_edges: Dict[str, tuple[RouteFn, Dict[str, Any]]]

    def invoke(self, initial: GraphStateT) -> GraphStateT:
        current = self.entry
        gs = initial
        for _ in range(1_000_000):
            if current is END:
                return gs
            fn = self.nodes.get(current)
            if fn is None:
                raise KeyError(f"Unknown node: {current}")
            gs = fn(gs)

            if current in self.cond_edges:
                router, mapping = self.cond_edges[current]
                key = router(gs)
                current = mapping.get(key)
                if current is None:
                    raise KeyError(f"Unknown route '{key}' from node '{current}'")
                continue

            if current in self.edges:
                current = self.edges[current]
                continue

            return gs

        raise RuntimeError("Graph execution exceeded step limit (possible cycle).")


class StateGraph(Generic[StateT]):
    """Tiny subset of LangGraph's API used by this repo.

    Prefer the real `langgraph` package when installed.
    """

    def __init__(self, _state_type: Any = None) -> None:
        self._entry: Optional[str] = None
        self._nodes: Dict[str, NodeFn] = {}
        self._edges: Dict[str, Any] = {}
        self._cond_edges: Dict[str, tuple[RouteFn, Dict[str, Any]]] = {}

    def add_node(self, name: str, fn: NodeFn) -> None:
        self._nodes[str(name)] = fn

    def set_entry_point(self, name: str) -> None:
        self._entry = str(name)

    def add_edge(self, src: str, dst: Any) -> None:
        self._edges[str(src)] = dst

    def add_conditional_edges(self, src: str, router: RouteFn, mapping: Mapping[str, Any]) -> None:
        self._cond_edges[str(src)] = (router, dict(mapping))

    def compile(self) -> _CompiledGraph:
        if not self._entry:
            raise ValueError("Entry point not set")
        return _CompiledGraph(entry=self._entry, nodes=dict(self._nodes), edges=dict(self._edges), cond_edges=dict(self._cond_edges))

