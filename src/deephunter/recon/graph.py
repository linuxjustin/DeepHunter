"""Attack Surface Graph — in-memory directed graph of recon entities and their relationships."""

from __future__ import annotations

from typing import Any

from deephunter.recon.events import GraphUpdatedEvent, ReconEventBus
from deephunter.recon.models import (
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
)


class AttackSurfaceGraph:
    """In-memory directed graph of attack surface entities.

    Nodes represent entities (programs, scopes, assets, hosts, apps,
    technologies, endpoints, etc.).  Edges represent relationships
    (belongs_to, hosts, uses, has_endpoint, etc.).

    This is NOT a graph database — it is an in-memory adjacency structure
    designed for query, correlation, and export to the Investigation Planner.
    """

    def __init__(self, event_bus: ReconEventBus | None = None) -> None:
        self._event_bus = event_bus or ReconEventBus()
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        self._outgoing: dict[str, list[GraphEdge]] = {}
        self._incoming: dict[str, list[GraphEdge]] = {}

    # ── Node management ──────────────────────────────────────────

    def add_node(self, node: GraphNode) -> None:
        if node.id in self._nodes:
            raise ValueError(f"GraphNode '{node.id}' already exists")
        self._nodes[node.id] = node
        self._outgoing[node.id] = []
        self._incoming[node.id] = []

    def get_node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def find_node_by_ref(self, ref_id: str) -> GraphNode | None:
        for node in self._nodes.values():
            if node.ref_id == ref_id:
                return node
        return None

    def find_nodes_by_type(self, node_type: GraphNodeType) -> list[GraphNode]:
        return [n for n in self._nodes.values() if n.node_type == node_type]

    def remove_node(self, node_id: str) -> bool:
        if node_id not in self._nodes:
            return False
        del self._nodes[node_id]
        self._outgoing.pop(node_id, None)
        self._incoming.pop(node_id, None)
        self._edges = [e for e in self._edges if e.source_id != node_id and e.target_id != node_id]
        return True

    # ── Edge management ──────────────────────────────────────────

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.source_id not in self._nodes:
            raise ValueError(f"Source node '{edge.source_id}' not found")
        if edge.target_id not in self._nodes:
            raise ValueError(f"Target node '{edge.target_id}' not found")
        self._edges.append(edge)
        self._outgoing[edge.source_id].append(edge)
        self._incoming[edge.target_id].append(edge)

    def get_edges(self, node_id: str) -> list[GraphEdge]:
        return self._outgoing.get(node_id, []) + self._incoming.get(node_id, [])

    def get_outgoing(self, node_id: str) -> list[GraphEdge]:
        return self._outgoing.get(node_id, [])

    def get_incoming(self, node_id: str) -> list[GraphEdge]:
        return self._incoming.get(node_id, [])

    # ── Query ────────────────────────────────────────────────────

    def get_neighbors(self, node_id: str) -> list[GraphNode]:
        neighbor_ids: set[str] = set()
        for edge in self.get_edges(node_id):
            neighbor_ids.add(edge.source_id if edge.target_id == node_id else edge.target_id)
        return [self._nodes[nid] for nid in neighbor_ids if nid in self._nodes]

    def get_upstream(self, node_id: str) -> list[GraphNode]:
        return [self._nodes[e.source_id] for e in self.get_incoming(node_id) if e.source_id in self._nodes]

    def get_downstream(self, node_id: str) -> list[GraphNode]:
        return [self._nodes[e.target_id] for e in self.get_outgoing(node_id) if e.target_id in self._nodes]

    def find_path(self, from_id: str, to_id: str) -> list[list[GraphEdge]]:
        """Simple BFS to find all paths between two nodes."""
        paths: list[list[GraphEdge]] = []
        visited: set[str] = set()

        def _dfs(current: str, target: str, path: list[GraphEdge]) -> None:
            if current == target:
                paths.append(list(path))
                return
            if current in visited:
                return
            visited.add(current)
            for edge in self._outgoing.get(current, []):
                path.append(edge)
                _dfs(edge.target_id, target, path)
                path.pop()
            visited.discard(current)

        _dfs(from_id, to_id, [])
        return paths

    # ── Graph building helpers ───────────────────────────────────

    def link(
        self, source_ref_id: str, target_ref_id: str,
        edge_type: GraphEdgeType, label: str = "",
    ) -> GraphEdge | None:
        """Create an edge between two entities identified by their ref_ids."""
        source = self.find_node_by_ref(source_ref_id)
        target = self.find_node_by_ref(target_ref_id)
        if source is None or target is None:
            return None
        edge = GraphEdge(source_id=source.id, target_id=target.id, edge_type=edge_type, label=label)
        self.add_edge(edge)
        return edge

    def ensure_node(self, ref_id: str, node_type: GraphNodeType, label: str = "", tags: list[str] | None = None) -> GraphNode:
        existing = self.find_node_by_ref(ref_id)
        if existing:
            return existing
        node = GraphNode(node_type=node_type, ref_id=ref_id, label=label, tags=tags or [])
        self.add_node(node)
        return node

    # ── Reports ──────────────────────────────────────────────────

    def emit_update(self, session_id: str = "") -> None:
        self._event_bus.emit(
            GraphUpdatedEvent(
                session_id=session_id,
                description=f"Graph: {self.node_count} nodes, {self.edge_count} edges",
                node_count=self.node_count,
                edge_count=self.edge_count,
            )
        )

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def clear(self) -> None:
        self._nodes.clear()
        self._edges.clear()
        self._outgoing.clear()
        self._incoming.clear()
