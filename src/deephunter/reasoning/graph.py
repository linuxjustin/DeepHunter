"""In-memory reasoning graph — a DAG of investigation nodes and edges.

Represents the relationships between observations, evidence, hypotheses,
experiments, pivots, and findings as a traversable directed graph.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from deephunter.reasoning.models import (
    EdgeType,
    Evidence,
    Experiment,
    Finding,
    NodeType,
    Observation,
    Pivot,
)


class GraphNode:
    """A single node in the reasoning graph.

    Wraps any model instance (Observation, Evidence, etc.) with
    graph metadata.
    """

    def __init__(self, data: Any, node_type: NodeType) -> None:
        self.id: str = data.id
        self.node_type: NodeType = node_type
        self.data: Any = data

    def __repr__(self) -> str:
        return f"GraphNode({self.node_type.value}: {self.id})"


class GraphEdge:
    """A directed edge between two graph nodes."""

    def __init__(self, source_id: str, target_id: str, edge_type: EdgeType) -> None:
        self.source_id: str = source_id
        self.target_id: str = target_id
        self.edge_type: EdgeType = edge_type

    def __repr__(self) -> str:
        return f"GraphEdge({self.source_id} -[{self.edge_type.value}]-> {self.target_id})"


class ReasoningGraph:
    """In-memory directed acyclic graph of reasoning nodes.

    Supports adding nodes and edges, traversing relationships,
    and serialization for persistence.

    This is NOT a graph database — it is an in-memory representation
    designed to be serialized as JSON alongside the investigation.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []

    # ── Node management ───────────────────────────────────────────

    def add_node(self, data: Any) -> GraphNode:
        """Add a model instance as a graph node.

        The node type is inferred from the model class.

        Args:
            data: An Observation, Evidence, Experiment, Pivot, or Finding instance.

        Returns:
            The created GraphNode.

        Raises:
            ValueError: If the model type is not recognized.
        """
        node_type = self._infer_type(data)
        if node_type is None:
            raise ValueError(f"Cannot infer graph node type for {type(data).__name__}")
        if data.id in self._nodes:
            return self._nodes[data.id]
        node = GraphNode(data, node_type)
        self._nodes[data.id] = node
        return node

    def get_node(self, node_id: str) -> GraphNode | None:
        """Retrieve a node by ID."""
        return self._nodes.get(node_id)

    def has_node(self, node_id: str) -> bool:
        """Check if a node exists."""
        return node_id in self._nodes

    def remove_node(self, node_id: str) -> bool:
        """Remove a node and all its edges.

        Returns:
            ``True`` if the node existed and was removed.
        """
        if node_id not in self._nodes:
            return False
        del self._nodes[node_id]
        self._edges = [
            e for e in self._edges
            if e.source_id != node_id and e.target_id != node_id
        ]
        return True

    def node_count(self) -> int:
        """Return the total number of nodes."""
        return len(self._nodes)

    def list_nodes(self, node_type: NodeType | None = None) -> list[GraphNode]:
        """List all nodes, optionally filtered by type."""
        if node_type is None:
            return list(self._nodes.values())
        return [n for n in self._nodes.values() if n.node_type == node_type]

    # ── Edge management ───────────────────────────────────────────

    def add_edge(
        self, source_id: str, target_id: str, edge_type: EdgeType
    ) -> GraphEdge:
        """Add a directed edge between two nodes.

        Args:
            source_id: Source node ID.
            target_id: Target node ID.
            edge_type: The relationship type.

        Returns:
            The created GraphEdge.

        Raises:
            ValueError: If either node does not exist.
        """
        if source_id not in self._nodes:
            raise ValueError(f"Source node not found: {source_id}")
        if target_id not in self._nodes:
            raise ValueError(f"Target node not found: {target_id}")
        edge = GraphEdge(source_id, target_id, edge_type)
        self._edges.append(edge)
        return edge

    def edge_count(self) -> int:
        return len(self._edges)

    def get_edges(
        self,
        source_id: str | None = None,
        target_id: str | None = None,
        edge_type: EdgeType | None = None,
    ) -> list[GraphEdge]:
        """Get edges matching the given filters (all optional)."""
        result = list(self._edges)
        if source_id is not None:
            result = [e for e in result if e.source_id == source_id]
        if target_id is not None:
            result = [e for e in result if e.target_id == target_id]
        if edge_type is not None:
            result = [e for e in result if e.edge_type == edge_type]
        return result

    # ── Traversal ─────────────────────────────────────────────────

    def successors(self, node_id: str) -> list[GraphNode]:
        """Get all direct successors of a node (outgoing edges)."""
        target_ids = {e.target_id for e in self._edges if e.source_id == node_id}
        return [self._nodes[nid] for nid in target_ids if nid in self._nodes]

    def predecessors(self, node_id: str) -> list[GraphNode]:
        """Get all direct predecessors of a node (incoming edges)."""
        source_ids = {e.source_id for e in self._edges if e.target_id == node_id}
        return [self._nodes[nid] for nid in source_ids if nid in self._nodes]

    def walk_from(self, node_id: str, edge_type: EdgeType | None = None) -> list[GraphNode]:
        """Walk forward from a node, collecting reachable nodes.

        Performs a breadth-first traversal, optionally filtering by
        edge type.
        """
        visited: set[str] = set()
        queue: list[str] = [node_id]
        result: list[GraphNode] = []

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            node = self._nodes.get(current)
            if node and current != node_id:
                result.append(node)
            for edge in self._edges:
                if edge.source_id == current:
                    if edge_type is None or edge.edge_type == edge_type:
                        if edge.target_id not in visited:
                            queue.append(edge.target_id)
        return result

    # ── Serialization ─────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialize the graph to a JSON-compatible dict."""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "node_type": n.node_type.value,
                    "data": n.data.model_dump(mode="json") if hasattr(n.data, "model_dump") else str(n.data),
                }
                for n in self._nodes.values()
            ],
            "edges": [
                {
                    "source_id": e.source_id,
                    "target_id": e.target_id,
                    "edge_type": e.edge_type.value,
                }
                for e in self._edges
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReasoningGraph:
        """Deserialize a graph from a dict.

        Node data is stored as dicts and must be reconstructed by
        the caller since the graph does not hold model class references.
        """
        from deephunter.reasoning.models import (
            Evidence,
            Experiment,
            Finding,
            Observation,
            Pivot,
        )

        _TYPE_MAP = {
            "observation": Observation,
            "evidence": Evidence,
            "experiment": Experiment,
            "pivot": Pivot,
            "finding": Finding,
        }

        graph = cls()
        for nd in data.get("nodes", []):
            model_cls = _TYPE_MAP.get(nd["node_type"])
            if model_cls is not None:
                instance = model_cls(**nd["data"])
                graph.add_node(instance)
        for ed in data.get("edges", []):
            graph.add_edge(
                ed["source_id"],
                ed["target_id"],
                EdgeType(ed["edge_type"]),
            )
        return graph

    # ── Internal ──────────────────────────────────────────────────

    @staticmethod
    def _infer_type(data: Any) -> NodeType | None:
        mapping = {
            Observation: NodeType.OBSERVATION,
            Evidence: NodeType.EVIDENCE,
            Experiment: NodeType.EXPERIMENT,
            Pivot: NodeType.PIVOT,
            Finding: NodeType.FINDING,
        }
        for cls, nt in mapping.items():
            if isinstance(data, cls):
                return nt
        return None
