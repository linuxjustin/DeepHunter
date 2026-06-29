"""Tests for the reasoning graph (in-memory DAG)."""

from __future__ import annotations

import pytest

from deephunter.reasoning.graph import (
    GraphEdge,
    GraphNode,
    ReasoningGraph,
)
from deephunter.reasoning.models import (
    EdgeType,
    Evidence,
    Experiment,
    Finding,
    NodeType,
    Observation,
    Pivot,
)


class TestGraphNode:
    def test_create(self) -> None:
        obs = Observation(type="other", description="Server")
        node = GraphNode(obs, NodeType.OBSERVATION)
        assert node.id == obs.id
        assert node.node_type == NodeType.OBSERVATION
        assert node.data is obs

    def test_with_experiment(self) -> None:
        exp = Experiment(hypothesis_id="hyp-1", description="Test", procedure="P", expected_result="R")
        node = GraphNode(exp, NodeType.EXPERIMENT)
        assert node.id == exp.id
        assert node.node_type == NodeType.EXPERIMENT


class TestGraphEdge:
    def test_create(self) -> None:
        edge = GraphEdge(source_id="obs-1", target_id="hyp-1", edge_type=EdgeType.SUGGESTS)
        assert edge.source_id == "obs-1"
        assert edge.target_id == "hyp-1"
        assert edge.edge_type == EdgeType.SUGGESTS

    def test_edge_type_values(self) -> None:
        for et in EdgeType:
            edge = GraphEdge(source_id="a", target_id="b", edge_type=et)
            assert edge.edge_type == et


class TestReasoningGraph:
    def test_empty_graph(self) -> None:
        g = ReasoningGraph()
        assert g.node_count() == 0
        assert g.edge_count() == 0

    def test_add_node(self) -> None:
        g = ReasoningGraph()
        obs = Observation(type="other", description="Server")
        g.add_node(obs)
        assert g.node_count() == 1
        assert g.has_node(obs.id)

    def test_add_duplicate_node(self) -> None:
        g = ReasoningGraph()
        obs = Observation(type="other", description="Server")
        g.add_node(obs)
        g.add_node(obs)
        assert g.node_count() == 1

    def test_add_edge(self) -> None:
        g = ReasoningGraph()
        a = Observation(type="other", description="A")
        b = Observation(type="other", description="B")
        g.add_node(a)
        g.add_node(b)

        edge = g.add_edge(a.id, b.id, EdgeType.SUGGESTS)
        assert edge is not None
        assert edge.source_id == a.id
        assert edge.target_id == b.id
        assert g.edge_count() == 1

    def test_add_edge_raises_on_missing_source(self) -> None:
        g = ReasoningGraph()
        with pytest.raises(ValueError, match="Source node not found"):
            g.add_edge("nonexistent", "obs-1", EdgeType.SUGGESTS)

    def test_add_edge_raises_on_missing_target(self) -> None:
        g = ReasoningGraph()
        obs = Observation(type="other", description="Server")
        g.add_node(obs)
        with pytest.raises(ValueError, match="Target node not found"):
            g.add_edge(obs.id, "nonexistent", EdgeType.SUGGESTS)

    def test_successors(self) -> None:
        g = ReasoningGraph()
        obs = Observation(type="other", description="O1")
        hyp = Observation(type="other", description="H1 placeholder")
        g.add_node(obs)
        g.add_node(hyp)
        g.add_edge(obs.id, hyp.id, EdgeType.SUGGESTS)

        successors = g.successors(obs.id)
        assert len(successors) == 1
        assert successors[0].id == hyp.id

    def test_predecessors(self) -> None:
        g = ReasoningGraph()
        obs = Observation(type="other", description="O1")
        hyp = Observation(type="other", description="H1 placeholder")
        g.add_node(obs)
        g.add_node(hyp)
        g.add_edge(obs.id, hyp.id, EdgeType.SUGGESTS)

        predecessors = g.predecessors(hyp.id)
        assert len(predecessors) == 1
        assert predecessors[0].id == obs.id

    def test_successors_no_edges(self) -> None:
        g = ReasoningGraph()
        obs = Observation(type="other", description="Server")
        g.add_node(obs)
        assert g.successors(obs.id) == []

    def test_predecessors_no_edges(self) -> None:
        g = ReasoningGraph()
        obs = Observation(type="other", description="Server")
        g.add_node(obs)
        assert g.predecessors(obs.id) == []

    def test_unsuccessful_both_ways(self) -> None:
        g = ReasoningGraph()
        a = Observation(type="other", description="A")
        b = Observation(type="other", description="B")
        g.add_node(a)
        g.add_node(b)
        assert g.successors(a.id) == []
        assert g.predecessors(a.id) == []

    def test_walk_from(self) -> None:
        g = ReasoningGraph()
        a = Observation(type="other", description="A")
        b = Observation(type="other", description="B")
        c = Observation(type="other", description="C")
        g.add_node(a)
        g.add_node(b)
        g.add_node(c)
        g.add_edge(a.id, b.id, EdgeType.SUGGESTS)
        g.add_edge(b.id, c.id, EdgeType.SUGGESTS)

        nodes = g.walk_from(a.id)
        assert len(nodes) == 2
        assert {n.id for n in nodes} == {b.id, c.id}

    def test_walk_from_with_edge_filter(self) -> None:
        g = ReasoningGraph()
        obs = Observation(type="other", description="O")
        ev = Evidence(observation_id=obs.id, content="E", source="S")
        g.add_node(obs)
        g.add_node(ev)
        g.add_edge(obs.id, ev.id, EdgeType.SUPPORTS)
        # Add a reverse edge with different type
        other = Observation(type="other", description="Other")
        g.add_node(other)
        g.add_edge(obs.id, other.id, EdgeType.SUGGESTS)

        nodes = g.walk_from(obs.id, edge_type=EdgeType.SUPPORTS)
        assert len(nodes) == 1
        assert nodes[0].id == ev.id

    def test_remove_node(self) -> None:
        g = ReasoningGraph()
        obs = Observation(type="other", description="Server")
        g.add_node(obs)
        assert g.node_count() == 1
        assert g.remove_node(obs.id) is True
        assert g.node_count() == 0

    def test_remove_node_unknown(self) -> None:
        g = ReasoningGraph()
        assert g.remove_node("nonexistent") is False

    def test_get_node(self) -> None:
        g = ReasoningGraph()
        obs = Observation(type="other", description="Server")
        g.add_node(obs)
        assert g.get_node(obs.id) is not None
        assert g.get_node(obs.id).data is obs

    def test_get_node_missing(self) -> None:
        g = ReasoningGraph()
        assert g.get_node("nonexistent") is None

    def test_infer_type_rejects_unknown(self) -> None:
        g = ReasoningGraph()
        with pytest.raises(ValueError, match="Cannot infer graph node type"):
            g.add_node("not_a_model")

    def test_list_nodes(self) -> None:
        g = ReasoningGraph()
        g.add_node(Observation(type="other", description="O1"))
        g.add_node(Evidence(observation_id="obs-1", content="E1", source="S"))
        assert len(g.list_nodes()) == 2
        assert len(g.list_nodes(NodeType.OBSERVATION)) == 1
        assert len(g.list_nodes(NodeType.EVIDENCE)) == 1

    def test_get_edges(self) -> None:
        g = ReasoningGraph()
        a = Observation(type="other", description="A")
        b = Observation(type="other", description="B")
        g.add_node(a)
        g.add_node(b)
        g.add_edge(a.id, b.id, EdgeType.SUGGESTS)

        assert len(g.get_edges()) == 1
        assert len(g.get_edges(source_id=a.id)) == 1
        assert len(g.get_edges(target_id=b.id)) == 1
        assert len(g.get_edges(edge_type=EdgeType.SUGGESTS)) == 1
        assert len(g.get_edges(edge_type=EdgeType.CONFIRMS)) == 0

    def test_to_dict_from_dict_roundtrip(self) -> None:
        g = ReasoningGraph()
        obs = Observation(type="other", description="Server process", source="scan")
        exp = Experiment(hypothesis_id="hyp-1", description="Test", procedure="P", expected_result="R")
        g.add_node(obs)
        g.add_node(exp)
        g.add_edge(obs.id, exp.id, EdgeType.SUGGESTS)

        data = g.to_dict()
        restored = ReasoningGraph.from_dict(data)

        assert restored.node_count() == 2
        assert restored.edge_count() == 1
        assert restored.get_node(obs.id) is not None
        assert restored.get_node(exp.id) is not None

    def test_to_dict_empty(self) -> None:
        g = ReasoningGraph()
        data = g.to_dict()
        assert "nodes" in data
        assert "edges" in data
        restored = ReasoningGraph.from_dict(data)
        assert restored.node_count() == 0
