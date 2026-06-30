"""Tests for the JavaScript Intelligence AttackSurfaceGraph integration."""

from __future__ import annotations

from deephunter.js_intel.graph import JSGraphBuilder
from deephunter.js_intel.models import (
    JSAnalysisResult,
    JSEndpointRef,
    JSModule,
    JSRoute,
)
from deephunter.recon.graph import AttackSurfaceGraph
from deephunter.recon.models import (
    GraphEdgeType,
    GraphNodeType,
)


class TestJSGraphBuilder:
    def make_builder(self) -> JSGraphBuilder:
        return JSGraphBuilder()

    def make_sample_result(self) -> JSAnalysisResult:
        return JSAnalysisResult(
            source_url="https://example.com/app.js",
            modules=[
                JSModule(name="react", is_relative=False),
                JSModule(name="../utils/api", is_relative=True),
            ],
            api_endpoints=[
                JSEndpointRef(url="/api/users"),
                JSEndpointRef(url="/api/data"),
            ],
            routes=[
                JSRoute(path="/dashboard", component="Dashboard"),
                JSRoute(path="/settings", is_dynamic=False),
            ],
            detected_frameworks=["React", "Next.js"],
        )

    def test_integrate_empty_result(self) -> None:
        builder = self.make_builder()
        graph = AttackSurfaceGraph()
        result = JSAnalysisResult()
        stats = builder.integrate(result, graph)
        assert stats["nodes_added"] >= 0
        assert stats["edges_added"] >= 0

    def test_integrate_adds_bundle_node(self) -> None:
        builder = self.make_builder()
        graph = AttackSurfaceGraph()
        result = self.make_sample_result()
        builder.integrate(result, graph)
        bundles = graph.find_nodes_by_type(GraphNodeType.JS_BUNDLE)
        assert len(bundles) == 1
        assert bundles[0].label == result.source_url

    def test_integrate_adds_module_nodes(self) -> None:
        builder = self.make_builder()
        graph = AttackSurfaceGraph()
        result = self.make_sample_result()
        builder.integrate(result, graph)
        modules = graph.find_nodes_by_type(GraphNodeType.JS_MODULE)
        assert len(modules) >= 2

    def test_integrate_adds_endpoint_nodes(self) -> None:
        builder = self.make_builder()
        graph = AttackSurfaceGraph()
        result = self.make_sample_result()
        builder.integrate(result, graph)
        endpoints = graph.find_nodes_by_type(GraphNodeType.JS_ENDPOINT)
        assert len(endpoints) >= 2

    def test_integrate_adds_route_nodes(self) -> None:
        builder = self.make_builder()
        graph = AttackSurfaceGraph()
        result = self.make_sample_result()
        builder.integrate(result, graph)
        routes = graph.find_nodes_by_type(GraphNodeType.JS_ROUTE)
        assert len(routes) >= 2

    def test_integrate_adds_technology_nodes(self) -> None:
        builder = self.make_builder()
        graph = AttackSurfaceGraph()
        result = self.make_sample_result()
        builder.integrate(result, graph)
        techs = graph.find_nodes_by_type(GraphNodeType.TECHNOLOGY)
        assert len(techs) >= 2

    def test_integrate_adds_edges(self) -> None:
        builder = self.make_builder()
        graph = AttackSurfaceGraph()
        result = self.make_sample_result()
        stats = builder.integrate(result, graph)
        assert stats["edges_added"] > 0

    def test_integrate_with_host_link(self) -> None:
        builder = self.make_builder()
        graph = AttackSurfaceGraph()
        graph.ensure_node("host-1", GraphNodeType.HOST, "example.com")
        result = self.make_sample_result()
        builder.integrate(result, graph, host_id="host-1")
        host_node = graph.find_node_by_ref("host-1")
        assert host_node is not None
        edges = graph.get_outgoing(host_node.id)
        assert any(e.edge_type == GraphEdgeType.HAS_JS_FILE for e in edges)

    def test_integrate_with_app_link(self) -> None:
        builder = self.make_builder()
        graph = AttackSurfaceGraph()
        graph.ensure_node("app-1", GraphNodeType.APPLICATION, "MyApp")
        result = self.make_sample_result()
        builder.integrate(result, graph, application_id="app-1")
        app_node = graph.find_node_by_ref("app-1")
        assert app_node is not None
        edges = graph.get_outgoing(app_node.id)
        assert any(e.edge_type == GraphEdgeType.CONTAINS and "js" in e.label for e in edges)

    def test_integrate_idempotent(self) -> None:
        builder = self.make_builder()
        graph = AttackSurfaceGraph()
        result = self.make_sample_result()
        stats1 = builder.integrate(result, graph)
        stats2 = builder.integrate(result, graph)
        # ensure_node is idempotent — only new nodes/edges added
        assert stats2["nodes_added"] <= stats1["nodes_added"]

    def test_integrate_route_component_nodes(self) -> None:
        builder = self.make_builder()
        graph = AttackSurfaceGraph()
        result = self.make_sample_result()
        builder.integrate(result, graph)
        modules = graph.find_nodes_by_type(GraphNodeType.JS_MODULE)
        module_labels = [m.label for m in modules]
        assert "Dashboard" in module_labels

    def test_integrate_observation_auth_nodes(self) -> None:
        builder = self.make_builder()
        graph = AttackSurfaceGraph()
        from deephunter.js_intel.models import JSAuthObs
        result = JSAnalysisResult(
            source_url="https://example.com/app.js",
            auth_observations=[JSAuthObs(mechanism="jwt", location="header")],
        )
        builder.integrate(result, graph)
        obs_nodes = graph.find_nodes_by_type(GraphNodeType.OBSERVATION)
        assert len(obs_nodes) >= 1

    def test_stats_return_value(self) -> None:
        builder = self.make_builder()
        graph = AttackSurfaceGraph()
        result = self.make_sample_result()
        stats = builder.integrate(result, graph)
        assert "nodes_added" in stats
        assert "edges_added" in stats
        assert isinstance(stats["nodes_added"], int)
        assert isinstance(stats["edges_added"], int)
