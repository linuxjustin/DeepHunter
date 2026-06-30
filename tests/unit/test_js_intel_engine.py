"""Tests for the JavaScript Intelligence Engine."""

from __future__ import annotations

from deephunter.js_intel.engine import JSAnalysisEngine
from deephunter.recon.graph import AttackSurfaceGraph
from deephunter.recon.models import ApplicationType, GraphNodeType, ReconSourceType, TechCategory
from deephunter.recon.plugin import PluginResult


class TestJSAnalysisEngine:
    def make_engine(self) -> JSAnalysisEngine:
        return JSAnalysisEngine()

    def test_analyze_returns_result(self) -> None:
        engine = self.make_engine()
        result = engine.analyze("const x = 1;", source_url="https://example.com/test.js")
        assert result is not None
        assert result.id.startswith("jsr-")
        assert result.source_url == "https://example.com/test.js"
        assert result.content_size > 0

    def test_analyze_empty(self) -> None:
        engine = self.make_engine()
        result = engine.analyze("")
        assert result is not None
        assert result.modules == []
        assert result.api_endpoints == []

    def test_analyze_with_graph(self) -> None:
        engine = self.make_engine()
        graph = AttackSurfaceGraph()
        js = """
import React from 'react';
fetch('/api/users');
const routes = [{ path: '/dashboard', component: Dashboard }];
"""
        result = engine.analyze(js, source_url="https://example.com/app.js", graph=graph)
        assert graph.node_count > 0
        assert graph.edge_count > 0

    def test_analyze_graph_adds_bundle_node(self) -> None:
        engine = self.make_engine()
        graph = AttackSurfaceGraph()
        js = "var x = 1;"
        result = engine.analyze(js, source_url="https://example.com/app.js", graph=graph)
        bundles = graph.find_nodes_by_type(GraphNodeType.JS_BUNDLE)
        assert len(bundles) >= 1

    def test_analyze_graph_adds_endpoint_nodes(self) -> None:
        engine = self.make_engine()
        graph = AttackSurfaceGraph()
        js = """fetch('/api/data'); axios.get('/api/users');"""
        result = engine.analyze(js, source_url="https://example.com/app.js", graph=graph)
        endpoints = graph.find_nodes_by_type(GraphNodeType.JS_ENDPOINT)
        assert len(endpoints) >= 2

    def test_analyze_graph_adds_route_nodes(self) -> None:
        engine = self.make_engine()
        graph = AttackSurfaceGraph()
        js = """const routes = [{ path: '/dashboard' }, { path: '/settings' }];"""
        result = engine.analyze(js, source_url="https://example.com/app.js", graph=graph)
        routes = graph.find_nodes_by_type(GraphNodeType.JS_ROUTE)
        assert len(routes) >= 2

    def test_analyze_graph_adds_technology_nodes(self) -> None:
        engine = self.make_engine()
        graph = AttackSurfaceGraph()
        js = """import React from 'react'; import Vue from 'vue';"""
        result = engine.analyze(js, source_url="https://example.com/app.js", graph=graph)
        techs = graph.find_nodes_by_type(GraphNodeType.TECHNOLOGY)
        assert len(techs) >= 2

    def test_analyze_normalize_returns_plugin_result(self) -> None:
        engine = self.make_engine()
        result = engine.analyze_and_normalize(
            "import React from 'react'; fetch('/api/data');",
            source_url="https://example.com/app.js",
        )
        assert isinstance(result, PluginResult)
        assert result.success is True

    def test_normalize_js_files(self) -> None:
        engine = self.make_engine()
        result = engine.analyze_and_normalize(
            "var x = 1;",
            source_url="https://example.com/app.js",
        )
        assert len(result.js_files) == 1
        assert result.js_files[0].url == "https://example.com/app.js"
        assert result.js_files[0].source == ReconSourceType.JAVASCRIPT_ANALYSIS

    def test_normalize_endpoints(self) -> None:
        engine = self.make_engine()
        result = engine.analyze_and_normalize(
            "fetch('/api/users'); axios.get('/api/data');",
            source_url="https://example.com/app.js",
        )
        assert len(result.js_endpoints) >= 2

    def test_normalize_technologies(self) -> None:
        engine = self.make_engine()
        result = engine.analyze_and_normalize(
            "import React from 'react'; import Vue from 'vue';",
            source_url="https://example.com/app.js",
        )
        tech_names = [t.name for t in result.technologies]
        assert "React" in tech_names
        assert "Vue" in tech_names

    def test_normalize_application(self) -> None:
        engine = self.make_engine()
        result = engine.analyze_and_normalize(
            "import React from 'react';",
            source_url="https://example.com/app.js",
        )
        assert len(result.applications) >= 1
        assert result.applications[0].app_type == ApplicationType.SINGLE_PAGE_APP

    def test_normalize_application_api(self) -> None:
        engine = self.make_engine()
        result = engine.analyze_and_normalize(
            "const app = express();",
            source_url="https://example.com/app.js",
        )
        assert len(result.applications) >= 1
        assert result.applications[0].app_type == ApplicationType.API

    def test_normalize_empty(self) -> None:
        engine = self.make_engine()
        result = engine.analyze_and_normalize("")
        assert result.success is True
        assert len(result.js_files) == 0
        assert result.js_endpoints == []

    def test_dependency_injection(self) -> None:
        from deephunter.js_intel.parser import JSParser
        from deephunter.js_intel.graph import JSGraphBuilder
        from deephunter.js_intel.sko import JSSKOGenerator

        parser = JSParser()
        graph_builder = JSGraphBuilder()
        sko_gen = JSSKOGenerator()
        engine = JSAnalysisEngine(parser=parser, graph_builder=graph_builder, sko_generator=sko_gen)
        result = engine.analyze("var x = 1;")
        assert result is not None

    def test_analyze_with_host_and_app(self) -> None:
        engine = self.make_engine()
        graph = AttackSurfaceGraph()
        graph.ensure_node("host-1", GraphNodeType.HOST, "example.com")
        js = "import React from 'react'; fetch('/api/users');"
        result = engine.analyze(js, source_url="https://example.com/app.js", graph=graph, host_id="host-1")
        assert result is not None
        assert result.detected_frameworks == ["React"]


class TestMapFrameworkToCategory:
    def test_frontend(self) -> None:
        engine = JSAnalysisEngine()
        assert engine._map_framework_to_category("React") == TechCategory.FRONTEND
        assert engine._map_framework_to_category("Vue") == TechCategory.FRONTEND
        assert engine._map_framework_to_category("Angular") == TechCategory.FRONTEND
        assert engine._map_framework_to_category("Svelte") == TechCategory.FRONTEND

    def test_framework(self) -> None:
        engine = JSAnalysisEngine()
        assert engine._map_framework_to_category("Next.js") == TechCategory.FRAMEWORK
        assert engine._map_framework_to_category("Express") == TechCategory.FRAMEWORK

    def test_unknown(self) -> None:
        engine = JSAnalysisEngine()
        assert engine._map_framework_to_category("UnknownLib") == TechCategory.UNKNOWN
        assert engine._map_framework_to_category("Axios") == TechCategory.UNKNOWN


class TestInferAppType:
    def test_spa(self) -> None:
        engine = JSAnalysisEngine()
        assert engine._infer_app_type(["React"]) == ApplicationType.SINGLE_PAGE_APP
        assert engine._infer_app_type(["Next.js"]) == ApplicationType.SINGLE_PAGE_APP
        assert engine._infer_app_type(["Vue"]) == ApplicationType.SINGLE_PAGE_APP

    def test_api(self) -> None:
        engine = JSAnalysisEngine()
        assert engine._infer_app_type(["Express"]) == ApplicationType.API

    def test_web_app(self) -> None:
        engine = JSAnalysisEngine()
        assert engine._infer_app_type(["jQuery"]) == ApplicationType.WEB_APP
        assert engine._infer_app_type([]) == ApplicationType.WEB_APP
