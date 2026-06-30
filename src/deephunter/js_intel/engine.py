"""JavaScript Intelligence Engine — orchestrates analysis of JavaScript artifacts.

Combines the parser with graph integration and SKO generation into a
single analysis pipeline.

Design:
  - ``JSAnalysisEngine`` is the top-level facade
  - Accepts raw JS content or a file URL
  - Returns a ``JSAnalysisResult`` with all observations
  - Optionally enriches an ``AttackSurfaceGraph``
  - Optionally produces ``SecurityKnowledgeObject`` entries

Thread-safe and stateless.
"""

from __future__ import annotations

from typing import Any

from deephunter.js_intel.graph import JSGraphBuilder
from deephunter.js_intel.models import JSAnalysisResult
from deephunter.js_intel.parser import JSParser
from deephunter.js_intel.sko import JSSKOGenerator
from deephunter.recon.graph import AttackSurfaceGraph
from deephunter.recon.plugin import PluginResult

from deephunter.recon.models import (
    Application,
    ApplicationType,
    JavaScriptEndpoint,
    JavaScriptFile,
    ReconSourceType,
    Technology,
    TechCategory,
)


class JSAnalysisEngine:
    """Top-level facade for JavaScript intelligence analysis.

    Usage::

        engine = JSAnalysisEngine()
        result = engine.analyze(js_content, source_url="https://example.com/app.js")

        # With graph integration:
        graph = AttackSurfaceGraph()
        result = engine.analyze(js_content, graph=graph)
    """

    def __init__(
        self,
        parser: JSParser | None = None,
        graph_builder: JSGraphBuilder | None = None,
        sko_generator: JSSKOGenerator | None = None,
    ) -> None:
        self._parser = parser or JSParser()
        self._graph_builder = graph_builder or JSGraphBuilder()
        self._sko_generator = sko_generator or JSSKOGenerator()

    def analyze(
        self,
        content: str,
        source_url: str = "",
        graph: AttackSurfaceGraph | None = None,
        host_id: str = "",
        application_id: str = "",
    ) -> JSAnalysisResult:
        """Analyze JavaScript source content.

        Args:
            content: Raw JavaScript source text.
            source_url: Origin URL of the JavaScript file.
            graph: Optional AttackSurfaceGraph to enrich.
            host_id: Host ID to associate JS files with.
            application_id: Application ID to associate JS files with.

        Returns:
            JSAnalysisResult with all extracted observations.
        """
        result = self._parser.parse(content, source_url=source_url)

        if graph:
            self._graph_builder.integrate(result, graph, host_id=host_id)

        return result

    def analyze_and_normalize(
        self,
        content: str,
        source_url: str = "",
        host_id: str = "",
        application_id: str = "",
    ) -> PluginResult:
        """Analyze JS content and normalize into a PluginResult.

        This is the primary integration point for the tool adapter
        and pipeline systems.

        Returns:
            PluginResult with recon models populated.
        """
        result = self.analyze(content, source_url=source_url)

        plugin_result = PluginResult()

        if not content or not content.strip():
            plugin_result.success = True
            return plugin_result

        # JavaScriptFile
        js_file = JavaScriptFile(
            host_id=host_id,
            url=source_url,
            size=result.content_size,
            hash=result.content_hash,
            contains_sources=True,
            contains_endpoints=len(result.api_endpoints) > 0 or len(result.graphql_endpoints) > 0,
            contains_secrets=len(result.secret_observations) > 0,
            source=ReconSourceType.JAVASCRIPT_ANALYSIS,
        )
        plugin_result.js_files.append(js_file)

        # JavaScriptEndpoints
        for ep in result.api_endpoints:
            plugin_result.js_endpoints.append(JavaScriptEndpoint(
                host_id=host_id,
                source_url=source_url,
                discovered_url=ep.url,
                line_number=ep.line_number,
                context=ep.context[:200],
                source=ReconSourceType.JAVASCRIPT_ANALYSIS,
            ))

        for ep in result.graphql_endpoints:
            plugin_result.js_endpoints.append(JavaScriptEndpoint(
                host_id=host_id,
                source_url=source_url,
                discovered_url=ep.url,
                line_number=ep.line_number,
                context=ep.context[:200],
                source=ReconSourceType.JAVASCRIPT_ANALYSIS,
            ))

        # Technologies from detected frameworks
        for fw in result.detected_frameworks:
            category = self._map_framework_to_category(fw)
            tech = Technology(
                name=fw,
                category=category,
                source=ReconSourceType.JAVASCRIPT_ANALYSIS,
                metadata={"detected_by": "js_intel", "evidence": fw, "source_url": source_url},
            )
            plugin_result.technologies.append(tech)

        for fw_obs in result.framework_observations:
            already = any(t.name == fw_obs.framework for t in plugin_result.technologies)
            if not already:
                category = self._map_framework_to_category(fw_obs.framework)
                plugin_result.technologies.append(Technology(
                    name=fw_obs.framework,
                    category=category,
                    source=ReconSourceType.JAVASCRIPT_ANALYSIS,
                    metadata={"detected_by": "js_intel", "evidence": fw_obs.evidence, "source_url": source_url},
                ))

        # Application inference
        if result.detected_frameworks:
            app = Application(
                host_id=host_id,
                name=source_url or "JavaScript Application",
                app_type=self._infer_app_type(result.detected_frameworks),
                tags=result.detected_frameworks + result.build_tool_hints,
                source=ReconSourceType.JAVASCRIPT_ANALYSIS,
                metadata={"source_url": source_url, "js_analysis_id": result.id},
            )
            plugin_result.applications.append(app)

        plugin_result.success = True
        return plugin_result

    @staticmethod
    def _map_framework_to_category(framework: str) -> TechCategory:
        fw = framework.lower().strip()
        if fw in {"react", "vue", "angular", "svelte", "jquery", "lodash"}:
            return TechCategory.FRONTEND
        if fw in {"next.js", "nuxt", "astro", "remix", "express"}:
            return TechCategory.FRAMEWORK
        if fw in {"axios", "moment"}:
            return TechCategory.UNKNOWN
        return TechCategory.UNKNOWN

    @staticmethod
    def _infer_app_type(frameworks: list[str]) -> ApplicationType:
        fw_lower = [f.lower() for f in frameworks]
        if any(f in fw_lower for f in {"next.js", "nuxt", "astro", "remix"}):
            return ApplicationType.SINGLE_PAGE_APP
        if any(f in fw_lower for f in {"express"}):
            return ApplicationType.API
        if any(f in fw_lower for f in {"react", "vue", "angular", "svelte"}):
            return ApplicationType.SINGLE_PAGE_APP
        return ApplicationType.WEB_APP
