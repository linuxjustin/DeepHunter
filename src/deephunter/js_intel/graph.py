"""AttackSurfaceGraph integration for JavaScript Intelligence.

Maps JS analysis results into graph nodes and edges:
  - JS_BUNDLE nodes for JavaScript files
  - JS_ENDPOINT nodes for discovered endpoints
  - JS_MODULE nodes for module dependencies
  - JS_ROUTE nodes for client-side routes
  - Edges connecting JS artifacts to hosts, apps, technologies, etc.
"""

from __future__ import annotations

from deephunter.js_intel.models import JSAnalysisResult
from deephunter.recon.graph import AttackSurfaceGraph
from deephunter.recon.models import (
    GraphEdgeType,
    GraphNodeType,
    ReconSourceType,
)


class JSGraphBuilder:
    """Builds and enriches an AttackSurfaceGraph from JS analysis results.

    Usage::

        builder = JSGraphBuilder()
        builder.integrate(result, graph)
    """

    def integrate(
        self,
        result: JSAnalysisResult,
        graph: AttackSurfaceGraph,
        host_id: str = "",
        application_id: str = "",
    ) -> dict[str, int]:
        """Add all JS intelligence observations to the graph.

        Args:
            result: JSAnalysisResult from the parser/engine.
            graph: AttackSurfaceGraph to enrich.
            host_id: Optional host ref_id to link JS artifacts to.
            application_id: Optional application ref_id to link JS artifacts to.

        Returns:
            Dict with counts of nodes and edges added.
        """
        nodes_before = graph.node_count
        edges_before = graph.edge_count

        # ── JS Bundle / File node ───────────────────────────────────
        bundle_ref = f"jsbundle-{result.id}"
        bundle_node = graph.ensure_node(
            ref_id=bundle_ref,
            node_type=GraphNodeType.JS_BUNDLE,
            label=result.source_url or "JavaScript Bundle",
            tags=["javascript", "bundle"] + result.detected_frameworks,
        )

        # Link bundle to host
        if host_id:
            graph.link(
                source_ref_id=host_id,
                target_ref_id=bundle_ref,
                edge_type=GraphEdgeType.HAS_JS_FILE,
                label="serves_js",
            )

        # Link bundle to application
        if application_id:
            graph.link(
                source_ref_id=application_id,
                target_ref_id=bundle_ref,
                edge_type=GraphEdgeType.CONTAINS,
                label="contains_js",
            )

        # ── Modules ─────────────────────────────────────────────────
        for mod in result.modules:
            mod_ref = f"jsmodule-{mod.id}"
            graph.ensure_node(
                ref_id=mod_ref,
                node_type=GraphNodeType.JS_MODULE,
                label=mod.name,
                tags=["module", mod.module_type.value],
            )
            graph.link(
                source_ref_id=bundle_ref,
                target_ref_id=mod_ref,
                edge_type=GraphEdgeType.CONTAINS,
                label=f"imports_{mod.name}",
            )

            if not mod.is_relative:
                graph.link(
                    source_ref_id=mod_ref,
                    target_ref_id=bundle_ref,
                    edge_type=GraphEdgeType.IMPORTS,
                    label=f"external_dep_{mod.name}",
                )

        # ── API Endpoints ───────────────────────────────────────────
        for ep in result.api_endpoints:
            ep_ref = f"jsendpoint-{ep.id}"
            graph.ensure_node(
                ref_id=ep_ref,
                node_type=GraphNodeType.JS_ENDPOINT,
                label=ep.url[:80],
                tags=["javascript", "endpoint", "api"],
            )
            graph.link(
                source_ref_id=bundle_ref,
                target_ref_id=ep_ref,
                edge_type=GraphEdgeType.DERIVED_FROM,
                label="extracted_from_js",
            )
            methods = ",".join(m.value for m in ep.methods)
            if methods:
                graph.link(
                    source_ref_id=ep_ref,
                    target_ref_id=ep_ref,
                    edge_type=GraphEdgeType.REFERENCES,
                    label=f"methods:{methods}",
                )

        # ── GraphQL Endpoints ───────────────────────────────────────
        for gql in result.graphql_endpoints:
            gql_ref = f"jsgraphql-{gql.id}"
            graph.ensure_node(
                ref_id=gql_ref,
                node_type=GraphNodeType.JS_ENDPOINT,
                label=gql.url[:80],
                tags=["javascript", "graphql"],
            )
            graph.link(
                source_ref_id=bundle_ref,
                target_ref_id=gql_ref,
                edge_type=GraphEdgeType.DERIVED_FROM,
                label="graphql_from_js",
            )

        # ── Routes ──────────────────────────────────────────────────
        for route in result.routes:
            route_ref = f"jsroute-{route.id}"
            graph.ensure_node(
                ref_id=route_ref,
                node_type=GraphNodeType.JS_ROUTE,
                label=route.path,
                tags=["route", "spa"],
            )
            graph.link(
                source_ref_id=bundle_ref,
                target_ref_id=route_ref,
                edge_type=GraphEdgeType.DEFINES_ROUTE,
                label="client_route",
            )

            if route.component:
                comp_ref = f"component-{route.component}"
                graph.ensure_node(
                    ref_id=comp_ref,
                    node_type=GraphNodeType.JS_MODULE,
                    label=route.component,
                    tags=["component"],
                )
                graph.link(
                    source_ref_id=route_ref,
                    target_ref_id=comp_ref,
                    edge_type=GraphEdgeType.REFERENCES,
                    label="renders",
                )

        # ── Auth observations ───────────────────────────────────────
        for auth in result.auth_observations:
            auth_ref = f"jsauth-{auth.id}"
            graph.ensure_node(
                ref_id=auth_ref,
                node_type=GraphNodeType.OBSERVATION,
                label=f"auth:{auth.mechanism}",
                tags=["auth", auth.mechanism],
            )
            graph.link(
                source_ref_id=bundle_ref,
                target_ref_id=auth_ref,
                edge_type=GraphEdgeType.REFERENCES,
                label=auth.mechanism,
            )

        # ── Frameworks → Technology nodes ──────────────────────────
        for fw in result.detected_frameworks:
            tech_ref = f"js-tech-{fw.lower().replace(' ', '_').replace('.', '_')}"
            graph.ensure_node(
                ref_id=tech_ref,
                node_type=GraphNodeType.TECHNOLOGY,
                label=fw,
                tags=["javascript", "framework"],
            )
            graph.link(
                source_ref_id=bundle_ref,
                target_ref_id=tech_ref,
                edge_type=GraphEdgeType.USES_TECHNOLOGY,
                label=f"uses_{fw}",
            )

        nodes_added = graph.node_count - nodes_before
        edges_added = graph.edge_count - edges_before

        return {"nodes_added": nodes_added, "edges_added": edges_added}
