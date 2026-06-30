"""Recon Pipeline — stage-based processing of reconnaissance data.

Follows the same pattern as ``PlanningPipeline``, ``ReasoningPipeline``,
and ``ContextPipeline``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from deephunter.recon.events import ReconEventBus, ReconPipelineEvent
from deephunter.recon.models import (
    APIEndpoint,
    Asset,
    AuthMechanism,
    AuthObservation,
    CloudResource,
    DNSRecord,
    Endpoint,
    HTTPObservation,
    Host,
    JavaScriptEndpoint,
    JavaScriptFile,
    Parameter,
    Program,
    ReconSourceType,
    Scope,
    Technology,
)
from deephunter.recon.scope import ScopeManager
from deephunter.recon.asset import AssetInventory
from deephunter.recon.host import HostRegistry
from deephunter.recon.http import HTTPIntelligence
from deephunter.recon.technology import TechnologyIntelligence
from deephunter.recon.endpoint import EndpointInventory
from deephunter.recon.auth import AuthIntelligence
from deephunter.recon.application import ApplicationInventory
from deephunter.recon.cloud import CloudIntelligence
from deephunter.recon.graph import AttackSurfaceGraph, GraphEdgeType, GraphNodeType


@dataclass
class PipelineReport:
    stage_times: dict[str, float] = field(default_factory=dict)
    total_seconds: float = 0.0
    entities_added: int = 0


class ReconStage:
    """Base class for a recon pipeline stage."""

    name: str = ""

    def process(
        self,
        data: dict[str, Any],
        scope_mgr: ScopeManager,
        assets: AssetInventory,
        hosts: HostRegistry,
        http_intel: HTTPIntelligence,
        tech_intel: TechnologyIntelligence,
        endpoints: EndpointInventory,
        auth_intel: AuthIntelligence,
        app_inv: ApplicationInventory,
        cloud_intel: CloudIntelligence,
        graph: AttackSurfaceGraph,
        event_bus: ReconEventBus,
    ) -> None:
        ...


class LoadScopeStage(ReconStage):
    """Stage 1: Load programs and scope entries."""

    name = "load_scope"

    def process(
        self,
        data: dict[str, Any],
        scope_mgr: ScopeManager,
        assets: AssetInventory,
        hosts: HostRegistry,
        http_intel: HTTPIntelligence,
        tech_intel: TechnologyIntelligence,
        endpoints: EndpointInventory,
        auth_intel: AuthIntelligence,
        app_inv: ApplicationInventory,
        cloud_intel: CloudIntelligence,
        graph: AttackSurfaceGraph,
        event_bus: ReconEventBus,
    ) -> None:
        for prog_data in data.get("programs", []):
            program = Program(**prog_data) if isinstance(prog_data, dict) else prog_data
            scope_mgr.add_program(program)
            graph.ensure_node(program.id, GraphNodeType.PROGRAM, program.name)
        for scope_data in data.get("scopes", []):
            scope = Scope(**scope_data) if isinstance(scope_data, dict) else scope_data
            scope_mgr.add_scope(scope)
            graph.ensure_node(scope.id, GraphNodeType.SCOPE, scope.target)

        # Link scopes to programs
        for scope in scope_mgr.list_scopes():
            scope_node = graph.find_node_by_ref(scope.id)
            prog_node = graph.find_node_by_ref(scope.program_id)
            if scope_node and prog_node:
                graph.link(scope.id, scope.program_id, GraphEdgeType.BELONGS_TO, "scope belongs to program")


class ProcessAssetsStage(ReconStage):
    """Stage 2: Process discovered assets."""

    name = "process_assets"

    def process(
        self,
        data: dict[str, Any],
        scope_mgr: ScopeManager,
        assets: AssetInventory,
        hosts: HostRegistry,
        http_intel: HTTPIntelligence,
        tech_intel: TechnologyIntelligence,
        endpoints: EndpointInventory,
        auth_intel: AuthIntelligence,
        app_inv: ApplicationInventory,
        cloud_intel: CloudIntelligence,
        graph: AttackSurfaceGraph,
        event_bus: ReconEventBus,
    ) -> None:
        for asset_data in data.get("assets", []):
            asset = Asset(**asset_data) if isinstance(asset_data, dict) else asset_data
            try:
                assets.add(asset)
            except ValueError:
                continue
            graph.ensure_node(asset.id, GraphNodeType.ASSET, asset.identifier)

            # Link asset to scope
            if asset.scope_id:
                graph.link(asset.id, asset.scope_id, GraphEdgeType.BELONGS_TO, "asset in scope")


class ProcessHostsStage(ReconStage):
    """Stage 3: Process discovered hosts."""

    name = "process_hosts"

    def process(
        self,
        data: dict[str, Any],
        scope_mgr: ScopeManager,
        assets: AssetInventory,
        hosts: HostRegistry,
        http_intel: HTTPIntelligence,
        tech_intel: TechnologyIntelligence,
        endpoints: EndpointInventory,
        auth_intel: AuthIntelligence,
        app_inv: ApplicationInventory,
        cloud_intel: CloudIntelligence,
        graph: AttackSurfaceGraph,
        event_bus: ReconEventBus,
    ) -> None:
        for host_data in data.get("hosts", []):
            host = Host(**host_data) if isinstance(host_data, dict) else host_data
            try:
                hosts.add(host)
            except ValueError:
                continue
            graph.ensure_node(host.id, GraphNodeType.HOST, f"{host.hostname}:{host.port}")

            # Link host to asset
            if host.asset_id:
                graph.link(host.id, host.asset_id, GraphEdgeType.RESOLVES_TO)

            # Link host to scope via asset
            asset = assets.get(host.asset_id)
            if asset and asset.scope_id:
                graph.link(host.id, asset.scope_id, GraphEdgeType.BELONGS_TO)


class ProcessTechnologiesStage(ReconStage):
    """Stage 4: Process detected technologies."""

    name = "process_technologies"

    def process(
        self,
        data: dict[str, Any],
        scope_mgr: ScopeManager,
        assets: AssetInventory,
        hosts: HostRegistry,
        http_intel: HTTPIntelligence,
        tech_intel: TechnologyIntelligence,
        endpoints: EndpointInventory,
        auth_intel: AuthIntelligence,
        app_inv: ApplicationInventory,
        cloud_intel: CloudIntelligence,
        graph: AttackSurfaceGraph,
        event_bus: ReconEventBus,
    ) -> None:
        for tech_data in data.get("technologies", []):
            tech = Technology(**tech_data) if isinstance(tech_data, dict) else tech_data
            try:
                tech_intel.add(tech)
            except ValueError:
                continue
            graph.ensure_node(tech.id, GraphNodeType.TECHNOLOGY, tech.name)


class ProcessEndpointsStage(ReconStage):
    """Stage 5: Process discovered endpoints and parameters."""

    name = "process_endpoints"

    def process(
        self,
        data: dict[str, Any],
        scope_mgr: ScopeManager,
        assets: AssetInventory,
        hosts: HostRegistry,
        http_intel: HTTPIntelligence,
        tech_intel: TechnologyIntelligence,
        endpoints: EndpointInventory,
        auth_intel: AuthIntelligence,
        app_inv: ApplicationInventory,
        cloud_intel: CloudIntelligence,
        graph: AttackSurfaceGraph,
        event_bus: ReconEventBus,
    ) -> None:
        for ep_data in data.get("endpoints", []):
            ep = Endpoint(**ep_data) if isinstance(ep_data, dict) else ep_data
            try:
                endpoints.add(ep)
            except ValueError:
                continue
            graph.ensure_node(ep.id, GraphNodeType.ENDPOINT, f"{ep.method.value} {ep.path}")

            # Link endpoint to host
            if ep.host_id:
                graph.link(ep.id, ep.host_id, GraphEdgeType.HAS_ENDPOINT)

            # Process parameters
            for param in ep.parameters:
                graph.ensure_node(param.id, GraphNodeType.PARAMETER, param.name)
                graph.link(param.id, ep.id, GraphEdgeType.HAS_PARAMETER)

        for api_data in data.get("api_endpoints", []):
            api_ep = APIEndpoint(**api_data) if isinstance(api_data, dict) else api_data
            try:
                app_inv.add_api_endpoint(api_ep)
            except ValueError:
                continue
            graph.ensure_node(api_ep.id, GraphNodeType.API_ENDPOINT, f"{api_ep.method.value} {api_ep.path}")


class ProcessAuthStage(ReconStage):
    """Stage 6: Process authentication observations."""

    name = "process_auth"

    def process(
        self,
        data: dict[str, Any],
        scope_mgr: ScopeManager,
        assets: AssetInventory,
        hosts: HostRegistry,
        http_intel: HTTPIntelligence,
        tech_intel: TechnologyIntelligence,
        endpoints: EndpointInventory,
        auth_intel: AuthIntelligence,
        app_inv: ApplicationInventory,
        cloud_intel: CloudIntelligence,
        graph: AttackSurfaceGraph,
        event_bus: ReconEventBus,
    ) -> None:
        for auth_data in data.get("auth_mechanisms", []):
            mech = AuthMechanism(**auth_data) if isinstance(auth_data, dict) else auth_data
            try:
                auth_intel.add_mechanism(mech)
            except ValueError:
                continue
            graph.ensure_node(mech.id, GraphNodeType.AUTH_METHOD, mech.auth_type.value)


class ProcessCloudStage(ReconStage):
    """Stage 7: Process cloud resources."""

    name = "process_cloud"

    def process(
        self,
        data: dict[str, Any],
        scope_mgr: ScopeManager,
        assets: AssetInventory,
        hosts: HostRegistry,
        http_intel: HTTPIntelligence,
        tech_intel: TechnologyIntelligence,
        endpoints: EndpointInventory,
        auth_intel: AuthIntelligence,
        app_inv: ApplicationInventory,
        cloud_intel: CloudIntelligence,
        graph: AttackSurfaceGraph,
        event_bus: ReconEventBus,
    ) -> None:
        for cloud_data in data.get("cloud_resources", []):
            resource = CloudResource(**cloud_data) if isinstance(cloud_data, dict) else cloud_data
            try:
                cloud_intel.add(resource)
            except ValueError:
                continue
            graph.ensure_node(resource.id, GraphNodeType.CLOUD_RESOURCE, f"{resource.provider}/{resource.name}")


class ReconPipeline:
    """Stage-based pipeline for processing reconnaissance data.

    Transforms raw recon input into structured intelligence through
    a series of composable stages, mirroring the pattern used by
    ``PlanningPipeline`` and ``ReasoningPipeline``.
    """

    def __init__(self) -> None:
        self._stages: list[ReconStage] = [
            LoadScopeStage(),
            ProcessAssetsStage(),
            ProcessHostsStage(),
            ProcessTechnologiesStage(),
            ProcessEndpointsStage(),
            ProcessAuthStage(),
            ProcessCloudStage(),
        ]

    def run(
        self,
        data: dict[str, Any],
        scope_mgr: ScopeManager,
        assets: AssetInventory,
        hosts: HostRegistry,
        http_intel: HTTPIntelligence,
        tech_intel: TechnologyIntelligence,
        endpoints: EndpointInventory,
        auth_intel: AuthIntelligence,
        app_inv: ApplicationInventory,
        cloud_intel: CloudIntelligence,
        graph: AttackSurfaceGraph,
        event_bus: ReconEventBus | None = None,
    ) -> PipelineReport:
        bus = event_bus or ReconEventBus()
        start = time.perf_counter()
        report = PipelineReport()

        for stage in self._stages:
            stage_start = time.perf_counter()
            bus.emit(
                ReconPipelineEvent(
                    stage=stage.name,
                    status="started",
                    description=f"Starting stage: {stage.name}",
                )
            )
            try:
                stage.process(
                    data, scope_mgr, assets, hosts, http_intel, tech_intel,
                    endpoints, auth_intel, app_inv, cloud_intel, graph, bus,
                )
            except Exception:
                import logging
                logging.getLogger(__name__).exception("Recon stage %s failed", stage.name)
                bus.emit(
                    ReconPipelineEvent(
                        stage=stage.name,
                        status="failed",
                        description=f"Stage {stage.name} failed",
                    )
                )
                break
            elapsed = time.perf_counter() - stage_start
            report.stage_times[stage.name] = elapsed
            bus.emit(
                ReconPipelineEvent(
                    stage=stage.name,
                    status="completed",
                    description=f"Stage {stage.name} completed in {elapsed:.3f}s",
                )
            )

        report.total_seconds = time.perf_counter() - start
        report.entities_added = (
            scope_mgr.scope_count
            + assets.count
            + hosts.count
            + tech_intel.count
            + endpoints.count
            + auth_intel.mechanism_count
            + cloud_intel.count
            + app_inv.application_count
            + app_inv.api_count
            + graph.node_count
        )
        bus.emit(
            ReconPipelineEvent(
                stage="pipeline",
                status="completed",
                description=f"Pipeline completed in {report.total_seconds:.3f}s ({report.entities_added} entities)",
            )
        )

        graph.emit_update()
        return report
