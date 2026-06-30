"""Recon Session — top-level orchestration for reconnaissance intelligence.

Wraps all recon managers into a single session with lifecycle management,
following the pattern of ``InvestigationSession`` in the reasoning module.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from deephunter.recon.application import ApplicationInventory
from deephunter.recon.asset import AssetInventory
from deephunter.recon.auth import AuthIntelligence
from deephunter.recon.cloud import CloudIntelligence
from deephunter.recon.endpoint import EndpointInventory
from deephunter.recon.events import ReconEventBus
from deephunter.recon.graph import AttackSurfaceGraph
from deephunter.recon.host import HostRegistry
from deephunter.recon.http import HTTPIntelligence
from deephunter.recon.pipeline import PipelineReport, ReconPipeline
from deephunter.recon.scope import ScopeManager
from deephunter.recon.store import ReconStore
from deephunter.recon.technology import TechnologyIntelligence
from deephunter.recon.timeline import ReconTimeline


class ReconSession:
    """Top-level session for a reconnaissance investigation.

    Manages all recon data managers and coordinates pipeline execution,
    persistence, and reporting.
    """

    def __init__(
        self,
        target: str = "",
        store: ReconStore | None = None,
        event_bus: ReconEventBus | None = None,
    ) -> None:
        self.id: str = f"rec-{uuid4().hex[:12]}"
        self.target: str = target
        self.created_at: datetime = datetime.now(UTC)
        self.updated_at: datetime = datetime.now(UTC)

        self._store = store
        self._event_bus = event_bus or ReconEventBus()

        # Managers
        self.scope_mgr = ScopeManager(event_bus=self._event_bus)
        self.assets = AssetInventory(event_bus=self._event_bus)
        self.hosts = HostRegistry(event_bus=self._event_bus)
        self.http_intel = HTTPIntelligence(event_bus=self._event_bus)
        self.tech_intel = TechnologyIntelligence(event_bus=self._event_bus)
        self.endpoints = EndpointInventory(event_bus=self._event_bus)
        self.auth_intel = AuthIntelligence(event_bus=self._event_bus)
        self.app_inv = ApplicationInventory(event_bus=self._event_bus)
        self.cloud_intel = CloudIntelligence(event_bus=self._event_bus)
        self.graph = AttackSurfaceGraph(event_bus=self._event_bus)
        self.timeline = ReconTimeline(session_id=self.id, event_bus=self._event_bus)

        # Pipeline
        self._pipeline = ReconPipeline()
        self._last_report: PipelineReport | None = None

    # ── Properties ───────────────────────────────────────────────

    @property
    def store(self) -> ReconStore | None:
        return self._store

    @store.setter
    def store(self, store: ReconStore) -> None:
        self._store = store

    @property
    def event_bus(self) -> ReconEventBus:
        return self._event_bus

    @property
    def last_report(self) -> PipelineReport | None:
        return self._last_report

    # ── Pipeline ─────────────────────────────────────────────────

    def process(self, data: dict[str, Any]) -> PipelineReport:
        """Process recon data through the pipeline."""
        report = self._pipeline.run(
            data=data,
            scope_mgr=self.scope_mgr,
            assets=self.assets,
            hosts=self.hosts,
            http_intel=self.http_intel,
            tech_intel=self.tech_intel,
            endpoints=self.endpoints,
            auth_intel=self.auth_intel,
            app_inv=self.app_inv,
            cloud_intel=self.cloud_intel,
            graph=self.graph,
            event_bus=self._event_bus,
        )
        self._last_report = report
        self.updated_at = datetime.now(UTC)
        return report

    # ── Persistence ──────────────────────────────────────────────

    def save(self) -> None:
        if self._store is None:
            raise ValueError("No store configured for this session")
        state = self.to_state()
        self._store.save_state(state)

    def to_state(self) -> Any:
        from deephunter.recon.models import ReconState
        return ReconState(
            id=self.id,
            target=self.target,
            programs=self.scope_mgr.list_programs(),
            scopes=self.scope_mgr.list_scopes(),
            assets=self.assets.list_all(),
            hosts=self.hosts.list_all(),
            http_observations=self.http_intel.list_all(),
            technologies=self.tech_intel.list_all(),
            endpoints=self.endpoints.list_all(),
            auth_mechanisms=self.auth_intel.list_mechanisms(),
            cloud_resources=self.cloud_intel.list_all(),
            timeline=self.timeline.list_all(),
            created_at=self.created_at,
            updated_at=self.updated_at,
        )

    def summary(self) -> dict[str, Any]:
        """Return a summary of the session state."""
        return {
            "session_id": self.id,
            "target": self.target,
            "programs": self.scope_mgr.program_count,
            "scopes": self.scope_mgr.scope_count,
            "assets": self.assets.count,
            "hosts": self.hosts.count,
            "http_observations": self.http_intel.count,
            "technologies": self.tech_intel.count,
            "endpoints": self.endpoints.count,
            "auth_mechanisms": self.auth_intel.mechanism_count,
            "cloud_resources": self.cloud_intel.count,
            "graph_nodes": self.graph.node_count,
            "graph_edges": self.graph.edge_count,
            "timeline_entries": self.timeline.count,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
