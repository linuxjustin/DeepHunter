"""Recon Correlation Engine — orchestrates the full intelligence pipeline.

Chains: adapter output → technology intel → framework intel → attack surface
profile → investigation hints.  Integrates with ReconSession for graph updates.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from deephunter.correlation.events import (
    CorrelationCompletedEvent,
    CorrelationEventBus,
    CorrelationFailedEvent,
    CorrelationStartedEvent,
    PipelineStageCompletedEvent,
    PipelineStageStartedEvent,
)
from deephunter.framework_intel.correlator import FrameworkCorrelator
from deephunter.framework_intel.models import (
    ApplicationProfile,
    AttackSurfaceProfile,
    StackCorrelation,
)
from deephunter.framework_intel.profiler import AttackSurfaceProfiler
from deephunter.intel.hints import InvestigationHintGenerator
from deephunter.intel.models import InvestigationHint
from deephunter.recon.graph import AttackSurfaceGraph
from deephunter.recon.models import GraphEdgeType, GraphNodeType, Technology as ReconTechnology
from deephunter.tech_intel.engine import TechnologyIntelEngine
from deephunter.tech_intel.models import TechnologyKnowledge


class CorrelationResult(BaseModel):
    """The full result of a correlation run."""

    id: str = Field(default_factory=lambda: f"cr-{uuid4().hex[:12]}")
    source_technologies: list[str] = Field(default_factory=list)
    technology_knowledge: TechnologyKnowledge | None = None
    stack_correlation: StackCorrelation | None = None
    attack_surface_profile: AttackSurfaceProfile | None = None
    investigation_hints: list[InvestigationHint] = Field(default_factory=list)
    graph_nodes_added: int = 0
    graph_edges_added: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CorrelationEngine:
    """Orchestrates the full recon intelligence pipeline.

    Stages:
      1. tech_intel — interpret detected technologies
      2. framework_intel — correlate into framework stacks
      3. profiler — generate attack surface profile
      4. graph — update attack surface graph
      5. hints — generate investigation hints
    """

    def __init__(
        self,
        tech_intel: TechnologyIntelEngine | None = None,
        correlator: FrameworkCorrelator | None = None,
        profiler: AttackSurfaceProfiler | None = None,
        hint_generator: InvestigationHintGenerator | None = None,
        event_bus: CorrelationEventBus | None = None,
    ) -> None:
        self._tech_intel = tech_intel or TechnologyIntelEngine()
        self._correlator = correlator or FrameworkCorrelator()
        self._profiler = profiler or AttackSurfaceProfiler(
            tech_intel=self._tech_intel,
            correlator=self._correlator,
        )
        self._hints = hint_generator or InvestigationHintGenerator()
        self._event_bus = event_bus or CorrelationEventBus()

    @property
    def event_bus(self) -> CorrelationEventBus:
        return self._event_bus

    def correlate(
        self,
        detected_technologies: list[str | ReconTechnology],
        *,
        graph: AttackSurfaceGraph | None = None,
        session_id: str = "",
    ) -> CorrelationResult:
        """Run the full correlation pipeline.

        Args:
            detected_technologies: Technologies detected by httpx or fingerprinting tools.
            graph: Optional AttackSurfaceGraph to update.
            session_id: Optional session ID for events.

        Returns:
            CorrelationResult with all pipeline outputs.
        """
        tech_names = [t.name if isinstance(t, ReconTechnology) else str(t) for t in detected_technologies]

        self._event_bus.emit(CorrelationStartedEvent(
            session_id=session_id,
            source_technologies=tech_names,
            host_count=0,
        ))

        # ── Stage 1: Technology Intelligence ────────────────────
        self._emit_stage("tech_intel", session_id)
        tech_knowledge = self._tech_intel.interpret(tech_names)
        self._emit_stage_complete("tech_intel", len(tech_knowledge.entries), session_id)

        # ── Stage 2: Framework Intelligence ─────────────────────
        self._emit_stage("framework_intel", session_id)
        stack_corr = self._correlator.correlate(tech_names)
        self._emit_stage_complete("framework_intel", len(stack_corr.stacks), session_id)

        # ── Stage 3: Attack Surface Profile ─────────────────────
        self._emit_stage("profiler", session_id)
        surface_profile = self._profiler.profile(tech_names)
        self._emit_stage_complete("profiler", surface_profile.total_attack_surface_areas, session_id)

        # ── Stage 4: Attack Surface Graph Update ────────────────
        nodes_added = 0
        edges_added = 0
        if graph is not None:
            self._emit_stage("graph_update", session_id)
            nodes_added, edges_added = self._update_graph(graph, tech_knowledge, stack_corr, surface_profile)
            self._emit_stage_complete("graph_update", nodes_added + edges_added, session_id)

        # ── Stage 5: Investigation Hints ────────────────────────
        self._emit_stage("hints", session_id)
        hints = self._hints.generate_from_knowledge(tech_knowledge)
        self._emit_stage_complete("hints", len(hints), session_id)

        result = CorrelationResult(
            source_technologies=tech_names,
            technology_knowledge=tech_knowledge,
            stack_correlation=stack_corr,
            attack_surface_profile=surface_profile,
            investigation_hints=hints,
            graph_nodes_added=nodes_added,
            graph_edges_added=edges_added,
        )

        self._event_bus.emit(CorrelationCompletedEvent(
            session_id=session_id,
            stack_count=len(stack_corr.stacks),
            surface_areas=surface_profile.total_attack_surface_areas,
            hints_generated=len(hints),
        ))

        return result

    def _update_graph(
        self,
        graph: AttackSurfaceGraph,
        tech_knowledge: TechnologyKnowledge,
        stack_corr: StackCorrelation,
        surface_profile: AttackSurfaceProfile,
    ) -> tuple[int, int]:
        nodes = 0
        edges = 0

        for entry in tech_knowledge.entries:
            node = graph.ensure_node(
                ref_id=f"tech_knowledge:{entry.technology_name.lower()}",
                node_type=GraphNodeType.TECHNOLOGY,
                label=entry.technology_name,
                tags=entry.tags,
            )
            if node.id:
                nodes += 1

        for stack in stack_corr.stacks:
            s_node = graph.ensure_node(
                ref_id=f"framework:{stack.name.lower().replace(' ', '_')}",
                node_type=GraphNodeType.TECHNOLOGY,
                label=stack.name,
            )
            if s_node.id:
                nodes += 1

            for tech_name in stack.technologies:
                t_node = graph.find_node_by_ref(f"tech_knowledge:{tech_name.lower()}")
                if t_node:
                    graph.link(
                        s_node.ref_id,
                        t_node.ref_id,
                        GraphEdgeType.RELATED_TO,
                        f"stack includes {tech_name}",
                    )
                    edges += 1

        return nodes, edges

    def _emit_stage(self, stage: str, session_id: str) -> None:
        self._event_bus.emit(PipelineStageStartedEvent(session_id=session_id, stage=stage))

    def _emit_stage_complete(self, stage: str, count: int, session_id: str) -> None:
        self._event_bus.emit(PipelineStageCompletedEvent(session_id=session_id, stage=stage, items_processed=count))
