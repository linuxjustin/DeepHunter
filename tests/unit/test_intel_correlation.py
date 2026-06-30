"""Tests for the Recon Correlation Engine."""

from __future__ import annotations

from deephunter.correlation.engine import CorrelationEngine, CorrelationResult
from deephunter.correlation.events import (
    CorrelationCompletedEvent,
    CorrelationEventBus,
    CorrelationStartedEvent,
    PipelineStageCompletedEvent,
    PipelineStageStartedEvent,
)
from deephunter.framework_intel.correlator import FrameworkCorrelator
from deephunter.framework_intel.profiler import AttackSurfaceProfiler
from deephunter.intel.hints import InvestigationHintGenerator
from deephunter.recon.graph import AttackSurfaceGraph
from deephunter.recon.models import Technology as ReconTechnology
from deephunter.tech_intel.engine import TechnologyIntelEngine


class TestCorrelationEngine:
    def test_correlate_laravel(self) -> None:
        engine = CorrelationEngine()
        result = engine.correlate(["nginx", "php", "laravel"])
        assert isinstance(result, CorrelationResult)
        assert result.id.startswith("cr-")
        assert len(result.stack_correlation.stacks) >= 1
        assert len(result.investigation_hints) >= 1

    def test_correlate_with_graph(self) -> None:
        engine = CorrelationEngine()
        graph = AttackSurfaceGraph()
        result = engine.correlate(["nginx", "php", "laravel"], graph=graph)
        assert result.graph_nodes_added >= 0
        assert result.graph_edges_added >= 0

    def test_correlate_empty(self) -> None:
        engine = CorrelationEngine()
        result = engine.correlate([])
        assert result.technology_knowledge is not None

    def test_correlate_events(self) -> None:
        bus = CorrelationEventBus()
        engine = CorrelationEngine(event_bus=bus)
        started: list[CorrelationStartedEvent] = []
        completed: list[CorrelationCompletedEvent] = []
        bus.subscribe(CorrelationStartedEvent, lambda e: started.append(e))
        bus.subscribe(CorrelationCompletedEvent, lambda e: completed.append(e))
        engine.correlate(["laravel"])
        assert len(started) >= 1
        assert len(completed) >= 1

    def test_correlate_stage_events(self) -> None:
        bus = CorrelationEventBus()
        engine = CorrelationEngine(event_bus=bus)
        stage_starts: list[PipelineStageStartedEvent] = []
        stage_ends: list[PipelineStageCompletedEvent] = []
        bus.subscribe(PipelineStageStartedEvent, lambda e: stage_starts.append(e))
        bus.subscribe(PipelineStageCompletedEvent, lambda e: stage_ends.append(e))
        engine.correlate(["laravel"])
        assert len(stage_starts) >= 3
        assert len(stage_ends) >= 3

    def test_correlate_with_graph_structure(self) -> None:
        engine = CorrelationEngine()
        graph = AttackSurfaceGraph()
        result = engine.correlate(["nginx", "php", "laravel"], graph=graph)
        assert result.stack_correlation is not None
        assert result.attack_surface_profile is not None
        assert result.technology_knowledge is not None

    def test_correlate_framework_ints(self) -> None:
        engine = CorrelationEngine()
        result = engine.correlate(["django", "python", "postgresql"])
        surface = result.attack_surface_profile
        assert surface.total_attack_surface_areas >= 3

    def test_correlate_custom_event_bus(self) -> None:
        bus = CorrelationEventBus()
        engine = CorrelationEngine(event_bus=bus)
        assert engine.event_bus is bus

    def test_correlate_recon_technology_input(self) -> None:
        engine = CorrelationEngine()
        result = engine.correlate([ReconTechnology(name="Laravel"), ReconTechnology(name="Nginx")])
        assert len(result.source_technologies) == 2

    def test_correlate_with_session_id(self) -> None:
        bus = CorrelationEventBus()
        engine = CorrelationEngine(event_bus=bus)
        session_events: list[str] = []
        bus.subscribe(CorrelationStartedEvent, lambda e: session_events.append(e.session_id))
        engine.correlate(["laravel"], session_id="sess_123")
        assert "sess_123" in session_events

    def test_correlate_attack_surface_suggestions(self) -> None:
        engine = CorrelationEngine()
        result = engine.correlate(["fastapi"])
        assert len(result.investigation_hints) >= 1

    def test_correlate_multi_tech(self) -> None:
        engine = CorrelationEngine()
        result = engine.correlate(["laravel", "django", "wordpress"])
        assert len(result.stack_correlation.stacks) >= 2


class TestCorrelationEventBus:
    def test_subscribe_emit(self) -> None:
        bus = CorrelationEventBus()
        received: list[CorrelationStartedEvent] = []
        bus.subscribe(CorrelationStartedEvent, lambda e: received.append(e))
        bus.emit(CorrelationStartedEvent(source_technologies=["laravel"]))
        assert len(received) == 1

    def test_unsubscribe(self) -> None:
        bus = CorrelationEventBus()
        received: list[CorrelationStartedEvent] = []
        handler = lambda e: received.append(e)
        bus.subscribe(CorrelationStartedEvent, handler)
        bus.unsubscribe(CorrelationStartedEvent, handler)
        bus.emit(CorrelationStartedEvent())
        assert len(received) == 0

    def test_clear(self) -> None:
        bus = CorrelationEventBus()
        received: list[CorrelationStartedEvent] = []
        bus.subscribe(CorrelationStartedEvent, lambda e: received.append(e))
        bus.clear()
        bus.emit(CorrelationStartedEvent())
        assert len(received) == 0

    def test_handler_exception(self) -> None:
        bus = CorrelationEventBus()
        bus.subscribe(CorrelationStartedEvent, lambda e: (_ for _ in ()).throw(ValueError("bad")))
        bus.emit(CorrelationStartedEvent())  # should not raise

    def test_different_event_types(self) -> None:
        bus = CorrelationEventBus()
        started: list[CorrelationStartedEvent] = []
        completed: list[CorrelationCompletedEvent] = []
        bus.subscribe(CorrelationStartedEvent, lambda e: started.append(e))
        bus.subscribe(CorrelationCompletedEvent, lambda e: completed.append(e))
        bus.emit(CorrelationStartedEvent())
        bus.emit(CorrelationCompletedEvent(stack_count=3))
        assert len(started) == 1
        assert len(completed) == 1
