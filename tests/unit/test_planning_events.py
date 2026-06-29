"""Tests for the planning event bus and event types."""

from __future__ import annotations

from deephunter.planning.events import (
    ContextLoadedEvent,
    PlanCompletedEvent,
    PlanFailedEvent,
    PlanStartedEvent,
    PlanUpdatedEvent,
    PlanningEvent,
    PlanningEventBus,
    StepGeneratedEvent,
    StepPrioritizedEvent,
)
from deephunter.planning.models import InvestigationPlan


class TestPlanningEventTypes:
    def test_plan_started(self) -> None:
        ev = PlanStartedEvent(investigation_id="inv-1", plan_id="plan-1")
        assert ev.investigation_id == "inv-1"
        assert ev.plan_id == "plan-1"

    def test_context_loaded(self) -> None:
        ev = ContextLoadedEvent(technology_count=3, observation_count=5)
        assert ev.technology_count == 3

    def test_step_generated(self) -> None:
        ev = StepGeneratedEvent(step_title="SQLi Test", phase="input_validation", priority_score=0.85)
        assert ev.step_title == "SQLi Test"

    def test_step_prioritized(self) -> None:
        ev = StepPrioritizedEvent(step_title="Recon", old_priority=0.5, new_priority=0.8)
        assert ev.old_priority == 0.5

    def test_plan_completed(self) -> None:
        ev = PlanCompletedEvent(total_steps=10, phases_covered=3, elapsed_seconds=0.5)
        assert ev.total_steps == 10

    def test_plan_failed(self) -> None:
        ev = PlanFailedEvent(error="Stage crashed")
        assert ev.error == "Stage crashed"

    def test_plan_updated(self) -> None:
        ev = PlanUpdatedEvent(version=2, new_step_count=15)
        assert ev.version == 2

    def test_all_events_have_timestamp(self) -> None:
        events: list[PlanningEvent] = [
            PlanStartedEvent(),
            ContextLoadedEvent(),
            StepGeneratedEvent(),
            StepPrioritizedEvent(),
            PlanCompletedEvent(),
            PlanFailedEvent(),
            PlanUpdatedEvent(),
        ]
        for ev in events:
            assert ev.timestamp is not None

    def test_investigation_id_on_all_events(self) -> None:
        ev = PlanStartedEvent(investigation_id="inv-abc")
        assert ev.investigation_id == "inv-abc"


class TestPlanningEventBus:
    def test_subscribe_and_emit(self) -> None:
        bus = PlanningEventBus()
        received: list[PlanningEvent] = []

        bus.subscribe(PlanStartedEvent, lambda e: received.append(e))
        bus.emit(PlanStartedEvent())

        assert len(received) == 1

    def test_multiple_handlers(self) -> None:
        bus = PlanningEventBus()
        results: list[int] = []

        bus.subscribe(PlanStartedEvent, lambda _: results.append(1))
        bus.subscribe(PlanStartedEvent, lambda _: results.append(2))

        bus.emit(PlanStartedEvent())
        assert results == [1, 2]

    def test_unsubscribe(self) -> None:
        bus = PlanningEventBus()
        results: list[int] = []

        def handler(_: PlanningEvent) -> None:
            results.append(1)

        bus.subscribe(PlanStartedEvent, handler)
        bus.emit(PlanStartedEvent())
        assert len(results) == 1

        bus.unsubscribe(PlanStartedEvent, handler)
        bus.emit(PlanStartedEvent())
        assert len(results) == 1

    def test_no_handlers_no_error(self) -> None:
        bus = PlanningEventBus()
        bus.emit(PlanStartedEvent())

    def test_handler_exception_does_not_crash(self) -> None:
        bus = PlanningEventBus()

        def failing(_: PlanningEvent) -> None:
            raise RuntimeError("boom")

        bus.subscribe(PlanStartedEvent, failing)
        bus.emit(PlanStartedEvent())

    def test_clear(self) -> None:
        bus = PlanningEventBus()
        results: list[int] = []

        bus.subscribe(PlanStartedEvent, lambda _: results.append(1))
        bus.clear()
        bus.emit(PlanStartedEvent())
        assert results == []

    def test_event_type_filtering(self) -> None:
        bus = PlanningEventBus()
        results: list[str] = []

        bus.subscribe(PlanStartedEvent, lambda _: results.append("start"))
        bus.subscribe(PlanCompletedEvent, lambda _: results.append("done"))

        bus.emit(PlanStartedEvent())
        bus.emit(PlanCompletedEvent())

        assert results == ["start", "done"]


class TestPlanToEventContext:
    def test_plan_to_event_context(self) -> None:
        from deephunter.planning.events import plan_to_event_context

        plan = InvestigationPlan(target="https://example.com")
        ctx = plan_to_event_context(plan)
        assert ctx["plan_id"] == plan.id
        assert ctx["steps"] == 0
        assert ctx["total_hours"] == 0.0
