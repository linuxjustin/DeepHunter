"""Tests for the reasoning event bus and event types."""

from __future__ import annotations

from deephunter.reasoning.events import (
    ConfidenceChangedEvent,
    EvidenceAddedEvent,
    ExperimentCompletedEvent,
    ExperimentCreatedEvent,
    FindingCreatedEvent,
    HypothesisCreatedEvent,
    HypothesisStatusChangedEvent,
    HypothesisUpdatedEvent,
    ObservationCreatedEvent,
    PivotCreatedEvent,
    ReasoningEvent,
    ReasoningEventBus,
)
from deephunter.reasoning.models import (
    Evidence,
    Experiment,
    Finding,
    Observation,
    Pivot,
)


class TestReasoningEventTypes:
    def test_observation_created(self) -> None:
        obs = Observation(type="other", description="Server found")
        ev = ObservationCreatedEvent(observation=obs)
        assert ev.observation is obs
        assert ev.timestamp is not None
        assert ev.investigation_id == ""

    def test_evidence_added(self) -> None:
        ev = EvidenceAddedEvent(observation_id="obs-1")
        assert ev.observation_id == "obs-1"

    def test_hypothesis_created(self) -> None:
        ev = HypothesisCreatedEvent(hypothesis_title="SQLi")
        assert ev.hypothesis_title == "SQLi"

    def test_hypothesis_updated(self) -> None:
        ev = HypothesisUpdatedEvent(hypothesis_title="SQLi", old_confidence=0.2, new_confidence=0.8)
        assert ev.old_confidence == 0.2
        assert ev.new_confidence == 0.8

    def test_experiment_created(self) -> None:
        exp = Experiment(hypothesis_id="hyp-1", description="Test", procedure="P", expected_result="R")
        ev = ExperimentCreatedEvent(experiment=exp)
        assert ev.experiment is exp

    def test_experiment_completed(self) -> None:
        ev = ExperimentCompletedEvent(passed=True)
        assert ev.passed is True

    def test_confidence_changed(self) -> None:
        ev = ConfidenceChangedEvent(hypothesis_id="hyp-1", old_score=0.3, new_score=0.9)
        assert ev.hypothesis_id == "hyp-1"
        assert ev.reason == ""

    def test_pivot_created(self) -> None:
        pvt = Pivot(description="Pivot", rationale="R", reason="other")
        ev = PivotCreatedEvent(pivot=pvt)
        assert ev.pivot is pvt

    def test_finding_created(self) -> None:
        fnd = Finding(title="Found", hypothesis_id="hyp-1", description="D", bug_classes=[], severity="medium", experiment_ids=[])
        ev = FindingCreatedEvent(finding=fnd)
        assert ev.finding is fnd

    def test_hypothesis_status_changed(self) -> None:
        ev = HypothesisStatusChangedEvent(hypothesis_id="hyp-1", old_status="proposed", new_status="confirmed")
        assert ev.old_status == "proposed"

    def test_all_events_have_timestamp(self) -> None:
        events: list[ReasoningEvent] = [
            ObservationCreatedEvent(),
            EvidenceAddedEvent(),
            HypothesisCreatedEvent(),
            HypothesisUpdatedEvent(),
            ExperimentCreatedEvent(),
            ExperimentCompletedEvent(),
            ConfidenceChangedEvent(),
            PivotCreatedEvent(),
            FindingCreatedEvent(),
            HypothesisStatusChangedEvent(),
        ]
        for ev in events:
            assert ev.timestamp is not None


class TestReasoningEventBus:
    def test_subscribe_and_emit(self) -> None:
        bus = ReasoningEventBus()
        received: list[ReasoningEvent] = []

        bus.subscribe(ObservationCreatedEvent, lambda e: received.append(e))
        bus.emit(ObservationCreatedEvent())

        assert len(received) == 1

    def test_multiple_handlers(self) -> None:
        bus = ReasoningEventBus()
        results: list[int] = []

        bus.subscribe(ObservationCreatedEvent, lambda _: results.append(1))
        bus.subscribe(ObservationCreatedEvent, lambda _: results.append(2))

        bus.emit(ObservationCreatedEvent())
        assert results == [1, 2]

    def test_unsubscribe(self) -> None:
        bus = ReasoningEventBus()
        results: list[int] = []

        def handler(_: ReasoningEvent) -> None:
            results.append(1)

        bus.subscribe(ObservationCreatedEvent, handler)
        bus.emit(ObservationCreatedEvent())
        assert len(results) == 1

        bus.unsubscribe(ObservationCreatedEvent, handler)
        bus.emit(ObservationCreatedEvent())
        assert len(results) == 1

    def test_no_handlers_no_error(self) -> None:
        bus = ReasoningEventBus()
        bus.emit(ObservationCreatedEvent())

    def test_handler_exception_does_not_crash(self) -> None:
        bus = ReasoningEventBus()

        def failing(_: ReasoningEvent) -> None:
            raise RuntimeError("boom")

        bus.subscribe(ObservationCreatedEvent, failing)
        bus.emit(ObservationCreatedEvent())

    def test_clear(self) -> None:
        bus = ReasoningEventBus()
        results: list[int] = []

        bus.subscribe(ObservationCreatedEvent, lambda _: results.append(1))
        bus.clear()
        bus.emit(ObservationCreatedEvent())
        assert results == []

    def test_event_type_filtering(self) -> None:
        bus = ReasoningEventBus()
        results: list[str] = []

        bus.subscribe(ObservationCreatedEvent, lambda _: results.append("obs"))
        bus.subscribe(HypothesisCreatedEvent, lambda _: results.append("hyp"))

        bus.emit(ObservationCreatedEvent())
        bus.emit(HypothesisCreatedEvent())

        assert results == ["obs", "hyp"]

    def test_handler_ordering_preserved(self) -> None:
        bus = ReasoningEventBus()
        results: list[int] = []

        def h1(_: ReasoningEvent) -> None:
            results.append(1)

        def h2(_: ReasoningEvent) -> None:
            results.append(2)

        bus.subscribe(ObservationCreatedEvent, h1)
        bus.subscribe(ObservationCreatedEvent, h2)
        bus.emit(ObservationCreatedEvent())

        assert results == [1, 2]

    def test_carry_investigation_id(self) -> None:
        bus = ReasoningEventBus()
        received: list[str] = []

        bus.subscribe(ObservationCreatedEvent, lambda e: received.append(e.investigation_id))
        obs = Observation(type="other", description="Test")
        bus.emit(ObservationCreatedEvent(observation=obs, investigation_id="inv-abc"))

        assert received == ["inv-abc"]
