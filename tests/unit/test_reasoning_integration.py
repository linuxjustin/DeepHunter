"""Integration tests for the full reasoning engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from deephunter.reasoning.events import (
    ExperimentCompletedEvent,
    FindingCreatedEvent,
    HypothesisCreatedEvent,
    ObservationCreatedEvent,
    PivotCreatedEvent,
)
from deephunter.reasoning.pipeline import ReasoningPipeline
from deephunter.reasoning.session import InvestigationSession


class TestFullLifecycle:
    """End-to-end test: create -> observe -> hypothesize -> experiment -> pivot -> find."""

    def test_full_investigation_lifecycle(self) -> None:
        session = InvestigationSession.new("https://example.com/api")
        assert session.investigation.target == "https://example.com/api"

        obs1 = session.create_observation(
            "endpoint",
            description="Login endpoint at /api/login returns 200 with JWT",
            source="manual exploration",
        )
        obs2 = session.create_observation(
            "behavior",
            description="Password reset endpoint /api/reset leaks user enumeration",
            source="burp",
        )
        assert len(session.state.observations) == 2

        ev1 = session.add_evidence(
            observation_id=obs1.id,
            content="Response: {'token': 'eyJhbGci...'}",
            source="burp",
        )
        ev2 = session.add_evidence(
            observation_id=obs2.id,
            content="Error differs for valid vs invalid email",
            source="manual",
        )
        assert ev1 is not None
        assert ev2 is not None

        hyp1 = session.create_hypothesis(
            title="JWT algorithm confusion",
            description="The JWT may accept 'none' algorithm or weak keys",
            technologies=["python", "flask"],
            observation_ids=[obs1.id],
        )
        hyp2 = session.create_hypothesis(
            title="User enumeration via password reset",
            description="Password reset endpoint reveals valid user accounts",
            technologies=["python", "flask"],
            observation_ids=[obs2.id],
        )
        assert len(session.state.hypotheses) == 2

        session.state.technology_fingerprint.operating_systems = ["linux"]
        from deephunter.core.types import Technology
        session.state.technology_fingerprint.technologies = [Technology.FLASK, Technology.OTHER]
        session.state.technology_fingerprint.frameworks = ["flask"]

        exp1 = session.create_experiment(
            hypothesis_id=hyp1["id"],
            description="Test JWT 'none' algorithm",
            procedure="Send JWT with alg:none",
            expected_result="Server accepts unsigned token",
        )
        exp2 = session.create_experiment(
            hypothesis_id=hyp2["id"],
            description="Test user enumeration",
            procedure="Send requests to /api/reset with valid and invalid emails",
            expected_result="Error messages differ",
        )
        assert exp1 is not None
        assert exp2 is not None
        assert exp1.status.value == "planned"
        assert exp2.status.value == "planned"

        assert session.record_result(
            experiment_id=exp1.id,
            status="completed",
            actual_result="Server rejected 'none' algorithm with 401",
        ) is True
        assert session.record_result(
            experiment_id=exp2.id,
            status="completed",
            actual_result="Confirmed: 'Email not found' vs 'Reset link sent' differ",
        ) is True

        updated_exp1 = [e for e in session.state.experiments if e.id == exp1.id][0]
        updated_exp2 = [e for e in session.state.experiments if e.id == exp2.id][0]
        assert updated_exp1.status.value == "completed"
        assert updated_exp2.status.value == "completed"

        session.update_hypothesis_confidence(hyp1["id"])
        session.update_hypothesis_confidence(hyp2["id"])
        hyp1_updated = [h for h in session.state.hypotheses if h["id"] == hyp1["id"]][0]
        hyp2_updated = [h for h in session.state.hypotheses if h["id"] == hyp2["id"]][0]
        assert hyp1_updated.get("confidence", 0) >= 0
        assert hyp2_updated.get("confidence", 0) >= 0

        pvt = session.create_pivot(
            description="Check for other JWT attacks (key confusion, KID injection)",
            rationale="JWT 'none' attack failed, try other vectors",
            reason="partial_confirmation",
            source_experiment_id=exp1.id,
        )
        assert pvt.id.startswith("pvt-")

        hyp1_updated["status"] = "confirmed"

        fnd = session.create_finding(
            title="JWT None Algorithm Rejected",
            hypothesis_id=hyp1["id"],
            description="Server rejects 'none' algorithm but may be vulnerable to other JWT attacks",
            bug_classes=["auth_bypass"],
            severity="medium",
            experiment_ids=[exp1.id],
        )
        assert fnd.id.startswith("fnd-")
        assert fnd.severity.value == "medium"

        summary = session.get_summary()
        assert "2 observations" in summary
        assert "2 hypotheses" in summary
        assert "2 experiments" in summary

    def test_pipeline_creates_events(self) -> None:
        session = InvestigationSession.new("https://example.com")
        events: list[str] = []

        def record_obs(_: object) -> None:
            events.append("obs")

        def record_hyp(_: object) -> None:
            events.append("hyp")

        session.events.subscribe(ObservationCreatedEvent, record_obs)
        session.events.subscribe(HypothesisCreatedEvent, record_hyp)

        pipeline = ReasoningPipeline()
        pipeline.run(session)

        assert "obs" in events
        assert "hyp" in events

    def test_save_and_resume(self, tmp_path: Path) -> None:
        session = InvestigationSession.new("https://example.com/api")
        session.create_observation("other", description="Initial observation", source="recon")
        hyp = session.create_hypothesis(title="Test hypothesis", description="Test")
        exp = session.create_experiment(
            hypothesis_id=hyp["id"],
            description="Experiment",
            procedure="Test procedure",
            expected_result="Vulnerability",
        )
        assert exp is not None
        assert session.record_result(experiment_id=exp.id, status="completed", actual_result="Confirmed")

        path = tmp_path / "resumed.json"
        session.save(str(path))

        resumed = InvestigationSession.load(str(path))
        assert resumed.investigation.target == "https://example.com/api"
        assert len(resumed.state.observations) == 1
        assert len(resumed.state.hypotheses) == 1
        assert len(resumed.state.experiments) == 1
        assert resumed.state.experiments[0].actual_result == "Confirmed"

        obs2 = resumed.create_observation("other", description="New observation after resume", source="manual")
        assert obs2.id.startswith("obs-")
        assert len(resumed.state.observations) == 2

        pipeline = ReasoningPipeline()
        report = pipeline.run(resumed)
        assert report.total_seconds > 0

    def test_empty_investigation_still_produces_report(self) -> None:
        session = InvestigationSession.new("https://example.com")
        pipeline = ReasoningPipeline()
        report = pipeline.run(session)
        assert report.total_seconds > 0
        assert len(report.stage_times) == 10

    def test_events_fired_during_pipeline(self) -> None:
        session = InvestigationSession.new("https://example.com")
        pipeline = ReasoningPipeline()
        fired: set[str] = set()

        def record(tag: str) -> callable:
            def handler(event: object) -> None:
                fired.add(tag)
            return handler

        session.events.subscribe(ObservationCreatedEvent, record("obs"))
        session.events.subscribe(HypothesisCreatedEvent, record("hyp"))

        pipeline.run(session)
        assert "obs" in fired
        assert "hyp" in fired
