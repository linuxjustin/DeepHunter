"""Integration tests for the full planning engine."""

from __future__ import annotations

from pathlib import Path

from deephunter.planning import (
    InvestigationPlan,
    Planner,
    PlannerContext,
    PlanningPhase,
)
from deephunter.planning.events import (
    PlanCompletedEvent,
    PlanStartedEvent,
    StepGeneratedEvent,
)
from deephunter.reasoning.session import InvestigationSession


class TestPlannerIntegration:
    """End-to-end tests for the Planner facade."""

    def test_plan_from_session(self) -> None:
        session = InvestigationSession.new("https://example.com")
        planner = Planner()
        result = planner.plan_from_session(session)

        assert result.plan.target == "https://example.com"
        assert len(result.plan.steps) > 0
        assert result.metrics.total_steps_produced > 0
        assert result.metrics.elapsed_seconds > 0

    def test_plan_from_context(self) -> None:
        ctx = PlannerContext(
            target="https://example.com/api",
            technologies=["django", "react"],
            auth_mechanisms=["jwt"],
            bug_classes=["sql_injection", "xss"],
            cloud_providers=["aws"],
        )
        planner = Planner()
        result = planner.plan_from_context(ctx)

        assert result.plan.target == "https://example.com/api"
        assert result.metrics.total_steps_produced > 0

    def test_plan_from_enriched_session(self) -> None:
        session = InvestigationSession.new("https://example.com")
        session.create_observation("endpoint", description="Login at /api/login")
        session.create_hypothesis(title="SQL Injection", description="Test SQLi")
        session.state.technology_fingerprint.frameworks = ["django"]
        session.state.technology_fingerprint.auth_mechanisms = ["jwt"]

        planner = Planner()
        result = planner.plan_from_session(session)

        assert len(result.plan.steps) > 0
        assert result.plan.investigation_id == session.investigation.id

    def test_plan_includes_all_recon(self) -> None:
        ctx = PlannerContext(target="https://example.com")
        planner = Planner()
        result = planner.plan_from_context(ctx)

        recon_steps = result.plan.steps_by_phase(PlanningPhase.RECON)
        assert len(recon_steps) >= 1

    def test_plan_respects_technology_rules(self) -> None:
        ctx = PlannerContext(
            target="https://example.com",
            technologies=["laravel", "django"],
        )
        planner = Planner()
        result = planner.plan_from_context(ctx)

        fingerprint_steps = result.plan.steps_by_phase(PlanningPhase.FINGERPRINT)
        assert len(fingerprint_steps) >= 2  # at least one per technology

    def test_plan_authentication_rules_fire(self) -> None:
        ctx = PlannerContext(
            target="https://example.com",
            auth_mechanisms=["jwt", "oauth2"],
        )
        planner = Planner()
        result = planner.plan_from_context(ctx)

        auth_steps = result.plan.steps_by_phase(PlanningPhase.AUTHENTICATION_ANALYSIS)
        assert len(auth_steps) >= 2

    def test_plan_with_all_inputs(self) -> None:
        ctx = PlannerContext(
            target="https://example.com",
            technologies=["flask", "react", "postgresql"],
            frameworks=["flask"],
            bug_classes=["sql_injection", "xss", "ssrf"],
            auth_mechanisms=["jwt", "session_cookie"],
            cloud_providers=["aws"],
            interesting_endpoints=["/api/login", "/api/upload", "/api/admin"],
            observation_types=["behavior", "endpoint"],
        )
        planner = Planner()
        result = planner.plan_from_context(ctx)

        assert result.metrics.total_steps_produced >= 8
        assert result.metrics.phases_covered >= 5
        assert result.plan.overall_priority > 0
        assert result.plan.total_estimated_hours > 0

    def test_plan_serialization_round_trip(self, tmp_path: Path) -> None:
        ctx = PlannerContext(
            target="https://example.com",
            technologies=["django"],
            bug_classes=["sql_injection"],
        )
        planner = Planner()
        result = planner.plan_from_context(ctx)

        path = tmp_path / "plan.json"
        planner.save_plan(result.plan, str(path))
        assert path.exists()

        loaded = planner.load_plan(str(path))
        assert loaded.id == result.plan.id
        assert loaded.target == result.plan.target
        assert len(loaded.steps) == len(result.plan.steps)

    def test_plan_emits_events(self) -> None:
        session = InvestigationSession.new("https://example.com")
        planner = Planner()
        events_received: list[str] = []

        planner.event_bus.subscribe(PlanStartedEvent, lambda _: events_received.append("started"))
        planner.event_bus.subscribe(PlanCompletedEvent, lambda _: events_received.append("completed"))

        result = planner.plan_from_session(session)

        assert "started" in events_received
        assert "completed" in events_received

    def test_plan_steps_have_phases(self) -> None:
        ctx = PlannerContext(target="https://example.com")
        planner = Planner()
        result = planner.plan_from_context(ctx)

        for step in result.plan.steps:
            assert isinstance(step.phase, PlanningPhase)

    def test_plan_metrics_populated(self) -> None:
        ctx = PlannerContext(
            target="https://example.com",
            technologies=["django"],
            bug_classes=["sql_injection"],
            auth_mechanisms=["jwt"],
        )
        planner = Planner()
        result = planner.plan_from_context(ctx)

        assert result.metrics.total_steps_produced > 0
        assert result.metrics.phases_covered > 0
        assert result.metrics.estimated_total_hours > 0
        assert result.metrics.elapsed_seconds > 0
        assert result.warnings == []
