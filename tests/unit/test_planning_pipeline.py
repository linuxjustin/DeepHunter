"""Tests for the planning pipeline."""

from __future__ import annotations

from deephunter.planning.events import (
    ContextLoadedEvent,
    PlanCompletedEvent,
    PlanFailedEvent,
    PlanStartedEvent,
    PlanningEventBus,
    StepGeneratedEvent,
)
from deephunter.planning.models import (
    InvestigationPlan,
    PlannerContext,
    PlanningPhase,
)
from deephunter.planning.pipeline import (
    EstimateCostStage,
    EvaluateRulesStage,
    LoadContextStage,
    PlanningPipeline,
    PlanningStage,
    PrioritizeStepsStage,
    SortAndGroupStage,
)
from deephunter.planning.priority import PriorityEngine
from deephunter.planning.rules import (
    ReconRule,
    RuleRegistry,
    TechnologyRule,
)


class TestPlanningStage:
    def test_base_not_abstract(self) -> None:
        stage = PlanningStage()
        assert stage.name == ""


class TestLoadContextStage:
    def test_sets_plan_metadata(self) -> None:
        stage = LoadContextStage()
        ctx = PlannerContext(
            target="https://example.com",
            investigation_id="inv-123",
        )
        plan = InvestigationPlan()
        bus = PlanningEventBus()
        received: list = []

        bus.subscribe(ContextLoadedEvent, lambda e: received.append(e))
        stage.process(ctx, plan, bus)

        assert plan.target == "https://example.com"
        assert plan.investigation_id == "inv-123"
        assert len(received) == 1


class TestEvaluateRulesStage:
    def test_evaluates_registry_rules(self) -> None:
        reg = RuleRegistry()
        reg.register(ReconRule())
        stage = EvaluateRulesStage(registry=reg)
        ctx = PlannerContext(target="https://example.com")
        plan = InvestigationPlan()
        bus = PlanningEventBus()
        received: list = []

        bus.subscribe(StepGeneratedEvent, lambda e: received.append(e))
        stage.process(ctx, plan, bus)

        assert len(plan.steps) >= 1
        assert len(received) >= 1

    def test_empty_registry(self) -> None:
        reg = RuleRegistry()
        stage = EvaluateRulesStage(registry=reg)
        ctx = PlannerContext()
        plan = InvestigationPlan()
        bus = PlanningEventBus()

        stage.process(ctx, plan, bus)
        assert plan.steps == []


class TestPrioritizeStepsStage:
    def test_priorities_calculated(self) -> None:
        engine = PriorityEngine()
        stage = PrioritizeStepsStage(engine=engine)
        plan = InvestigationPlan()
        from deephunter.planning.models import InvestigationStep

        plan.steps = [
            InvestigationStep(
                phase=PlanningPhase.RECON, title="Recon",
                priority_score=0.5,
                estimated_cost_hours=2.0, complexity=0.3,
            ),
        ]
        ctx = PlannerContext()
        bus = PlanningEventBus()

        stage.process(ctx, plan, bus)
        assert plan.steps[0].priority_score > 0


class TestSortAndGroupStage:
    def test_sorts_by_phase_then_priority(self) -> None:
        stage = SortAndGroupStage()
        plan = InvestigationPlan()
        from deephunter.planning.models import InvestigationStep

        plan.steps = [
            InvestigationStep(phase=PlanningPhase.INPUT_VALIDATION, title="B", priority_score=0.5),
            InvestigationStep(phase=PlanningPhase.RECON, title="A", priority_score=0.9),
            InvestigationStep(phase=PlanningPhase.CLOUD_ANALYSIS, title="C", priority_score=0.7),
        ]
        stage.process(PlannerContext(), plan, PlanningEventBus())
        assert plan.steps[0].phase == PlanningPhase.RECON
        assert plan.steps[1].phase == PlanningPhase.INPUT_VALIDATION
        assert plan.steps[2].phase == PlanningPhase.CLOUD_ANALYSIS


class TestEstimateCostStage:
    def test_risk_calculated(self) -> None:
        stage = EstimateCostStage()
        plan = InvestigationPlan()
        from deephunter.planning.models import InvestigationStep, RiskScore

        plan.steps = [
            InvestigationStep(
                phase=PlanningPhase.RECON, title="A",
                risk=RiskScore(likelihood=8.0, impact=9.0, confidence=0.7),
                estimated_cost_hours=2.0,
                priority_score=0.8,
            ),
            InvestigationStep(
                phase=PlanningPhase.INPUT_VALIDATION, title="B",
                risk=RiskScore(likelihood=6.0, impact=7.0, confidence=0.5),
                estimated_cost_hours=3.0,
                priority_score=0.6,
            ),
        ]
        stage.process(PlannerContext(), plan, PlanningEventBus())
        assert plan.total_estimated_hours == 5.0
        assert plan.risk.overall > 0
        assert plan.overall_priority > 0


class TestPlanningPipeline:
    def test_run_produces_plan(self) -> None:
        pipeline = PlanningPipeline()
        ctx = PlannerContext(
            target="https://example.com",
            technologies=["laravel", "react"],
            auth_mechanisms=["jwt"],
        )
        result = pipeline.run(ctx)

        assert result.plan.id.startswith("plan-")
        assert result.metrics.total_steps_produced > 0
        assert result.metrics.elapsed_seconds > 0

    def test_run_with_empty_context(self) -> None:
        pipeline = PlanningPipeline()
        ctx = PlannerContext()
        result = pipeline.run(ctx)
        assert result.plan is not None
        assert result.metrics.total_steps_produced >= 0

    def test_run_emits_events(self) -> None:
        pipeline = PlanningPipeline()
        ctx = PlannerContext(target="https://example.com")
        bus = PlanningEventBus()
        events: list[str] = []

        bus.subscribe(PlanStartedEvent, lambda _: events.append("start"))
        bus.subscribe(PlanCompletedEvent, lambda _: events.append("done"))

        pipeline.run(ctx, event_bus=bus)
        assert "start" in events
        assert "done" in events

    def test_stage_failure_returns_early(self) -> None:
        class CrashingStage(PlanningStage):
            name = "crash"

            def process(self, ctx, plan, bus):
                raise RuntimeError("simulated crash")

        pipeline = PlanningPipeline()
        pipeline._stages.insert(0, CrashingStage())

        ctx = PlannerContext()
        result = pipeline.run(ctx)
        assert len(result.warnings) > 0

    def test_run_context_from_session(self) -> None:
        """Integration: verify PlannerContext.from_session works with pipeline."""
        from deephunter.reasoning.session import InvestigationSession

        session = InvestigationSession.new("https://example.com")
        ctx = PlannerContext.from_session(session)
        pipeline = PlanningPipeline()
        result = pipeline.run(ctx)
        assert result.plan.target == "https://example.com"
