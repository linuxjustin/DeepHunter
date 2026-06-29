"""Tests for planning engine core models."""

from __future__ import annotations

import pytest

from deephunter.planning.models import (
    InvestigationPlan,
    InvestigationStep,
    ManualTest,
    PlannerContext,
    PlannerMetrics,
    PlannerResult,
    PlanningPhase,
    PriorityWeights,
    RiskScore,
    StepStatus,
)


class TestPlanningPhase:
    def test_all_phases_defined(self) -> None:
        phases = list(PlanningPhase)
        assert len(phases) == 13
        assert phases[0] == PlanningPhase.RECON
        assert phases[-1] == PlanningPhase.REPORT_PREPARATION

    def test_phase_order_preserved(self) -> None:
        assert PlanningPhase.RECON.value == "recon"
        assert PlanningPhase.AUTHENTICATION_ANALYSIS.value == "authentication_analysis"
        assert PlanningPhase.INPUT_VALIDATION.value == "input_validation"


class TestStepStatus:
    def test_all_statuses(self) -> None:
        assert StepStatus.PLANNED.value == "planned"
        assert StepStatus.COMPLETED.value == "completed"
        assert StepStatus.BLOCKED.value == "blocked"


class TestRiskScore:
    def test_defaults(self) -> None:
        r = RiskScore()
        assert r.overall == 0.0
        assert r.likelihood == 0.0
        assert r.impact == 0.0
        assert r.confidence == 0.0

    def test_calculate_overall(self) -> None:
        r = RiskScore(likelihood=8.0, impact=9.0, confidence=0.7)
        val = r.calculate_overall()
        assert val == 7.2
        assert r.overall == 7.2

    def test_calculate_overall_zero(self) -> None:
        r = RiskScore()
        assert r.calculate_overall() == 0.0


class TestPriorityWeights:
    def test_defaults(self) -> None:
        w = PriorityWeights()
        assert w.likelihood == 0.30
        assert w.impact == 0.25

    def test_normalize(self) -> None:
        w = PriorityWeights()
        w.normalize()
        total = w.likelihood + w.impact + w.confidence + w.complexity_inverted + w.effort_inverted + w.reward
        assert total == pytest.approx(1.0, abs=0.01)

    def test_custom_weights(self) -> None:
        w = PriorityWeights(likelihood=1.0, impact=1.0, confidence=0.0, complexity_inverted=0.0, effort_inverted=0.0, reward=0.0)
        w.normalize()
        assert w.likelihood == 0.5
        assert w.impact == 0.5


class TestManualTest:
    def test_create_minimal(self) -> None:
        mt = ManualTest(description="Test SQL injection")
        assert mt.id.startswith("mt-")
        assert mt.description == "Test SQL injection"
        assert mt.priority == 0.0

    def test_with_all_fields(self) -> None:
        mt = ManualTest(
            description="Test",
            procedure="Send payloads",
            expected_result="Error",
            bug_classes=["sql_injection"],
            priority=0.8,
            estimated_effort_hours=2.0,
        )
        assert mt.bug_classes == ["sql_injection"]
        assert mt.estimated_effort_hours == 2.0


class TestInvestigationStep:
    def test_create_minimal(self) -> None:
        step = InvestigationStep(
            phase=PlanningPhase.RECON,
            title="Reconnaissance",
        )
        assert step.id.startswith("step-")
        assert step.phase == PlanningPhase.RECON
        assert step.status == StepStatus.PLANNED

    def test_with_dependencies(self) -> None:
        step = InvestigationStep(
            phase=PlanningPhase.INPUT_VALIDATION,
            title="SQL Injection Test",
            depends_on=["step-1", "step-2"],
        )
        assert step.depends_on == ["step-1", "step-2"]

    def test_risk_defaults(self) -> None:
        step = InvestigationStep(phase=PlanningPhase.RECON, title="Test")
        assert step.risk.overall == 0.0

    def test_auto_id(self) -> None:
        s1 = InvestigationStep(phase=PlanningPhase.RECON, title="A")
        s2 = InvestigationStep(phase=PlanningPhase.RECON, title="B")
        assert s1.id != s2.id


class TestInvestigationPlan:
    def test_create_empty(self) -> None:
        plan = InvestigationPlan()
        assert plan.id.startswith("plan-")
        assert plan.steps == []
        assert plan.total_estimated_hours == 0.0

    def test_recalculate_empty(self) -> None:
        plan = InvestigationPlan()
        plan.recalculate()
        assert plan.total_estimated_hours == 0.0
        assert plan.overall_priority == 0.0
        assert plan.phases_covered == []

    def test_recalculate_with_steps(self) -> None:
        plan = InvestigationPlan()
        plan.steps = [
            InvestigationStep(phase=PlanningPhase.RECON, title="Recon", priority_score=0.8, estimated_cost_hours=2.0),
            InvestigationStep(phase=PlanningPhase.INPUT_VALIDATION, title="SQLi", priority_score=0.9, estimated_cost_hours=3.0),
        ]
        plan.recalculate()
        assert plan.total_estimated_hours == 5.0
        assert plan.overall_priority == 0.85
        assert len(plan.phases_covered) == 2

    def test_steps_by_phase(self) -> None:
        plan = InvestigationPlan()
        plan.steps = [
            InvestigationStep(phase=PlanningPhase.RECON, title="A"),
            InvestigationStep(phase=PlanningPhase.INPUT_VALIDATION, title="B"),
            InvestigationStep(phase=PlanningPhase.RECON, title="C"),
        ]
        recon_steps = plan.steps_by_phase(PlanningPhase.RECON)
        assert len(recon_steps) == 2
        assert recon_steps[0].title == "A"

    def test_steps_by_status(self) -> None:
        plan = InvestigationPlan()
        plan.steps = [
            InvestigationStep(phase=PlanningPhase.RECON, title="A"),
            InvestigationStep(phase=PlanningPhase.RECON, title="B"),
        ]
        plan.steps[1].status = StepStatus.COMPLETED
        assert len(plan.steps_by_status(StepStatus.PLANNED)) == 1
        assert len(plan.steps_by_status(StepStatus.COMPLETED)) == 1

    def test_serialization_round_trip(self) -> None:
        plan = InvestigationPlan(target="https://example.com")
        plan.steps = [
            InvestigationStep(phase=PlanningPhase.RECON, title="Recon", description="Initial scan"),
        ]
        plan.recalculate()

        data = plan.model_dump_for_storage()
        restored = InvestigationPlan.from_dict(data)

        assert restored.id == plan.id
        assert len(restored.steps) == 1
        assert restored.steps[0].title == "Recon"
        assert restored.total_estimated_hours == plan.total_estimated_hours

    def test_version_default(self) -> None:
        plan = InvestigationPlan()
        assert plan.version == 1


class TestPlannerContext:
    def test_empty_context(self) -> None:
        ctx = PlannerContext()
        assert ctx.target == ""
        assert ctx.technologies == []
        assert ctx.bug_classes == []

    def test_with_values(self) -> None:
        ctx = PlannerContext(
            target="https://example.com",
            technologies=["flask", "python"],
            bug_classes=["sql_injection", "xss"],
            auth_mechanisms=["jwt"],
        )
        assert "flask" in ctx.technologies
        assert "sql_injection" in ctx.bug_classes

    def test_from_session_invalid(self) -> None:
        with pytest.raises(TypeError):
            PlannerContext.from_session("not_a_session")  # type: ignore[arg-type]


class TestPlannerMetrics:
    def test_defaults(self) -> None:
        m = PlannerMetrics()
        assert m.total_rules_evaluated == 0
        assert m.total_steps_produced == 0
        assert m.elapsed_seconds == 0.0


class TestPlannerResult:
    def test_defaults(self) -> None:
        from deephunter.planning.models import InvestigationPlan

        plan = InvestigationPlan()
        result = PlannerResult(plan=plan)
        assert result.plan.id == plan.id
        assert result.warnings == []
