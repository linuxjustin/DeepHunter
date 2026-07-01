"""Planning pipeline — stage-based plan generation.

Transforms a PlannerContext into a complete InvestigationPlan
through a series of composable stages.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from deephunter.planning.config import PlanningConfig
from deephunter.planning.events import (
    ContextLoadedEvent,
    PlanCompletedEvent,
    PlanFailedEvent,
    PlanStartedEvent,
    PlanningEventBus,
    StepGeneratedEvent,
    StepPrioritizedEvent,
)
from deephunter.planning.models import (
    InvestigationPath,
    InvestigationPlan,
    InvestigationStep,
    PlanningPhase,
    PlannerContext,
    PlannerMetrics,
    PlannerResult,
    PriorityWeights,
    RiskScore,
)
from deephunter.planning.priority import PriorityEngine
from deephunter.planning.rules import RuleRegistry
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)

_PHASE_ORDER = [p for p in PlanningPhase]


@dataclass
class PipelineReport:
    """Timing and status report for a pipeline run."""

    stage_times: dict[str, float] = field(default_factory=dict)
    total_seconds: float = 0.0


class PlanningStage:
    """Base class for a planning pipeline stage."""

    name: str = ""

    def process(
        self,
        context: PlannerContext,
        plan: InvestigationPlan,
        event_bus: PlanningEventBus,
    ) -> None:
        """Execute this stage.

        Args:
            context: The planner context.
            plan: The investigation plan being built (mutated in place).
            event_bus: Event bus for emitting stage events.
        """


class LoadContextStage(PlanningStage):
    """Stage 1: Load and validate the planner context."""

    name = "load_context"

    def process(
        self,
        context: PlannerContext,
        plan: InvestigationPlan,
        event_bus: PlanningEventBus,
    ) -> None:
        plan.target = context.target
        plan.investigation_id = context.investigation_id
        plan.title = f"Investigation Plan for {context.target}" if context.target else "Investigation Plan"

        event_bus.emit(
            ContextLoadedEvent(
                investigation_id=context.investigation_id,
                plan_id=plan.id,
                technology_count=len(context.technologies),
                observation_count=len(context.observation_types),
            )
        )


class EvaluateRulesStage(PlanningStage):
    """Stage 2: Evaluate all planning rules against context."""

    name = "evaluate_rules"

    def __init__(self, registry: RuleRegistry | None = None) -> None:
        self._registry = registry or RuleRegistry.with_default_rules()

    def process(
        self,
        context: PlannerContext,
        plan: InvestigationPlan,
        event_bus: PlanningEventBus,
    ) -> None:
        all_steps = self._registry.evaluate_all(context)

        for step in all_steps:
            event_bus.emit(
                StepGeneratedEvent(
                    investigation_id=context.investigation_id,
                    plan_id=plan.id,
                    step_title=step.title,
                    phase=step.phase.value,
                    priority_score=step.priority_score,
                )
            )

        plan.steps = all_steps
        plan.recalculate()


class PrioritizeStepsStage(PlanningStage):
    """Stage 3: Recalculate priority scores for all steps."""

    name = "prioritize_steps"

    def __init__(self, engine: PriorityEngine | None = None) -> None:
        self._engine = engine or PriorityEngine()

    def process(
        self,
        context: PlannerContext,
        plan: InvestigationPlan,
        event_bus: PlanningEventBus,
    ) -> None:
        for step in plan.steps:
            old = step.priority_score
            step.priority_score = self._engine.calculate_from_risk(
                step.risk,
                complexity=step.complexity,
                effort_hours=step.estimated_cost_hours,
                reward=0.5,
            )
            if abs(step.priority_score - old) > 0.01:
                event_bus.emit(
                    StepPrioritizedEvent(
                        investigation_id=context.investigation_id,
                        plan_id=plan.id,
                        step_title=step.title,
                        old_priority=old,
                        new_priority=step.priority_score,
                    )
                )

        plan.recalculate()


class SortAndGroupStage(PlanningStage):
    """Stage 4: Sort steps by phase order then priority, group dependencies."""

    name = "sort_and_group"

    def process(
        self,
        context: PlannerContext,
        plan: InvestigationPlan,
        event_bus: PlanningEventBus,
    ) -> None:
        plan.steps.sort(
            key=lambda s: (
                _PHASE_ORDER.index(s.phase) if s.phase in _PHASE_ORDER else 999,
                -s.priority_score,
            )
        )
        plan.recalculate()


class BuildAlternativePathsStage(PlanningStage):
    """Stage 5: Build alternative investigation paths from decision tree conclusions.

    Steps with is_decision_tree_conclusion=True are grouped into named
    InvestigationPath objects for analyst selection.
    """

    name = "build_alternative_paths"

    def process(
        self,
        context: PlannerContext,
        plan: InvestigationPlan,
        event_bus: PlanningEventBus,
    ) -> None:
        tree_steps = [
            s for s in plan.steps
            if s.metadata.get("is_decision_tree_conclusion") is True
        ]

        if not tree_steps:
            return

        packs_map: dict[str, list[InvestigationStep]] = {}
        for step in tree_steps:
            pack_name = step.metadata.get("pack_name", "unknown")
            packs_map.setdefault(pack_name, []).append(step)

        for pack_name, steps in packs_map.items():
            if not steps:
                continue

            phases_in_path = sorted(
                {s.phase for s in steps},
                key=lambda p: _PHASE_ORDER.index(p) if p in _PHASE_ORDER else 999,
            )

            avg_priority = sum(s.priority_score for s in steps) / len(steps)

            path = InvestigationPath(
                name=f"{pack_name} Decision Path",
                description=(
                    f"Adaptive investigation path from {pack_name} decision tree. "
                    f"{len(steps)} specialized steps based on context-aware analysis."
                ),
                priority=avg_priority,
                phases=phases_in_path,
                step_ids=[s.id for s in steps],
                hypothesis_ids=self._collect_hypothesis_ids(steps),
                recommended_by=[pack_name],
                metadata={
                    "path_type": "decision_tree",
                    "pack": pack_name,
                    "step_count": str(len(steps)),
                },
            )
            plan.alternative_paths.append(path)

        plan.alternative_paths.sort(key=lambda p: -p.priority)

    @staticmethod
    def _collect_hypothesis_ids(steps: list[InvestigationStep]) -> list[str]:
        ids: list[str] = []
        for step in steps:
            for hid in step.hypothesis_ids:
                if hid not in ids:
                    ids.append(hid)
        return ids


class EstimateCostStage(PlanningStage):
    """Stage 5: Estimate total investigation cost and risk."""

    name = "estimate_cost"

    def process(
        self,
        context: PlannerContext,
        plan: InvestigationPlan,
        event_bus: PlanningEventBus,
    ) -> None:
        plan.recalculate()

        if plan.steps:
            avg_likelihood = sum(s.risk.likelihood for s in plan.steps) / len(plan.steps)
            avg_impact = sum(s.risk.impact for s in plan.steps) / len(plan.steps)
            plan.risk = RiskScore(
                likelihood=round(avg_likelihood, 1),
                impact=round(avg_impact, 1),
                confidence=round(plan.overall_priority, 2),
            )
            plan.risk.calculate_overall()


class PlanningPipeline:
    """Stage-based planning pipeline.

    Transforms a PlannerContext into a complete InvestigationPlan.
    """

    def __init__(
        self,
        registry: RuleRegistry | None = None,
        priority_engine: PriorityEngine | None = None,
        config: PlanningConfig | None = None,
    ) -> None:
        self._config = config or PlanningConfig()
        self._rule_registry = registry or RuleRegistry.with_default_rules()
        self._stages: list[PlanningStage] = [
            LoadContextStage(),
            EvaluateRulesStage(registry=self._rule_registry),
            PrioritizeStepsStage(engine=priority_engine),
            SortAndGroupStage(),
            BuildAlternativePathsStage(),
            EstimateCostStage(),
        ]

    def run(
        self,
        context: PlannerContext,
        event_bus: PlanningEventBus | None = None,
    ) -> PlannerResult:
        """Run the planning pipeline.

        Args:
            context: The planner context.
            event_bus: Optional event bus for emitting events.

        Returns:
            A PlannerResult with the generated plan and metrics.
        """
        start = time.perf_counter()
        bus = event_bus or PlanningEventBus()
        plan = InvestigationPlan()
        report = PipelineReport()

        bus.emit(
            PlanStartedEvent(
                investigation_id=context.investigation_id,
                plan_id=plan.id,
            )
        )

        metrics = PlannerMetrics()

        for stage in self._stages:
            stage_start = time.perf_counter()
            try:
                stage.process(context, plan, bus)
            except Exception:
                logger.exception("Planning stage %s failed", stage.name)
                bus.emit(
                    PlanFailedEvent(
                        investigation_id=context.investigation_id,
                        plan_id=plan.id,
                        error=f"Stage {stage.name} failed",
                    )
                )
                return PlannerResult(
                    plan=plan,
                    metrics=metrics,
                    warnings=[f"Stage {stage.name} failed"],
                )
            report.stage_times[stage.name] = time.perf_counter() - stage_start

        plan.recalculate()
        elapsed = time.perf_counter() - start

        metrics.total_rules_evaluated = len(self._rule_registry.list_rules())
        metrics.total_candidates_generated = len(plan.steps)
        metrics.total_steps_produced = len(plan.steps)
        metrics.phases_covered = len(plan.phases_covered)
        metrics.estimated_total_hours = plan.total_estimated_hours
        metrics.average_priority = plan.overall_priority
        metrics.risk_score = plan.risk.overall
        metrics.elapsed_seconds = round(elapsed, 4)

        bus.emit(
            PlanCompletedEvent(
                investigation_id=context.investigation_id,
                plan_id=plan.id,
                total_steps=len(plan.steps),
                phases_covered=len(plan.phases_covered),
                elapsed_seconds=elapsed,
            )
        )

        return PlannerResult(plan=plan, metrics=metrics)
