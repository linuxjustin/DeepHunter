"""High-level Planner facade.

The ``Planner`` is the single public entry point for generating
investigation plans.  It wires together the rule registry, priority
engine, pipeline, and event bus.
"""

from __future__ import annotations

from pathlib import Path

from deephunter.planning.config import PlanningConfig
from deephunter.planning.events import PlanningEventBus
from deephunter.planning.models import (
    InvestigationPlan,
    PlannerContext,
    PlannerMetrics,
    PlannerResult,
)
from deephunter.planning.pipeline import PlanningPipeline
from deephunter.planning.priority import PriorityEngine
from deephunter.planning.rules import RuleRegistry
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class Planner:
    """High-level planner that generates investigation plans.

    Usage::

        from deephunter.planning import Planner

        session = InvestigationSession.new("https://example.com")
        planner = Planner()

        # Generate a plan from a session
        result = planner.plan(session)

        # Access the plan
        for step in result.plan.steps:
            print(f"[{step.phase.value}] {step.title} (priority={step.priority_score})")

        # Get metrics
        print(f"Generated {result.metrics.total_steps_produced} steps")
    """

    def __init__(
        self,
        config: PlanningConfig | None = None,
        registry: RuleRegistry | None = None,
        priority_engine: PriorityEngine | None = None,
    ) -> None:
        self._config = config or PlanningConfig()
        self._registry = registry or RuleRegistry.with_default_rules()
        self._priority_engine = priority_engine or PriorityEngine()
        self._event_bus = PlanningEventBus()

    @property
    def event_bus(self) -> PlanningEventBus:
        return self._event_bus

    @property
    def registry(self) -> RuleRegistry:
        return self._registry

    def plan_from_session(self, session: object) -> PlannerResult:
        """Generate an investigation plan from a session.

        Args:
            session: An ``InvestigationSession`` instance.

        Returns:
            A ``PlannerResult`` with the generated plan and metrics.
        """
        context = PlannerContext.from_session(session)
        return self._run_pipeline(context)

    def plan_from_context(self, context: PlannerContext) -> PlannerResult:
        """Generate an investigation plan from a pre-built context.

        Args:
            context: A ``PlannerContext`` instance.

        Returns:
            A ``PlannerResult`` with the generated plan and metrics.
        """
        return self._run_pipeline(context)

    def _run_pipeline(self, context: PlannerContext) -> PlannerResult:
        pipeline = PlanningPipeline(
            registry=self._registry,
            priority_engine=self._priority_engine,
            config=self._config,
        )
        return pipeline.run(context, event_bus=self._event_bus)

    def save_plan(self, plan: InvestigationPlan, path: str | Path) -> Path:
        """Persist an investigation plan to a JSON file.

        Args:
            plan: The plan to save.
            path: Destination file path.

        Returns:
            The resolved Path.
        """
        p = Path(path).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        import json

        data = plan.model_dump_for_storage()
        p.write_text(json.dumps(data, indent=2, default=str), "utf-8")
        logger.debug("Saved plan %s to %s", plan.id, p)
        return p

    def load_plan(self, path: str | Path) -> InvestigationPlan:
        """Load an investigation plan from a JSON file.

        Args:
            path: Path to the saved plan JSON.

        Returns:
            A restored InvestigationPlan.

        Raises:
            FileNotFoundError: If the path does not exist.
        """
        p = Path(path).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"Plan file not found: {p}")
        import json

        data = json.loads(p.read_text("utf-8"))
        return InvestigationPlan.from_dict(data)
