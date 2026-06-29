"""Context Engine facade — the public API for building structured context."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from deephunter.context.budget import ContextBudget
from deephunter.context.events import ContextEventBus
from deephunter.context.models import Context
from deephunter.context.pipeline import (
    BudgetStage,
    CollectPlanStage,
    CollectSessionStage,
    CollectUserInputStage,
    ContextPipeline,
    DeduplicateStage,
    InitContextStage,
    PrioritizeStage,
    RecalculateStage,
)

try:
    from deephunter.planning.models import InvestigationPlan
    from deephunter.reasoning.session import InvestigationSession
except ImportError:
    InvestigationPlan = None  # type: ignore[assignment, misc]
    InvestigationSession = None  # type: ignore[assignment, misc]


class ContextEngine:
    """Facade for the Context Engine.

    Orchestrates source collection, deduplication, prioritization,
    and token budgeting to produce a structured ``Context`` object.
    """

    def __init__(
        self,
        event_bus: ContextEventBus | None = None,
        budget: ContextBudget | None = None,
    ) -> None:
        self._event_bus = event_bus or ContextEventBus()
        self._budget = budget
        self._pipeline = self._build_pipeline()

    def _build_pipeline(self) -> ContextPipeline:
        stages = [
            InitContextStage(),
            CollectUserInputStage(),
            CollectSessionStage(),
            CollectPlanStage(),
            DeduplicateStage(),
            PrioritizeStage(),
            BudgetStage(self._budget),
            RecalculateStage(),
        ]
        return ContextPipeline(stages)

    def build(
        self,
        *,
        investigation_id: str = "",
        plan_id: str = "",
        session: Any = None,
        plan: Any = None,
        query: str = "",
        constraints: list[str] | None = None,
    ) -> Context:
        """Build a structured Context object from all available sources.

        Args:
            investigation_id: ID of the investigation.
            plan_id: ID of the investigation plan.
            session: An ``InvestigationSession`` instance.
            plan: An ``InvestigationPlan`` instance.
            query: A user query string.
            constraints: A list of user constraints.

        Returns:
            A fully populated Context object.
        """
        context = Context()
        context.investigation_id = investigation_id
        context.plan_id = plan_id

        pipeline = self._build_pipeline_with_inputs(session, plan, query, constraints, investigation_id, plan_id)
        pipeline.run(context, self._event_bus)

        return context

    def _build_pipeline_with_inputs(
        self,
        session: Any,
        plan: Any,
        query: str,
        constraints: list[str] | None,
        investigation_id: str,
        plan_id: str,
    ) -> ContextPipeline:
        stages: list = [
            InitContextStage(investigation_id, plan_id),
            CollectUserInputStage(query, constraints or []),
        ]
        if session is not None:
            stages.append(CollectSessionStage(session))
        if plan is not None:
            stages.append(CollectPlanStage(plan))
        stages.extend([
            DeduplicateStage(),
            PrioritizeStage(),
            BudgetStage(self._budget),
            RecalculateStage(),
        ])
        return ContextPipeline(stages)

    def save_context(self, context: Context, path: str | Path) -> Path:
        """Persist a Context object to a JSON file.

        Args:
            context: The Context to save.
            path: Destination file path.

        Returns:
            The resolved Path to the saved file.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = context.model_dump(mode="json")
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def load_context(self, path: str | Path) -> Context:
        """Load a Context object from a JSON file.

        Args:
            path: Path to the saved context JSON.

        Returns:
            The deserialized Context.
        """
        path = Path(path)
        with open(path) as f:
            data: dict[str, Any] = json.load(f)
        return Context.from_dict(data)

    @property
    def event_bus(self) -> ContextEventBus:
        return self._event_bus
