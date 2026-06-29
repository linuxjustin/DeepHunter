"""Stage-based pipeline for the Context Engine.

Each stage is a ``ContextStage`` subclass that transforms a work-in-progress
``Context`` object.  Stages are independent, testable, and failure-isolated.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from deephunter.context.budget import apply_budget
from deephunter.context.events import (
    ContextBudgetExceededEvent,
    ContextCreatedEvent,
    ContextDeduplicatedEvent,
    ContextEventBus,
)
from deephunter.context.models import (
    Context,
    ContextBlock,
    ContextBudget,
    ContextImportance,
    ContextSection,
    ContextSource,
    ContextSourceType,
)


class ContextStage(ABC):
    """Base class for a single context pipeline stage."""

    name: str = ""

    @abstractmethod
    def process(
        self, context: Context, event_bus: ContextEventBus | None = None
    ) -> None:
        """Process one stage of the context pipeline."""


class InitContextStage(ContextStage):
    """Initialize the context object with metadata."""

    name = "init_context"

    def __init__(self, investigation_id: str = "", plan_id: str = "") -> None:
        self._investigation_id = investigation_id
        self._plan_id = plan_id

    def process(self, context: Context, event_bus: ContextEventBus | None = None) -> None:
        if self._investigation_id:
            context.investigation_id = self._investigation_id
        if self._plan_id:
            context.plan_id = self._plan_id
        if event_bus:
            event_bus.emit(ContextCreatedEvent(
                investigation_id=context.investigation_id,
                plan_id=context.plan_id,
                context_id=context.id,
                source_count=0,
                section_count=0,
            ))


class CollectUserInputStage(ContextStage):
    """Collect user query and constraints into context."""

    name = "collect_user_input"

    def __init__(self, query: str = "", constraints: list[str] | None = None) -> None:
        self._query = query
        self._constraints = constraints or []

    def process(self, context: Context, event_bus: ContextEventBus | None = None) -> None:
        from deephunter.context.sources import collect_from_constraints, collect_from_query

        if self._query:
            collect_from_query(self._query, context)
        if self._constraints:
            collect_from_constraints(self._constraints, context)


class CollectSessionStage(ContextStage):
    """Collect context from an InvestigationSession."""

    name = "collect_session"

    def __init__(self, session: Any | None = None) -> None:
        self._session = session

    def process(self, context: Context, event_bus: ContextEventBus | None = None) -> None:
        if self._session is None:
            return
        from deephunter.context.sources import collect_from_session

        collect_from_session(self._session, context)


class CollectPlanStage(ContextStage):
    """Collect context from an InvestigationPlan."""

    name = "collect_plan"

    def __init__(self, plan: Any | None = None) -> None:
        self._plan = plan

    def process(self, context: Context, event_bus: ContextEventBus | None = None) -> None:
        if self._plan is None:
            return
        from deephunter.context.sources import collect_from_plan

        collect_from_plan(self._plan, context)


class DeduplicateStage(ContextStage):
    """Remove duplicate blocks within the context.

    Blocks with the same ``dedup_key`` and identical content are
    deduplicated.  The first occurrence by section order is kept.
    """

    name = "deduplicate"

    def process(self, context: Context, event_bus: ContextEventBus | None = None) -> None:
        if not context.sections:
            return

        seen: set[tuple[str, str]] = set()
        original_count = sum(len(s.blocks) for s in context.sections)
        removed_count = 0

        for section in context.sections:
            unique: list[ContextBlock] = []
            for block in section.blocks:
                key = (block.dedup_key, block.content)
                if key not in seen:
                    seen.add(key)
                    unique.append(block)
                else:
                    removed_count += 1
            section.blocks = unique

        if removed_count > 0 and event_bus:
            event_bus.emit(ContextDeduplicatedEvent(
                context_id=context.id,
                original_count=original_count,
                deduped_count=removed_count,
            ))


class PrioritizeStage(ContextStage):
    """Sort blocks within each section by descending priority."""

    name = "prioritize"

    def process(self, context: Context, event_bus: ContextEventBus | None = None) -> None:
        for section in context.sections:
            section.blocks.sort(key=lambda b: b.priority, reverse=True)
            section.recalculate()


class BudgetStage(ContextStage):
    """Apply token budget to trim context to fit within limits."""

    name = "apply_budget"

    def __init__(self, budget: ContextBudget | None = None) -> None:
        self._budget = budget

    def process(self, context: Context, event_bus: ContextEventBus | None = None) -> None:
        original_tokens = context.get_total_tokens()
        apply_budget(context, self._budget)
        final_tokens = context.get_total_tokens()

        if final_tokens > original_tokens and event_bus:
            budget = self._budget or context.budget
            event_bus.emit(ContextBudgetExceededEvent(
                context_id=context.id,
                total_tokens=final_tokens,
                max_tokens=budget.max_tokens,
                action_taken="trimmed",
            ))


class RecalculateStage(ContextStage):
    """Recalculate all statistics on the context."""

    name = "recalculate"

    def process(self, context: Context, event_bus: ContextEventBus | None = None) -> None:
        context.recalculate()


class ContextPipelineReport:
    """Report produced by the ContextPipeline after execution."""

    def __init__(
        self,
        stages_run: list[str] = None,
        elapsed_seconds: float = 0.0,
        errors: list[str] = None,
        warnings: list[str] = None,
    ) -> None:
        self.stages_run = stages_run or []
        self.elapsed_seconds = elapsed_seconds
        self.errors = errors or []
        self.warnings = warnings or []

    @property
    def success(self) -> bool:
        return len(self.errors) == 0


class ContextPipeline:
    """Stage-based context assembly pipeline.

    Runs all registered stages sequentially.  Stage failures are caught
    and recorded — they never crash the pipeline.
    """

    def __init__(self, stages: list[ContextStage] | None = None) -> None:
        self._stages = stages or self._default_stages()

    @staticmethod
    def _default_stages() -> list[ContextStage]:
        return [
            InitContextStage(),
            CollectUserInputStage(),
            CollectSessionStage(),
            CollectPlanStage(),
            DeduplicateStage(),
            PrioritizeStage(),
            BudgetStage(),
            RecalculateStage(),
        ]

    def run(
        self,
        context: Context,
        event_bus: ContextEventBus | None = None,
    ) -> ContextPipelineReport:
        """Run all stages on the given context object."""
        stages_run: list[str] = []
        errors: list[str] = []
        start = time.perf_counter()

        for stage in self._stages:
            try:
                stage.process(context, event_bus)
                stages_run.append(stage.name)
            except Exception as exc:
                msg = f"Stage '{stage.name}' failed: {exc}"
                errors.append(msg)
                context.warnings.append(msg)

        elapsed = time.perf_counter() - start
        context.recalculate()

        return ContextPipelineReport(
            stages_run=stages_run,
            elapsed_seconds=elapsed,
            errors=errors,
            warnings=context.warnings,
        )
