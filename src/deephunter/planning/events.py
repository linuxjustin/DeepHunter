"""Event bus for the Investigation Planning Engine.

Follows the same pattern as the ReasoningEventBus and EventBus
from ingestion.  Typed events are emitted at every planning
pipeline stage for metrics, logging, webhooks, and UI.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from deephunter.planning.models import InvestigationPlan, InvestigationStep


@dataclass
class PlanningEvent:
    """Base event for all planning pipeline events."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    investigation_id: str = ""
    plan_id: str = ""


@dataclass
class PlanStartedEvent(PlanningEvent):
    """Emitted when planning begins."""


@dataclass
class ContextLoadedEvent(PlanningEvent):
    """Emitted when the planner context has been built."""

    technology_count: int = 0
    observation_count: int = 0


@dataclass
class StepGeneratedEvent(PlanningEvent):
    """Emitted when a single investigation step is generated."""

    step_title: str = ""
    phase: str = ""
    priority_score: float = 0.0


@dataclass
class StepPrioritizedEvent(PlanningEvent):
    """Emitted when a step's priority is calculated."""

    step_title: str = ""
    old_priority: float = 0.0
    new_priority: float = 0.0


@dataclass
class PlanCompletedEvent(PlanningEvent):
    """Emitted when planning finishes successfully."""

    total_steps: int = 0
    phases_covered: int = 0
    elapsed_seconds: float = 0.0


@dataclass
class PlanFailedEvent(PlanningEvent):
    """Emitted when planning fails."""

    error: str = ""


@dataclass
class PlanUpdatedEvent(PlanningEvent):
    """Emitted when an existing plan is updated."""

    version: int = 1
    new_step_count: int = 0


PlanningEventHandler = Callable[[PlanningEvent], None]


class PlanningEventBus:
    """Synchronous event bus for planning pipeline events.

    Mirrors the pattern from ``ReasoningEventBus`` and ingestion
    ``EventBus``.
    """

    def __init__(self) -> None:
        self._handlers: dict[type[PlanningEvent], list[PlanningEventHandler]] = {}

    def subscribe(
        self, event_type: type[PlanningEvent], handler: PlanningEventHandler
    ) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def unsubscribe(
        self, event_type: type[PlanningEvent], handler: PlanningEventHandler
    ) -> None:
        handlers = self._handlers.get(event_type)
        if handlers:
            try:
                handlers.remove(handler)
            except ValueError:
                pass

    def emit(self, event: PlanningEvent) -> None:
        handlers = self._handlers.get(type(event), [])
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                import logging

                logging.getLogger(__name__).exception(
                    "Planning event handler %r failed for %s",
                    handler,
                    type(event).__name__,
                )

    def clear(self) -> None:
        self._handlers.clear()


def plan_to_event_context(plan: InvestigationPlan) -> dict:
    """Extract a summary dict from a plan for event metadata."""
    return {
        "plan_id": plan.id,
        "steps": len(plan.steps),
        "phases": [p.value for p in plan.phases_covered],
        "total_hours": plan.total_estimated_hours,
        "priority": plan.overall_priority,
    }
