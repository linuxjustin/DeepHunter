"""Event bus for the Reasoning Engine.

Mirrors the ingestion event pattern.  Typed events emitted at every
reasoning pipeline stage so that future modules (metrics, logging,
webhooks, UI) can subscribe without coupling.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from deephunter.reasoning.models import (
    Evidence,
    Experiment,
    Finding,
    HypothesisStatus,
    Observation,
    Pivot,
)


# ── Event types ──────────────────────────────────────────────────────────────


@dataclass
class ReasoningEvent:
    """Base event for all reasoning pipeline events."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    investigation_id: str = ""


@dataclass
class ObservationCreatedEvent(ReasoningEvent):
    """Emitted when an observation is created."""

    observation: Observation | None = None


@dataclass
class EvidenceAddedEvent(ReasoningEvent):
    """Emitted when evidence is added to an observation."""

    evidence: Evidence | None = None
    observation_id: str = ""


@dataclass
class HypothesisCreatedEvent(ReasoningEvent):
    """Emitted when a hypothesis is generated."""

    hypothesis_title: str = ""
    bug_classes: list[str] = field(default_factory=list)


@dataclass
class HypothesisUpdatedEvent(ReasoningEvent):
    """Emitted when a hypothesis is updated (e.g. confidence changes)."""

    hypothesis_title: str = ""
    old_confidence: float = 0.0
    new_confidence: float = 0.0
    new_status: str = ""


@dataclass
class ExperimentCreatedEvent(ReasoningEvent):
    """Emitted when a new experiment is planned."""

    experiment: Experiment | None = None


@dataclass
class ExperimentCompletedEvent(ReasoningEvent):
    """Emitted when an experiment finishes."""

    experiment: Experiment | None = None
    passed: bool = False


@dataclass
class ConfidenceChangedEvent(ReasoningEvent):
    """Emitted when hypothesis confidence changes significantly."""

    hypothesis_id: str = ""
    old_score: float = 0.0
    new_score: float = 0.0
    reason: str = ""


@dataclass
class PivotCreatedEvent(ReasoningEvent):
    """Emitted when a pivot is generated."""

    pivot: Pivot | None = None


@dataclass
class FindingCreatedEvent(ReasoningEvent):
    """Emitted when a finding is confirmed."""

    finding: Finding | None = None


@dataclass
class HypothesisStatusChangedEvent(ReasoningEvent):
    """Emitted when a hypothesis status changes."""

    hypothesis_id: str = ""
    old_status: str = ""
    new_status: str = ""


# ── Event bus ────────────────────────────────────────────────────────────────

ReasoningEventHandler = Callable[[ReasoningEvent], None]


class ReasoningEventBus:
    """Synchronous event bus for reasoning pipeline events.

    Follows the same pattern as the ingestion ``EventBus``.
    """

    def __init__(self) -> None:
        self._handlers: dict[type[ReasoningEvent], list[ReasoningEventHandler]] = {}

    def subscribe(
        self, event_type: type[ReasoningEvent], handler: ReasoningEventHandler
    ) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def unsubscribe(
        self, event_type: type[ReasoningEvent], handler: ReasoningEventHandler
    ) -> None:
        handlers = self._handlers.get(event_type)
        if handlers:
            try:
                handlers.remove(handler)
            except ValueError:
                pass

    def emit(self, event: ReasoningEvent) -> None:
        handlers = self._handlers.get(type(event), [])
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                import logging

                logging.getLogger(__name__).exception(
                    "Reasoning event handler %r failed for %s",
                    handler,
                    type(event).__name__,
                )

    def clear(self) -> None:
        self._handlers.clear()
