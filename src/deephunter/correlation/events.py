"""Event bus and typed events for the Correlation Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


@dataclass
class CorrelationEvent:
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    session_id: str = ""
    description: str = ""


@dataclass
class CorrelationStartedEvent(CorrelationEvent):
    source_technologies: list[str] = field(default_factory=list)
    host_count: int = 0


@dataclass
class CorrelationCompletedEvent(CorrelationEvent):
    stack_count: int = 0
    surface_areas: int = 0
    hints_generated: int = 0


@dataclass
class CorrelationFailedEvent(CorrelationEvent):
    stage: str = ""
    error: str = ""


@dataclass
class PipelineStageStartedEvent(CorrelationEvent):
    stage: str = ""


@dataclass
class PipelineStageCompletedEvent(CorrelationEvent):
    stage: str = ""
    items_processed: int = 0


CorrelationEventHandler = Callable[[CorrelationEvent], None]


class CorrelationEventBus:
    def __init__(self) -> None:
        self._handlers: dict[type[CorrelationEvent], list[CorrelationEventHandler]] = {}

    def subscribe(self, event_type: type[CorrelationEvent], handler: CorrelationEventHandler) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def unsubscribe(self, event_type: type[CorrelationEvent], handler: CorrelationEventHandler) -> None:
        handlers = self._handlers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)

    def emit(self, event: CorrelationEvent) -> None:
        handlers = self._handlers.get(type(event), [])
        for h in handlers:
            try:
                h(event)
            except Exception:
                pass

    def clear(self) -> None:
        self._handlers.clear()
