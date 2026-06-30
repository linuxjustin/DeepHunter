"""Event models for the methodology engine."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Callable
from uuid import uuid4

from pydantic import BaseModel, Field


class MethodologyEvent(BaseModel):
    """Base event for methodology engine events."""

    event_id: str = Field(default_factory=lambda: f"me-{uuid4().hex[:12]}")
    event_type: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    data: dict[str, Any] = Field(default_factory=dict)


class MethodologyStartedEvent(MethodologyEvent):
    event_type: str = "methodology_started"


class MethodologySelectedEvent(MethodologyEvent):
    event_type: str = "methodology_selected"


class ChecklistGeneratedEvent(MethodologyEvent):
    event_type: str = "checklist_generated"


class WorkflowBuiltEvent(MethodologyEvent):
    event_type: str = "workflow_built"


class StepCompletedEvent(MethodologyEvent):
    event_type: str = "step_completed"


class MethodologyCompletedEvent(MethodologyEvent):
    event_type: str = "methodology_completed"


EventHandler = Callable[[MethodologyEvent], None]


class MethodologyEventBus:
    """Simple event bus for methodology engine events."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = {}

    def on(self, event_type: str, handler: EventHandler) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def off(self, event_type: str, handler: EventHandler) -> None:
        self._handlers.setdefault(event_type, [])
        if handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)

    def emit(self, event: MethodologyEvent) -> None:
        for handler in self._handlers.get(event.event_type, []):
            handler(event)
