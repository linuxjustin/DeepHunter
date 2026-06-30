"""Event bus for the Tool Integration SDK & Plugin Framework."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from deephunter.tools.models import ExecutionReport, ToolStatus


@dataclass
class ToolEvent:
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    plugin_name: str = ""
    session_id: str = ""
    description: str = ""


@dataclass
class ToolExecutionStartedEvent(ToolEvent):
    report: ExecutionReport | None = None
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolExecutionCompletedEvent(ToolEvent):
    report: ExecutionReport | None = None
    duration_ms: float = 0.0


@dataclass
class ToolExecutionFailedEvent(ToolEvent):
    report: ExecutionReport | None = None
    error: str = ""
    retry_attempt: int = 0


@dataclass
class ToolPluginDiscoveredEvent(ToolEvent):
    plugin_class: str = ""
    version: str = ""


@dataclass
class ToolPluginRegisteredEvent(ToolEvent):
    plugin_class: str = ""
    version: str = ""


@dataclass
class ToolImportStartedEvent(ToolEvent):
    parsed_count: int = 0


@dataclass
class ToolImportCompletedEvent(ToolEvent):
    imported_count: int = 0
    report: ExecutionReport | None = None


@dataclass
class ToolImportFailedEvent(ToolEvent):
    error: str = ""


ToolEventHandler = Callable[[ToolEvent], None]


class ToolEventBus:
    def __init__(self) -> None:
        self._handlers: dict[type[ToolEvent], list[ToolEventHandler]] = {}

    def subscribe(self, event_type: type[ToolEvent], handler: ToolEventHandler) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def unsubscribe(self, event_type: type[ToolEvent], handler: ToolEventHandler) -> None:
        handlers = self._handlers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)

    def emit(self, event: ToolEvent) -> None:
        handlers = self._handlers.get(type(event), [])
        for h in handlers:
            try:
                h(event)
            except Exception:
                pass

    def clear(self) -> None:
        self._handlers.clear()
