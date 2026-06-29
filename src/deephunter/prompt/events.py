"""Event bus for the Prompt Builder.

Follows the same pattern as ContextEventBus, ReasoningEventBus,
PlanningEventBus, and ingestion EventBus.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class PromptEvent:
    """Base event for all prompt builder events."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    investigation_id: str = ""
    context_id: str = ""
    prompt_id: str = ""


@dataclass
class PromptGeneratedEvent(PromptEvent):
    """Emitted when a prompt is successfully generated."""

    style: str = ""
    message_count: int = 0
    estimated_tokens: int = 0


@dataclass
class PromptTemplateLoadedEvent(PromptEvent):
    """Emitted when a prompt template is loaded."""

    template_name: str = ""
    template_style: str = ""


@dataclass
class PromptTemplateNotFoundEvent(PromptEvent):
    """Emitted when a requested template is not found."""

    template_name: str = ""


@dataclass
class PromptFormatAppliedEvent(PromptEvent):
    """Emitted when a format is applied to the prompt."""

    format_name: str = ""


@dataclass
class PromptAdapterAppliedEvent(PromptEvent):
    """Emitted when a model adapter is applied to the prompt."""

    adapter_name: str = ""


PromptEventHandler = Callable[[PromptEvent], None]


class PromptEventBus:
    """Synchronous event bus for prompt builder events."""

    def __init__(self) -> None:
        self._handlers: dict[type[PromptEvent], list[PromptEventHandler]] = {}

    def subscribe(
        self, event_type: type[PromptEvent], handler: PromptEventHandler
    ) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def unsubscribe(
        self, event_type: type[PromptEvent], handler: PromptEventHandler
    ) -> None:
        handlers = self._handlers.get(event_type)
        if handlers:
            try:
                handlers.remove(handler)
            except ValueError:
                pass

    def emit(self, event: PromptEvent) -> None:
        handlers = self._handlers.get(type(event), [])
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                import logging

                logging.getLogger(__name__).exception(
                    "Prompt event handler %r failed for %s",
                    handler,
                    type(event).__name__,
                )

    def clear(self) -> None:
        self._handlers.clear()
