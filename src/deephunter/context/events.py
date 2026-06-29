"""Event bus for the Context Engine.

Follows the same pattern as ReasoningEventBus, PlanningEventBus,
and ingestion EventBus.  Typed events are emitted at every context
pipeline stage for metrics, logging, webhooks, and UI.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class ContextEvent:
    """Base event for all context pipeline events."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    investigation_id: str = ""
    plan_id: str = ""
    context_id: str = ""


@dataclass
class ContextCreatedEvent(ContextEvent):
    """Emitted when a new context object is created."""

    source_count: int = 0
    section_count: int = 0


@dataclass
class ContextUpdatedEvent(ContextEvent):
    """Emitted when an existing context is updated."""

    section_count: int = 0
    block_count: int = 0


@dataclass
class ContextTrimmedEvent(ContextEvent):
    """Emitted when the context is trimmed to fit a token budget."""

    original_tokens: int = 0
    trimmed_tokens: int = 0
    blocks_removed: int = 0


@dataclass
class ContextMergeEvent(ContextEvent):
    """Emitted when multiple context sources are merged."""

    merged_sources: int = 0
    total_blocks: int = 0


@dataclass
class ContextDeduplicatedEvent(ContextEvent):
    """Emitted when duplicate blocks are removed."""

    original_count: int = 0
    deduped_count: int = 0


@dataclass
class ContextBudgetExceededEvent(ContextEvent):
    """Emitted when the context exceeds the token budget."""

    total_tokens: int = 0
    max_tokens: int = 0
    action_taken: str = ""


ContextEventHandler = Callable[[ContextEvent], None]


class ContextEventBus:
    """Synchronous event bus for context pipeline events."""

    def __init__(self) -> None:
        self._handlers: dict[type[ContextEvent], list[ContextEventHandler]] = {}

    def subscribe(
        self, event_type: type[ContextEvent], handler: ContextEventHandler
    ) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def unsubscribe(
        self, event_type: type[ContextEvent], handler: ContextEventHandler
    ) -> None:
        handlers = self._handlers.get(event_type)
        if handlers:
            try:
                handlers.remove(handler)
            except ValueError:
                pass

    def emit(self, event: ContextEvent) -> None:
        handlers = self._handlers.get(type(event), [])
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                import logging

                logging.getLogger(__name__).exception(
                    "Context event handler %r failed for %s",
                    handler,
                    type(event).__name__,
                )

    def clear(self) -> None:
        self._handlers.clear()
