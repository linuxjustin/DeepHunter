"""Event bus for the ingestion pipeline.

Typed events emitted at every pipeline stage so that future modules
(e.g. metrics, logging, webhooks) can subscribe without coupling.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from deephunter.knowledge.models import SecurityKnowledgeObject


# ── Event types ──────────────────────────────────────────────────────────────


@dataclass
class IngestionEvent:
    """Base event — all pipeline events inherit from this."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class DocumentDiscoveredEvent(IngestionEvent):
    """Emitted when a file is discovered for ingestion."""

    path: Path = Path()


@dataclass
class DocumentSkippedEvent(IngestionEvent):
    """Emitted when a file is skipped (no parser, too large, etc.)."""

    path: Path = Path()
    reason: str = ""


@dataclass
class ParseStartedEvent(IngestionEvent):
    """Emitted before a document is parsed."""

    path: Path = Path()


@dataclass
class ParseCompletedEvent(IngestionEvent):
    """Emitted after a document is successfully parsed."""

    path: Path = Path()
    content_length: int = 0
    sections_count: int = 0


@dataclass
class ParseFailedEvent(IngestionEvent):
    """Emitted when parsing fails."""

    path: Path = Path()
    error: str = ""


@dataclass
class MetadataExtractedEvent(IngestionEvent):
    """Emitted after metadata is extracted from parsed content."""

    path: Path = Path()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SKOCreatedEvent(IngestionEvent):
    """Emitted when an SKO is built from parsed content."""

    sko: SecurityKnowledgeObject | None = None


@dataclass
class ValidationFailedEvent(IngestionEvent):
    """Emitted when an SKO fails validation."""

    sko_id: str = ""
    errors: list[str] = field(default_factory=list)


@dataclass
class DuplicateSkippedEvent(IngestionEvent):
    """Emitted when a duplicate SKO is detected and skipped."""

    sko: SecurityKnowledgeObject | None = None
    strategy: str = ""


@dataclass
class DocumentStoredEvent(IngestionEvent):
    """Emitted after an SKO is stored."""

    sko: SecurityKnowledgeObject | None = None
    backend: str = ""


@dataclass
class IngestionCompleteEvent(IngestionEvent):
    """Emitted when the entire pipeline run finishes."""

    total: int = 0
    parsed: int = 0
    stored: int = 0
    skipped: int = 0
    duplicates: int = 0
    failed: int = 0
    elapsed_seconds: float = 0.0


# ── Event bus ────────────────────────────────────────────────────────────────

EventHandler = Callable[[IngestionEvent], None]


class EventBus:
    """Simple synchronous event bus for the ingestion pipeline.

    Handlers are called in registration order.  If a handler raises,
    the exception is logged but other handlers still run.
    """

    def __init__(self) -> None:
        self._handlers: dict[type[IngestionEvent], list[EventHandler]] = {}

    def subscribe(self, event_type: type[IngestionEvent], handler: EventHandler) -> None:
        """Register a handler for an event type.

        Args:
            event_type: The event class to subscribe to (e.g. ``SKOCreatedEvent``).
            handler: A callable that accepts the event instance.
        """
        self._handlers.setdefault(event_type, []).append(handler)

    def unsubscribe(self, event_type: type[IngestionEvent], handler: EventHandler) -> None:
        """Remove a previously registered handler."""
        handlers = self._handlers.get(event_type)
        if handlers:
            try:
                handlers.remove(handler)
            except ValueError:
                pass

    def emit(self, event: IngestionEvent) -> None:
        """Emit an event to all subscribed handlers.

        Args:
            event: The event instance to dispatch.
        """
        handlers = self._handlers.get(type(event), [])
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                import logging

                logging.getLogger(__name__).exception(
                    "Event handler %r failed for %s", handler, type(event).__name__
                )

    def clear(self) -> None:
        """Remove all handlers (primarily for testing)."""
        self._handlers.clear()
