"""Event bus for the Model Router.

Follows the same synchronous typed event bus pattern as all other
DeepHunter modules.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class RouterEvent:
    """Base event for all router events."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    request_id: str = ""


@dataclass
class ProviderSelectedEvent(RouterEvent):
    """Emitted when a provider is selected for a request."""

    provider_name: str = ""
    model_name: str = ""
    reason: str = ""
    attempt_number: int = 1


@dataclass
class ProviderFailedEvent(RouterEvent):
    """Emitted when a provider fails during execution."""

    provider_name: str = ""
    model_name: str = ""
    error: str = ""


@dataclass
class FallbackStartedEvent(RouterEvent):
    """Emitted when the router starts a fallback attempt."""

    failed_provider: str = ""
    fallback_provider: str = ""
    attempt_number: int = 1


@dataclass
class RouteCompletedEvent(RouterEvent):
    """Emitted when a route completes successfully."""

    provider_name: str = ""
    model_name: str = ""
    elapsed_ms: float = 0.0


@dataclass
class RouteFailedEvent(RouterEvent):
    """Emitted when all routing attempts fail."""

    error: str = ""
    attempts_made: int = 0


@dataclass
class ProviderRegisteredEvent(RouterEvent):
    """Emitted when a new provider is registered."""

    provider_name: str = ""
    model_count: int = 0


RouterEventHandler = Callable[[RouterEvent], None]


class RouterEventBus:
    """Synchronous event bus for router events."""

    def __init__(self) -> None:
        self._handlers: dict[type[RouterEvent], list[RouterEventHandler]] = {}

    def subscribe(
        self, event_type: type[RouterEvent], handler: RouterEventHandler
    ) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def unsubscribe(
        self, event_type: type[RouterEvent], handler: RouterEventHandler
    ) -> None:
        handlers = self._handlers.get(event_type)
        if handlers:
            try:
                handlers.remove(handler)
            except ValueError:
                pass

    def emit(self, event: RouterEvent) -> None:
        handlers = self._handlers.get(type(event), [])
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                import logging

                logging.getLogger(__name__).exception(
                    "Router event handler %r failed for %s",
                    handler,
                    type(event).__name__,
                )

    def clear(self) -> None:
        self._handlers.clear()
