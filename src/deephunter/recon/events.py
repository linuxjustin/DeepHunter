"""Event bus for the Recon Intelligence Platform v1.

Follows the same pattern as ``PlanningEventBus``, ``ReasoningEventBus``,
and other event buses in the DeepHunter platform.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class ReconEvent:
    """Base event for all recon pipeline events."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    session_id: str = ""
    entity_id: str = ""
    description: str = ""


@dataclass
class ScopeLoadedEvent(ReconEvent):
    """Emitted when scope is loaded into a session."""


@dataclass
class AssetCreatedEvent(ReconEvent):
    """Emitted when a new asset is created."""

    asset_type: str = ""
    identifier: str = ""


@dataclass
class HostDiscoveredEvent(ReconEvent):
    """Emitted when a host is added."""

    hostname: str = ""
    ip: str = ""
    port: int = 0


@dataclass
class DNSRecordObservedEvent(ReconEvent):
    """Emitted when a DNS record is observed."""

    record_type: str = ""
    value: str = ""


@dataclass
class HTTPObservedEvent(ReconEvent):
    """Emitted when an HTTP probe result is recorded."""

    url: str = ""
    status_code: int = 0


@dataclass
class EndpointAddedEvent(ReconEvent):
    """Emitted when a new endpoint is added."""

    path: str = ""
    method: str = ""


@dataclass
class ParameterAddedEvent(ReconEvent):
    """Emitted when a parameter is added to an endpoint."""

    param_name: str = ""
    location: str = ""


@dataclass
class TechnologyDetectedEvent(ReconEvent):
    """Emitted when a technology is detected."""

    tech_name: str = ""
    category: str = ""


@dataclass
class AuthObservedEvent(ReconEvent):
    """Emitted when an auth mechanism is observed."""

    auth_type: str = ""
    url: str = ""


@dataclass
class ApplicationDiscoveredEvent(ReconEvent):
    """Emitted when an application is identified."""

    app_name: str = ""
    app_type: str = ""


@dataclass
class CloudResourceDiscoveredEvent(ReconEvent):
    """Emitted when a cloud resource is found."""

    provider: str = ""
    resource_type: str = ""


@dataclass
class JSEndpointDiscoveredEvent(ReconEvent):
    """Emitted when a URL is found in JavaScript."""

    source_url: str = ""
    discovered_url: str = ""


@dataclass
class APIDiscoveredEvent(ReconEvent):
    """Emitted when an API endpoint is discovered."""

    path: str = ""
    method: str = ""


@dataclass
class GraphUpdatedEvent(ReconEvent):
    """Emitted when the attack surface graph is updated."""

    node_count: int = 0
    edge_count: int = 0


@dataclass
class ReconPipelineEvent(ReconEvent):
    """Emitted during pipeline stage execution."""

    stage: str = ""
    status: str = ""


ReconEventHandler = Callable[[ReconEvent], None]


class ReconEventBus:
    """Synchronous event bus for recon pipeline events.

    Mirrors the pattern from ``PlanningEventBus``, ``ReasoningEventBus``,
    and other event buses.
    """

    def __init__(self) -> None:
        self._handlers: dict[type[ReconEvent], list[ReconEventHandler]] = {}

    def subscribe(
        self, event_type: type[ReconEvent], handler: ReconEventHandler
    ) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def unsubscribe(
        self, event_type: type[ReconEvent], handler: ReconEventHandler
    ) -> None:
        handlers = self._handlers.get(event_type)
        if handlers:
            try:
                handlers.remove(handler)
            except ValueError:
                pass

    def emit(self, event: ReconEvent) -> None:
        handlers = self._handlers.get(type(event), [])
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                import logging

                logging.getLogger(__name__).exception(
                    "Recon event handler %r failed for %s",
                    handler,
                    type(event).__name__,
                )

    def clear(self) -> None:
        self._handlers.clear()
