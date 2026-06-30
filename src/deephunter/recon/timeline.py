"""Recon Timeline — ordered event log for a recon session."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from deephunter.recon.events import (
    AssetCreatedEvent,
    AuthObservedEvent,
    EndpointAddedEvent,
    HostDiscoveredEvent,
    ParameterAddedEvent,
    ReconEventBus,
    ReconEventHandler,
    ScopeLoadedEvent,
    TechnologyDetectedEvent,
)
from deephunter.recon.models import TimelineEntry


class ReconTimeline:
    """Ordered timeline of all events in a reconnaissance session.

    Subscribes to the event bus and records every event as a
    ``TimelineEntry`` for auditing, replay, and reporting.
    """

    def __init__(
        self,
        session_id: str = "",
        event_bus: ReconEventBus | None = None,
    ) -> None:
        self._session_id = session_id
        self._entries: list[TimelineEntry] = []
        self._event_bus = event_bus

        if self._event_bus:
            self._subscribe()

    def _subscribe(self) -> None:
        handlers: list[tuple[type, ReconEventHandler]] = [
            (ScopeLoadedEvent, self._on_scope_loaded),
            (AssetCreatedEvent, self._on_asset_created),
            (HostDiscoveredEvent, self._on_host_discovered),
            (EndpointAddedEvent, self._on_endpoint_added),
            (ParameterAddedEvent, self._on_parameter_added),
            (TechnologyDetectedEvent, self._on_technology_detected),
            (AuthObservedEvent, self._on_auth_observed),
        ]
        for event_type, handler in handlers:
            self._event_bus.subscribe(event_type, handler)

    def _add_entry(
        self, event_type: str, description: str = "",
        entity_type: str = "", entity_id: str = "",
        detail: str = "", metadata: dict[str, Any] | None = None,
    ) -> None:
        entry = TimelineEntry(
            session_id=self._session_id,
            event_type=event_type,
            description=description,
            entity_type=entity_type,
            entity_id=entity_id,
            detail=detail,
            metadata=metadata or {},
        )
        self._entries.append(entry)

    def _on_scope_loaded(self, event: ScopeLoadedEvent) -> None:
        self._add_entry("scope_loaded", event.description, "scope", event.entity_id)

    def _on_asset_created(self, event: AssetCreatedEvent) -> None:
        self._add_entry(
            "asset_created", event.description, "asset", event.entity_id,
            detail=f"type={event.asset_type} identifier={event.identifier}",
        )

    def _on_host_discovered(self, event: HostDiscoveredEvent) -> None:
        self._add_entry(
            "host_discovered", event.description, "host", event.entity_id,
            detail=f"{event.hostname}:{event.port} ({event.ip})",
        )

    def _on_endpoint_added(self, event: EndpointAddedEvent) -> None:
        self._add_entry(
            "endpoint_added", event.description, "endpoint", event.entity_id,
            detail=f"{event.method} {event.path}",
        )

    def _on_parameter_added(self, event: ParameterAddedEvent) -> None:
        self._add_entry(
            "parameter_added", event.description, "parameter", event.entity_id,
            detail=f"name={event.param_name} location={event.location}",
        )

    def _on_technology_detected(self, event: TechnologyDetectedEvent) -> None:
        self._add_entry(
            "technology_detected", event.description, "technology", event.entity_id,
            detail=f"tech={event.tech_name} category={event.category}",
        )

    def _on_auth_observed(self, event: AuthObservedEvent) -> None:
        self._add_entry(
            "auth_observed", event.description, "auth", event.entity_id,
            detail=f"type={event.auth_type} url={event.url}",
        )

    # ── Public API ───────────────────────────────────────────────

    def add_entry(self, entry: TimelineEntry) -> None:
        self._entries.append(entry)

    def list_all(self) -> list[TimelineEntry]:
        return list(self._entries)

    def list_by_event_type(self, event_type: str) -> list[TimelineEntry]:
        return [e for e in self._entries if e.event_type == event_type]

    def list_since(self, timestamp: datetime) -> list[TimelineEntry]:
        return [e for e in self._entries if e.timestamp >= timestamp]

    def clear(self) -> None:
        self._entries.clear()

    @property
    def count(self) -> int:
        return len(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __getitem__(self, index: int) -> TimelineEntry:
        return self._entries[index]
