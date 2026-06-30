"""Application Inventory — manages discovered applications, services, and API endpoints."""

from __future__ import annotations

from typing import Any

from deephunter.recon.events import (
    APIDiscoveredEvent,
    ApplicationDiscoveredEvent,
    ReconEventBus,
)
from deephunter.recon.models import (
    APIEndpoint,
    Application,
    ApplicationType,
    HttpMethod,
    ReconSourceType,
)


class ApplicationInventory:
    """Manages discovered applications, services, and API endpoints."""

    def __init__(self, event_bus: ReconEventBus | None = None) -> None:
        self._event_bus = event_bus or ReconEventBus()
        self._applications: dict[str, Application] = {}
        self._api_endpoints: dict[str, APIEndpoint] = {}

    # ── Applications ─────────────────────────────────────────────

    def add_application(self, app: Application) -> None:
        if app.id in self._applications:
            raise ValueError(f"Application '{app.id}' already exists")
        self._applications[app.id] = app
        self._event_bus.emit(
            ApplicationDiscoveredEvent(
                entity_id=app.id,
                description=f"App {app.name} ({app.app_type.value})",
                app_name=app.name,
                app_type=app.app_type.value,
            )
        )

    def get_application(self, app_id: str) -> Application | None:
        return self._applications.get(app_id)

    def find_by_host(self, host_id: str) -> list[Application]:
        return [a for a in self._applications.values() if a.host_id == host_id]

    def find_by_type(self, app_type: ApplicationType) -> list[Application]:
        return [a for a in self._applications.values() if a.app_type == app_type]

    def list_applications(self) -> list[Application]:
        return list(self._applications.values())

    # ── API Endpoints ────────────────────────────────────────────

    def add_api_endpoint(self, api_ep: APIEndpoint) -> None:
        if api_ep.id in self._api_endpoints:
            raise ValueError(f"APIEndpoint '{api_ep.id}' already exists")
        self._api_endpoints[api_ep.id] = api_ep
        self._event_bus.emit(
            APIDiscoveredEvent(
                entity_id=api_ep.id,
                description=f"API {api_ep.method} {api_ep.path}",
                path=api_ep.path,
                method=api_ep.method.value,
            )
        )

    def get_api_endpoint(self, api_id: str) -> APIEndpoint | None:
        return self._api_endpoints.get(api_id)

    def find_api_by_application(self, app_id: str) -> list[APIEndpoint]:
        return [a for a in self._api_endpoints.values() if a.application_id == app_id]

    def find_api_by_host(self, host_id: str) -> list[APIEndpoint]:
        return [a for a in self._api_endpoints.values() if a.host_id == host_id]

    def find_api_by_path(self, path: str) -> list[APIEndpoint]:
        return [a for a in self._api_endpoints.values() if a.path == path]

    def find_api_by_method(self, method: HttpMethod) -> list[APIEndpoint]:
        return [a for a in self._api_endpoints.values() if a.method == method]

    def list_api_endpoints(self) -> list[APIEndpoint]:
        return list(self._api_endpoints.values())

    def clear(self) -> None:
        self._applications.clear()
        self._api_endpoints.clear()

    @property
    def application_count(self) -> int:
        return len(self._applications)

    @property
    def api_count(self) -> int:
        return len(self._api_endpoints)
