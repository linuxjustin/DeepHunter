"""Endpoint and Parameter Inventory — manages discovered URL endpoints and parameters."""

from __future__ import annotations

from typing import Any

from deephunter.recon.events import EndpointAddedEvent, ParameterAddedEvent, ReconEventBus
from deephunter.recon.models import (
    Endpoint,
    EndpointCategory,
    HttpMethod,
    Parameter,
    ParamLocation,
    ParamType,
    ReconSourceType,
)


class EndpointInventory:
    """Inventory of discovered HTTP endpoints with associated parameters."""

    def __init__(self, event_bus: ReconEventBus | None = None) -> None:
        self._event_bus = event_bus or ReconEventBus()
        self._endpoints: dict[str, Endpoint] = {}

    # ── CRUD ──────────────────────────────────────────────────────

    def add(self, endpoint: Endpoint) -> None:
        if endpoint.id in self._endpoints:
            raise ValueError(f"Endpoint '{endpoint.id}' already exists")
        self._endpoints[endpoint.id] = endpoint
        self._event_bus.emit(
            EndpointAddedEvent(
                entity_id=endpoint.id,
                description=f"{endpoint.method} {endpoint.path}",
                path=endpoint.path,
                method=endpoint.method.value,
            )
        )

    def get(self, endpoint_id: str) -> Endpoint | None:
        return self._endpoints.get(endpoint_id)

    def update(self, endpoint: Endpoint) -> None:
        if endpoint.id not in self._endpoints:
            raise ValueError(f"Endpoint '{endpoint.id}' not found")
        self._endpoints[endpoint.id] = endpoint

    def remove(self, endpoint_id: str) -> bool:
        if endpoint_id in self._endpoints:
            del self._endpoints[endpoint_id]
            return True
        return False

    def find_by_path(self, path: str) -> list[Endpoint]:
        return [e for e in self._endpoints.values() if e.path == path]

    def find_by_method(self, method: HttpMethod) -> list[Endpoint]:
        return [e for e in self._endpoints.values() if e.method == method]

    def find_by_application(self, application_id: str) -> list[Endpoint]:
        return [e for e in self._endpoints.values() if e.application_id == application_id]

    def find_by_host(self, host_id: str) -> list[Endpoint]:
        return [e for e in self._endpoints.values() if e.host_id == host_id]

    def find_by_category(self, category: EndpointCategory) -> list[Endpoint]:
        return [e for e in self._endpoints.values() if e.category == category]

    def find_by_auth(self, requires_auth: bool) -> list[Endpoint]:
        return [e for e in self._endpoints.values() if e.auth_required == requires_auth]

    def list_all(self) -> list[Endpoint]:
        return list(self._endpoints.values())

    # ── Parameters ───────────────────────────────────────────────

    def add_parameter(self, endpoint_id: str, parameter: Parameter) -> None:
        endpoint = self._endpoints.get(endpoint_id)
        if endpoint is None:
            raise ValueError(f"Endpoint '{endpoint_id}' not found")
        parameter.endpoint_id = endpoint_id
        endpoint.parameters.append(parameter)
        self._event_bus.emit(
            ParameterAddedEvent(
                entity_id=parameter.id,
                description=f"Param {parameter.name} ({parameter.location.value})",
                param_name=parameter.name,
                location=parameter.location.value,
            )
        )

    def get_parameters(self, endpoint_id: str) -> list[Parameter]:
        endpoint = self._endpoints.get(endpoint_id)
        if endpoint is None:
            return []
        return endpoint.parameters

    def find_parameters_by_name(self, name: str) -> list[Parameter]:
        results: list[Parameter] = []
        for ep in self._endpoints.values():
            for param in ep.parameters:
                if param.name == name:
                    results.append(param)
        return results

    def find_parameters_by_location(self, location: ParamLocation) -> list[Parameter]:
        results: list[Parameter] = []
        for ep in self._endpoints.values():
            for param in ep.parameters:
                if param.location == location:
                    results.append(param)
        return results

    # ── Bulk ──────────────────────────────────────────────────────

    def add_batch(self, endpoints: list[Endpoint]) -> None:
        for ep in endpoints:
            if ep.id not in self._endpoints:
                self._endpoints[ep.id] = ep

    def clear(self) -> None:
        self._endpoints.clear()

    @property
    def count(self) -> int:
        return len(self._endpoints)

    def __len__(self) -> int:
        return len(self._endpoints)
