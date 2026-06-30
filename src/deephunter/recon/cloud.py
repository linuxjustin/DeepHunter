"""Cloud Intelligence — manages discovered cloud resources and infrastructure."""

from __future__ import annotations

from typing import Any

from deephunter.recon.events import CloudResourceDiscoveredEvent, ReconEventBus
from deephunter.recon.models import CloudResource, CloudResourceType, ReconSourceType


class CloudIntelligence:
    """Manages cloud resource discovery and organization.

    Tracks cloud resources across providers, with type classification
    and relationship tracking.
    """

    def __init__(self, event_bus: ReconEventBus | None = None) -> None:
        self._event_bus = event_bus or ReconEventBus()
        self._resources: dict[str, CloudResource] = {}

    def add(self, resource: CloudResource) -> None:
        if resource.id in self._resources:
            raise ValueError(f"CloudResource '{resource.id}' already exists")
        self._resources[resource.id] = resource
        self._event_bus.emit(
            CloudResourceDiscoveredEvent(
                entity_id=resource.id,
                description=f"Cloud {resource.provider}/{resource.resource_type.value}: {resource.name}",
                provider=resource.provider,
                resource_type=resource.resource_type.value,
            )
        )

    def get(self, resource_id: str) -> CloudResource | None:
        return self._resources.get(resource_id)

    def find_by_provider(self, provider: str) -> list[CloudResource]:
        return [r for r in self._resources.values() if r.provider.lower() == provider.lower()]

    def find_by_type(self, resource_type: CloudResourceType) -> list[CloudResource]:
        return [r for r in self._resources.values() if r.resource_type == resource_type]

    def find_by_program(self, program_id: str) -> list[CloudResource]:
        return [r for r in self._resources.values() if r.program_id == program_id]

    def find_by_region(self, region: str) -> list[CloudResource]:
        return [r for r in self._resources.values() if r.region.lower() == region.lower()]

    def list_all(self) -> list[CloudResource]:
        return list(self._resources.values())

    def get_providers_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for r in self._resources.values():
            summary[r.provider] = summary.get(r.provider, 0) + 1
        return summary

    def clear(self) -> None:
        self._resources.clear()

    @property
    def count(self) -> int:
        return len(self._resources)
