"""Technology Intelligence — manages detected technologies and framework fingerprints."""

from __future__ import annotations

from typing import Any

from deephunter.recon.events import ReconEventBus, TechnologyDetectedEvent
from deephunter.recon.models import ReconSourceType, TechCategory, Technology


class TechnologyIntelligence:
    """Collects and organizes detected technologies across hosts and applications.

    Technologies are tracked independently and associated with hosts
    or applications via the Attack Surface Graph.
    """

    def __init__(self, event_bus: ReconEventBus | None = None) -> None:
        self._event_bus = event_bus or ReconEventBus()
        self._technologies: dict[str, Technology] = {}

    # ── CRUD ──────────────────────────────────────────────────────

    def add(self, technology: Technology) -> None:
        if technology.id in self._technologies:
            raise ValueError(f"Technology '{technology.id}' already exists")
        self._technologies[technology.id] = technology
        self._event_bus.emit(
            TechnologyDetectedEvent(
                entity_id=technology.id,
                description=f"Tech {technology.name} ({technology.category.value})",
                tech_name=technology.name,
                category=technology.category.value,
            )
        )

    def get(self, tech_id: str) -> Technology | None:
        return self._technologies.get(tech_id)

    def remove(self, tech_id: str) -> bool:
        if tech_id in self._technologies:
            del self._technologies[tech_id]
            return True
        return False

    def find_by_name(self, name: str) -> list[Technology]:
        return [t for t in self._technologies.values() if t.name.lower() == name.lower()]

    def find_by_category(self, category: TechCategory) -> list[Technology]:
        return [t for t in self._technologies.values() if t.category == category]

    def find_by_source(self, source: ReconSourceType) -> list[Technology]:
        return [t for t in self._technologies.values() if t.source == source]

    def list_all(self) -> list[Technology]:
        return list(self._technologies.values())

    # ── Lookup helpers ────────────────────────────────────────────

    def get_frontend_technologies(self) -> list[Technology]:
        return [t for t in self._technologies.values() if t.category in (
            TechCategory.FRONTEND, TechCategory.FRAMEWORK,
        )]

    def get_backend_technologies(self) -> list[Technology]:
        return [t for t in self._technologies.values() if t.category in (
            TechCategory.BACKEND, TechCategory.RUNTIME,
            TechCategory.APPLICATION_SERVER,
        )]

    def get_security_technologies(self) -> list[Technology]:
        return [t for t in self._technologies.values() if t.category in (
            TechCategory.WAF, TechCategory.CDN_SECURITY,
            TechCategory.IDENTITY_PROVIDER,
        )]

    def get_categories_summary(self) -> dict[str, list[str]]:
        summary: dict[str, list[str]] = {}
        for tech in self._technologies.values():
            cat = tech.category.value
            if cat not in summary:
                summary[cat] = []
            summary[cat].append(tech.name)
        return summary

    # ── Bulk ──────────────────────────────────────────────────────

    def add_batch(self, technologies: list[Technology]) -> None:
        for tech in technologies:
            if tech.id not in self._technologies:
                self._technologies[tech.id] = tech

    def clear(self) -> None:
        self._technologies.clear()

    @property
    def count(self) -> int:
        return len(self._technologies)

    def __len__(self) -> int:
        return len(self._technologies)
