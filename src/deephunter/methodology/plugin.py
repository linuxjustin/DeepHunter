"""Plugin interface for the methodology engine.

Supports custom/company-specific methodology additions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from deephunter.methodology.models import (
    ChecklistItem,
    FrameworkProfile,
    InvestigationWorkflow,
    Methodology,
)


class MethodologyPlugin(ABC):
    """Abstract base for methodology plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        ...

    def get_methodologies(self) -> list[Methodology]:
        """Return additional methodologies provided by this plugin."""
        return []

    def get_profiles(self) -> list[FrameworkProfile]:
        """Return additional framework profiles provided by this plugin."""
        return []

    def custom_checklist_items(
        self, framework_profile: FrameworkProfile | None = None
    ) -> list[ChecklistItem]:
        """Return custom checklist items for the given profile or general."""
        return []

    def custom_workflows(
        self, framework_profile: FrameworkProfile | None = None
    ) -> list[InvestigationWorkflow]:
        """Return custom workflows for the given profile or general."""
        return []
