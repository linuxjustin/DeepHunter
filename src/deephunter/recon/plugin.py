"""Plugin architecture for the Recon Intelligence Platform.

Each plugin ingests data from an external source and returns structured
recon entities.  Plugins are isolated behind interfaces — they NEVER
execute external tools directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PluginResult:
    """Result from a recon plugin execution."""
    success: bool = True
    error: str = ""
    assets: list[Any] = field(default_factory=list)
    hosts: list[Any] = field(default_factory=list)
    technologies: list[Any] = field(default_factory=list)
    endpoints: list[Any] = field(default_factory=list)
    parameters: list[Any] = field(default_factory=list)
    auth_mechanisms: list[Any] = field(default_factory=list)
    dns_records: list[Any] = field(default_factory=list)
    http_observations: list[Any] = field(default_factory=list)
    js_files: list[Any] = field(default_factory=list)
    js_endpoints: list[Any] = field(default_factory=list)
    api_endpoints: list[Any] = field(default_factory=list)
    cloud_resources: list[Any] = field(default_factory=list)
    applications: list[Any] = field(default_factory=list)


class ReconPlugin(ABC):
    """Base class for a recon data ingestion plugin.

    Subclasses implement ``process()`` which transforms raw input
    into structured recon entities.

    Plugins are NEVER responsible for executing external tools.
    They accept data that has already been collected.
    """

    name: str = ""
    description: str = ""
    version: str = "1.0.0"

    @abstractmethod
    def process(self, raw_data: Any) -> PluginResult:
        ...

    def validate(self, raw_data: Any) -> bool:
        return True


class PluginRegistry:
    """Registry of available recon plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, ReconPlugin] = {}

    def register(self, plugin: ReconPlugin) -> None:
        if plugin.name in self._plugins:
            raise ValueError(f"Plugin '{plugin.name}' is already registered")
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> ReconPlugin | None:
        return self._plugins.get(name)

    def list_names(self) -> list[str]:
        return list(self._plugins.keys())

    def list_plugins(self) -> list[ReconPlugin]:
        return list(self._plugins.values())

    def clear(self) -> None:
        self._plugins.clear()
