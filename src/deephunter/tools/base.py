"""Base class for Tool Plugins.

Defines the full lifecycle for executing and integrating external tools.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from deephunter.recon.plugin import PluginResult
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolMetadata


class BaseToolPlugin(ABC):
    """Abstract base for a tool plugin.

    Lifecycle::

        validate(context) -> bool
        prepare(context) -> None
        execute(context) -> str | bytes | Path
        parse_output(raw_output, context) -> Any
        normalize(parsed, context) -> PluginResult
        import_results(result, context) -> dict[str, int]
        cleanup(context) -> None
        health(context) -> PluginHealth
    """

    metadata: ToolMetadata = ToolMetadata(name="base_tool_plugin")

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def description(self) -> str:
        return self.metadata.description

    @property
    def version(self) -> str:
        return self.metadata.version

    @property
    def category(self) -> ToolCategory:
        return self.metadata.category

    def validate_context(self, context: ExecutionContext) -> bool:
        return True

    def prepare(self, context: ExecutionContext) -> None:
        pass

    @abstractmethod
    def execute(self, context: ExecutionContext) -> str | bytes | None:
        ...

    def parse_output(self, raw_output: str | bytes | None, context: ExecutionContext) -> Any:
        return raw_output

    def normalize(self, parsed: Any, context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        return result

    def import_results(self, result: PluginResult, context: ExecutionContext) -> dict[str, int]:
        return {}

    def cleanup(self, context: ExecutionContext) -> None:
        pass

    def health(self, context: ExecutionContext) -> PluginHealth:
        return PluginHealth()

    def build_command(self, context: ExecutionContext) -> str:
        return ""
