"""Tool Integration SDK & Plugin Framework for DeepHunter.

Enables third-party tools (subdomain enums, port scanners, URL discoverers,
technology detectors, etc.) to be wrapped as plugins and executed within the
DeepHunter platform through a consistent lifecycle.
"""

from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.config import ToolPluginConfig
from deephunter.tools.context import ExecutionContext
from deephunter.tools.events import (
    ToolEvent,
    ToolEventBus,
    ToolExecutionCompletedEvent,
    ToolExecutionFailedEvent,
    ToolExecutionStartedEvent,
    ToolImportCompletedEvent,
    ToolImportFailedEvent,
    ToolImportStartedEvent,
    ToolPluginDiscoveredEvent,
    ToolPluginRegisteredEvent,
)
from deephunter.tools.exceptions import (
    PluginConfigError,
    PluginDiscoveryError,
    PluginExecutionError,
    PluginImportError,
    PluginNormalizeError,
    PluginNotFoundError,
    PluginNotInstalledError,
    ToolPluginError,
)
from deephunter.tools.executor import ToolExecutor, check_tool_installed
from deephunter.tools.models import (
    ExecutionReport,
    PluginHealth,
    ToolCategory,
    ToolMetadata,
    ToolParameter,
    ToolStatus,
)
from deephunter.tools.normalizer import (
    ImportPipeline,
    build_default_pipeline,
    parse_csv,
    parse_json,
    parse_ndjson,
    parse_txt,
    parse_yaml,
)
from deephunter.tools.registry import ToolPluginRegistry
from deephunter.tools.reporter import build_report, report_summary

__all__ = [
    "BaseToolPlugin",
    "ToolPluginConfig",
    "ExecutionContext",
    "ToolEventBus",
    "ToolEvent",
    "ToolExecutionStartedEvent",
    "ToolExecutionCompletedEvent",
    "ToolExecutionFailedEvent",
    "ToolImportStartedEvent",
    "ToolImportCompletedEvent",
    "ToolImportFailedEvent",
    "ToolPluginDiscoveredEvent",
    "ToolPluginRegisteredEvent",
    "ToolPluginError",
    "PluginNotFoundError",
    "PluginExecutionError",
    "PluginImportError",
    "PluginNormalizeError",
    "PluginConfigError",
    "PluginNotInstalledError",
    "PluginDiscoveryError",
    "ToolExecutor",
    "check_tool_installed",
    "ToolMetadata",
    "ToolParameter",
    "ToolStatus",
    "ToolCategory",
    "PluginHealth",
    "ExecutionReport",
    "ToolPluginRegistry",
    "ImportPipeline",
    "build_default_pipeline",
    "parse_json",
    "parse_yaml",
    "parse_csv",
    "parse_txt",
    "parse_ndjson",
    "build_report",
    "report_summary",
]
