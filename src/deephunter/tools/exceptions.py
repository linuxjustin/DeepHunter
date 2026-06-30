"""Custom exceptions for the Tool Integration SDK."""

from deephunter.core.exceptions import ToolPluginError


class PluginNotFoundError(ToolPluginError):
    """Raised when a plugin is not found in the registry."""


class PluginRegistrationError(ToolPluginError):
    """Raised when plugin registration fails."""


class PluginValidationError(ToolPluginError):
    """Raised when plugin validation fails."""


class PluginExecutionError(ToolPluginError):
    """Raised when plugin execution fails."""


class PluginTimeoutError(ToolPluginError):
    """Raised when a plugin execution times out."""


class PluginNotInstalledError(ToolPluginError):
    """Raised when a required tool is not installed."""


class PluginImportError(ToolPluginError):
    """Raised when a result cannot be imported into the platform."""


class PluginParseError(ToolPluginError):
    """Raised when tool output cannot be parsed."""


class PluginNormalizeError(ToolPluginError):
    """Raised when parsed data cannot be normalized into domain models."""


class PluginConfigError(ToolPluginError):
    """Raised when a plugin configuration is invalid."""


class PluginDiscoveryError(ToolPluginError):
    """Raised when plugin auto-discovery fails."""
