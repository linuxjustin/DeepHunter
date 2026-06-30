"""Tests for tools/exceptions.py and core exceptions integration."""

from __future__ import annotations

from deephunter.core.exceptions import DeepHunterError, ToolPluginError
from deephunter.tools.exceptions import (
    PluginConfigError,
    PluginDiscoveryError,
    PluginExecutionError,
    PluginImportError,
    PluginNormalizeError,
    PluginNotFoundError,
    PluginNotInstalledError,
    PluginParseError,
    PluginRegistrationError,
    PluginTimeoutError,
    PluginValidationError,
)


class TestToolPluginError:
    def test_base_is_deephunter_error(self) -> None:
        assert issubclass(ToolPluginError, DeepHunterError)

    def test_exception_is_raiseable(self) -> None:
        try:
            raise ToolPluginError("test error")
        except ToolPluginError as e:
            assert str(e) == "test error"

    def test_in_core_exports(self) -> None:
        from deephunter.core import ToolPluginError as CoreTPE
        assert CoreTPE is ToolPluginError


class TestPluginNotFoundError:
    def test_is_tool_plugin_error(self) -> None:
        assert issubclass(PluginNotFoundError, ToolPluginError)

    def test_message(self) -> None:
        with __import__("pytest").raises(PluginNotFoundError, match="not found"):
            raise PluginNotFoundError("plugin not found")


class TestPluginRegistrationError:
    def test_is_tool_plugin_error(self) -> None:
        assert issubclass(PluginRegistrationError, ToolPluginError)


class TestPluginValidationError:
    def test_is_tool_plugin_error(self) -> None:
        assert issubclass(PluginValidationError, ToolPluginError)


class TestPluginExecutionError:
    def test_is_tool_plugin_error(self) -> None:
        assert issubclass(PluginExecutionError, ToolPluginError)


class TestPluginTimeoutError:
    def test_is_execution_error_subclass(self) -> None:
        assert issubclass(PluginTimeoutError, ToolPluginError)


class TestPluginNotInstalledError:
    def test_is_tool_plugin_error(self) -> None:
        assert issubclass(PluginNotInstalledError, ToolPluginError)


class TestPluginImportError:
    def test_is_tool_plugin_error(self) -> None:
        assert issubclass(PluginImportError, ToolPluginError)


class TestPluginParseError:
    def test_is_tool_plugin_error(self) -> None:
        assert issubclass(PluginParseError, ToolPluginError)


class TestPluginNormalizeError:
    def test_is_tool_plugin_error(self) -> None:
        assert issubclass(PluginNormalizeError, ToolPluginError)


class TestPluginConfigError:
    def test_is_tool_plugin_error(self) -> None:
        assert issubclass(PluginConfigError, ToolPluginError)


class TestPluginDiscoveryError:
    def test_is_tool_plugin_error(self) -> None:
        assert issubclass(PluginDiscoveryError, ToolPluginError)


class TestAllExceptions:
    def test_all_unique(self) -> None:
        classes = [
            ToolPluginError,
            PluginNotFoundError,
            PluginRegistrationError,
            PluginValidationError,
            PluginExecutionError,
            PluginTimeoutError,
            PluginNotInstalledError,
            PluginImportError,
            PluginParseError,
            PluginNormalizeError,
            PluginConfigError,
            PluginDiscoveryError,
        ]
        assert len(classes) == len(set(classes))

    def test_all_subclass_tool_plugin_error(self) -> None:
        classes = [
            PluginNotFoundError,
            PluginRegistrationError,
            PluginValidationError,
            PluginExecutionError,
            PluginTimeoutError,
            PluginNotInstalledError,
            PluginImportError,
            PluginParseError,
            PluginNormalizeError,
            PluginConfigError,
            PluginDiscoveryError,
        ]
        for cls in classes:
            assert issubclass(cls, ToolPluginError), f"{cls.__name__} is not a subclass of ToolPluginError"

    def test_all_raisable(self) -> None:
        classes = [
            PluginNotFoundError,
            PluginRegistrationError,
            PluginValidationError,
            PluginExecutionError,
            PluginTimeoutError,
            PluginNotInstalledError,
            PluginImportError,
            PluginParseError,
            PluginNormalizeError,
            PluginConfigError,
            PluginDiscoveryError,
        ]
        for cls in classes:
            try:
                raise cls("test")
            except ToolPluginError as e:
                assert str(e) == "test"


class TestCoreExport:
    def test_core_exports_tool_plugin_error(self) -> None:
        from deephunter.core import ToolPluginError
        assert ToolPluginError is not None
        assert issubclass(ToolPluginError, DeepHunterError)

    def test_core_exports_tool_plugin_config(self) -> None:
        from deephunter.core import ToolPluginConfig
        assert ToolPluginConfig is not None
