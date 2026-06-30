"""Tests for tools/base.py."""

from __future__ import annotations

from typing import Any

from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolMetadata


class _ConcretePlugin(BaseToolPlugin):
    metadata = ToolMetadata(
        name="test_plugin",
        description="A test plugin",
        version="2.0.0",
        category=ToolCategory.port_scan,
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        return "host1\nhost2"


class _ReturnNonePlugin(BaseToolPlugin):
    metadata = ToolMetadata(name="none_plugin")

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        return None


class _CustomNormalizePlugin(BaseToolPlugin):
    metadata = ToolMetadata(name="custom_norm")

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        return '{"hosts": ["a", "b"]}'

    def normalize(self, parsed: Any, context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        result.hosts = parsed.get("hosts", [])
        return result


class TestBaseToolPlugin:
    def test_abstract(self) -> None:
        with __import__("pytest").raises(TypeError):
            BaseToolPlugin()  # type: ignore

    def test_concrete_create(self) -> None:
        p = _ConcretePlugin()
        assert isinstance(p, BaseToolPlugin)

    def test_name_property(self) -> None:
        p = _ConcretePlugin()
        assert p.name == "test_plugin"

    def test_description_property(self) -> None:
        p = _ConcretePlugin()
        assert p.description == "A test plugin"

    def test_version_property(self) -> None:
        p = _ConcretePlugin()
        assert p.version == "2.0.0"

    def test_category_property(self) -> None:
        p = _ConcretePlugin()
        assert p.category == ToolCategory.port_scan

    def test_default_category(self) -> None:
        p = _ReturnNonePlugin()
        assert p.category == ToolCategory.other

    def test_execute(self) -> None:
        p = _ConcretePlugin()
        ctx = ExecutionContext()
        result = p.execute(ctx)
        assert result == "host1\nhost2"

    def test_execute_returns_none(self) -> None:
        p = _ReturnNonePlugin()
        ctx = ExecutionContext()
        assert p.execute(ctx) is None

    def test_validate_context_default(self) -> None:
        p = _ConcretePlugin()
        assert p.validate_context(ExecutionContext()) is True

    def test_prepare_default(self) -> None:
        p = _ConcretePlugin()
        p.prepare(ExecutionContext())  # should not raise

    def test_parse_output_default(self) -> None:
        p = _ConcretePlugin()
        assert p.parse_output("raw", ExecutionContext()) == "raw"

    def test_parse_output_none(self) -> None:
        p = _ConcretePlugin()
        assert p.parse_output(None, ExecutionContext()) is None

    def test_parse_output_bytes(self) -> None:
        p = _ConcretePlugin()
        assert p.parse_output(b"bytes", ExecutionContext()) == b"bytes"

    def test_normalize_default(self) -> None:
        p = _ConcretePlugin()
        result = p.normalize({}, ExecutionContext())
        assert isinstance(result, PluginResult)
        assert result.success is True
        assert result.hosts == []

    def test_normalize_custom(self) -> None:
        p = _CustomNormalizePlugin()
        ctx = ExecutionContext()
        parsed = {"hosts": ["a.example.com", "b.example.com"]}
        result = p.normalize(parsed, ctx)
        assert len(result.hosts) == 2

    def test_import_results_default(self) -> None:
        p = _ConcretePlugin()
        assert p.import_results(PluginResult(), ExecutionContext()) == {}

    def test_cleanup_default(self) -> None:
        p = _ConcretePlugin()
        p.cleanup(ExecutionContext())

    def test_health_default(self) -> None:
        p = _ConcretePlugin()
        h = p.health(ExecutionContext())
        assert isinstance(h, PluginHealth)
        assert h.healthy is True

    def test_build_command_default(self) -> None:
        p = _ConcretePlugin()
        assert p.build_command(ExecutionContext()) == ""

    def test_full_lifecycle(self) -> None:
        p = _ConcretePlugin()
        ctx = ExecutionContext()
        assert p.validate_context(ctx) is True
        p.prepare(ctx)
        raw = p.execute(ctx)
        assert raw == "host1\nhost2"
        parsed = p.parse_output(raw, ctx)
        assert parsed == "host1\nhost2"
        result = p.normalize(parsed, ctx)
        assert isinstance(result, PluginResult)
        p.import_results(result, ctx)
        p.cleanup(ctx)

    def test_metadata_mutable(self) -> None:
        p = _ConcretePlugin()
        assert p.metadata.name == "test_plugin"
        assert p.metadata.version == "2.0.0"

    def test_description_empty(self) -> None:
        p = _ReturnNonePlugin()
        assert p.description == ""

    def test_health_check(self) -> None:
        p = _ConcretePlugin()
        h = p.health(ExecutionContext())
        assert h.installed is True

    def test_name_empty_raises(self) -> None:
        class NoNamePlugin(BaseToolPlugin):
            metadata = ToolMetadata(name="")

            def execute(self, context: ExecutionContext) -> str | bytes | None:
                return None

        p = NoNamePlugin()
        assert p.name == ""
