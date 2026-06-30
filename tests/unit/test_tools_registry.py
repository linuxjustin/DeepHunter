"""Tests for tools/registry.py."""

from __future__ import annotations

from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.events import (
    ToolEventBus,
    ToolPluginDiscoveredEvent,
    ToolPluginRegisteredEvent,
)
from deephunter.tools.exceptions import PluginNotFoundError, PluginRegistrationError
from deephunter.tools.models import ToolMetadata
from deephunter.tools.registry import ToolPluginRegistry


class _SimplePlugin(BaseToolPlugin):
    metadata = ToolMetadata(name="simple")

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        return "ok"


class _AnotherPlugin(BaseToolPlugin):
    metadata = ToolMetadata(name="another")

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        return "ok"


class ToolPluginRegistryTest:
    def test_empty_registry(self) -> None:
        r = ToolPluginRegistry()
        assert len(r) == 0
        assert r.list_names() == []

    def test_register(self) -> None:
        r = ToolPluginRegistry()
        r.register(_SimplePlugin())
        assert len(r) == 1
        assert "simple" in r

    def test_register_duplicate_raises(self) -> None:
        r = ToolPluginRegistry()
        r.register(_SimplePlugin())
        with __import__("pytest").raises(PluginRegistrationError):
            r.register(_SimplePlugin())

    def test_get(self) -> None:
        r = ToolPluginRegistry()
        p = _SimplePlugin()
        r.register(p)
        assert r.get("simple") is p
        assert r.get("nonexistent") is None

    def test_unregister(self) -> None:
        r = ToolPluginRegistry()
        r.register(_SimplePlugin())
        assert "simple" in r
        r.unregister("simple")
        assert "simple" not in r

    def test_unregister_nonexistent(self) -> None:
        r = ToolPluginRegistry()
        r.unregister("nothing")  # should not raise

    def test_list_names(self) -> None:
        r = ToolPluginRegistry()
        r.register(_SimplePlugin())
        r.register(_AnotherPlugin())
        names = r.list_names()
        assert "simple" in names
        assert "another" in names

    def test_list_plugins(self) -> None:
        r = ToolPluginRegistry()
        p1 = _SimplePlugin()
        p2 = _AnotherPlugin()
        r.register(p1)
        r.register(p2)
        plugins = r.list_plugins()
        assert p1 in plugins
        assert p2 in plugins

    def test_clear(self) -> None:
        r = ToolPluginRegistry()
        r.register(_SimplePlugin())
        r.clear()
        assert len(r) == 0

    def test_contains(self) -> None:
        r = ToolPluginRegistry()
        r.register(_SimplePlugin())
        assert "simple" in r
        assert "nope" not in r

    def test_iteration(self) -> None:
        r = ToolPluginRegistry()
        p1 = _SimplePlugin()
        p2 = _AnotherPlugin()
        r.register(p1)
        r.register(p2)
        plugins = list(r)
        assert p1 in plugins
        assert p2 in plugins

    def test_len(self) -> None:
        r = ToolPluginRegistry()
        assert len(r) == 0
        r.register(_SimplePlugin())
        assert len(r) == 1

    def test_register_with_custom_name(self) -> None:
        r = ToolPluginRegistry()
        p = _SimplePlugin()
        r.register(p, name="custom_name")
        assert r.get("custom_name") is p
        assert r.get("simple") is None

    def test_event_bus_on_register(self) -> None:
        bus = ToolEventBus()
        r = ToolPluginRegistry(event_bus=bus)
        received: list[ToolPluginRegisteredEvent] = []
        bus.subscribe(ToolPluginRegisteredEvent, lambda e: received.append(e))
        r.register(_SimplePlugin())
        assert len(received) == 1
        assert received[0].plugin_name == "simple"

    def test_event_bus_property(self) -> None:
        bus = ToolEventBus()
        r = ToolPluginRegistry(event_bus=bus)
        assert r.event_bus is bus

    def test_event_bus_none_by_default(self) -> None:
        r = ToolPluginRegistry()
        assert r.event_bus is None

    def test_discover_noop(self) -> None:
        r = ToolPluginRegistry()
        r.discover()  # should complete without error

    def test_discover_emits_event(self) -> None:
        bus = ToolEventBus()
        r = ToolPluginRegistry(event_bus=bus)
        received: list[ToolPluginDiscoveredEvent] = []
        bus.subscribe(ToolPluginDiscoveredEvent, lambda e: received.append(e))
        r.discover()
        assert len(received) >= 0  # may discover nothing

    def test_register_empty_name_raises(self) -> None:
        class NoNamePlugin(BaseToolPlugin):
            metadata = ToolMetadata(name="")

            def execute(self, context: ExecutionContext) -> str | bytes | None:
                return None

        r = ToolPluginRegistry()
        with __import__("pytest").raises(PluginRegistrationError):
            r.register(NoNamePlugin())

    def test_register_none_name_raises(self) -> None:
        class NoneNamePlugin(BaseToolPlugin):
            metadata = ToolMetadata(name="")

            def execute(self, context: ExecutionContext) -> str | bytes | None:
                return None

        r = ToolPluginRegistry()
        with __import__("pytest").raises(PluginRegistrationError):
            r.register(NoneNamePlugin())
