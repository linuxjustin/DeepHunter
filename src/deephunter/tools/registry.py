"""Plugin registry with auto-discovery for the Tool Integration SDK."""

from __future__ import annotations

import importlib
import importlib.metadata
import inspect
import os
import pkgutil
import sys
from pathlib import Path
from typing import Any

from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.config import ToolPluginConfig
from deephunter.tools.events import (
    ToolEventBus,
    ToolPluginDiscoveredEvent,
    ToolPluginRegisteredEvent,
)
from deephunter.tools.exceptions import PluginDiscoveryError, PluginRegistrationError


class ToolPluginRegistry:
    """Registry with auto-discovery."""

    def __init__(self, event_bus: ToolEventBus | None = None) -> None:
        self._plugins: dict[str, BaseToolPlugin] = {}
        self._event_bus = event_bus

    @property
    def event_bus(self) -> ToolEventBus | None:
        return self._event_bus

    def register(self, plugin: BaseToolPlugin, *, name: str | None = None) -> None:
        key = name or plugin.name
        if not key:
            raise PluginRegistrationError("Plugin must have a name")
        if key in self._plugins:
            raise PluginRegistrationError(f"Plugin '{key}' is already registered")
        self._plugins[key] = plugin
        if self._event_bus:
            self._event_bus.emit(ToolPluginRegisteredEvent(
                plugin_name=key,
                plugin_class=type(plugin).__name__,
                version=plugin.version,
            ))

    def unregister(self, name: str) -> None:
        self._plugins.pop(name, None)

    def get(self, name: str) -> BaseToolPlugin | None:
        return self._plugins.get(name)

    def list_names(self) -> list[str]:
        return list(self._plugins.keys())

    def list_plugins(self) -> list[BaseToolPlugin]:
        return list(self._plugins.values())

    def clear(self) -> None:
        self._plugins.clear()

    def __contains__(self, name: str) -> bool:
        return name in self._plugins

    def __len__(self) -> int:
        return len(self._plugins)

    def __iter__(self):
        return iter(self._plugins.values())

    def discover(self, config: ToolPluginConfig | None = None) -> int:
        cfg = config or ToolPluginConfig()
        count = 0
        count += self._discover_entry_points(cfg)
        count += self._discover_plugins_dir(cfg)
        count += self._discover_builtin_plugins()
        if self._event_bus:
            self._event_bus.emit(ToolPluginDiscoveredEvent(
                plugin_name="_discovery_",
                description=f"Discovered {count} plugins",
            ))
        return count

    def _discover_entry_points(self, config: ToolPluginConfig) -> int:
        count = 0
        group = config.entry_point_group
        try:
            eps = importlib.metadata.entry_points(group=group)
        except (TypeError, importlib.metadata.PackageNotFoundError):
            eps = []
        for ep in eps:
            try:
                cls = ep.load()
                if inspect.isclass(cls) and issubclass(cls, BaseToolPlugin) and not inspect.isabstract(cls):
                    inst = cls()
                    self.register(inst, name=ep.name)
                    count += 1
            except Exception:
                continue
        return count

    def _discover_plugins_dir(self, config: ToolPluginConfig) -> int:
        count = 0
        for d in config.plugin_dirs:
            resolved = Path(d).expanduser().resolve()
            if not resolved.is_dir():
                continue
            sys.path.insert(0, str(resolved))
            for mod_info in pkgutil.iter_modules([str(resolved)]):
                try:
                    mod = importlib.import_module(mod_info.name)
                    for _name, obj in inspect.getmembers(mod):
                        if (inspect.isclass(obj) and issubclass(obj, BaseToolPlugin)
                                and obj is not BaseToolPlugin and not inspect.isabstract(obj)):
                            inst = obj()
                            self.register(inst)
                            count += 1
                except Exception:
                    continue
        return count

    def _discover_builtin_plugins(self) -> int:
        count = 0
        import deephunter.tools.plugins as tpkg
        for mod_info in pkgutil.iter_modules(tpkg.__path__, tpkg.__name__ + "."):
            try:
                mod = importlib.import_module(mod_info.name)
                for _name, obj in inspect.getmembers(mod):
                    if (inspect.isclass(obj) and issubclass(obj, BaseToolPlugin)
                            and obj is not BaseToolPlugin and not inspect.isabstract(obj)):
                        inst = obj()
                        self.register(inst)
                        count += 1
            except Exception:
                continue
        return count
