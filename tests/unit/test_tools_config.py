"""Tests for tools/config.py and core config integration."""

from __future__ import annotations

from deephunter.core import DeepHunterConfig
from deephunter.core.config import ToolPluginConfig


class TestToolPluginConfig:
    def test_defaults(self) -> None:
        cfg = ToolPluginConfig()
        assert cfg.enabled is True
        assert cfg.enabled_plugins == []
        assert cfg.disabled_plugins == []
        assert cfg.entry_point_group == "deephunter.tool_plugins"
        assert cfg.enable_discovery is True
        assert cfg.enable_event_bus is True
        assert cfg.enable_metrics is True
        assert cfg.default_timeout == 120.0
        assert cfg.default_retries == 2
        assert cfg.retry_delay_seconds == 2.0
        assert cfg.max_concurrent == 4

    def test_plugin_dirs_default(self) -> None:
        cfg = ToolPluginConfig()
        assert "~/.deephunter/plugins" in cfg.plugin_dirs

    def test_security_defaults(self) -> None:
        cfg = ToolPluginConfig()
        assert cfg.security["allow_subprocess"] is True
        assert cfg.security["allow_network"] is True
        assert cfg.security["sandbox"] is False

    def test_enabled_plugins_filter(self) -> None:
        cfg = ToolPluginConfig(enabled_plugins=["subfinder", "nuclei"])
        assert "subfinder" in cfg.enabled_plugins
        assert "nuclei" in cfg.enabled_plugins

    def test_disabled_plugins(self) -> None:
        cfg = ToolPluginConfig(disabled_plugins=["slow_plugin"])
        assert "slow_plugin" in cfg.disabled_plugins

    def test_plugin_timeouts(self) -> None:
        cfg = ToolPluginConfig(plugin_timeouts={"subfinder": 300.0})
        assert cfg.plugin_timeouts["subfinder"] == 300.0

    def test_plugin_retries(self) -> None:
        cfg = ToolPluginConfig(plugin_retries={"nuclei": 1})
        assert cfg.plugin_retries["nuclei"] == 1

    def test_env_overrides(self) -> None:
        cfg = ToolPluginConfig(env_overrides={"PATH": "/custom/bin"})
        assert cfg.env_overrides["PATH"] == "/custom/bin"

    def test_install_flags(self) -> None:
        cfg = ToolPluginConfig(pip_install=True, npm_install=True, auto_install=True)
        assert cfg.pip_install is True
        assert cfg.npm_install is True
        assert cfg.auto_install is True

    def test_output_dir(self) -> None:
        cfg = ToolPluginConfig(output_dir="./custom_output")
        assert cfg.output_dir == "./custom_output"

    def test_serialization(self) -> None:
        cfg = ToolPluginConfig(enabled=False, default_timeout=60.0)
        d = cfg.model_dump()
        assert d["enabled"] is False
        assert d["default_timeout"] == 60.0

    def test_in_deephunter_config(self) -> None:
        dhc = DeepHunterConfig()
        assert hasattr(dhc, "tool_plugins")
        assert isinstance(dhc.tool_plugins, ToolPluginConfig)

    def test_env_prefix(self) -> None:
        import os
        os.environ["DEEPHUNTER_TOOL_PLUGINS__ENABLED"] = "false"
        os.environ["DEEPHUNTER_TOOL_PLUGINS__DEFAULT_TIMEOUT"] = "300"
        cfg = DeepHunterConfig()
        assert cfg.tool_plugins.enabled is False
        assert cfg.tool_plugins.default_timeout == 300.0
        del os.environ["DEEPHUNTER_TOOL_PLUGINS__ENABLED"]
        del os.environ["DEEPHUNTER_TOOL_PLUGINS__DEFAULT_TIMEOUT"]

    def test_per_plugin_settings(self) -> None:
        cfg = ToolPluginConfig(
            plugin_timeouts={"slow": 600.0},
            plugin_retries={"fast": 0},
        )
        assert cfg.plugin_timeouts == {"slow": 600.0}
        assert cfg.plugin_retries == {"fast": 0}

    def test_disabled_plugin_set(self) -> None:
        cfg = ToolPluginConfig(disabled_plugins=["a", "b"])
        assert len(cfg.disabled_plugins) == 2
