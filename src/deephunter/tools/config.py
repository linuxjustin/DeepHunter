"""Configuration for the Tool Integration SDK & Plugin Framework."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ToolPluginConfig(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    enabled: bool = Field(default=True, description="Enable tool plugins")
    enabled_plugins: list[str] = Field(default_factory=list, description="Explicitly enabled plugin names (empty = all)")
    disabled_plugins: list[str] = Field(default_factory=list, description="Disabled plugin names")
    plugin_dirs: list[str] = Field(default_factory=lambda: ["~/.deephunter/plugins"], description="Directories to scan for plugins")
    entry_point_group: str = Field(default="deephunter.tool_plugins", description="Entry point group for plugin discovery")
    enable_discovery: bool = Field(default=True, description="Enable plugin auto-discovery")
    enable_event_bus: bool = Field(default=True, description="Enable tool event bus")
    enable_metrics: bool = Field(default=True, description="Enable execution metrics")
    default_timeout: float = Field(default=120.0, ge=1.0, description="Default tool execution timeout in seconds")
    default_retries: int = Field(default=2, ge=0, le=10, description="Default retry count")
    retry_delay_seconds: float = Field(default=2.0, ge=0.0, description="Delay between retries")
    max_concurrent: int = Field(default=4, ge=1, le=64, description="Max concurrent tool executions")
    temp_dir: str = Field(default="", description="Working directory for tool execution (empty = system temp)")
    output_dir: str = Field(default="./tool_output", description="Directory for captured tool outputs")
    pip_install: bool = Field(default=False, description="Allow pip install of plugin extras")
    npm_install: bool = Field(default=False, description="Allow npm install of plugin extras")
    auto_install: bool = Field(default=False, description="Attempt auto-install of missing tools")
    plugin_timeouts: dict[str, float] = Field(default_factory=dict, description="Per-plugin timeout overrides")
    plugin_retries: dict[str, int] = Field(default_factory=dict, description="Per-plugin retry overrides")
    env_overrides: dict[str, str] = Field(default_factory=dict, description="Environment variable overrides")
    security: dict[str, Any] = Field(default_factory=lambda: {
        "allow_subprocess": True,
        "allow_network": True,
        "allowed_commands": [],
        "blocked_commands": [],
        "sandbox": False,
    }, description="Security constraints for tool execution")
