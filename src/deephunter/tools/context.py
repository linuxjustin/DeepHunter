"""Execution context for the Tool Integration SDK & Plugin Framework.

Encapsulates all runtime state needed to invoke a tool plugin:
scope, target, configuration, environment, working directory, and
cancellation support.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Any

from deephunter.tools.config import ToolPluginConfig


@dataclass
class ExecutionContext:
    target: str = ""
    plugin_name: str = ""
    config: ToolPluginConfig = field(default_factory=ToolPluginConfig)
    scope: dict[str, Any] = field(default_factory=dict)
    args: dict[str, Any] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=lambda: dict(os.environ))
    working_dir: str = field(default_factory=lambda: tempfile.mkdtemp(prefix="dh_tool_"))
    cancel_event: Event = field(default_factory=Event)
    metadata: dict[str, Any] = field(default_factory=dict)
    session_id: str = ""

    def cancel(self) -> None:
        self.cancel_event.set()

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def make_output_path(self, name: str) -> str:
        return os.path.join(self.working_dir, name)

    def get_plugin_timeout(self, default: float = 120.0) -> float:
        return self.config.plugin_timeouts.get(self.plugin_name, default)

    def get_plugin_retries(self, default: int = 2) -> int:
        return self.config.plugin_retries.get(self.plugin_name, default)
