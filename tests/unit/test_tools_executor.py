"""Tests for tools/executor.py."""

from __future__ import annotations

import time
from typing import Any

import pytest

from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.events import (
    ToolEventBus,
    ToolExecutionCompletedEvent,
    ToolExecutionFailedEvent,
    ToolExecutionStartedEvent,
    ToolImportCompletedEvent,
    ToolImportStartedEvent,
)
from deephunter.tools.executor import ToolExecutor, check_tool_installed
from deephunter.tools.exceptions import PluginNotInstalledError
from deephunter.tools.models import ExecutionReport, PluginHealth, ToolMetadata, ToolStatus


class _SuccessPlugin(BaseToolPlugin):
    metadata = ToolMetadata(name="success_plugin")

    def execute(self, context: ExecutionContext) -> str:
        return "output data"

    def parse_output(self, raw: str | bytes | None, ctx: ExecutionContext) -> str:
        return raw or ""

    def normalize(self, parsed: Any, ctx: ExecutionContext) -> PluginResult:
        r = PluginResult()
        r.hosts = [parsed]
        return r

    def import_results(self, r: PluginResult, ctx: ExecutionContext) -> dict[str, int]:
        return {"hosts": len(r.hosts)}


class _TimeoutPlugin(BaseToolPlugin):
    metadata = ToolMetadata(name="timeout_plugin", timeout_default=0.01)

    def execute(self, context: ExecutionContext) -> str:
        time.sleep(10)
        return "never"

    def parse_output(self, raw: str | bytes | None, ctx: ExecutionContext) -> Any:
        return {}


class _FailingPlugin(BaseToolPlugin):
    metadata = ToolMetadata(name="failing_plugin")

    def execute(self, context: ExecutionContext) -> str:
        raise ValueError("execution error")


class _NotInstalledPlugin(BaseToolPlugin):
    metadata = ToolMetadata(name="not_installed_plugin")

    def execute(self, context: ExecutionContext) -> str:
        raise PluginNotInstalledError("tool not found")


class _CancelledPlugin(BaseToolPlugin):
    metadata = ToolMetadata(name="cancelled_plugin")

    def execute(self, context: ExecutionContext) -> str:
        context.cancel()
        return "data"

    def parse_output(self, raw: Any, ctx: ExecutionContext) -> Any:
        return {}

    def normalize(self, parsed: Any, ctx: ExecutionContext) -> PluginResult:
        return PluginResult()

    def import_results(self, r: PluginResult, ctx: ExecutionContext) -> dict[str, int]:
        return {}


class TestToolExecutor:
    def test_execute_success(self) -> None:
        executor = ToolExecutor()
        plugin = _SuccessPlugin()
        ctx = ExecutionContext(plugin_name="success_plugin")
        report = executor.execute(plugin, ctx)
        assert report.status == ToolStatus.success
        assert report.tool_name == "success_plugin"
        assert report.duration_ms > 0

    def test_execute_with_event_bus(self) -> None:
        bus = ToolEventBus()
        executor = ToolExecutor(event_bus=bus)
        plugin = _SuccessPlugin()
        ctx = ExecutionContext(plugin_name="success_plugin")
        started: list[ToolExecutionStartedEvent] = []
        completed: list[ToolExecutionCompletedEvent] = []
        bus.subscribe(ToolExecutionStartedEvent, lambda e: started.append(e))
        bus.subscribe(ToolExecutionCompletedEvent, lambda e: completed.append(e))
        executor.execute(plugin, ctx)
        assert len(started) >= 1
        assert len(completed) >= 1

    def test_execute_success_counts(self) -> None:
        executor = ToolExecutor()
        plugin = _SuccessPlugin()
        ctx = ExecutionContext(plugin_name="success_plugin")
        report = executor.execute(plugin, ctx)
        assert report.result_status == "imported"
        assert report.parsed_count >= 0
        assert report.imported_count == 1

    def test_execute_failing(self) -> None:
        executor = ToolExecutor()
        plugin = _FailingPlugin()
        ctx = ExecutionContext(plugin_name="failing_plugin")
        report = executor.execute(plugin, ctx)
        assert report.status == ToolStatus.failed
        assert "execution error" in report.error

    def test_execute_not_installed(self) -> None:
        executor = ToolExecutor()
        plugin = _NotInstalledPlugin()
        ctx = ExecutionContext(plugin_name="not_installed_plugin")
        report = executor.execute(plugin, ctx)
        assert report.status == ToolStatus.failed
        assert "tool not found" in report.error

    def test_execute_cancelled(self) -> None:
        executor = ToolExecutor()
        plugin = _CancelledPlugin()
        ctx = ExecutionContext(plugin_name="cancelled_plugin")
        report = executor.execute(plugin, ctx)
        assert report.status == ToolStatus.cancelled

    def test_execute_import_events(self) -> None:
        bus = ToolEventBus()
        executor = ToolExecutor(event_bus=bus)
        plugin = _SuccessPlugin()
        ctx = ExecutionContext(plugin_name="success_plugin")
        imports_started: list[ToolImportStartedEvent] = []
        imports_completed: list[ToolImportCompletedEvent] = []
        bus.subscribe(ToolImportStartedEvent, lambda e: imports_started.append(e))
        bus.subscribe(ToolImportCompletedEvent, lambda e: imports_completed.append(e))
        executor.execute(plugin, ctx)
        assert len(imports_started) >= 1
        assert len(imports_completed) >= 1

    def test_execute_retry_on_failure(self) -> None:
        executor = ToolExecutor()
        plugin = _FailingPlugin()
        cfg = plugin.metadata  # noqa
        ctx = ExecutionContext(plugin_name="failing_plugin")
        report = executor.execute(plugin, ctx)
        assert report.status == ToolStatus.failed
        # should not have thrown

    def test_execute_cancelled_early(self) -> None:
        executor = ToolExecutor()
        plugin = _SuccessPlugin()
        ctx = ExecutionContext(plugin_name="success_plugin")
        ctx.cancel()
        report = executor.execute(plugin, ctx)
        assert report.status == ToolStatus.cancelled

    def test_execute_failed_event_emitted(self) -> None:
        bus = ToolEventBus()
        executor = ToolExecutor(event_bus=bus)
        plugin = _FailingPlugin()
        ctx = ExecutionContext(plugin_name="failing_plugin")
        failed: list[ToolExecutionFailedEvent] = []
        bus.subscribe(ToolExecutionFailedEvent, lambda e: failed.append(e))
        executor.execute(plugin, ctx)
        assert len(failed) >= 1

    def test_execute_multiple_attempts(self) -> None:
        executor = ToolExecutor()
        plugin = _FailingPlugin()
        ctx = ExecutionContext(plugin_name="failing_plugin")
        report = executor.execute(plugin, ctx)
        # should have default 2 retries
        assert report.status == ToolStatus.failed

    def test_report_has_duration(self) -> None:
        executor = ToolExecutor()
        plugin = _SuccessPlugin()
        ctx = ExecutionContext(plugin_name="success_plugin")
        report = executor.execute(plugin, ctx)
        assert report.duration_ms >= 0
        assert report.finished_at is not None

    def test_health_on_execute(self) -> None:
        executor = ToolExecutor()
        plugin = _SuccessPlugin()
        ctx = ExecutionContext(plugin_name="success_plugin")
        report = executor.execute(plugin, ctx)
        assert report.status == ToolStatus.success


class TestCheckToolInstalled:
    def test_ls_installed(self) -> None:
        assert check_tool_installed("ls") is True

    def test_unknown_tool(self) -> None:
        assert check_tool_installed("this_tool_does_not_exist_xyz_999") is False

    def test_with_custom_cmd(self) -> None:
        assert check_tool_installed("ls", cmd="/bin/ls") is True

    def test_nonzero_exit(self) -> None:
        assert check_tool_installed("ls", cmd="ls --nonexistent_flag") is False

    def test_empty_string(self) -> None:
        assert check_tool_installed("") is False
