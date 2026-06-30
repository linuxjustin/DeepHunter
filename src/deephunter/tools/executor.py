"""Tool Executor — manages the full execution lifecycle of a tool plugin.

Handles subprocess invocation, timeouts, retries, output capture,
and lifecycle event emission.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
from typing import Any

from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.events import (
    ToolEventBus,
    ToolExecutionCompletedEvent,
    ToolExecutionFailedEvent,
    ToolExecutionStartedEvent,
    ToolImportCompletedEvent,
    ToolImportFailedEvent,
    ToolImportStartedEvent,
)
from deephunter.tools.exceptions import (
    PluginExecutionError,
    PluginNotInstalledError,
    PluginTimeoutError,
)
from deephunter.tools.models import ExecutionReport, ToolStatus


def check_tool_installed(tool_name: str, cmd: str = "") -> bool:
    """Check if a command-line tool is available on PATH."""
    check = cmd or tool_name
    return shutil.which(check) is not None


class ToolExecutor:
    """Executes tool plugins through their full lifecycle."""

    def __init__(self, event_bus: ToolEventBus | None = None) -> None:
        self._event_bus = event_bus

    @property
    def event_bus(self) -> ToolEventBus | None:
        return self._event_bus

    def execute(
        self,
        plugin: BaseToolPlugin,
        context: ExecutionContext,
    ) -> ExecutionReport:
        report = ExecutionReport(
            tool_name=plugin.name,
            plugin_name=plugin.name,
            status=ToolStatus.pending,
        )
        max_retries = context.get_plugin_retries()
        timeout = context.get_plugin_timeout()
        started = time.monotonic()

        for attempt in range(max_retries + 1):
            report.retry_attempt = attempt
            report.status = ToolStatus.running
            self._emit(ToolExecutionStartedEvent(
                plugin_name=plugin.name,
                report=report,
                args=context.args,
            ))

            try:
                if context.cancelled:
                    report.status = ToolStatus.cancelled
                    break

                raw_output = plugin.execute(context)

                parsed = plugin.parse_output(raw_output, context)
                result = plugin.normalize(parsed, context)

                if context.cancelled:
                    report.status = ToolStatus.cancelled
                    break

                self._emit(ToolImportStartedEvent(
                    plugin_name=plugin.name,
                    parsed_count=len(result.assets) + len(result.hosts),
                ))

                import_counts = plugin.import_results(result, context)

                self._emit(ToolImportCompletedEvent(
                    plugin_name=plugin.name,
                    imported_count=sum(import_counts.values()),
                    report=report,
                ))

                report.status = ToolStatus.success
                report.result_status = "imported"
                report.parsed_count = sum(len(getattr(result, f, [])) for f in [
                    "assets", "hosts", "technologies", "endpoints",
                    "parameters", "dns_records", "http_observations",
                    "js_files", "js_endpoints", "api_endpoints",
                    "cloud_resources", "applications", "auth_mechanisms",
                ])
                report.imported_count = sum(import_counts.values())

                elapsed = time.monotonic() - started
                report.duration_ms = round(elapsed * 1000, 1)
                report.finished_at = report.started_at

                self._emit(ToolExecutionCompletedEvent(
                    plugin_name=plugin.name,
                    report=report,
                    duration_ms=report.duration_ms,
                ))
                return report

            except (PluginTimeoutError, subprocess.TimeoutExpired) as exc:
                report.error = str(exc)
                report.status = ToolStatus.timeout
                self._emit(ToolExecutionFailedEvent(
                    plugin_name=plugin.name,
                    report=report,
                    error=str(exc),
                    retry_attempt=attempt,
                ))

            except PluginNotInstalledError as exc:
                report.error = str(exc)
                report.status = ToolStatus.failed
                self._emit(ToolExecutionFailedEvent(
                    plugin_name=plugin.name,
                    report=report,
                    error=str(exc),
                    retry_attempt=attempt,
                ))
                break

            except Exception as exc:
                report.error = str(exc)
                report.status = ToolStatus.failed
                self._emit(ToolExecutionFailedEvent(
                    plugin_name=plugin.name,
                    report=report,
                    error=str(exc),
                    retry_attempt=attempt,
                ))

        elapsed = time.monotonic() - started
        report.duration_ms = round(elapsed * 1000, 1)
        report.finished_at = report.started_at
        return report

    def _emit(self, event: Any) -> None:
        if self._event_bus:
            try:
                self._event_bus.emit(event)
            except Exception:
                pass

    def run_subprocess(
        self,
        cmd: str | list[str],
        context: ExecutionContext,
        *,
        timeout: float | None = None,
        capture_output: bool = True,
    ) -> tuple[str, str, int | None]:
        if isinstance(cmd, str):
            cmd_list = shlex.split(cmd)
        else:
            cmd_list = list(cmd)

        effective_timeout = timeout or context.get_plugin_timeout()
        env = context.env.copy()
        env.update(context.config.env_overrides)

        try:
            proc = subprocess.run(
                cmd_list,
                capture_output=capture_output,
                text=True,
                timeout=effective_timeout,
                env=env,
                cwd=context.working_dir,
            )
            return proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired:
            raise PluginTimeoutError(
                f"Command timed out after {effective_timeout}s: {' '.join(cmd_list)}"
            )
