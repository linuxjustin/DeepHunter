"""Reporter — builds execution reports and summaries for the Tool SDK."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from deephunter.recon.plugin import PluginResult
from deephunter.tools.models import ExecutionReport, ToolStatus


def build_report(
    *,
    tool_name: str = "",
    plugin_name: str = "",
    status: ToolStatus = ToolStatus.pending,
    command: str = "",
    stdout: str = "",
    stderr: str = "",
    exit_code: int | None = None,
    error: str = "",
    result: PluginResult | None = None,
    duration_ms: float = 0.0,
    retry_attempt: int = 0,
    metadata: dict[str, Any] | None = None,
) -> ExecutionReport:
    report = ExecutionReport(
        tool_name=tool_name,
        plugin_name=plugin_name,
        status=status,
        command=command,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        error=error,
        duration_ms=duration_ms,
        retry_attempt=retry_attempt,
        metadata=metadata or {},
    )
    finished = datetime.now(timezone.utc)
    report.finished_at = finished
    if result:
        report.result_status = "imported" if result.success else "failed"
        report.parsed_count = sum(len(getattr(result, f, [])) for f in [
            "assets", "hosts", "technologies", "endpoints",
            "parameters", "dns_records", "http_observations",
            "js_files", "js_endpoints", "api_endpoints",
            "cloud_resources", "applications", "auth_mechanisms",
        ])
    return report


def report_summary(reports: list[ExecutionReport]) -> dict[str, Any]:
    total = len(reports)
    by_status: dict[str, int] = {}
    total_ms = 0.0
    for r in reports:
        by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
        total_ms += r.duration_ms
    return {
        "total": total,
        "by_status": by_status,
        "total_duration_ms": round(total_ms, 1),
        "avg_duration_ms": round(total_ms / max(total, 1), 1),
        "succeeded": by_status.get("success", 0),
        "failed": by_status.get("failed", 0),
        "timed_out": by_status.get("timeout", 0),
        "skipped": by_status.get("skipped", 0),
    }
