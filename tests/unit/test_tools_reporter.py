"""Tests for tools/reporter.py."""

from __future__ import annotations

from deephunter.recon.plugin import PluginResult
from deephunter.tools.models import ExecutionReport, ToolStatus
from deephunter.tools.reporter import build_report, report_summary


class TestBuildReport:
    def test_minimal(self) -> None:
        r = build_report(tool_name="t", plugin_name="p", status=ToolStatus.success)
        assert r.tool_name == "t"
        assert r.status == ToolStatus.success
        assert r.finished_at is not None

    def test_defaults(self) -> None:
        r = build_report()
        assert r.tool_name == ""
        assert r.plugin_name == ""
        assert r.status == ToolStatus.pending

    def test_with_result(self) -> None:
        result = PluginResult(success=True, hosts=["h1", "h2"])
        r = build_report(tool_name="t", plugin_name="p", status=ToolStatus.success, result=result)
        assert r.result_status == "imported"
        assert r.parsed_count >= 1

    def test_with_error_result(self) -> None:
        result = PluginResult(success=False)
        r = build_report(tool_name="t", plugin_name="p", status=ToolStatus.failed, result=result)
        assert r.result_status == "failed"

    def test_with_command(self) -> None:
        r = build_report(tool_name="t", plugin_name="p", status=ToolStatus.success, command="tool --flag")
        assert r.command == "tool --flag"

    def test_with_stdout_stderr(self) -> None:
        r = build_report(tool_name="t", plugin_name="p", status=ToolStatus.success, stdout="ok", stderr="")
        assert r.stdout == "ok"
        assert r.stderr == ""

    def test_with_duration(self) -> None:
        r = build_report(tool_name="t", plugin_name="p", status=ToolStatus.success, duration_ms=1234.5)
        assert r.duration_ms == 1234.5

    def test_with_exit_code(self) -> None:
        r = build_report(tool_name="t", plugin_name="p", status=ToolStatus.failed, exit_code=1)
        assert r.exit_code == 1

    def test_with_error(self) -> None:
        r = build_report(tool_name="t", plugin_name="p", status=ToolStatus.failed, error="something went wrong")
        assert r.error == "something went wrong"

    def test_with_retry(self) -> None:
        r = build_report(tool_name="t", plugin_name="p", status=ToolStatus.success, retry_attempt=2)
        assert r.retry_attempt == 2

    def test_with_metadata(self) -> None:
        r = build_report(tool_name="t", plugin_name="p", status=ToolStatus.success, metadata={"domain": "x.com"})
        assert r.metadata["domain"] == "x.com"
        assert r.metadata is not None

    def test_parsed_count_from_result(self) -> None:
        result = PluginResult(
            hosts=["h1", "h2"],
            endpoints=["e1"],
            technologies=["t1", "t2", "t3"],
        )
        r = build_report(tool_name="t", plugin_name="p", status=ToolStatus.success, result=result)
        assert r.parsed_count == 6

    def test_empty_result(self) -> None:
        result = PluginResult()
        r = build_report(tool_name="t", plugin_name="p", status=ToolStatus.success, result=result)
        assert r.parsed_count == 0


class TestReportSummary:
    def test_empty(self) -> None:
        assert report_summary([])["total"] == 0

    def test_single_success(self) -> None:
        reports = [
            ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.success, duration_ms=100.0),
        ]
        s = report_summary(reports)
        assert s["total"] == 1
        assert s["succeeded"] == 1
        assert s["failed"] == 0

    def test_multiple_statuses(self) -> None:
        reports = [
            ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.success, duration_ms=100.0),
            ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.failed, duration_ms=50.0),
            ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.timeout, duration_ms=200.0),
        ]
        s = report_summary(reports)
        assert s["total"] == 3
        assert s["succeeded"] == 1
        assert s["failed"] == 1
        assert s["timed_out"] == 1

    def test_duration_calculation(self) -> None:
        reports = [
            ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.success, duration_ms=100.0),
            ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.success, duration_ms=200.0),
        ]
        s = report_summary(reports)
        assert s["total_duration_ms"] == 300.0
        assert s["avg_duration_ms"] == 150.0

    def test_skipped(self) -> None:
        reports = [
            ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.skipped, duration_ms=0.0),
        ]
        s = report_summary(reports)
        assert s["skipped"] == 1

    def test_no_duration(self) -> None:
        reports = [
            ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.pending),
        ]
        s = report_summary(reports)
        assert s["total"] == 1
        assert s["total_duration_ms"] == 0.0
