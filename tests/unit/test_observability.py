"""Tests for observability module."""

from __future__ import annotations

import time

from deephunter.observability import (
    AuditEvent,
    AuditLogger,
    HealthCheck,
    HealthReport,
    MetricsCollector,
    MetricsSnapshot,
    ObservabilityManager,
    get_observability,
    log_operation,
    trace,
)


class TestMetricsCollector:
    def test_increment(self) -> None:
        mc = MetricsCollector()
        mc.increment("test.count")
        mc.increment("test.count", 5)
        snap = mc.snapshot()
        assert snap.counters.get("test.count", 0) == 6

    def test_gauge(self) -> None:
        mc = MetricsCollector()
        mc.gauge("test.value", 42.0)
        snap = mc.snapshot()
        assert snap.gauges.get("test.value") == 42.0

    def test_histogram(self) -> None:
        mc = MetricsCollector()
        mc.histogram("test.latency", 100.0)
        mc.histogram("test.latency", 200.0)
        snap = mc.snapshot()
        assert len(snap.histograms.get("test.latency", [])) == 2


class TestAuditLogger:
    def test_log_event(self) -> None:
        al = AuditLogger()
        event = al.log(event_type="user.login", actor_id="user-1", action="login")
        assert event.id.startswith("audit-")
        assert event.action == "login"

    def test_get_events(self) -> None:
        al = AuditLogger()
        al.log(event_type="test", actor_id="u1", action="a1")
        al.log(event_type="test", actor_id="u2", action="a2")
        events = al.get_events()
        assert len(events) == 2


class TestObservabilityManager:
    def test_span(self) -> None:
        obs = ObservabilityManager()
        with obs.span("test-operation") as ctx:
            assert "trace_id" in ctx
            assert "span_id" in ctx

    def test_health_checks(self) -> None:
        obs = ObservabilityManager()
        obs.register_health_check("test", lambda: HealthCheck(name="test", status="healthy"))
        report = obs.run_health_checks()
        assert report.status == "healthy"
        assert len(report.checks) == 1


class TestDecorators:
    def test_log_operation_decorator(self) -> None:
        @log_operation("test-op")
        def sample_function() -> str:
            return "result"

        result = sample_function()
        assert result == "result"
        obs = get_observability()
        assert obs.metrics._counters.get("operation.test-op.count", 0) >= 1

    def test_trace_decorator(self) -> None:
        @trace("sample-operation")
        def compute() -> int:
            return 42

        result = compute()
        assert result == 42