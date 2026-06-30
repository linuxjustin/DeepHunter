"""Observability module for DeepHunter.

Provides structured logging, metrics collection, health checks,
and tracing hooks for production deployments.
"""

from __future__ import annotations

import logging
import sys
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import wraps
from typing import Any, Callable
from uuid import uuid4

from pydantic import BaseModel, Field


TRACE_ID_CTX_KEY = "trace_id"
_SPAN_ID_COUNTER = 0


class LogLevel(str):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class StructuredLogRecord(BaseModel):
    """A structured log record with consistent fields."""

    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    level: str = ""
    logger: str = ""
    message: str = ""
    trace_id: str = ""
    span_id: str = ""
    user_id: str = ""
    workspace_id: str = ""
    target_id: str = ""
    duration_ms: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class MetricsSnapshot(BaseModel):
    """A point-in-time snapshot of application metrics."""

    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    counters: dict[str, int] = Field(default_factory=dict)
    gauges: dict[str, float] = Field(default_factory=dict)
    histograms: dict[str, list[float]] = Field(default_factory=dict)


class HealthCheck(BaseModel):
    """A single health check result."""

    name: str
    status: str = "healthy"
    latency_ms: float = 0.0
    message: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class HealthReport(BaseModel):
    """Complete health report with all checks."""

    status: str = "healthy"
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    checks: list[HealthCheck] = Field(default_factory=list)
    version: str = "1.0.0"


class AuditEvent(BaseModel):
    """An audit trail event for security and compliance."""

    id: str = Field(default_factory=lambda: f"audit-{uuid4().hex[:12]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    event_type: str
    actor_id: str
    actor_email: str = ""
    workspace_id: str = ""
    target_id: str = ""
    action: str
    resource_type: str = ""
    resource_id: str = ""
    outcome: str = "success"
    ip_address: str = ""
    user_agent: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditLogger:
    """Structured audit logger for security events."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def log(self, event_type: str, actor_id: str, action: str, **kwargs: Any) -> AuditEvent:
        event = AuditEvent(event_type=event_type, actor_id=actor_id, action=action, **kwargs)
        self._events.append(event)
        logging.getLogger("deephunter.audit").info(event.model_dump_json())
        return event

    def get_events(self, workspace_id: str | None = None, limit: int = 100) -> list[AuditEvent]:
        if workspace_id:
            return [e for e in self._events if e.workspace_id == workspace_id][-limit:]
        return self._events[-limit:]

    def clear(self) -> None:
        self._events.clear()


class MetricsCollector:
    """Collects application metrics for monitoring."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = {}

    def increment(self, name: str, value: int = 1, tags: dict[str, str] | None = None) -> None:
        key = self._make_key(name, tags)
        self._counters[key] = self._counters.get(key, 0) + value

    def gauge(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        key = self._make_key(name, tags)
        self._gauges[key] = value

    def histogram(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        key = self._make_key(name, tags)
        if key not in self._histograms:
            self._histograms[key] = []
        self._histograms[key].append(value)
        if len(self._histograms[key]) > 1000:
            self._histograms[key] = self._histograms[key][-1000:]

    def snapshot(self) -> MetricsSnapshot:
        return MetricsSnapshot(
            counters=dict(self._counters),
            gauges=dict(self._gauges),
            histograms=dict(self._histograms),
        )

    @staticmethod
    def _make_key(name: str, tags: dict[str, str] | None = None) -> str:
        if not tags:
            return name
        tag_str = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
        return f"{name}[{tag_str}]"


class ObservabilityManager:
    """Centralized observability for DeepHunter."""

    def __init__(self) -> None:
        self.audit = AuditLogger()
        self.metrics = MetricsCollector()
        self._health_checks: dict[str, Callable[[], HealthCheck]] = {}
        self._setup_logging()

    def _setup_logging(self) -> None:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        logging.getLogger("deephunter").addHandler(handler)
        logging.getLogger("deephunter.audit").setLevel(logging.INFO)

    def register_health_check(self, name: str, check_fn: Callable[[], HealthCheck]) -> None:
        self._health_checks[name] = check_fn

    def run_health_checks(self) -> HealthReport:
        checks = []
        overall_status = "healthy"
        for name, check_fn in self._health_checks.items():
            try:
                start = time.perf_counter()
                check = check_fn()
                check.latency_ms = (time.perf_counter() - start) * 1000
                if check.status == "unhealthy":
                    overall_status = "unhealthy"
                checks.append(check)
            except Exception as exc:
                checks.append(HealthCheck(name=name, status="unhealthy", message=str(exc)))
                overall_status = "unhealthy"
        return HealthReport(status=overall_status, checks=checks)

    @contextmanager
    def span(self, name: str, trace_id: str | None = None):
        global _SPAN_ID_COUNTER
        trace_id = trace_id or uuid4().hex[:16]
        _SPAN_ID_COUNTER += 1
        span_id = f"span-{_SPAN_ID_COUNTER:04d}"
        start = time.perf_counter()
        try:
            yield {"trace_id": trace_id, "span_id": span_id}
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            self.metrics.histogram(f"span.duration.{name}", duration_ms)


_global_observability: ObservabilityManager | None = None


def get_observability() -> ObservabilityManager:
    global _global_observability
    if _global_observability is None:
        _global_observability = ObservabilityManager()
    return _global_observability


def log_operation(operation: str) -> Callable:
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            obs = get_observability()
            obs.metrics.increment(f"operation.{operation}.count")
            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                obs.metrics.histogram(f"operation.{operation}.duration", (time.perf_counter() - start) * 1000)
                return result
            except Exception as exc:
                obs.metrics.increment(f"operation.{operation}.error")
                raise
        return wrapper
    return decorator


def trace(trace_name: str | None = None) -> Callable:
    def decorator(func: Callable) -> Callable:
        name = trace_name or func.__name__
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            obs = get_observability()
            with obs.span(name) as span_ctx:
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as exc:
                    obs.metrics.increment(f"error.{name}")
                    raise
        return wrapper
    return decorator