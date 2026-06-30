"""Provider metrics, cost tracking, and latency tracking.

Tracks request counts, token usage, latency percentiles, costs,
and provider health for all LLM providers.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ProviderStatus(str, Enum):
    """Health status of a provider."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


@dataclass
class RequestMetrics:
    """Metrics for a single request."""

    provider: str
    model: str
    latency_ms: float
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    cached: bool = False
    error: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class LatencyStats:
    """Latency statistics."""

    count: int = 0
    total_ms: float = 0.0
    min_ms: float = float("inf")
    max_ms: float = 0.0
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0

    def add(self, latency_ms: float) -> None:
        self.count += 1
        self.total_ms += latency_ms
        self.min_ms = min(self.min_ms, latency_ms)
        self.max_ms = max(self.max_ms, latency_ms)


class TokenUsage(BaseModel):
    """Aggregated token usage."""

    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_tokens: int = 0
    total_requests: int = 0
    cached_tokens: int = 0

    def add(self, prompt: int = 0, completion: int = 0, cached: int = 0) -> None:
        self.total_prompt_tokens += prompt
        self.total_completion_tokens += completion
        self.total_tokens += prompt + completion
        self.total_requests += 1
        self.cached_tokens += cached

    def avg_tokens_per_request(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_tokens / self.total_requests


class CostTracker(BaseModel):
    """Tracks costs per provider and model."""

    provider_costs: dict[str, float] = Field(default_factory=dict)
    model_costs: dict[str, float] = Field(default_factory=dict)
    total_cost: float = 0.0

    def add_cost(self, provider: str, model: str, cost_usd: float) -> None:
        self.total_cost += cost_usd
        self.provider_costs[provider] = self.provider_costs.get(provider, 0.0) + cost_usd
        self.model_costs[model] = self.model_costs.get(model, 0.0) + cost_usd


PRICING_PER_1M_TOKENS: dict[str, tuple[float, float]] = {
    "gpt-4o": (5.0, 15.0),
    "gpt-4o-mini": (0.15, 0.6),
    "gpt-4-turbo": (10.0, 30.0),
    "gpt-3.5-turbo": (0.5, 1.5),
    "claude-sonnet-4-20250514": (3.0, 15.0),
    "claude-opus-4-20250514": (15.0, 75.0),
    "claude-3-5-haiku-20241022": (0.8, 4.0),
    "deepseek-chat": (0.14, 0.28),
    "deepseek-reasoner": (0.55, 2.19),
    "gemini-2.0-flash": (0.0, 0.0),
    "gemini-1.5-pro": (1.25, 5.0),
    "gemini-1.5-flash": (0.035, 0.14),
}


def calculate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Calculate cost in USD based on token usage."""
    model_base = model.split("/")[-1].lower()
    for key, (prompt_price, completion_price) in PRICING_PER_1M_TOKENS.items():
        if key in model_base:
            return (prompt_tokens / 1_000_000) * prompt_price + (completion_tokens / 1_000_000) * completion_price
    return 0.0


class ProviderMetrics:
    """Aggregated metrics for a single provider."""

    def __init__(self, provider_name: str) -> None:
        self.provider_name = provider_name
        self._lock = threading.Lock()
        self._request_times: list[float] = []
        self.total_requests = 0
        self.failed_requests = 0
        self.total_latency_ms = 0.0
        self.min_latency_ms = float("inf")
        self.max_latency_ms = 0.0
        self.token_usage = TokenUsage()
        self.cost_tracker = CostTracker()
        self.last_request_at: datetime | None = None
        self.health_status = ProviderStatus.UNKNOWN
        self.health_failures = 0

    def record_request(self, metrics: RequestMetrics) -> None:
        with self._lock:
            self.total_requests += 1
            self.last_request_at = metrics.timestamp
            if metrics.error:
                self.failed_requests += 1
            else:
                latency = metrics.latency_ms
                self.total_latency_ms += latency
                self.min_latency_ms = min(self.min_latency_ms, latency)
                self.max_latency_ms = max(self.max_latency_ms, latency)
                self._request_times.append(latency)
                if len(self._request_times) > 1000:
                    self._request_times = self._request_times[-1000:]
                self.token_usage.add(
                    prompt=metrics.prompt_tokens,
                    completion=metrics.completion_tokens,
                    cached=metrics.prompt_tokens if metrics.cached else 0,
                )
                self.cost_tracker.add_cost(
                    self.provider_name,
                    metrics.model,
                    metrics.cost_usd,
                )

    def record_failure(self) -> None:
        with self._lock:
            self.failed_requests += 1
            self.health_failures += 1
            if self.health_failures >= 3:
                self.health_status = ProviderStatus.UNAVAILABLE

    def record_success(self) -> None:
        with self._lock:
            if self.health_status == ProviderStatus.UNAVAILABLE:
                self.health_status = ProviderStatus.DEGRADED
            elif self.health_failures > 0:
                self.health_failures = max(0, self.health_failures - 1)
                if self.health_failures == 0:
                    self.health_status = ProviderStatus.HEALTHY

    def get_latency_stats(self) -> dict[str, float]:
        with self._lock:
            if not self._request_times:
                return {"avg_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0}
            times = sorted(self._request_times)
            n = len(times)
            return {
                "avg_ms": self.total_latency_ms / max(1, self.total_requests - self.failed_requests),
                "p50_ms": times[n // 2],
                "p95_ms": times[int(n * 0.95)] if n > 1 else times[0],
                "p99_ms": times[int(n * 0.99)] if n > 1 else times[0],
                "min_ms": self.min_latency_ms if self.min_latency_ms != float("inf") else 0.0,
                "max_ms": self.max_latency_ms,
            }

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            success = self.total_requests - self.failed_requests
            error_rate = (self.failed_requests / self.total_requests * 100) if self.total_requests > 0 else 0.0
            return {
                "provider": self.provider_name,
                "total_requests": self.total_requests,
                "success_requests": success,
                "failed_requests": self.failed_requests,
                "error_rate_pct": round(error_rate, 2),
                "latency": self.get_latency_stats(),
                "token_usage": self.token_usage.model_dump(),
                "total_cost_usd": round(self.cost_tracker.total_cost, 6),
                "last_request_at": self.last_request_at.isoformat() if self.last_request_at else None,
                "health_status": self.health_status.value,
            }


class MetricsCollector:
    """Global metrics collector for all providers."""

    _instance: "MetricsCollector | None" = None
    _lock = threading.Lock()

    def __new__(cls) -> "MetricsCollector":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._providers = {}
                    cls._instance._lock = threading.Lock()
        return cls._instance

    def get_provider_metrics(self, provider: str) -> ProviderMetrics:
        with self._lock:
            if provider not in self._providers:
                self._providers[provider] = ProviderMetrics(provider)
            return self._providers[provider]

    def record_request(self, provider: str, model: str, latency_ms: float, prompt_tokens: int = 0, completion_tokens: int = 0, cached: bool = False, error: str | None = None) -> None:
        metrics = ProviderMetrics(provider)
        req_metrics = RequestMetrics(
            provider=provider,
            model=model,
            latency_ms=latency_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=calculate_cost(model, prompt_tokens, completion_tokens),
            cached=cached,
            error=error,
        )
        self.get_provider_metrics(provider).record_request(req_metrics)
        if error:
            self.get_provider_metrics(provider).record_failure()
        else:
            self.get_provider_metrics(provider).record_success()

    def get_all_summaries(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {p: m.get_summary() for p, m in self._providers.items()}

    def reset(self) -> None:
        with self._lock:
            self._providers.clear()

    def total_cost(self) -> float:
        with self._lock:
            return sum(m.cost_tracker.total_cost for m in self._providers.values())

    def total_requests(self) -> int:
        with self._lock:
            return sum(m.total_requests for m in self._providers.values())

    def total_tokens(self) -> int:
        with self._lock:
            return sum(m.token_usage.total_tokens for m in self._providers.values())


def get_metrics_collector() -> MetricsCollector:
    return MetricsCollector()