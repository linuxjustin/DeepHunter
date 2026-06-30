"""Tests for LLM metrics, cost tracking, and latency monitoring."""

from __future__ import annotations

from datetime import UTC, datetime

from deephunter.llm.metrics import (
    CostTracker,
    MetricsCollector,
    ProviderMetrics,
    ProviderStatus,
    RequestMetrics,
    TokenUsage,
    calculate_cost,
    get_metrics_collector,
)


class TestCostTracking:
    def test_calculate_cost_gpt4o(self) -> None:
        cost = calculate_cost("gpt-4o", 1000, 500)
        assert cost > 0
        expected = (1000 / 1_000_000) * 5.0 + (500 / 1_000_000) * 15.0
        assert abs(cost - expected) < 0.001

    def test_calculate_cost_deepseek(self) -> None:
        cost = calculate_cost("deepseek-chat", 1000, 500)
        expected = (1000 / 1_000_000) * 0.14 + (500 / 1_000_000) * 0.28
        assert abs(cost - expected) < 0.001

    def test_calculate_cost_unknown_model(self) -> None:
        cost = calculate_cost("unknown-model", 1000, 500)
        assert cost == 0.0

    def test_cost_tracker_add(self) -> None:
        tracker = CostTracker()
        tracker.add_cost("openai", "gpt-4o", 0.05)
        tracker.add_cost("openai", "gpt-4o", 0.03)
        tracker.add_cost("claude", "claude-sonnet", 0.10)
        assert tracker.provider_costs["openai"] == 0.08
        assert tracker.provider_costs["claude"] == 0.10
        assert tracker.total_cost == 0.18


class TestTokenUsage:
    def test_token_usage_add(self) -> None:
        usage = TokenUsage()
        usage.add(prompt=100, completion=50)
        usage.add(prompt=200, completion=100)
        assert usage.total_prompt_tokens == 300
        assert usage.total_completion_tokens == 150
        assert usage.total_tokens == 450
        assert usage.total_requests == 2

    def test_avg_tokens_per_request(self) -> None:
        usage = TokenUsage()
        usage.add(prompt=100, completion=50)
        usage.add(prompt=200, completion=100)
        assert usage.avg_tokens_per_request() == 225.0

    def test_avg_tokens_no_requests(self) -> None:
        usage = TokenUsage()
        assert usage.avg_tokens_per_request() == 0.0


class TestProviderMetrics:
    def test_record_successful_request(self) -> None:
        m = ProviderMetrics("test-provider")
        metrics = RequestMetrics(
            provider="test-provider",
            model="test-model",
            latency_ms=100.0,
            prompt_tokens=50,
            completion_tokens=100,
            cost_usd=0.001,
        )
        m.record_request(metrics)
        assert m.total_requests == 1
        assert m.failed_requests == 0
        assert m.health_status == ProviderStatus.HEALTHY

    def test_record_failed_request(self) -> None:
        m = ProviderMetrics("test-provider")
        metrics = RequestMetrics(
            provider="test-provider",
            model="test-model",
            latency_ms=100.0,
            error="Connection timeout",
        )
        m.record_request(metrics)
        assert m.total_requests == 1
        assert m.failed_requests == 1

    def test_latency_stats(self) -> None:
        m = ProviderMetrics("test-provider")
        for latency in [100.0, 200.0, 150.0, 300.0, 250.0]:
            m.record_request(
                RequestMetrics(provider="p", model="m", latency_ms=latency)
            )
        stats = m.get_latency_stats()
        assert stats["count"] == 5
        assert stats["min_ms"] == 100.0
        assert stats["max_ms"] == 300.0
        assert stats["avg_ms"] == 200.0

    def test_health_status_transitions(self) -> None:
        m = ProviderMetrics("test-provider")
        assert m.health_status == ProviderStatus.UNKNOWN
        m.record_success()
        assert m.health_status == ProviderStatus.HEALTHY
        m.record_failure()
        m.record_failure()
        m.record_failure()
        assert m.health_status == ProviderStatus.UNAVAILABLE
        m.record_success()
        assert m.health_status == ProviderStatus.DEGRADED

    def test_get_summary(self) -> None:
        m = ProviderMetrics("test-provider")
        m.record_request(RequestMetrics(provider="test", model="gpt-4o", latency_ms=50.0, prompt_tokens=10, completion_tokens=20, cost_usd=0.001))
        summary = m.get_summary()
        assert summary["provider"] == "test-provider"
        assert summary["total_requests"] == 1
        assert summary["success_requests"] == 1
        assert summary["total_cost_usd"] == 0.001


class TestMetricsCollector:
    def test_singleton(self) -> None:
        m1 = get_metrics_collector()
        m2 = get_metrics_collector()
        assert m1 is m2

    def test_record_request(self) -> None:
        collector = MetricsCollector()
        collector._providers.clear()
        collector.record_request("test-provider", "gpt-4o", 100.0, prompt_tokens=50, completion_tokens=100)
        summary = collector.get_all_summaries()
        assert "test-provider" in summary
        assert summary["test-provider"]["total_requests"] == 1

    def test_total_cost(self) -> None:
        collector = MetricsCollector()
        collector._providers.clear()
        collector.record_request("p1", "gpt-4o", 50.0, prompt_tokens=1000, completion_tokens=500)
        collector.record_request("p2", "claude", 50.0, prompt_tokens=1000, completion_tokens=500)
        total = collector.total_cost()
        assert total > 0

    def test_reset(self) -> None:
        collector = MetricsCollector()
        collector.record_request("p1", "gpt-4o", 50.0, prompt_tokens=100, completion_tokens=50)
        collector.reset()
        assert collector.total_requests() == 0