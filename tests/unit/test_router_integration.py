"""Integration tests for the Model Router with multiple providers."""

from __future__ import annotations

import pytest

from deephunter.core.config import RouterConfig
from deephunter.core.exceptions import RouterError
from deephunter.router.models import ModelRequest, ProviderStatus
from deephunter.router.provider import ModelProvider
from deephunter.router.registry import ProviderRegistry
from deephunter.router.router import ModelRouter

from deephunter.router.models import ModelInfo, ProviderMetadata

from tests.unit.test_router_registry import FakeProvider


@pytest.fixture
def full_registry() -> ProviderRegistry:
    reg = ProviderRegistry()
    reg.register(FakeProvider("openai", {"reasoning", "code_review", "vision",
                                           "json_output", "streaming", "large_context",
                                           "structured_output", "fast_response"}))
    reg.register(FakeProvider("ollama", {"reasoning", "code_review", "offline",
                                           "cost_efficient", "large_context"}))
    reg.register(FakeProvider("claude", {"reasoning", "code_review", "large_context",
                                           "structured_output", "safety"}))
    reg.register(FakeProvider("gemini", {"reasoning", "vision", "large_context",
                                           "fast_response"}))
    reg.register(FakeProvider("deepseek", {"reasoning", "code_generation",
                                             "cost_efficient"}))
    return reg


class TestRouterIntegration:
    def test_all_tasks_routable(self, full_registry: ProviderRegistry) -> None:
        router = ModelRouter(registry=full_registry)
        tasks = [
            "reasoning", "planning", "code_analysis", "code_generation",
            "documentation", "report_writing", "security_analysis",
            "summarization", "translation", "classification",
        ]
        for task in tasks:
            request = ModelRequest(task_type=task)
            decision = router.route(request)
            assert decision.provider_name, f"Task '{task}' returned no provider"
            assert decision.model_name, f"Task '{task}' returned no model"

    def test_preferred_provider_overrides_default(self, full_registry: ProviderRegistry) -> None:
        config = RouterConfig(default_provider="openai")
        router = ModelRouter(registry=full_registry, config=config)

        request = ModelRequest(
            task_type="reasoning",
            preferred_providers=["claude"],
        )
        decision = router.route(request)
        assert decision.provider_name == "claude"

    def test_excluded_providers_filtered(self, full_registry: ProviderRegistry) -> None:
        router = ModelRouter(registry=full_registry)

        request = ModelRequest(
            task_type="reasoning",
            excluded_providers=["openai", "claude", "gemini", "deepseek"],
        )
        decision = router.route(request)
        assert decision.provider_name == "ollama"

    def test_vision_task_auto_routes(self, full_registry: ProviderRegistry) -> None:
        router = ModelRouter(registry=full_registry)

        request = ModelRequest(task_type="reasoning", require_vision=True)
        decision = router.route(request)
        # openai and gemini have vision
        assert decision.provider_name in ("openai", "gemini")

    def test_offline_mode_routes_to_ollama(self, full_registry: ProviderRegistry) -> None:
        router = ModelRouter(registry=full_registry)

        request = ModelRequest(task_type="reasoning", require_offline=True)
        decision = router.route(request)
        assert decision.provider_name == "ollama"

    def test_metrics_accumulate(self, full_registry: ProviderRegistry) -> None:
        router = ModelRouter(registry=full_registry)

        for _ in range(5):
            router.route(ModelRequest(task_type="reasoning"))
        for _ in range(3):
            router.route(ModelRequest(task_type="code_analysis"))
        router.execute(ModelRequest(task_type="summarization"), prompt="test")

        metrics = router.metrics
        assert metrics.total_requests >= 9
        assert metrics.successful_routes >= 1
        assert metrics.provider_counts
        assert metrics.task_counts.get("reasoning", 0) == 5

    def test_fallback_chain_order(self, full_registry: ProviderRegistry) -> None:
        config = RouterConfig(
            default_provider="claude",
            fallback_providers=["openai", "deepseek"],
            max_fallback_attempts=5,
        )
        router = ModelRouter(registry=full_registry, config=config)

        request = ModelRequest(task_type="reasoning")
        decision = router.route(request)
        assert decision.fallback_chain[0] == "claude"
        assert "openai" in decision.fallback_chain
        assert decision.provider_name == "claude"

    def test_all_providers_excluded_raises(self, full_registry: ProviderRegistry) -> None:
        router = ModelRouter(registry=full_registry)

        all_names = full_registry.list_names()
        request = ModelRequest(
            task_type="reasoning",
            excluded_providers=all_names,
        )
        with pytest.raises(RouterError, match="No provider found"):
            router.route(request)

    def test_route_then_execute_pipeline(self, full_registry: ProviderRegistry) -> None:
        router = ModelRouter(registry=full_registry)

        request = ModelRequest(task_type="reasoning")
        decision = router.route(request)

        # Execute with the selected provider's model
        provider = router.get_provider(decision.provider_name)
        assert provider is not None

        response = provider.generate(
            prompt="Test prompt",
            model=decision.model_name,
        )
        assert response.content
        assert response.provider == decision.provider_name

    def test_execute_preserves_routing_metadata(self, full_registry: ProviderRegistry) -> None:
        router = ModelRouter(registry=full_registry)

        request = ModelRequest(
            task_type="reasoning",
            required_capabilities={"reasoning"},
        )
        response = router.execute(request, prompt="Analysis")

        assert response.request_id == request.id
        assert response.routing_decision.provider_name
        assert response.routing_decision.matched_capabilities
