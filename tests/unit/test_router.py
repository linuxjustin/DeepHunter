"""Tests for the Model Router."""

from __future__ import annotations

import pytest

from deephunter.core.config import RouterConfig
from deephunter.core.exceptions import RouterError
from deephunter.router.events import ProviderSelectedEvent, RouterEventBus
from deephunter.router.models import (
    ModelRequest,
    ModelResponse,
    ProviderStatus,
    RoutingDecision,
)
from deephunter.router.provider import ModelProvider
from deephunter.router.registry import ProviderRegistry
from deephunter.router.router import ModelRouter

from deephunter.router.models import ModelInfo, ProviderMetadata

from tests.unit.test_router_registry import FakeProvider


@pytest.fixture
def router() -> ModelRouter:
    r = ModelRouter()
    r.register_provider(FakeProvider("openai", {"reasoning", "code_review", "vision",
                                                  "json_output", "streaming", "large_context"}))
    r.register_provider(FakeProvider("ollama", {"reasoning", "code_review", "offline",
                                                  "cost_efficient", "large_context"}))
    r.register_provider(FakeProvider("claude", {"reasoning", "code_review", "large_context",
                                                  "structured_output"}))
    return r

@pytest.fixture
def router_no_large_context() -> ModelRouter:
    r = ModelRouter()
    r.register_provider(FakeProvider("openai", {"reasoning", "code_review", "large_context"}))
    r.register_provider(FakeProvider("ollama", {"reasoning", "code_review"}))
    return r


class TestModelRouter:
    def test_register_and_list(self, router: ModelRouter) -> None:
        names = [p.name for p in router.list_providers()]
        assert "openai" in names
        assert "ollama" in names
        assert "claude" in names

    def test_deregister(self, router: ModelRouter) -> None:
        router.deregister_provider("claude")
        assert router.get_provider("claude") is None

    def test_get_provider(self, router: ModelRouter) -> None:
        provider = router.get_provider("openai")
        assert provider is not None
        assert provider.name == "openai"

    def test_route_simple(self, router: ModelRouter) -> None:
        request = ModelRequest(task_type="reasoning")
        decision = router.route(request)
        assert decision.provider_name in ("openai", "ollama", "claude")
        assert decision.model_name
        assert decision.attempt_number == 1
        assert len(decision.fallback_chain) >= 1

    def test_route_with_preferred_provider(self, router: ModelRouter) -> None:
        request = ModelRequest(
            task_type="reasoning",
            preferred_providers=["ollama"],
        )
        decision = router.route(request)
        assert decision.provider_name == "ollama"

    def test_route_with_excluded_provider(self, router: ModelRouter) -> None:
        request = ModelRequest(
            task_type="code_analysis",
            excluded_providers=["openai"],
        )
        decision = router.route(request)
        assert decision.provider_name != "openai"

    def test_route_with_vision_requirement(self, router: ModelRouter) -> None:
        request = ModelRequest(
            task_type="reasoning",
            required_capabilities={"vision"},
        )
        decision = router.route(request)
        assert decision.provider_name == "openai"
        assert "vision" in decision.matched_capabilities

    def test_route_with_offline_requirement(self, router: ModelRouter) -> None:
        request = ModelRequest(
            task_type="reasoning",
            require_offline=True,
        )
        decision = router.route(request)
        assert decision.provider_name == "ollama"

    def test_route_no_matching_provider(self, router: ModelRouter) -> None:
        request = ModelRequest(
            task_type="reasoning",
            required_capabilities={"impossible_capability"},
        )
        with pytest.raises(RouterError, match="No provider found"):
            router.route(request)

    def test_execute(self, router: ModelRouter) -> None:
        request = ModelRequest(task_type="reasoning")
        response = router.execute(request, prompt="Test prompt")
        assert isinstance(response, ModelResponse)
        assert response.content
        assert response.routing_decision.provider_name
        assert response.request_id == request.id

    def test_execute_with_system_prompt(self, router: ModelRouter) -> None:
        request = ModelRequest(task_type="reasoning")
        response = router.execute(
            request,
            prompt="Analyze this",
            system_prompt="You are a security expert",
            temperature=0.5,
            max_tokens=1024,
        )
        assert response.content

    def test_metrics_after_routing(self, router: ModelRouter) -> None:
        router.route(ModelRequest(task_type="reasoning"))
        router.route(ModelRequest(task_type="code_analysis"))
        router.execute(ModelRequest(task_type="reasoning"), prompt="test")

        metrics = router.metrics
        assert metrics.total_requests >= 3
        assert metrics.successful_routes >= 1
        assert "reasoning" in metrics.task_counts

    def test_fallback_chain(self, router: ModelRouter) -> None:
        request = ModelRequest(task_type="reasoning")
        decision = router.route(request)
        assert len(decision.fallback_chain) >= 2  # default + fallback config providers
        assert decision.total_attempts >= 1

    def test_config_default_provider(self) -> None:
        config = RouterConfig(default_provider="ollama", fallback_providers=["openai"])
        router = ModelRouter(config=config)
        router.register_provider(FakeProvider("openai", {"reasoning", "large_context"}))
        router.register_provider(FakeProvider("ollama", {"reasoning", "large_context"}))

        request = ModelRequest(task_type="reasoning")
        decision = router.route(request)
        # Default provider should be preferred
        assert decision.provider_name == "ollama"


class TestModelRouterEdgeCases:
    def test_empty_registry(self) -> None:
        router = ModelRouter()
        with pytest.raises(RouterError, match="No provider found"):
            router.route(ModelRequest(task_type="reasoning"))

    def test_all_providers_unavailable(self) -> None:
        class UnavailableProvider(FakeProvider):
            def is_available(self) -> ProviderStatus:
                return ProviderStatus.UNAVAILABLE

        router = ModelRouter()
        router.register_provider(UnavailableProvider("broken", {"reasoning", "large_context"}))

        with pytest.raises(RouterError, match="All.*providers failed"):
            router.route(ModelRequest(task_type="reasoning"))

    def test_execute_after_deregister(self, router: ModelRouter) -> None:
        # Register a sole provider, route, then deregister
        single = ModelRouter()
        single.register_provider(FakeProvider("only_provider", {"reasoning", "large_context"}))
        request = ModelRequest(task_type="reasoning", preferred_providers=["only_provider"])
        decision = single.route(request)
        assert decision.provider_name == "only_provider"

        single.deregister_provider("only_provider")
        with pytest.raises(RouterError, match="No provider found"):
            single.execute(request, prompt="test")

    def test_route_event_emission(self) -> None:
        bus = RouterEventBus()
        events: list[ProviderSelectedEvent] = []

        bus.subscribe(ProviderSelectedEvent, lambda e: events.append(e))
        router = ModelRouter(event_bus=bus)
        router.register_provider(FakeProvider("openai", {"reasoning", "large_context"}))

        decision = router.route(ModelRequest(task_type="reasoning"))
        assert decision.provider_name == "openai"
        assert len(events) >= 1

    def test_multiple_capability_matching(self, router: ModelRouter) -> None:
        request = ModelRequest(
            task_type="reasoning",
            required_capabilities={"reasoning", "code_review"},
        )
        decision = router.route(request)
        assert "reasoning" in decision.matched_capabilities
        assert "code_review" in decision.matched_capabilities

    def test_route_raises_on_all_failures(self) -> None:
        class AlwaysFailsProvider(FakeProvider):
            def is_available(self) -> ProviderStatus:
                return ProviderStatus.DEGRADED

        router = ModelRouter()
        router.register_provider(AlwaysFailsProvider("p1", {"reasoning", "large_context"}))
        router.register_provider(AlwaysFailsProvider("p2", {"reasoning", "large_context"}))

        with pytest.raises(RouterError, match="All.*providers failed"):
            router.route(ModelRequest(task_type="reasoning"))
