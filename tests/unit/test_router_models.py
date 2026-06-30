"""Tests for router models."""

from __future__ import annotations

from deephunter.router.models import (
    ExecutionContext,
    ModelInfo,
    ModelRequest,
    ModelResponse,
    ProviderMetadata,
    ProviderStatus,
    RoutingDecision,
    RoutingMetrics,
)


class TestProviderStatus:
    def test_values(self) -> None:
        assert ProviderStatus.AVAILABLE.value == "available"
        assert ProviderStatus.UNAVAILABLE.value == "unavailable"
        assert ProviderStatus.DEGRADED.value == "degraded"
        assert ProviderStatus.UNKNOWN.value == "unknown"


class TestModelInfo:
    def test_minimal_creation(self) -> None:
        info = ModelInfo()
        assert info.id == ""
        assert info.capabilities == set()
        assert info.max_tokens == 0

    def test_with_values(self) -> None:
        info = ModelInfo(
            id="gpt-4o",
            name="GPT-4o",
            provider_name="openai",
            capabilities={"reasoning", "vision"},
            max_tokens=4096,
            max_context=128000,
            cost_per_1k_input=0.01,
            cost_per_1k_output=0.03,
            supports_streaming=True,
            supports_vision=True,
        )
        assert info.id == "gpt-4o"
        assert info.provider_name == "openai"
        assert "reasoning" in info.capabilities
        assert info.max_tokens == 4096
        assert info.supports_streaming is True


class TestProviderMetadata:
    def test_minimal(self) -> None:
        meta = ProviderMetadata()
        assert meta.name == ""
        assert meta.models == []
        assert meta.requires_api_key is True

    def test_with_models(self) -> None:
        model = ModelInfo(id="test-model", name="Test Model")
        meta = ProviderMetadata(
            name="test_provider",
            description="A test provider",
            models=[model],
            default_model="test-model",
            api_type="openai-compatible",
            environment="cloud",
        )
        assert meta.name == "test_provider"
        assert len(meta.models) == 1
        assert meta.default_model == "test-model"


class TestExecutionContext:
    def test_minimal(self) -> None:
        ctx = ExecutionContext()
        assert ctx.task_type == "reasoning"
        assert ctx.required_capabilities == set()
        assert ctx.timeout_seconds == 120.0

    def test_with_values(self) -> None:
        ctx = ExecutionContext(
            task_type="code_analysis",
            required_capabilities={"reasoning", "code_review"},
            require_json=True,
            require_offline=True,
            max_tokens=8192,
        )
        assert ctx.task_type == "code_analysis"
        assert ctx.required_capabilities == {"reasoning", "code_review"}
        assert ctx.require_json is True
        assert ctx.require_offline is True


class TestModelRequest:
    def test_minimal_creation(self) -> None:
        req = ModelRequest()
        assert req.id.startswith("req-")
        assert req.task_type == "reasoning"
        assert req.max_tokens == 4096

    def test_with_values(self) -> None:
        req = ModelRequest(
            context_id="ctx-1",
            prompt_id="prompt-1",
            task_type="code_analysis",
            required_capabilities={"reasoning", "code_review"},
            preferred_providers=["ollama"],
            max_tokens=8192,
        )
        assert req.context_id == "ctx-1"
        assert req.prompt_id == "prompt-1"
        assert req.task_type == "code_analysis"
        assert "ollama" in req.preferred_providers

    def test_to_execution_context(self) -> None:
        req = ModelRequest(
            task_type="code_analysis",
            required_capabilities={"reasoning"},
            require_offline=True,
        )
        ctx = req.to_execution_context()
        assert ctx.task_type == "code_analysis"
        assert "reasoning" in ctx.required_capabilities
        assert ctx.require_offline is True

    def test_to_execution_context_defaults(self) -> None:
        req = ModelRequest()
        ctx = req.to_execution_context()
        assert ctx.task_type == "reasoning"
        assert ctx.timeout_seconds == 120.0


class TestRoutingDecision:
    def test_minimal(self) -> None:
        decision = RoutingDecision()
        assert decision.provider_name == ""
        assert decision.attempt_number == 1
        assert decision.fallback_chain == []

    def test_with_values(self) -> None:
        decision = RoutingDecision(
            provider_name="openai",
            model_name="gpt-4o",
            reason="Best capability match",
            matched_capabilities=["reasoning", "code_review"],
            attempt_number=1,
            total_attempts=3,
            fallback_chain=["openai", "ollama", "deepseek"],
        )
        assert decision.provider_name == "openai"
        assert decision.model_name == "gpt-4o"
        assert len(decision.fallback_chain) == 3


class TestModelResponse:
    def test_minimal(self) -> None:
        resp = ModelResponse()
        assert resp.id.startswith("resp-")
        assert resp.content == ""

    def test_with_values(self) -> None:
        resp = ModelResponse(
            request_id="req-1",
            content="Generated response text",
            model="gpt-4o",
            provider="openai",
            usage={"prompt_tokens": 100, "completion_tokens": 50},
        )
        assert resp.request_id == "req-1"
        assert resp.content == "Generated response text"
        assert resp.usage["prompt_tokens"] == 100


class TestRoutingMetrics:
    def test_defaults(self) -> None:
        metrics = RoutingMetrics()
        assert metrics.total_requests == 0
        assert metrics.successful_routes == 0
        assert metrics.provider_counts == {}

    def test_tracking(self) -> None:
        metrics = RoutingMetrics(
            total_requests=10,
            successful_routes=8,
            failed_routes=2,
            provider_counts={"openai": 5, "ollama": 3},
        )
        assert metrics.total_requests == 10
        assert metrics.successful_routes == 8
        assert metrics.provider_counts["openai"] == 5
