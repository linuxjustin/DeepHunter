"""Tests for router provider interface and legacy adapter."""

from __future__ import annotations

import pytest

from deephunter.router.models import ModelResponse, ProviderStatus
from deephunter.router.provider import LegacyProviderAdapter, ModelProvider


class DummyLegacyProvider:
    """Simulates an existing LLMProvider for adapter testing."""

    def generate(self, messages, temperature=None, max_tokens=None, **kwargs):
        from deephunter.llm.base import LLMMessage, LLMResponse
        if messages:
            user_msg = next((m for m in messages if isinstance(m, LLMMessage) and m.role == "user"), None)
            content = user_msg.content if user_msg else str(messages[0])
        else:
            content = str(messages)
        return LLMResponse(
            content=f"Response to: {content[:20]}",
            model="test-model",
            usage={"prompt_tokens": 10, "completion_tokens": 5},
        )

    def generate_batch(self, prompts, system_prompt=None):
        return [self.generate(p) for p in prompts]


class TestLegacyProviderAdapter:
    def test_wraps_legacy_provider(self) -> None:
        legacy = DummyLegacyProvider()
        adapter = LegacyProviderAdapter(legacy, name="test_provider")

        assert adapter.name == "test_provider"
        assert adapter.is_available() == ProviderStatus.AVAILABLE

    def test_generate(self) -> None:
        legacy = DummyLegacyProvider()
        adapter = LegacyProviderAdapter(legacy, name="test")

        response = adapter.generate(prompt="Hello world")
        assert isinstance(response, ModelResponse)
        assert "Response to: Hello world" in response.content
        assert response.provider == "test"

    def test_generate_with_system_prompt(self) -> None:
        legacy = DummyLegacyProvider()
        adapter = LegacyProviderAdapter(legacy, name="test")

        response = adapter.generate(
            prompt="Analyze this",
            system_prompt="Be a security expert",
            temperature=0.3,
            max_tokens=500,
        )
        assert response.content

    def test_metadata(self) -> None:
        legacy = DummyLegacyProvider()
        adapter = LegacyProviderAdapter(legacy, name="ollama")

        meta = adapter.metadata
        assert meta.name == "ollama"
        assert meta.environment == "local"
        assert len(meta.models) >= 1

    def test_metadata_openai(self) -> None:
        legacy = DummyLegacyProvider()
        adapter = LegacyProviderAdapter(legacy, name="openai")

        meta = adapter.metadata
        assert meta.environment == "cloud"
        assert meta.requires_api_key is True

    def test_get_models(self) -> None:
        legacy = DummyLegacyProvider()
        adapter = LegacyProviderAdapter(legacy, name="test")

        models = adapter.get_models()
        assert len(models) >= 1
        assert models[0].provider_name == "test"

    def test_get_model_found(self) -> None:
        legacy = DummyLegacyProvider()
        adapter = LegacyProviderAdapter(legacy, name="test")

        model = adapter.get_model("test")
        assert model is not None

    def test_get_model_not_found(self) -> None:
        legacy = DummyLegacyProvider()
        adapter = LegacyProviderAdapter(legacy, name="test")

        model = adapter.get_model("nonexistent-model")
        assert model is None

    def test_supports_capability(self) -> None:
        legacy = DummyLegacyProvider()
        adapter = LegacyProviderAdapter(legacy, name="ollama")

        assert adapter.supports_capability("offline") is True
        assert adapter.supports_capability("vision") is False

    def test_find_model_by_capability(self) -> None:
        legacy = DummyLegacyProvider()
        adapter = LegacyProviderAdapter(legacy, name="openai")

        models = adapter.find_model_by_capability("reasoning")
        assert len(models) >= 1


class TestModelProviderABC:
    def test_cannot_instantiate_abc(self) -> None:
        with pytest.raises(TypeError):
            ModelProvider()  # type: ignore[abstract]
