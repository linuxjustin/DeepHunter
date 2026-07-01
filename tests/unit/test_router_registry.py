"""Tests for provider registry."""

from __future__ import annotations

import pytest

from deephunter.router.models import (
    ModelInfo,
    ProviderMetadata,
    ProviderStatus,
)
from deephunter.router.provider import ModelProvider
from deephunter.router.registry import ProviderRegistry


class FakeProvider(ModelProvider):
    """Minimal fake provider for testing."""

    def __init__(
        self,
        name: str,
        capabilities: set[str] | None = None,
        environment: str = "cloud",
    ) -> None:
        self._name = name
        self._caps = capabilities or {"reasoning", "code_review"}

    @property
    def name(self) -> str:
        return self._name

    @property
    def metadata(self) -> ProviderMetadata:
        model = ModelInfo(
            id=f"{self._name}-model",
            name=f"{self._name.title()} Model",
            provider_name=self._name,
            capabilities=self._caps,
            max_tokens=4096,
        )
        return ProviderMetadata(
            name=self._name,
            models=[model],
            default_model=model.id,
            environment="local" if self._name == "ollama" else "cloud",
        )

    def get_models(self) -> list[ModelInfo]:
        return self.metadata.models

    def get_model(self, model_name: str) -> ModelInfo | None:
        for m in self.metadata.models:
            if m.name == model_name or m.id == model_name:
                return m
        return None

    def is_available(self) -> ProviderStatus:
        return ProviderStatus.AVAILABLE

    def generate(self, prompt, system_prompt=None, temperature=None, max_tokens=None, model=None, tools=None):
        from deephunter.router.models import ModelResponse
        return ModelResponse(
            content=f"Response from {self._name}",
            model=model or self._name,
            provider=self._name,
        )

    def supports_capability(self, capability: str) -> bool:
        return capability in self._caps

    def find_model_by_capability(self, capability: str) -> list[ModelInfo]:
        return [m for m in self.metadata.models if capability in m.capabilities]


@pytest.fixture
def registry() -> ProviderRegistry:
    return ProviderRegistry()


class TestProviderRegistry:
    def test_register(self, registry: ProviderRegistry) -> None:
        provider = FakeProvider("openai")
        registry.register(provider)
        assert registry.get("openai") is provider
        assert registry.count() == 1

    def test_register_duplicate_raises(self, registry: ProviderRegistry) -> None:
        registry.register(FakeProvider("openai"))
        with pytest.raises(ValueError, match="already registered"):
            registry.register(FakeProvider("openai"))

    def test_deregister(self, registry: ProviderRegistry) -> None:
        registry.register(FakeProvider("openai"))
        registry.deregister("openai")
        assert registry.get("openai") is None

    def test_deregister_nonexistent(self, registry: ProviderRegistry) -> None:
        registry.deregister("nonexistent")  # Should not raise

    def test_get_nonexistent(self, registry: ProviderRegistry) -> None:
        assert registry.get("nonexistent") is None

    def test_list_providers(self, registry: ProviderRegistry) -> None:
        registry.register(FakeProvider("openai"))
        registry.register(FakeProvider("ollama"))
        assert len(registry.list_providers()) == 2

    def test_list_names(self, registry: ProviderRegistry) -> None:
        registry.register(FakeProvider("openai"))
        registry.register(FakeProvider("ollama"))
        names = registry.list_names()
        assert "openai" in names
        assert "ollama" in names

    def test_find_by_capability(self, registry: ProviderRegistry) -> None:
        registry.register(FakeProvider("openai", {"reasoning", "vision"}))
        registry.register(FakeProvider("ollama", {"offline", "cost_efficient"}))

        vision_providers = registry.find_by_capability("vision")
        assert len(vision_providers) == 1
        assert vision_providers[0].name == "openai"

        offline_providers = registry.find_by_capability("offline")
        assert len(offline_providers) == 1
        assert offline_providers[0].name == "ollama"

    def test_find_by_capability_none_match(self, registry: ProviderRegistry) -> None:
        registry.register(FakeProvider("openai", {"reasoning"}))
        result = registry.find_by_capability("vision")
        assert result == []

    def test_find_by_task(self, registry: ProviderRegistry) -> None:
        registry.register(FakeProvider("openai", {"reasoning", "code_review", "large_context"}))
        registry.register(FakeProvider("simple", {"code_generation"}))

        providers = registry.find_by_task("code_analysis")
        assert len(providers) == 1
        assert providers[0].name == "openai"

    def test_find_by_task_unknown_type(self, registry: ProviderRegistry) -> None:
        registry.register(FakeProvider("openai"))
        providers = registry.find_by_task("nonexistent_task")
        assert len(providers) == 1  # Falls back to all providers

    def test_clear(self, registry: ProviderRegistry) -> None:
        registry.register(FakeProvider("openai"))
        registry.register(FakeProvider("ollama"))
        registry.clear()
        assert registry.count() == 0

    def test_empty_registry(self, registry: ProviderRegistry) -> None:
        assert registry.count() == 0
        assert registry.list_providers() == []
        assert registry.find_by_capability("reasoning") == []
