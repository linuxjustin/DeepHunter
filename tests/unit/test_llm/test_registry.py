"""Tests for Provider Registry with fallback chains and health monitoring."""

from __future__ import annotations

from deephunter.llm.base import LLMMessage
from deephunter.llm.metrics import ProviderStatus
from deephunter.llm.profiles import (
    PRESET_PROFILES,
    ProfileManager,
    ProviderProfile,
    get_profile_manager,
)
from deephunter.llm.registry import (
    ProviderConfig,
    ProviderRegistry,
    SelectionStrategy,
    get_provider_registry,
)
from tests.unit.test_llm.mocks import MockProvider, MockResponse


class TestProviderRegistry:
    def setup_method(self) -> None:
        self.registry = ProviderRegistry()
        self.registry._providers.clear()

    def test_register_provider(self) -> None:
        mock = MockProvider()
        self.registry.register_provider("test-provider", mock, priority=10)
        config = self.registry.get_provider("test-provider")
        assert config is not None
        assert config.name == "test-provider"
        assert config.priority == 10

    def test_unregister_provider(self) -> None:
        mock = MockProvider()
        self.registry.register_provider("test-provider", mock)
        result = self.registry.unregister_provider("test-provider")
        assert result is True
        assert self.registry.get_provider("test-provider") is None

    def test_list_providers(self) -> None:
        mock1 = MockProvider()
        mock2 = MockProvider()
        self.registry.register_provider("low-priority", mock1, priority=1)
        self.registry.register_provider("high-priority", mock2, priority=10)
        providers = self.registry.list_providers()
        assert len(providers) == 2
        assert providers[0].name == "high-priority"
        assert providers[1].name == "low-priority"

    def test_list_providers_enabled_only(self) -> None:
        mock = MockProvider()
        self.registry.register_provider("provider", mock, priority=5)
        self.registry.disable_provider("provider")
        providers = self.registry.list_providers(enabled_only=True)
        assert len(providers) == 0
        providers = self.registry.list_providers(enabled_only=False)
        assert len(providers) == 1

    def test_get_fallback_chain_priority_order(self) -> None:
        mock1 = MockProvider(model="model-1")
        mock2 = MockProvider(model="model-2")
        self.registry.register_provider("p1", mock1, priority=1)
        self.registry.register_provider("p2", mock2, priority=10)
        chain = self.registry.get_fallback_chain()
        assert chain[0].name == "p2"
        assert chain[1].name == "p1"

    def test_get_fallback_chain_with_preferred(self) -> None:
        mock1 = MockProvider(model="model-1")
        mock2 = MockProvider(model="model-2")
        self.registry.register_provider("p1", mock1, priority=10)
        self.registry.register_provider("p2", mock2, priority=5)
        chain = self.registry.get_fallback_chain(preferred_provider="p2")
        assert chain[0].name == "p2"
        assert chain[1].name == "p1"

    def test_execute_with_fallback_success(self) -> None:
        mock = MockProvider(mock_response=MockResponse(content="Success response"))
        self.registry.register_provider("test", mock)
        messages = [LLMMessage(role="user", content="Hello")]
        response = self.registry.execute_with_fallback(messages)
        assert response.content == "Success response"

    def test_execute_with_fallback_failure(self) -> None:
        mock = MockProvider(fail_with=RuntimeError("Provider error"))
        self.registry.register_provider("failing", mock)
        messages = [LLMMessage(role="user", content="Hello")]
        try:
            self.registry.execute_with_fallback(messages)
            assert False, "Should have raised"
        except RuntimeError as e:
            assert "failed" in str(e).lower()

    def test_enable_disable_provider(self) -> None:
        mock = MockProvider()
        self.registry.register_provider("test", mock)
        self.registry.disable_provider("test")
        config = self.registry.get_provider("test")
        assert config is not None
        assert config.enabled is False
        self.registry.enable_provider("test")
        assert config.enabled is True

    def test_set_strategy(self) -> None:
        self.registry.set_strategy(SelectionStrategy.COST_AWARE)
        assert self.registry._default_strategy == SelectionStrategy.COST_AWARE


class TestProfileManager:
    def test_get_preset_profiles(self) -> None:
        manager = get_profile_manager()
        profiles = manager.list_profiles()
        assert len(profiles) > 0
        assert any(p.name == "ollama-local" for p in profiles)
        assert any(p.name == "openai-gpt4o" for p in profiles)
        assert any(p.name == "claude-sonnet" for p in profiles)

    def test_get_profile(self) -> None:
        manager = get_profile_manager()
        profile = manager.get_profile("ollama-local")
        assert profile is not None
        assert profile.provider == "ollama"
        assert profile.model == "deepseek-coder:6.7b"

    def test_register_profile(self) -> None:
        manager = get_profile_manager()
        new_profile = ProviderProfile(
            name="custom-profile",
            provider="openai",
            model="gpt-4o",
        )
        manager.register_profile(new_profile)
        retrieved = manager.get_profile("custom-profile")
        assert retrieved is not None
        assert retrieved.model == "gpt-4o"

    def test_delete_custom_profile(self) -> None:
        manager = get_profile_manager()
        new_profile = ProviderProfile(name="temp-profile", provider="ollama", model="test")
        manager.register_profile(new_profile)
        result = manager.delete_profile("temp-profile")
        assert result is True
        assert manager.get_profile("temp-profile") is None

    def test_delete_preset_profile_fails(self) -> None:
        manager = get_profile_manager()
        result = manager.delete_profile("ollama-local")
        assert result is False


class TestPresetsComplete:
    def test_all_required_providers_have_profiles(self) -> None:
        required_providers = {"ollama", "openai", "claude", "deepseek", "gemini", "openrouter"}
        manager = get_profile_manager()
        for provider in required_providers:
            profiles = [p for p in manager.list_profiles() if p.provider == provider]
            assert len(profiles) > 0, f"No profiles for provider: {provider}"