"""Provider configuration profiles.

Pre-configured profiles for different use cases and providers.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ProviderProfile(BaseModel):
    """A named configuration profile for a provider."""

    name: str
    provider: str
    model: str
    base_url: str | None = None
    api_key: str | None = None
    temperature: float = 0.1
    max_tokens: int = 4096
    max_retries: int = 3
    rate_limit_tpm: int = 60
    timeout: float = 120.0
    capabilities: list[str] = Field(default_factory=list)
    description: str = ""


PRESET_PROFILES: dict[str, ProviderProfile] = {
    "ollama-local": ProviderProfile(
        name="ollama-local",
        provider="ollama",
        model="deepseek-coder:6.7b",
        base_url="http://localhost:11434",
        temperature=0.1,
        max_tokens=4096,
        max_retries=3,
        rate_limit_tpm=60,
        timeout=120.0,
        capabilities=["offline", "cost_efficient", "reasoning", "code_generation", "code_review"],
        description="Local Ollama with DeepSeek Coder",
    ),
    "ollama-qwen": ProviderProfile(
        name="ollama-qwen",
        provider="ollama",
        model="qwen2.5-coder:7b",
        base_url="http://localhost:11434",
        temperature=0.1,
        max_tokens=4096,
        max_retries=3,
        rate_limit_tpm=60,
        timeout=120.0,
        capabilities=["offline", "cost_efficient", "code_generation", "code_review"],
        description="Local Ollama with Qwen 2.5 Coder",
    ),
    "openai-gpt4o": ProviderProfile(
        name="openai-gpt4o",
        provider="openai",
        model="gpt-4o",
        temperature=0.1,
        max_tokens=4096,
        max_retries=3,
        rate_limit_tpm=10000,
        timeout=120.0,
        capabilities=["reasoning", "code_generation", "code_review", "json_output", "streaming", "structured_output", "large_context", "vision", "tool_use"],
        description="OpenAI GPT-4o with all capabilities",
    ),
    "openai-gpt4o-mini": ProviderProfile(
        name="openai-gpt4o-mini",
        provider="openai",
        model="gpt-4o-mini",
        temperature=0.1,
        max_tokens=4096,
        max_retries=3,
        rate_limit_tpm=10000,
        timeout=120.0,
        capabilities=["reasoning", "code_generation", "json_output", "streaming", "fast_response"],
        description="OpenAI GPT-4o mini for fast responses",
    ),
    "claude-sonnet": ProviderProfile(
        name="claude-sonnet",
        provider="claude",
        model="claude-sonnet-4-20250514",
        temperature=0.1,
        max_tokens=4096,
        max_retries=3,
        rate_limit_tpm=5000,
        timeout=120.0,
        capabilities=["reasoning", "code_generation", "code_review", "json_output", "streaming", "structured_output", "large_context", "tool_use"],
        description="Claude Sonnet 4 for balanced performance",
    ),
    "claude-opus": ProviderProfile(
        name="claude-opus",
        provider="claude",
        model="claude-opus-4-20250514",
        temperature=0.1,
        max_tokens=8192,
        max_retries=3,
        rate_limit_tpm=5000,
        timeout=120.0,
        capabilities=["reasoning", "code_generation", "code_review", "json_output", "streaming", "structured_output", "large_context", "tool_use"],
        description="Claude Opus 4 for complex reasoning",
    ),
    "deepseek-chat": ProviderProfile(
        name="deepseek-chat",
        provider="deepseek",
        model="deepseek-chat",
        base_url="https://api.deepseek.com/v1",
        temperature=0.1,
        max_tokens=4096,
        max_retries=3,
        rate_limit_tpm=5000,
        timeout=120.0,
        capabilities=["reasoning", "code_generation", "json_output", "streaming", "cost_efficient"],
        description="DeepSeek Chat for cost-effective reasoning",
    ),
    "deepseek-reasoner": ProviderProfile(
        name="deepseek-reasoner",
        provider="deepseek",
        model="deepseek-reasoner",
        base_url="https://api.deepseek.com/v1",
        temperature=0.1,
        max_tokens=8192,
        max_retries=3,
        rate_limit_tpm=5000,
        timeout=120.0,
        capabilities=["reasoning", "code_generation", "json_output", "large_context"],
        description="DeepSeek Reasoner for advanced reasoning",
    ),
    "gemini-flash": ProviderProfile(
        name="gemini-flash",
        provider="gemini",
        model="gemini-2.0-flash",
        temperature=0.1,
        max_tokens=8192,
        max_retries=3,
        rate_limit_tpm=2000,
        timeout=120.0,
        capabilities=["reasoning", "code_generation", "json_output", "streaming", "fast_response", "cost_efficient"],
        description="Gemini 2.0 Flash for fast cost-effective responses",
    ),
    "gemini-pro": ProviderProfile(
        name="gemini-pro",
        provider="gemini",
        model="gemini-1.5-pro",
        temperature=0.1,
        max_tokens=8192,
        max_retries=3,
        rate_limit_tpm=2000,
        timeout=120.0,
        capabilities=["reasoning", "code_generation", "json_output", "streaming", "large_context", "vision"],
        description="Gemini 1.5 Pro for complex tasks",
    ),
    "openrouter-claude": ProviderProfile(
        name="openrouter-claude",
        provider="openrouter",
        model="anthropic/claude-sonnet-4",
        base_url="https://openrouter.ai/api/v1",
        temperature=0.1,
        max_tokens=4096,
        max_retries=3,
        rate_limit_tpm=5000,
        timeout=120.0,
        capabilities=["reasoning", "code_generation", "code_review", "json_output", "streaming", "structured_output", "large_context", "tool_use"],
        description="Claude via OpenRouter",
    ),
    "openrouter-deepseek": ProviderProfile(
        name="openrouter-deepseek",
        provider="openrouter",
        model="deepseek/deepseek-chat-v3",
        base_url="https://openrouter.ai/api/v1",
        temperature=0.1,
        max_tokens=4096,
        max_retries=3,
        rate_limit_tpm=5000,
        timeout=120.0,
        capabilities=["reasoning", "code_generation", "json_output", "streaming", "cost_efficient"],
        description="DeepSeek via OpenRouter",
    ),
}


class ProfileManager:
    """Manages provider configuration profiles."""

    def __init__(self) -> None:
        self._profiles: dict[str, ProviderProfile] = dict(PRESET_PROFILES)

    def register_profile(self, profile: ProviderProfile) -> None:
        self._profiles[profile.name] = profile

    def get_profile(self, name: str) -> ProviderProfile | None:
        return self._profiles.get(name)

    def list_profiles(self) -> list[ProviderProfile]:
        return list(self._profiles.values())

    def create_provider_from_profile(self, name: str) -> Any:
        profile = self._profiles.get(name)
        if not profile:
            raise ValueError(f"Unknown profile: {name}")

        config = type("ProfileConfig", (), {
            "provider": profile.provider,
            "model": profile.model,
            "base_url": profile.base_url,
            "api_key": profile.api_key,
            "temperature": profile.temperature,
            "max_tokens": profile.max_tokens,
            "max_retries": profile.max_retries,
            "rate_limit_tpm": profile.rate_limit_tpm,
            "timeout": profile.timeout,
        })()

        from deephunter.llm.base import LLMProviderFactory
        return LLMProviderFactory.create(config)

    def delete_profile(self, name: str) -> bool:
        if name in PRESET_PROFILES:
            return False
        return bool(self._profiles.pop(name, None))


def get_profile_manager() -> ProfileManager:
    return ProfileManager()