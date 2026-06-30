"""Abstract provider interface for the Model Router.

This is the NEW richer provider interface.  The existing ``LLMProvider`` ABC
in ``llm/base.py`` is preserved unchanged for backward compatibility.
New providers should implement ``ModelProvider``.

A ``LegacyProviderAdapter`` is provided to wrap existing ``LLMProvider``
implementations into ``ModelProvider``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from deephunter.router.models import ModelInfo, ModelResponse, ProviderMetadata, ProviderStatus

from deephunter.llm.base import LLMMessage, LLMProvider, LLMResponse


class ModelProvider(ABC):
    """Extended provider interface with capabilities, metadata, and routing support.

    Implement this interface for new providers.  Existing ``LLMProvider``
    implementations can be wrapped via ``LegacyProviderAdapter``.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique provider name (e.g. 'claude', 'openai', 'ollama')."""

    @property
    @abstractmethod
    def metadata(self) -> ProviderMetadata:
        """Provider metadata including models, API type, and description."""

    @abstractmethod
    def get_models(self) -> list[ModelInfo]:
        """Return list of available models with their capabilities."""

    @abstractmethod
    def get_model(self, model_name: str) -> ModelInfo | None:
        """Get a specific model by name, or None if not found."""

    @abstractmethod
    def is_available(self) -> ProviderStatus:
        """Return the current availability status.

        Default implementation returns AVAILABLE.  Subclasses may check
        API health endpoints.
        """

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        model: str | None = None,
    ) -> ModelResponse:
        """Generate a response from the provider.

        Args:
            prompt: The user prompt.
            system_prompt: Optional system instruction.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens to generate.
            model: Specific model to use (uses default if None).

        Returns:
            A ModelResponse with content and metadata.

        Raises:
            RouterError: On provider failure.
        """

    @abstractmethod
    def supports_capability(self, capability: str) -> bool:
        """Check whether any model in this provider supports a capability."""

    @abstractmethod
    def find_model_by_capability(self, capability: str) -> list[ModelInfo]:
        """Find models that support a specific capability."""


class LegacyProviderAdapter(ModelProvider):
    """Adapter that wraps an existing ``LLMProvider`` as a ``ModelProvider``.

    Allows the router to use legacy providers without modification.
    Capabilities are inferred from the provider name heuristically.
    """

    _CAPABILITY_MAP: dict[str, set[str]] = {
        "ollama": {"offline", "cost_efficient", "reasoning", "code_generation", "code_review"},
        "openai": {"reasoning", "code_generation", "code_review", "json_output", "streaming",
                    "structured_output", "large_context", "vision", "tool_use", "safety",
                    "fast_response"},
    }

    def __init__(self, provider: LLMProvider, name: str = "", default_model: str = "") -> None:
        self._provider = provider
        self._name = name or type(provider).__name__.replace("Provider", "").lower()
        self._default_model = default_model or self._name

    @property
    def name(self) -> str:
        return self._name

    @property
    def metadata(self) -> ProviderMetadata:
        caps = self._CAPABILITY_MAP.get(self._name, set())
        model = ModelInfo(
            id=self._default_model,
            name=self._default_model,
            provider_name=self._name,
            capabilities=caps,
            max_tokens=4096,
            max_context=8192,
        )
        return ProviderMetadata(
            name=self._name,
            description=f"Legacy adapter for {type(self._provider).__name__}",
            models=[model],
            default_model=self._default_model,
            api_type="openai-compatible",
            requires_api_key="openai" in self._name,
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

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        model: str | None = None,
    ) -> ModelResponse:
        messages: list[LLMMessage] = []
        if system_prompt:
            messages.append(LLMMessage(role="system", content=system_prompt))
        messages.append(LLMMessage(role="user", content=prompt))
        llm_response: LLMResponse = self._provider.generate(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return ModelResponse(
            content=llm_response.content,
            model=llm_response.model or model or self._default_model,
            provider=self._name,
            usage=dict(llm_response.usage),
        )

    def supports_capability(self, capability: str) -> bool:
        caps = self._CAPABILITY_MAP.get(self._name, set())
        return capability in caps

    def find_model_by_capability(self, capability: str) -> list[ModelInfo]:
        return [m for m in self.metadata.models if capability in m.capabilities]
