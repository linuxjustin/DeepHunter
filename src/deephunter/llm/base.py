"""LLM provider abstraction.

Defines a pluggable interface for interacting with large language models.
Supports chat completions with configurable system prompts, temperature,
and token limits.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from deephunter.core.config import LLMConfig
from deephunter.core.exceptions import ReasoningError
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class LLMResponse:
    """Response from an LLM provider."""

    content: str
    model: str
    usage: dict[str, int] = field(default_factory=dict)
    raw: Any = None


class LLMProvider(ABC):
    """Abstract interface for LLM interactions.

    Implementations wrap specific model APIs (Ollama, OpenAI, Anthropic, etc.)
    and provide a unified ``generate()`` method.
    """

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Generate a response from the LLM.

        Args:
            prompt: The user prompt to send.
            system_prompt: Optional system-level instruction.
            temperature: Sampling temperature (0.0-2.0).
            max_tokens: Maximum tokens in the response.

        Returns:
            An LLMResponse containing the generated text.

        Raises:
            ReasoningError: If the API call fails.
        """

    @abstractmethod
    def generate_batch(
        self,
        prompts: list[str],
        system_prompt: str | None = None,
    ) -> list[LLMResponse]:
        """Generate responses for multiple prompts.

        The default implementation calls ``generate()`` sequentially.
        Subclasses may override for batched API calls.
        """


class LLMProviderFactory:
    """Creates LLM providers from configuration."""

    @staticmethod
    def create(config: LLMConfig) -> LLMProvider:
        """Create an LLM provider based on config.

        Args:
            config: LLM configuration.

        Returns:
            An LLMProvider instance.

        Raises:
            ReasoningError: If the configured provider is unsupported.
        """
        provider = config.provider.lower()
        if provider == "ollama":
            from deephunter.llm.ollama_provider import OllamaProvider
            return OllamaProvider(
                model=config.model,
                base_url=config.base_url or "http://localhost:11434",
            )
        if provider == "openai":
            from deephunter.llm.openai_provider import OpenAIProvider
            return OpenAIProvider(
                model=config.model,
                api_key=config.api_key,
                base_url=config.base_url,
            )
        msg = f"Unsupported LLM provider: {config.provider}. Supported: ollama, openai"
        raise ReasoningError(msg)
