"""Model adapters for the Prompt Builder.

Adapters transform a structured ``Prompt`` into model-specific message
formats.  Only the ABC interface is provided — no concrete adapters are
implemented per the requirements.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from deephunter.prompt.models import Prompt


class ModelAdapter(ABC):
    """Base class for model-specific prompt adapters.

    Subclasses transform a Prompt into the message format expected
    by a specific LLM provider (Claude, OpenAI, DeepSeek, etc.).
    No concrete adapters are implemented in this module.
    """

    @abstractmethod
    def adapt(self, prompt: Prompt) -> Prompt:
        """Transform a Prompt into the model's expected format.

        May reorder messages, add/remove fields, or adjust formatting
        to match the target model's API requirements.
        """
        ...

    @abstractmethod
    def estimate_tokens(self, text: str) -> int:
        """Estimate the token count for the target model's tokenizer.

        Args:
            text: The text to estimate tokens for.

        Returns:
            Estimated number of tokens.
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the adapter (e.g. 'claude', 'openai')."""


class IdentityAdapter(ModelAdapter):
    """A no-op adapter that returns the prompt unchanged.

    Useful as a default when no model-specific adaptation is needed.
    """

    def adapt(self, prompt: Prompt) -> Prompt:
        return prompt

    def estimate_tokens(self, text: str) -> int:
        words = len(text.split())
        return max(1, int(words / 0.75))

    @property
    def name(self) -> str:
        return "identity"
