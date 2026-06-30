"""OpenRouter LLM provider — unified API for 200+ models.

Default endpoint: https://openrouter.ai/api/v1
Supports fallback models via model string like "model1,model2".
"""

from __future__ import annotations

from deephunter.llm.openai_provider import OpenAIProvider


class OpenRouterProvider(OpenAIProvider):
    """OpenRouter LLM provider — unified API for 200+ models.

    Default endpoint: https://openrouter.ai/api/v1
    Supports fallback models via model string like "model1,model2".
    """

    name = "openrouter"

    def __init__(
        self,
        model: str = "anthropic/claude-sonnet-4",
        base_url: str | None = None,
        api_key: str | None = None,
        max_retries: int = 3,
        rate_limit_tpm: int = 5000,
        timeout: float = 120.0,
    ) -> None:
        if base_url is None:
            base_url = "https://openrouter.ai/api/v1"
        default_headers = {
            "HTTP-Referer": "https://deephunter.dev",
            "X-Title": "DeepHunter",
        }
        super().__init__(
            model=model,
            base_url=base_url,
            api_key=api_key,
            max_retries=max_retries,
            rate_limit_tpm=rate_limit_tpm,
            timeout=timeout,
        )
        # Set OpenRouter-specific headers on the client
        self._client._client._custom_headers = default_headers  # noqa: SLF001
