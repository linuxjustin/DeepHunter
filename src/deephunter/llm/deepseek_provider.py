"""DeepSeek LLM provider — uses OpenAI-compatible API.

Default endpoint: https://api.deepseek.com/v1
Supported models: deepseek-chat, deepseek-reasoner
"""

from __future__ import annotations

from deephunter.llm.openai_provider import OpenAIProvider


class DeepSeekProvider(OpenAIProvider):
    """DeepSeek LLM provider — uses OpenAI-compatible API.

    Default endpoint: https://api.deepseek.com/v1
    Supported models: deepseek-chat, deepseek-reasoner
    """

    name = "deepseek"

    def __init__(
        self,
        model: str = "deepseek-chat",
        base_url: str | None = None,
        api_key: str | None = None,
        max_retries: int = 3,
        rate_limit_tpm: int = 5000,
        timeout: float = 120.0,
    ) -> None:
        if base_url is None:
            base_url = "https://api.deepseek.com/v1"
        super().__init__(
            model=model,
            base_url=base_url,
            api_key=api_key,
            max_retries=max_retries,
            rate_limit_tpm=rate_limit_tpm,
            timeout=timeout,
        )
