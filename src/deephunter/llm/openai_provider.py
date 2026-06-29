"""OpenAI-compatible LLM provider.

Supports OpenAI API, and any OpenAI-compatible endpoint
(e.g. Azure OpenAI, Together AI, Groq, etc.).
"""

from __future__ import annotations

from deephunter.core.exceptions import ReasoningError
from deephunter.llm.base import LLMProvider, LLMResponse
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class OpenAIProvider(LLMProvider):
    """LLM provider for OpenAI-compatible APIs.

    Supports GPT-4, GPT-4o, GPT-3.5, and any custom endpoint
    that implements the OpenAI chat completions interface.
    """

    def __init__(
        self,
        model: str = "gpt-4o",
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 120.0,
    ) -> None:
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ReasoningError(
                "openai package is required. Install with: pip install deephunter[openai]"
            ) from exc

        self._model = model
        self._client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout)

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        kwargs = {"model": self._model, "messages": messages}
        if temperature is not None:
            kwargs["temperature"] = temperature
        if max_tokens is not None:
            kwargs["max_tokens"] = max_tokens

        try:
            resp = self._client.chat.completions.create(**kwargs)
        except Exception as exc:
            raise ReasoningError(f"OpenAI API call failed: {exc}") from exc

        choice = resp.choices[0]
        content = choice.message.content or ""

        usage = {
            "prompt_tokens": resp.usage.prompt_tokens if resp.usage else 0,
            "completion_tokens": resp.usage.completion_tokens if resp.usage else 0,
        }

        logger.debug(
            "OpenAI generate: model=%s tokens=%d",
            self._model,
            usage.get("completion_tokens", 0),
        )
        return LLMResponse(content=content, model=self._model, usage=usage, raw=resp)

    def generate_batch(
        self,
        prompts: list[str],
        system_prompt: str | None = None,
    ) -> list[LLMResponse]:
        return [self.generate(p, system_prompt=system_prompt) for p in prompts]
