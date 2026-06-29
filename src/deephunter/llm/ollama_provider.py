"""Ollama LLM provider.

Connects to a local Ollama instance for running models like
DeepSeek, Qwen, Llama, and others.
"""

from __future__ import annotations

from typing import Any

import httpx

from deephunter.core.exceptions import ReasoningError
from deephunter.llm.base import LLMProvider, LLMResponse
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class OllamaProvider(LLMProvider):
    """LLM provider for Ollama (local models).

    Connects to a running Ollama instance (default: http://localhost:11434)
    and supports any model served by Ollama.
    """

    def __init__(
        self,
        model: str = "deepseek-coder:6.7b",
        base_url: str = "http://localhost:11434",
        timeout: float = 120.0,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {},
        }
        if system_prompt:
            payload["system"] = system_prompt
        if temperature is not None:
            payload["options"]["temperature"] = temperature
        if max_tokens is not None:
            payload["options"]["num_predict"] = max_tokens

        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(f"{self._base_url}/api/generate", json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.RequestError as exc:
            raise ReasoningError(f"Ollama request failed: {exc}") from exc

        content = data.get("response", "")
        usage = {
            "prompt_tokens": data.get("prompt_eval_count", 0),
            "completion_tokens": data.get("eval_count", 0),
        }

        logger.debug(
            "Ollama generate: model=%s tokens=%d",
            self._model,
            usage.get("completion_tokens", 0),
        )
        return LLMResponse(content=content, model=self._model, usage=usage, raw=data)

    def generate_batch(
        self,
        prompts: list[str],
        system_prompt: str | None = None,
    ) -> list[LLMResponse]:
        return [self.generate(p, system_prompt=system_prompt) for p in prompts]
