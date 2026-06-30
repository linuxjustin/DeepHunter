"""Ollama LLM provider.

Connects to a local Ollama instance for running models like
DeepSeek, Qwen, Llama, and others. Supports streaming and JSON mode.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import httpx

from deephunter.core.exceptions import LLMError
from deephunter.llm.base import (
    LLMChunk,
    LLMMessage,
    LLMProvider,
    LLMResponse,
    ToolDefinition,
)
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class OllamaProvider(LLMProvider):
    """LLM provider for Ollama (local models).

    Connects to a running Ollama instance (default: http://localhost:11434)
    and supports any model served by Ollama.
    """

    name = "ollama"

    def __init__(
        self,
        model: str = "deepseek-coder:6.7b",
        base_url: str | None = None,
        api_key: str | None = None,
        max_retries: int = 3,
        rate_limit_tpm: int = 60,
        timeout: float = 120.0,
    ) -> None:
        super().__init__(model, max_retries=max_retries, rate_limit_tpm=rate_limit_tpm, timeout=timeout)
        self._base_url = (base_url or "http://localhost:11434").rstrip("/")

    def _convert_messages(self, messages: list[LLMMessage]) -> tuple[str, list[dict]]:
        system = ""
        api_messages: list[dict] = []
        for m in messages:
            if m.role == "system":
                system = m.content
            elif m.role == "tool":
                api_messages.append({
                    "role": "user",
                    "content": f"Tool result ({m.tool_call_id}): {m.content}",
                })
            else:
                api_messages.append({"role": m.role, "content": m.content})
        return system, api_messages

    def _generate(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
        tools: list[ToolDefinition] | None = None,
    ) -> LLMResponse:
        system, api_messages = self._convert_messages(messages)

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": api_messages,
            "stream": False,
            "options": {},
        }
        if system:
            payload["system"] = system
        if temperature is not None:
            payload["options"]["temperature"] = temperature
        if max_tokens is not None:
            payload["options"]["num_predict"] = max_tokens
        if json_mode:
            payload["format"] = "json"

        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(f"{self._base_url}/api/chat", json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.RequestError as exc:
            raise LLMError(f"Ollama request failed: {exc}") from exc

        content = data.get("message", {}).get("content", "")
        return LLMResponse(
            content=content,
            model=data.get("model", self._model),
            usage={
                "prompt_tokens": data.get("prompt_eval_count", 0),
                "completion_tokens": data.get("eval_count", 0),
            },
            raw=data,
        )

    def _generate_stream(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
        tools: list[ToolDefinition] | None = None,
    ) -> Generator[LLMChunk, None, LLMResponse]:
        import json as _json

        system, api_messages = self._convert_messages(messages)

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": api_messages,
            "stream": True,
            "options": {},
        }
        if system:
            payload["system"] = system
        if temperature is not None:
            payload["options"]["temperature"] = temperature
        if max_tokens is not None:
            payload["options"]["num_predict"] = max_tokens
        if json_mode:
            payload["format"] = "json"

        try:
            with httpx.Client(timeout=self._timeout) as client:
                with client.stream("POST", f"{self._base_url}/api/chat", json=payload) as resp:
                    resp.raise_for_status()
                    full_content: list[str] = []
                    model_used = self._model
                    last_data: dict = {}
                    for line in resp.iter_lines():
                        if not line.strip():
                            continue
                        data = _json.loads(line)
                        last_data = data
                        if "message" in data and "content" in data["message"]:
                            chunk = data["message"]["content"]
                            full_content.append(chunk)
                            yield LLMChunk(content=chunk)
                        if data.get("done"):
                            model_used = data.get("model", model_used)
                            break
        except httpx.RequestError as exc:
            raise LLMError(f"Ollama stream failed: {exc}") from exc

        return LLMResponse(
            content="".join(full_content),
            model=model_used,
            usage={
                "prompt_tokens": last_data.get("prompt_eval_count", 0),
                "completion_tokens": last_data.get("eval_count", 0),
            },
        )

    def check_health(self) -> bool:
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"{self._base_url}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False
