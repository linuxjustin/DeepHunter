"""OpenAI-compatible LLM provider.

Supports OpenAI API, Azure OpenAI, Together AI, Groq, and any
OpenAI-compatible endpoint. Features streaming, JSON mode, tool calling,
and structured outputs.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

from deephunter.core.exceptions import LLMError
from deephunter.llm.base import (
    LLMChunk,
    LLMMessage,
    LLMProvider,
    LLMResponse,
    ToolDefinition,
    message_as_dict,
)
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class OpenAIProvider(LLMProvider):
    """Production OpenAI-compatible provider with streaming, JSON mode, and tools."""

    name = "openai"

    def __init__(
        self,
        model: str = "gpt-4o",
        base_url: str | None = None,
        api_key: str | None = None,
        max_retries: int = 3,
        rate_limit_tpm: int = 10000,
        timeout: float = 120.0,
    ) -> None:
        super().__init__(model, max_retries=max_retries, rate_limit_tpm=rate_limit_tpm, timeout=timeout)
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise LLMError("openai package required. Install with: pip install deephunter[openai]") from exc
        try:
            self._client = OpenAI(api_key=api_key, base_url=base_url, timeout=self._timeout, max_retries=0)  # we do our own retry
        except Exception as exc:
            raise LLMError(f"Failed to create OpenAI client: {exc}") from exc

    def _generate(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
        tools: list[ToolDefinition] | None = None,
    ) -> LLMResponse:
        from openai import APIError, RateLimitError as OpenAIRateLimitError

        kwargs = self._build_kwargs(messages, temperature=temperature, max_tokens=max_tokens, json_mode=json_mode, tools=tools, stream=False)
        try:
            resp = self._client.chat.completions.create(**kwargs)
        except OpenAIRateLimitError as exc:
            from deephunter.core.exceptions import RateLimitError
            raise RateLimitError(str(exc)) from exc
        except APIError as exc:
            raise LLMError(f"OpenAI API error: {exc}") from exc

        choice = resp.choices[0]
        content = choice.message.content or ""
        tool_calls_raw = choice.message.tool_calls
        tool_calls = []
        if tool_calls_raw:
            tool_calls = [
                {"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in tool_calls_raw
            ]

        return LLMResponse(
            content=content,
            model=resp.model or self._model,
            usage={
                "prompt_tokens": resp.usage.prompt_tokens if resp.usage else 0,
                "completion_tokens": resp.usage.completion_tokens if resp.usage else 0,
                "total_tokens": resp.usage.total_tokens if resp.usage else 0,
            },
            tool_calls=tool_calls,
            finish_reason=choice.finish_reason or "",
            raw=resp,
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
        from openai import APIError, RateLimitError as OpenAIRateLimitError

        kwargs = self._build_kwargs(messages, temperature=temperature, max_tokens=max_tokens, json_mode=json_mode, tools=tools, stream=True)
        try:
            stream = self._client.chat.completions.create(**kwargs)
        except OpenAIRateLimitError as exc:
            from deephunter.core.exceptions import RateLimitError
            raise RateLimitError(str(exc)) from exc
        except APIError as exc:
            raise LLMError(f"OpenAI API error: {exc}") from exc

        full_content: list[str] = []
        model_used = self._model
        usage: dict[str, int] = {}
        finish_reason = ""

        for chunk in stream:
            delta = chunk.choices[0].delta if chunk.choices else None
            if not delta:
                continue
            if delta.content:
                full_content.append(delta.content)
                yield LLMChunk(content=delta.content)
            if chunk.usage:
                usage = {
                    "prompt_tokens": chunk.usage.prompt_tokens or 0,
                    "completion_tokens": chunk.usage.completion_tokens or 0,
                    "total_tokens": chunk.usage.total_tokens or 0,
                }
            if chunk.choices and chunk.choices[0].finish_reason:
                finish_reason = chunk.choices[0].finish_reason
            model_used = chunk.model or model_used

        return LLMResponse(
            content="".join(full_content),
            model=model_used,
            usage=usage,
            finish_reason=finish_reason,
        )

    def _build_kwargs(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
        tools: list[ToolDefinition] | None = None,
        stream: bool = False,
    ) -> dict[str, Any]:
        api_messages = [message_as_dict(m) for m in messages]
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": api_messages,
            "stream": stream,
        }
        if temperature is not None:
            kwargs["temperature"] = temperature
        if max_tokens is not None:
            kwargs["max_tokens"] = max_tokens
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        if tools:
            kwargs["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    },
                }
                for t in tools
            ]
            kwargs["tool_choice"] = "auto"
        return kwargs

    def check_health(self) -> bool:
        try:
            self._client.models.list()
            return True
        except Exception:
            return False
