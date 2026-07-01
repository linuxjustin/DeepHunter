"""Anthropic Claude LLM provider.

Uses the Anthropic Python SDK to support Claude models (Claude 4 Sonnet,
Claude 3.5 Haiku, etc.) with streaming, JSON mode, and tool calling.
"""

from __future__ import annotations

import json
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


class ClaudeProvider(LLMProvider):
    """Production Claude provider with streaming, JSON mode, and tools."""

    name = "claude"

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        base_url: str | None = None,
        api_key: str | None = None,
        max_retries: int = 3,
        rate_limit_tpm: int = 5000,
        timeout: float = 120.0,
    ) -> None:
        super().__init__(model, max_retries=max_retries, rate_limit_tpm=rate_limit_tpm, timeout=timeout)
        try:
            from anthropic import Anthropic
        except ImportError as exc:
            raise LLMError("anthropic package required. Install with: pip install anthropic") from exc
        self._client = Anthropic(api_key=api_key, timeout=self._timeout, max_retries=0)

    def _build_messages(self, messages: list[LLMMessage]) -> tuple[list[dict], str]:
        system = ""
        api_messages = []
        for m in messages:
            if m.role == "system":
                system = m.content
            elif m.role == "tool":
                api_messages.append({
                    "role": "user",
                    "content": [{"type": "tool_result", "tool_use_id": m.tool_call_id or "", "content": m.content}],
                })
            else:
                content: list[dict] = []
                if m.content:
                    content.append({"type": "text", "text": m.content})
                if m.tool_calls:
                    for tc in m.tool_calls:
                        content.append({
                            "type": "tool_use",
                            "id": tc.get("id", ""),
                            "name": tc.get("function", {}).get("name", ""),
                            "input": tc.get("function", {}).get("arguments", {}),
                        })
                api_messages.append({"role": m.role, "content": content})
        return api_messages, system

    def _generate(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
        tools: list[ToolDefinition] | None = None,
    ) -> LLMResponse:
        from anthropic import APIStatusError, RateLimitError as AnthRateLimit

        api_messages, system = self._build_messages(messages)

        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": api_messages,
            "max_tokens": max_tokens or 4096,
        }
        if system:
            kwargs["system"] = system
        if temperature is not None:
            kwargs["temperature"] = temperature
        if json_mode:
            kwargs["system"] = (
                kwargs.get("system", "") + "\n\nIMPORTANT: Respond with ONLY valid JSON. No markdown fences."
            ).strip()
        if tools:
            kwargs["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.parameters}
                for t in tools
            ]

        try:
            resp = self._client.messages.create(**kwargs)
        except AnthRateLimit as exc:
            from deephunter.core.exceptions import RateLimitError

            raise RateLimitError(str(exc)) from exc
        except APIStatusError as exc:
            raise LLMError(f"Claude API error: {exc}") from exc

        content = ""
        tool_calls = []
        for block in resp.content:
            if block.type == "text":
                content += block.text
            elif block.type == "tool_use":
                tool_calls.append({
                    "id": block.id,
                    "type": "function",
                    "function": {"name": block.name, "arguments": json.dumps(block.input)},
                })

        return LLMResponse(
            content=content,
            model=resp.model,
            usage={
                "input_tokens": resp.usage.input_tokens,
                "output_tokens": resp.usage.output_tokens,
            },
            tool_calls=tool_calls,
            finish_reason=resp.stop_reason or "",
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
        from anthropic import APIStatusError, RateLimitError as AnthRateLimit

        api_messages, system = self._build_messages(messages)

        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": api_messages,
            "max_tokens": max_tokens or 4096,
        }
        if system:
            kwargs["system"] = system
        if temperature is not None:
            kwargs["temperature"] = temperature
        if json_mode:
            kwargs["system"] = (
                kwargs.get("system", "") + "\n\nIMPORTANT: Respond with ONLY valid JSON."
            ).strip()
        if tools:
            kwargs["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.parameters}
                for t in tools
            ]
        kwargs["stream"] = True

        try:
            stream = self._client.messages.create(**kwargs)
        except AnthRateLimit as exc:
            from deephunter.core.exceptions import RateLimitError

            raise RateLimitError(str(exc)) from exc
        except APIStatusError as exc:
            raise LLMError(f"Claude API error: {exc}") from exc

        full_content: list[str] = []
        model_used = self._model
        usage: dict[str, int] = {}

        for event in stream:
            if event.type == "content_block_delta" and event.delta.type == "text_delta":
                full_content.append(event.delta.text)
                yield LLMChunk(content=event.delta.text)
            if event.type == "message_delta":
                if event.usage:
                    usage = {
                        "input_tokens": event.usage.input_tokens or 0,
                        "output_tokens": event.usage.output_tokens or 0,
                    }
                model_used = event.model or model_used

        return LLMResponse(content="".join(full_content), model=model_used, usage=usage)

    def check_health(self) -> bool:
        try:
            self._client.messages.create(
                model=self._model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=1,
            )
            return True
        except Exception:
            return False
