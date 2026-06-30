"""Mock LLM providers for testing.

These mocks simulate provider behavior without requiring API keys or network access.
Supports streaming simulation, tool calling, and configurable responses.
"""

from __future__ import annotations

import json
import time
from collections.abc import Generator
from dataclasses import dataclass, field
from typing import Any

from deephunter.llm.base import LLMChunk, LLMMessage, LLMProvider, LLMResponse, ToolDefinition


@dataclass
class MockResponse:
    """Configurable mock response."""

    content: str = "Mock response"
    model: str = "mock-model"
    finish_reason: str = "stop"
    usage: dict[str, int] = field(default_factory=lambda: {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30})
    tool_calls: list[dict] = field(default_factory=list)
    latency_ms: float = 50.0


class MockProvider(LLMProvider):
    """Mock provider that returns configurable responses without network access."""

    name = "mock"

    def __init__(
        self,
        model: str = "mock-model",
        mock_response: MockResponse | None = None,
        fail_after: int = 0,
        fail_with: Exception | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(model, **kwargs)
        self._mock_response = mock_response or MockResponse()
        self._fail_after = fail_after
        self._fail_with = fail_with
        self._call_count = 0
        self._last_messages: list[LLMMessage] = []
        self._last_kwargs: dict[str, Any] = {}

    def _generate(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
        tools: list[ToolDefinition] | None = None,
    ) -> LLMResponse:
        self._call_count += 1
        self._last_messages = messages
        self._last_kwargs = {"temperature": temperature, "max_tokens": max_tokens, "json_mode": json_mode, "tools": tools}

        if self._fail_with and (self._fail_after <= 0 or self._call_count > self._fail_after):
            raise self._fail_with

        if self._fail_after > 0 and self._call_count <= self._fail_after:
            from deephunter.core.exceptions import RateLimitError

            raise RateLimitError("Mock rate limit")

        resp = self._mock_response
        content = resp.content

        if json_mode:
            try:
                json.loads(content)
            except Exception:
                content = '{"result": "mock_json_response"}'

        return LLMResponse(
            content=content,
            model=resp.model or self._model,
            usage=resp.usage,
            tool_calls=resp.tool_calls,
            finish_reason=resp.finish_reason,
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
        resp = self._mock_response
        words = resp.content.split()
        full_content = []

        for i, word in enumerate(words):
            yield LLMChunk(content=word + (" " if i < len(words) - 1 else ""))
            full_content.append(word)
            time.sleep(0.001)

        full = " ".join(full_content)
        return LLMResponse(
            content=full,
            model=resp.model or self._model,
            usage=resp.usage,
            finish_reason=resp.finish_reason,
        )

    def check_health(self) -> bool:
        return True

    @property
    def call_count(self) -> int:
        return self._call_count

    @property
    def last_messages(self) -> list[LLMMessage]:
        return self._last_messages

    @property
    def last_kwargs(self) -> dict[str, Any]:
        return self._last_kwargs


class StreamingMockProvider(MockProvider):
    """Mock provider that simulates streaming responses."""

    name = "mock-streaming"

    def __init__(
        self,
        model: str = "mock-streaming-model",
        chunks: list[str] | None = None,
        chunk_delay_ms: float = 10.0,
        **kwargs: Any,
    ) -> None:
        super().__init__(model, **kwargs)
        self._chunks = chunks or ["This ", "is ", "a ", "streaming ", "response."]
        self._chunk_delay_ms = chunk_delay_ms

    def _generate_stream(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
        tools: list[ToolDefinition] | None = None,
    ) -> Generator[LLMChunk, None, LLMResponse]:
        full_content = []
        for chunk_text in self._chunks:
            yield LLMChunk(content=chunk_text)
            full_content.append(chunk_text)
            if self._chunk_delay_ms > 0:
                time.sleep(self._chunk_delay_ms / 1000.0)

        return LLMResponse(
            content="".join(full_content),
            model=self._model,
            usage={"prompt_tokens": 10, "completion_tokens": len(full_content), "total_tokens": 10 + len(full_content)},
            finish_reason="stop",
        )


class ToolCallingMockProvider(MockProvider):
    """Mock provider that simulates tool calling."""

    name = "mock-tool-calling"

    def __init__(
        self,
        model: str = "mock-tool-model",
        tool_response: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(model, **kwargs)
        self._tool_response = tool_response

    def _generate(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
        tools: list[ToolDefinition] | None = None,
    ) -> LLMResponse:
        if tools:
            return LLMResponse(
                content="I'll use a tool to help with this.",
                model=self._model,
                usage={"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
                tool_calls=[
                    {
                        "id": "tool_call_1",
                        "type": "function",
                        "function": {
                            "name": tools[0].name,
                            "arguments": json.dumps({"input": "test"}),
                        },
                    }
                ],
                finish_reason="tool_calls",
            )

        return super()._generate(messages, temperature=temperature, max_tokens=max_tokens, json_mode=json_mode, tools=tools)


class FallbackSequenceProvider:
    """Simulates a provider that fails and falls back.

    Useful for testing fallback chain behavior.
    """

    def __init__(self, providers: list[MockProvider]) -> None:
        self._providers = providers
        self._current_index = 0

    def get_next_provider(self) -> MockProvider | None:
        if self._current_index < len(self._providers):
            provider = self._providers[self._current_index]
            self._current_index += 1
            return provider
        return None

    def reset(self) -> None:
        self._current_index = 0


def create_mock_provider(
    provider_type: str = "mock",
    **kwargs: Any,
) -> MockProvider:
    """Factory to create mock providers by type."""
    mock_types = {
        "mock": MockProvider,
        "streaming": StreamingMockProvider,
        "tool_calling": ToolCallingMockProvider,
    }
    cls = mock_types.get(provider_type, MockProvider)
    return cls(**kwargs)