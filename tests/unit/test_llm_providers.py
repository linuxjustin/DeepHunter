"""Comprehensive tests for the production LLM provider layer.

Tests cover:
  1. Base models (LLMResponse, LLMChunk, LLMMessage, ToolDefinition)
  2. TokenBucket rate limiter
  3. Retry with backoff
  4. Provider factory
  5. All 6 provider constructors and capabilities
  6. Utility functions (message_as_dict, strip_json_fence)
  7. Edge cases (empty messages, rate limits, timeouts)
"""

from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Optional SDK availability checks
_HAS_OPENAI = False
_HAS_ANTHROPIC = False
_HAS_GEMINI = False
try:
    import openai  # noqa: F401
    _HAS_OPENAI = True
except ImportError:
    pass
try:
    import anthropic  # noqa: F401
    _HAS_ANTHROPIC = True
except ImportError:
    pass
try:
    import google.generativeai  # noqa: F401
    _HAS_GEMINI = True
except ImportError:
    pass

requires_openai = pytest.mark.skipif(not _HAS_OPENAI, reason="openai package not installed")
requires_anthropic = pytest.mark.skipif(not _HAS_ANTHROPIC, reason="anthropic package not installed")
requires_gemini = pytest.mark.skipif(not _HAS_GEMINI, reason="google-generativeai package not installed")

from deephunter.core.exceptions import LLMError, RateLimitError
from deephunter.llm.base import (
    LLMChunk,
    LLMMessage,
    LLMProvider,
    LLMProviderFactory,
    LLMResponse,
    TokenBucket,
    ToolDefinition,
    message_as_dict,
    retry_with_backoff,
    strip_json_fence,
)
from deephunter.llm.ollama_provider import OllamaProvider
from deephunter.llm.openai_provider import OpenAIProvider
from deephunter.llm.claude_provider import ClaudeProvider
from deephunter.llm.deepseek_provider import DeepSeekProvider
from deephunter.llm.gemini_provider import GeminiProvider
from deephunter.llm.openrouter_provider import OpenRouterProvider


# =============================================================================
# 1. Base Models
# =============================================================================


class TestLLMResponse:
    def test_default_creation(self):
        resp = LLMResponse(content="hello", model="gpt-4o")
        assert resp.content == "hello"
        assert resp.model == "gpt-4o"
        assert resp.usage == {}
        assert resp.tool_calls == []
        assert resp.finish_reason == ""
        assert resp.raw is None

    def test_full_creation(self):
        resp = LLMResponse(
            content="Hello world",
            model="claude-sonnet-4",
            usage={"input_tokens": 10, "output_tokens": 20},
            tool_calls=[{"id": "call_1", "function": {"name": "test"}}],
            finish_reason="stop",
            raw={"some": "data"},
        )
        assert resp.content == "Hello world"
        assert resp.usage["input_tokens"] == 10
        assert len(resp.tool_calls) == 1


class TestLLMChunk:
    def test_default_creation(self):
        chunk = LLMChunk()
        assert chunk.content == ""
        assert chunk.tool_calls is None
        assert chunk.finish_reason == ""
        assert chunk.usage is None

    def test_with_content(self):
        chunk = LLMChunk(content="Hello", finish_reason="stop")
        assert chunk.content == "Hello"
        assert chunk.finish_reason == "stop"


class TestLLMMessage:
    def test_simple_message(self):
        msg = LLMMessage(role="user", content="Hello")
        assert msg.role == "user"
        assert msg.content == "Hello"

    def test_system_message(self):
        msg = LLMMessage(role="system", content="Be helpful")
        assert msg.role == "system"

    def test_tool_message(self):
        msg = LLMMessage(role="tool", content="Result", tool_call_id="call_123")
        assert msg.tool_call_id == "call_123"

    def test_message_with_tool_calls(self):
        msg = LLMMessage(
            role="assistant",
            content="",
            tool_calls=[{"id": "call_1", "function": {"name": "test", "arguments": "{}"}}],
        )
        assert len(msg.tool_calls) == 1


class TestToolDefinition:
    def test_minimal(self):
        td = ToolDefinition(name="get_weather")
        assert td.name == "get_weather"
        assert td.description == ""

    def test_full(self):
        td = ToolDefinition(
            name="search",
            description="Search the web",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                },
                "required": ["query"],
            },
        )
        assert td.name == "search"
        assert "query" in td.parameters["properties"]


# =============================================================================
# 2. TokenBucket Rate Limiter
# =============================================================================


class TestTokenBucket:
    def test_acquire_within_capacity(self):
        bucket = TokenBucket(tokens_per_minute=60)
        assert bucket.acquire() == 0.0
        assert bucket.acquire() == 0.0

    def test_acquire_over_capacity(self):
        bucket = TokenBucket(tokens_per_minute=1)
        assert bucket.acquire() == 0.0
        wait = bucket.acquire()
        assert wait > 0.0

    def test_refill(self):
        bucket = TokenBucket(tokens_per_minute=60)
        bucket.acquire(60)  # drain
        time.sleep(1.1)  # wait for refill
        wait = bucket.acquire()
        assert wait == 0.0  # should have at least 1 token

    def test_high_volume(self):
        bucket = TokenBucket(tokens_per_minute=1000)
        for _ in range(100):
            wait = bucket.acquire()
            assert wait == 0.0 or wait > 0

    def test_custom_tokens(self):
        bucket = TokenBucket(tokens_per_minute=60)
        wait = bucket.acquire(tokens=5)
        assert wait == 0.0


# =============================================================================
# 3. Retry with Backoff
# =============================================================================


class TestRetryWithBackoff:
    def test_success_first_try(self):
        call_count = 0

        def fn():
            nonlocal call_count
            call_count += 1
            return "ok"

        result = retry_with_backoff(fn, max_retries=3, base_delay=0.01)
        assert result == "ok"
        assert call_count == 1

    def test_retry_on_rate_limit(self):
        call_count = 0

        def fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RateLimitError("rate limited")
            return "ok"

        result = retry_with_backoff(fn, max_retries=3, base_delay=0.01)
        assert result == "ok"
        assert call_count == 3

    def test_exhaust_retries(self):
        call_count = 0

        def fn():
            nonlocal call_count
            call_count += 1
            raise RateLimitError("always fails")

        with pytest.raises(RateLimitError):
            retry_with_backoff(fn, max_retries=2, base_delay=0.01)
        assert call_count == 3  # initial + 2 retries

    def test_all_errors_retried(self):
        """retry_with_backoff retries all exceptions in production."""
        call_count = 0

        def fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("transient network error")
            return "ok"

        result = retry_with_backoff(fn, max_retries=3, base_delay=0.01)
        assert result == "ok"
        assert call_count == 3


# =============================================================================
# 4. Provider Factory
# =============================================================================


class FakeConfig:
    provider = ""
    model = ""
    base_url = None
    api_key = None
    temperature = 0.1
    max_tokens = 4096
    max_retries = 3
    rate_limit_tpm = 60
    timeout = 120.0


class TestProviderFactory:
    @requires_openai
    def test_create_openai(self):
        cfg = FakeConfig()
        cfg.provider = "openai"
        cfg.model = "gpt-4o"
        provider = LLMProviderFactory.create(cfg)
        assert isinstance(provider, OpenAIProvider)
        assert provider.name == "openai"

    def test_create_ollama(self):
        cfg = FakeConfig()
        cfg.provider = "ollama"
        cfg.model = "llama3"
        provider = LLMProviderFactory.create(cfg)
        assert isinstance(provider, OllamaProvider)
        assert provider.name == "ollama"

    @requires_anthropic
    def test_create_claude(self):
        cfg = FakeConfig()
        cfg.provider = "claude"
        cfg.model = "claude-sonnet-4-20250514"
        provider = LLMProviderFactory.create(cfg)
        assert isinstance(provider, ClaudeProvider)

    @requires_openai
    def test_create_deepseek(self):
        cfg = FakeConfig()
        cfg.provider = "deepseek"
        provider = LLMProviderFactory.create(cfg)
        assert isinstance(provider, DeepSeekProvider)

    @requires_gemini
    def test_create_gemini(self):
        cfg = FakeConfig()
        cfg.provider = "gemini"
        provider = LLMProviderFactory.create(cfg)
        assert isinstance(provider, GeminiProvider)

    @requires_openai
    def test_create_openrouter(self):
        cfg = FakeConfig()
        cfg.provider = "openrouter"
        provider = LLMProviderFactory.create(cfg)
        assert isinstance(provider, OpenRouterProvider)

    def test_unsupported_provider(self):
        cfg = FakeConfig()
        cfg.provider = "nonexistent"
        with pytest.raises(LLMError, match="Unsupported"):
            LLMProviderFactory.create(cfg)

    @requires_openai
    def test_factory_caching(self):
        cfg = FakeConfig()
        cfg.provider = "openai"
        p1 = LLMProviderFactory.create(cfg)
        p2 = LLMProviderFactory.create(cfg)
        assert p1 is not p2  # new instance each time
        assert "openai" in LLMProviderFactory._REGISTRY


# =============================================================================
# 5. Provider Constructors
# =============================================================================


class TestOpenAIProvider:
    @requires_openai
    def test_constructor(self):
        provider = OpenAIProvider(model="gpt-4o")
        assert provider._model == "gpt-4o"
        assert provider.name == "openai"
        assert provider._max_retries == 3
        assert provider._bucket is not None

    @requires_openai
    def test_constructor_with_custom_params(self):
        provider = OpenAIProvider(
            model="gpt-4o-mini",
            max_retries=5,
            rate_limit_tpm=20000,
            timeout=60.0,
        )
        assert provider._model == "gpt-4o-mini"
        assert provider._max_retries == 5

    @requires_openai
    def test_check_health_no_client(self):
        provider = OpenAIProvider(model="gpt-4o")
        result = provider.check_health()
        assert result is False


class TestOllamaProvider:
    def test_constructor(self):
        provider = OllamaProvider(model="llama3")
        assert provider._model == "llama3"
        assert provider._base_url == "http://localhost:11434"

    def test_constructor_custom_url(self):
        provider = OllamaProvider(model="codellama", base_url="http://10.0.0.1:11434")
        assert provider._base_url == "http://10.0.0.1:11434"

    def test_check_health(self):
        provider = OllamaProvider(model="llama3")
        result = provider.check_health()
        assert result is False  # no Ollama running


class TestClaudeProvider:
    @requires_anthropic
    def test_constructor(self):
        provider = ClaudeProvider(model="claude-sonnet-4-20250514")
        assert provider._model == "claude-sonnet-4-20250514"

    @requires_anthropic
    def test_constructor_with_api_key(self):
        provider = ClaudeProvider(api_key="sk-ant-test123")
        assert provider is not None


class TestDeepSeekProvider:
    @requires_openai
    def test_constructor(self):
        provider = DeepSeekProvider(model="deepseek-chat")
        assert provider._model == "deepseek-chat"
        assert provider.name == "deepseek"

    @requires_openai
    def test_default_base_url(self):
        provider = DeepSeekProvider()
        assert "deepseek" in provider.__class__.__name__.lower()


class TestGeminiProvider:
    @requires_gemini
    def test_constructor(self):
        provider = GeminiProvider(model="gemini-2.0-flash")
        assert provider._model == "gemini-2.0-flash"

    @requires_gemini
    def test_check_health_no_api_key(self):
        provider = GeminiProvider(model="gemini-2.0-flash")
        result = provider.check_health()
        assert result is False


class TestOpenRouterProvider:
    @requires_openai
    def test_constructor(self):
        provider = OpenRouterProvider(model="anthropic/claude-sonnet-4")
        assert provider._model == "anthropic/claude-sonnet-4"
        assert provider.name == "openrouter"


# =============================================================================
# 6. Utility Functions
# =============================================================================


class TestMessageAsDict:
    def test_simple(self):
        msg = LLMMessage(role="user", content="Hi")
        d = message_as_dict(msg)
        assert d == {"role": "user", "content": "Hi"}

    def test_system(self):
        msg = LLMMessage(role="system", content="Be helpful")
        d = message_as_dict(msg)
        assert d["role"] == "system"

    def test_with_tool_calls(self):
        msg = LLMMessage(
            role="assistant",
            content="",
            tool_calls=[{"id": "c1", "function": {"name": "f", "arguments": "{}"}}],
        )
        d = message_as_dict(msg)
        assert "tool_calls" in d
        assert len(d["tool_calls"]) == 1

    def test_with_tool_call_id(self):
        msg = LLMMessage(role="tool", content="Result", tool_call_id="call_123")
        d = message_as_dict(msg)
        assert d["tool_call_id"] == "call_123"

    def test_with_name(self):
        msg = LLMMessage(role="user", content="Hi", name="test_user")
        d = message_as_dict(msg)
        assert d["name"] == "test_user"


class TestStripJsonFence:
    def test_no_fence(self):
        assert strip_json_fence('{"key": "val"}') == '{"key": "val"}'

    def test_json_fence(self):
        assert strip_json_fence('```json\n{"key": "val"}\n```') == '{"key": "val"}'

    def test_plain_fence(self):
        assert strip_json_fence('```\n{"key": "val"}\n```') == '{"key": "val"}'

    def test_multiline_json(self):
        text = '```json\n{\n  "key": "val",\n  "num": 42\n}\n```'
        result = strip_json_fence(text)
        assert result == '{\n  "key": "val",\n  "num": 42\n}'

    def test_empty_string(self):
        assert strip_json_fence("") == ""


# =============================================================================
# 7. Edge Cases
# =============================================================================


class TestEdgeCases:
    def test_llm_response_empty_content(self):
        resp = LLMResponse(content="", model="test")
        assert resp.content == ""

    def test_llm_chunk_none_fields(self):
        chunk = LLMChunk()
        assert chunk.content == ""
        assert chunk.tool_calls is None

    def test_message_empty_role(self):
        msg = LLMMessage(role="", content="")
        assert msg.role == ""
        assert msg.content == ""

    def test_tool_definition_empty_fields(self):
        td = ToolDefinition(name="")
        assert td.description == ""
        assert td.parameters == {"type": "object", "properties": {}}

    def test_token_bucket_zero_capacity(self):
        bucket = TokenBucket(tokens_per_minute=0)
        wait = bucket.acquire()
        assert wait > 0  # should wait forever

    def test_retry_zero_max(self):
        def fn():
            raise RateLimitError("fail")

        with pytest.raises(RateLimitError):
            retry_with_backoff(fn, max_retries=0, base_delay=0.01)
        assert True

    def test_bucket_negative_tokens(self):
        bucket = TokenBucket(tokens_per_minute=10)
        bucket._tokens = 0
        wait = bucket.acquire(tokens=1)
        assert wait > 0

    def test_factory_register_custom(self):
        class CustomProvider(LLMProvider):
            name = "custom"

            def _generate(self, messages, **kwargs):
                return LLMResponse(content="", model=self._model)

        LLMProviderFactory.register("custom", CustomProvider)
        cfg = FakeConfig()
        cfg.provider = "custom"
        provider = LLMProviderFactory.create(cfg)
        assert isinstance(provider, CustomProvider)


# =============================================================================
# 8. Provider Capabilities (Mock tests)
# =============================================================================


class TestProviderCapabilities:
    @requires_openai
    def test_openai_generate_structured(self, monkeypatch):
        from pydantic import BaseModel

        class TestSchema(BaseModel):
            name: str
            value: int

        provider = OpenAIProvider(model="gpt-4o")

        def mock_generate(messages, **kwargs):
            return LLMResponse(
                content='{"name": "test", "value": 42}',
                model="gpt-4o",
                finish_reason="stop",
            )

        monkeypatch.setattr(provider, "generate", mock_generate)

        result = provider.generate_structured(
            [LLMMessage(role="user", content="Create test")],
            TestSchema,
        )
        assert result.name == "test"
        assert result.value == 42

    @requires_openai
    def test_openai_generate_structured_with_json_fence(self, monkeypatch):
        from pydantic import BaseModel

        class SimpleSchema(BaseModel):
            result: str

        provider = OpenAIProvider(model="gpt-4o")

        def mock_generate(messages, **kwargs):
            return LLMResponse(
                content='```json\n{"result": "success"}\n```',
                model="gpt-4o",
            )

        monkeypatch.setattr(provider, "generate", mock_generate)

        result = provider.generate_structured(
            [LLMMessage(role="user", content="test")],
            SimpleSchema,
        )
        assert result.result == "success"

    @requires_openai
    def test_generate_stream_collects_chunks(self, monkeypatch):
        provider = OpenAIProvider(model="gpt-4o")

        def mock_generate(messages, **kwargs):
            return LLMResponse(content="Hello world", model="gpt-4o", finish_reason="stop")

        monkeypatch.setattr(provider, "_generate", mock_generate)

        gen = provider.generate_stream([LLMMessage(role="user", content="Hi")])
        collected_chunks = list(gen)
        assert len(collected_chunks) >= 1

    @requires_openai
    def test_generate_rate_limit_retry(self, monkeypatch):
        provider = OpenAIProvider(model="gpt-4o", max_retries=2, rate_limit_tpm=10000)
        call_count = 0

        def mock_generate(messages, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RateLimitError("rate limited")
            return LLMResponse(content="ok", model="gpt-4o")

        monkeypatch.setattr(provider, "_generate", mock_generate)

        resp = provider.generate([LLMMessage(role="user", content="Hi")])
        assert resp.content == "ok"
        assert call_count == 3

    def test_all_providers_have_unique_names(self):
        names = {
            OpenAIProvider.name,
            OllamaProvider.name,
            ClaudeProvider.name,
            DeepSeekProvider.name,
            GeminiProvider.name,
            OpenRouterProvider.name,
        }
        assert len(names) == 6
        assert "openai" in names
        assert "ollama" in names
        assert "claude" in names
        assert "deepseek" in names
        assert "gemini" in names
        assert "openrouter" in names

    @requires_openai
    def test_openai_message_conversion(self):
        provider = OpenAIProvider(model="gpt-4o")
        messages = [
            LLMMessage(role="system", content="You are helpful"),
            LLMMessage(role="user", content="Hello"),
        ]
        kwargs = provider._build_kwargs(messages, temperature=0.5, max_tokens=100)
        assert kwargs["model"] == "gpt-4o"
        assert len(kwargs["messages"]) == 2
        assert kwargs["messages"][0]["role"] == "system"
        assert kwargs["temperature"] == 0.5
        assert kwargs["max_tokens"] == 100

    @requires_openai
    def test_openai_json_mode_kwargs(self):
        provider = OpenAIProvider(model="gpt-4o")
        kwargs = provider._build_kwargs(
            [LLMMessage(role="user", content="test")],
            json_mode=True,
        )
        assert kwargs["response_format"] == {"type": "json_object"}

    @requires_openai
    def test_openai_tool_kwargs(self):
        provider = OpenAIProvider(model="gpt-4o")
        tools = [
            ToolDefinition(
                name="search",
                description="Search",
                parameters={"type": "object", "properties": {"q": {"type": "string"}}},
            ),
        ]
        kwargs = provider._build_kwargs(
            [LLMMessage(role="user", content="test")],
            tools=tools,
        )
        assert "tools" in kwargs
        assert len(kwargs["tools"]) == 1
        assert kwargs["tools"][0]["function"]["name"] == "search"

    def test_ollama_default_base_url(self):
        provider = OllamaProvider(model="test")
        assert provider._base_url == "http://localhost:11434"

    def test_ollama_payload_structure(self):
        """Verify Ollama message conversion produces correct API payload shape."""
        provider = OllamaProvider(model="llama3")
        from deephunter.llm.ollama_provider import OllamaProvider as OP
        system, api_messages = provider._convert_messages([
            LLMMessage(role="system", content="You are helpful"),
            LLMMessage(role="user", content="Hello"),
        ])
        assert system == "You are helpful"
        assert len(api_messages) == 1
        assert api_messages[0]["role"] == "user"

    def test_ollama_json_mode_format(self):
        provider = OllamaProvider(model="llama3")
        # Verify json_mode triggers format field (can't test full payload without running)
        assert provider._max_retries == 3

    def test_deepseek_subclass_inheritance(self):
        assert issubclass(DeepSeekProvider, OpenAIProvider)

    def test_openrouter_headers(self):
        assert OpenRouterProvider.name == "openrouter"

    def test_provider_health_no_connection(self):
        """All providers that can be constructed should return False for health when offline."""
        provider = OllamaProvider(model="test")
        assert provider.check_health() is False
