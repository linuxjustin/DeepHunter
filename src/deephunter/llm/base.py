"""Production LLM provider abstraction.

Every provider implements:
  - Basic generation
  - Streaming (async generator)
  - JSON mode (forced valid JSON)
  - Tool / function calling
  - Structured output (Pydantic schema)
  - Retry with exponential backoff
  - Rate limiting (token bucket)
  - Health checks

The base class provides retry and rate limiting; providers
override ``_generate()`` and ``_generate_stream()``.
"""

from __future__ import annotations

import json
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Generator
from dataclasses import dataclass, field
from typing import Any, TypeVar

from pydantic import BaseModel

from deephunter.core.exceptions import LLMError, RateLimitError
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T", bound=BaseModel)

# ── Data models ──────────────────────────────────────────────────────────────


@dataclass
class LLMMessage:
    """A single message in a chat conversation."""

    role: str  # system, user, assistant, tool
    content: str
    tool_calls: list[dict] | None = None
    tool_call_id: str | None = None
    name: str | None = None


@dataclass
class ToolDefinition:
    """Definition of a tool/function the model may call."""

    name: str
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})


@dataclass
class LLMResponse:
    """Complete response from an LLM provider."""

    content: str
    model: str
    usage: dict[str, int] = field(default_factory=dict)
    tool_calls: list[dict] = field(default_factory=list)
    finish_reason: str = ""
    raw: Any = None


@dataclass
class LLMChunk:
    """A streaming chunk from an LLM provider."""

    content: str = ""
    tool_calls: list[dict] | None = None
    finish_reason: str = ""
    usage: dict[str, int] | None = None


# ── Retry & Rate Limit ───────────────────────────────────────────────────────


class TokenBucket:
    """Token bucket rate limiter — thread-safe for sequential use."""

    def __init__(self, tokens_per_minute: int = 60) -> None:
        self._capacity = float(tokens_per_minute)
        self._tokens = float(tokens_per_minute)
        self._refill_rate = tokens_per_minute / 60.0 if tokens_per_minute > 0 else 0.0
        self._last_refill = time.monotonic()

    def acquire(self, tokens: float = 1.0) -> float:
        """Acquire tokens. Returns seconds to wait (0 if available)."""
        if self._capacity <= 0:
            return float("inf")
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_rate)
        self._last_refill = now
        if self._tokens >= tokens:
            self._tokens -= tokens
            return 0.0
        wait = (tokens - self._tokens) / self._refill_rate if self._refill_rate > 0 else float("inf")
        return wait


def retry_with_backoff(
    fn, max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 30.0
) -> Any:
    """Call ``fn`` with exponential backoff retry."""
    import random
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return fn()
        except RateLimitError:
            if attempt < max_retries:
                delay = min(base_delay * (2 ** attempt) + random.uniform(0, 0.5), max_delay)
                logger.info("Rate limited, retrying in %.1fs (attempt %d/%d)", delay, attempt + 1, max_retries)
                time.sleep(delay)
            else:
                raise
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries:
                delay = min(base_delay * (2 ** attempt) + random.uniform(0, 0.5), max_delay)
                logger.warning("Retry %d/%d after error: %s", attempt + 1, max_retries, exc)
                time.sleep(delay)
            else:
                raise
    if last_exc:
        raise last_exc


# ── Abstract provider ────────────────────────────────────────────────────────


class LLMProvider(ABC):
    """Production-grade LLM provider with retry, rate limiting, and
    support for streaming, JSON mode, tool calling, and structured output.
    """

    name: str = "base"

    def __init__(
        self,
        model: str,
        *,
        max_retries: int = 3,
        rate_limit_tpm: int = 60,
        timeout: float = 120.0,
        **kwargs: Any,
    ) -> None:
        self._model = model
        self._max_retries = max_retries
        self._bucket = TokenBucket(tokens_per_minute=rate_limit_tpm)
        self._timeout = timeout

    # ── Public API ───────────────────────────────────────────────────────

    def generate(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
        tools: list[ToolDefinition] | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Generate a response with retry and rate limiting."""
        wait = self._bucket.acquire()
        if wait > 0:
            logger.debug("Rate limit wait: %.2fs", wait)
            time.sleep(wait)
        return retry_with_backoff(
            lambda: self._generate(messages, temperature=temperature, max_tokens=max_tokens, json_mode=json_mode, tools=tools, **kwargs),
            max_retries=self._max_retries,
        )

    def generate_stream(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
        tools: list[ToolDefinition] | None = None,
        **kwargs: Any,
    ) -> Generator[LLMChunk, None, LLMResponse]:
        """Stream a response. Yields chunks, returns final response."""
        wait = self._bucket.acquire()
        if wait > 0:
            logger.debug("Rate limit wait: %.2fs", wait)
            time.sleep(wait)
        yield from self._generate_stream(
            messages, temperature=temperature, max_tokens=max_tokens,
            json_mode=json_mode, tools=tools, **kwargs,
        )

    def generate_structured(
        self,
        messages: list[LLMMessage],
        schema: type[T],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> T:
        """Generate a structured (Pydantic) output. Uses JSON mode."""
        resp = self.generate(
            messages, temperature=temperature, max_tokens=max_tokens,
            json_mode=True, **kwargs,
        )
        raw = resp.content
        # Strip markdown fences if present
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0].strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LLMError(f"Structured output JSON parse failed: {exc}\nRaw: {raw[:200]}") from exc
        return schema.model_validate(data)

    def check_health(self) -> bool:
        """Check provider availability. Returns True if healthy."""
        try:
            self.generate([LLMMessage(role="user", content="ping")], max_tokens=1)
            return True
        except Exception:
            return False

    # ── Subclass interface ───────────────────────────────────────────────

    @abstractmethod
    def _generate(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
        tools: list[ToolDefinition] | None = None,
    ) -> LLMResponse:
        ...

    def _generate_stream(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
        tools: list[ToolDefinition] | None = None,
    ) -> Generator[LLMChunk, None, LLMResponse]:
        """Default: collect chunks from a single non-streaming call."""
        resp = self._generate(messages, temperature=temperature, max_tokens=max_tokens, json_mode=json_mode, tools=tools)
        yield LLMChunk(content=resp.content, finish_reason=resp.finish_reason)
        return resp


# ── Factory ──────────────────────────────────────────────────────────────────


class LLMProviderFactory:
    """Creates LLM providers from configuration."""

    _REGISTRY: dict[str, type[LLMProvider]] = {}

    @classmethod
    def register(cls, name: str, provider_cls: type[LLMProvider]) -> None:
        cls._REGISTRY[name.lower()] = provider_cls

    @classmethod
    def create(cls, config: Any) -> LLMProvider:  # noqa: ANN401
        """Create an LLM provider from any config-like object.

        Expects ``provider``, ``model``, ``base_url``, ``api_key``,
        ``temperature``, ``max_tokens`` attributes.
        """
        provider_name = getattr(config, "provider", "openai").lower()
        model = getattr(config, "model", "gpt-4o")
        base_url = getattr(config, "base_url", None)
        api_key = getattr(config, "api_key", None)
        temperature = getattr(config, "temperature", 0.1)
        max_tokens = getattr(config, "max_tokens", 4096)
        max_retries = getattr(config, "max_retries", 3)
        rate_limit_tpm = getattr(config, "rate_limit_tpm", 60)
        timeout = getattr(config, "timeout", 120.0)

        if provider_name in cls._REGISTRY:
            provider_cls = cls._REGISTRY[provider_name]
            return provider_cls(
                model=model,
                base_url=base_url,
                api_key=api_key,
                max_retries=max_retries,
                rate_limit_tpm=rate_limit_tpm,
                timeout=timeout,
            )

        # Dynamic imports for known providers
        provider_map = {
            "openai": ("deephunter.llm.openai_provider", "OpenAIProvider"),
            "ollama": ("deephunter.llm.ollama_provider", "OllamaProvider"),
            "claude": ("deephunter.llm.claude_provider", "ClaudeProvider"),
            "deepseek": ("deephunter.llm.deepseek_provider", "DeepSeekProvider"),
            "gemini": ("deephunter.llm.gemini_provider", "GeminiProvider"),
            "openrouter": ("deephunter.llm.openrouter_provider", "OpenRouterProvider"),
        }
        if provider_name not in provider_map:
            raise LLMError(f"Unsupported LLM provider: {provider_name}. Supported: {', '.join(provider_map)}")

        mod_path, cls_name = provider_map[provider_name]
        import importlib
        try:
            mod = importlib.import_module(mod_path)
        except ImportError as exc:
            raise LLMError(f"Provider {provider_name} not available: {exc}") from exc
        provider_cls = getattr(mod, cls_name)
        cls._REGISTRY[provider_name] = provider_cls
        return provider_cls(
            model=model,
            base_url=base_url,
            api_key=api_key,
            max_retries=max_retries,
            rate_limit_tpm=rate_limit_tpm,
            timeout=timeout,
        )


# ── Utility ──────────────────────────────────────────────────────────────────


def message_as_dict(msg: LLMMessage) -> dict[str, Any]:
    """Convert an LLMMessage to a provider-agnostic dict."""
    d: dict[str, Any] = {"role": msg.role, "content": msg.content}
    if msg.tool_calls:
        d["tool_calls"] = msg.tool_calls
    if msg.tool_call_id:
        d["tool_call_id"] = msg.tool_call_id
    if msg.name:
        d["name"] = msg.name
    return d


def estimate_token_count(text: str) -> int:
    """Rough token estimate (~4 chars per token)."""
    return len(text) // 4 + 1


def strip_json_fence(text: str) -> str:
    """Remove markdown JSON fences from response text."""
    text = re.sub(r"^```json\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"^```\s*$", "", text, flags=re.MULTILINE)
    return text.strip()
