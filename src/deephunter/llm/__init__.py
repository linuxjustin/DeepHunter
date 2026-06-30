"""LLM abstraction layer — multi-model provider support.

Production-grade providers with streaming, JSON mode, tool calling,
structured output, retry, and rate limiting.
"""

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

__all__ = [
    "ClaudeProvider",
    "DeepSeekProvider",
    "GeminiProvider",
    "LLMChunk",
    "LLMMessage",
    "LLMProvider",
    "LLMProviderFactory",
    "LLMResponse",
    "OllamaProvider",
    "OpenAIProvider",
    "OpenRouterProvider",
    "TokenBucket",
    "ToolDefinition",
    "message_as_dict",
    "retry_with_backoff",
    "strip_json_fence",
]
