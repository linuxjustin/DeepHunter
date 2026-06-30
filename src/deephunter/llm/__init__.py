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
from deephunter.llm.claude_provider import ClaudeProvider
from deephunter.llm.deepseek_provider import DeepSeekProvider
from deephunter.llm.gemini_provider import GeminiProvider
from deephunter.llm.metrics import (
    CostTracker,
    MetricsCollector,
    ProviderMetrics,
    ProviderStatus,
    RequestMetrics,
    TokenUsage,
    calculate_cost,
    get_metrics_collector,
)
from deephunter.llm.ollama_provider import OllamaProvider
from deephunter.llm.openai_provider import OpenAIProvider
from deephunter.llm.openrouter_provider import OpenRouterProvider
from deephunter.llm.profiles import (
    PRESET_PROFILES,
    ProfileManager,
    ProviderProfile,
    get_profile_manager,
)
from deephunter.llm.registry import (
    ProviderConfig,
    ProviderRegistry,
    SelectionStrategy,
    get_provider_registry,
)
from deephunter.llm.session import (
    AISession,
    AISessionManager,
    ContextLevel,
    Message,
    SessionConfig,
    SessionStatus,
)

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
    "CostTracker",
    "MetricsCollector",
    "ProviderMetrics",
    "ProviderStatus",
    "RequestMetrics",
    "TokenUsage",
    "calculate_cost",
    "get_metrics_collector",
    "AISession",
    "AISessionManager",
    "ContextLevel",
    "Message",
    "SessionConfig",
    "SessionStatus",
    "ProviderConfig",
    "ProviderRegistry",
    "SelectionStrategy",
    "get_provider_registry",
    "ProviderProfile",
    "ProfileManager",
    "PRESET_PROFILES",
    "get_profile_manager",
]
