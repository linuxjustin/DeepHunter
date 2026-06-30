"""Model Router & Provider Abstraction Layer.

Selects the best AI provider and model for a given task based on
capabilities, task type, configuration, and fallback chains.

Completely provider-independent.  No AI, no API calls, no API keys.
"""

from deephunter.router.capabilities import (
    Capability,
    TaskType,
    get_capabilities_for_task,
    get_capabilities_for_task_str,
    TASK_CAPABILITY_MAP,
)
from deephunter.router.config import RouterConfig
from deephunter.router.events import (
    FallbackStartedEvent,
    ProviderFailedEvent,
    ProviderRegisteredEvent,
    ProviderSelectedEvent,
    RouteCompletedEvent,
    RouteFailedEvent,
    RouterEvent,
    RouterEventBus,
)
from deephunter.router.models import (
    ExecutionContext,
    ModelInfo,
    ModelRequest,
    ModelResponse,
    ProviderMetadata,
    ProviderStatus,
    RoutingDecision,
    RoutingMetrics,
)
from deephunter.router.provider import (
    LegacyProviderAdapter,
    ModelProvider,
)
from deephunter.router.registry import ProviderRegistry
from deephunter.router.router import ModelRouter

__all__ = [
    # Config
    "RouterConfig",
    # Capabilities
    "Capability",
    "TaskType",
    "TASK_CAPABILITY_MAP",
    "get_capabilities_for_task",
    "get_capabilities_for_task_str",
    # Models
    "ExecutionContext",
    "ModelInfo",
    "ModelRequest",
    "ModelResponse",
    "ProviderMetadata",
    "ProviderStatus",
    "RoutingDecision",
    "RoutingMetrics",
    # Providers
    "LegacyProviderAdapter",
    "ModelProvider",
    # Registry
    "ProviderRegistry",
    # Router
    "ModelRouter",
    # Events
    "FallbackStartedEvent",
    "ProviderFailedEvent",
    "ProviderRegisteredEvent",
    "ProviderSelectedEvent",
    "RouteCompletedEvent",
    "RouteFailedEvent",
    "RouterEvent",
    "RouterEventBus",
]
