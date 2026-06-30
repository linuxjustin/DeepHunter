"""Agent orchestration — multi-agent coordination framework."""

from deephunter.agents.agent import BaseAgent
from deephunter.agents.base import Agent, AgentRegistry, AgentResult
from deephunter.agents.context import AgentExecutionContext
from deephunter.agents.dependency_graph import DependencyGraph
from deephunter.agents.events import (
    AgentEvent,
    AgentEventBus,
    AgentExecutionCompletedEvent,
    AgentExecutionFailedEvent,
    AgentExecutionStartedEvent,
)
from deephunter.agents.models import (
    AgentCapability,
    AgentDependency,
    AgentExecutionPlan,
    AgentMessage,
    AgentRequest,
    AgentResponse,
    AgentStatus,
    ExecutionStrategyType,
)
from deephunter.agents.orchestrator import AgentOrchestrator
from deephunter.agents.orchestrator_v2 import AgentOrchestratorV2
from deephunter.agents.registry import AgentRegistryV2
from deephunter.agents.strategies import (
    ConditionalStrategy,
    ExecutionStrategy,
    FanInStrategy,
    FanOutStrategy,
    ParallelStrategy,
    PipelineStrategy,
    SequentialStrategy,
)

default_registry = AgentRegistry()

__all__ = [
    "Agent",
    "AgentResult",
    "AgentRegistry",
    "default_registry",
    "AgentOrchestrator",
    # --- v2 ---
    "BaseAgent",
    "AgentStatus",
    "AgentCapability",
    "AgentDependency",
    "AgentMessage",
    "AgentRequest",
    "AgentResponse",
    "AgentExecutionPlan",
    "ExecutionStrategyType",
    "AgentEvent",
    "AgentEventBus",
    "AgentExecutionStartedEvent",
    "AgentExecutionCompletedEvent",
    "AgentExecutionFailedEvent",
    "AgentExecutionContext",
    "DependencyGraph",
    "AgentRegistryV2",
    "ExecutionStrategy",
    "SequentialStrategy",
    "ParallelStrategy",
    "ConditionalStrategy",
    "PipelineStrategy",
    "FanOutStrategy",
    "FanInStrategy",
    "AgentOrchestratorV2",
]
