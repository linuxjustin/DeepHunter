"""Agent orchestration — multi-agent coordination framework."""

from deephunter.agents.base import Agent, AgentRegistry, AgentResult
from deephunter.agents.orchestrator import AgentOrchestrator

default_registry = AgentRegistry()

__all__ = [
    "Agent",
    "AgentResult",
    "AgentRegistry",
    "default_registry",
    "AgentOrchestrator",
]
