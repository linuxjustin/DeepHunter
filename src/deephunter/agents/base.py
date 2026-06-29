"""Base agent interface and registry.

Agents are composable units of work that perform a specific task
in the research pipeline — parsing, reasoning, retrieval, reporting.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


@dataclass
class AgentResult:
    """Result produced by an agent execution."""

    agent_name: str
    success: bool
    data: Any = None
    error: str | None = None
    execution_time_ms: float = 0.0
    result_id: str = field(default_factory=lambda: f"res-{uuid4().hex[:12]}")
    created: datetime = field(default_factory=lambda: datetime.now(UTC))


class Agent(ABC):
    """Abstract base for all agents.

    Each agent has a name, description, and implements ``execute``.
    Agents are registered globally and can be discovered by the
    orchestrator.
    """

    def __init__(self, name: str | None = None) -> None:
        self._name = name or self.__class__.__name__
        self._description = ""

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @abstractmethod
    def execute(self, context: dict[str, Any]) -> AgentResult:
        """Execute the agent's task.

        Args:
            context: A dictionary of input parameters and shared state.

        Returns:
            An AgentResult with the output.
        """


class AgentRegistry:
    """Registry of available agent classes."""

    def __init__(self) -> None:
        self._agents: dict[str, type[Agent]] = {}

    def register(self, agent_cls: type[Agent]) -> type[Agent]:
        """Register an agent class by its name.

        Can be used as a decorator::

            registry = AgentRegistry()

            @registry.register
            class MyAgent(Agent): ...
        """
        name = agent_cls.__name__
        if name in self._agents:
            raise ValueError(f"Agent '{name}' is already registered")
        self._agents[name] = agent_cls
        return agent_cls

    def get(self, name: str) -> type[Agent] | None:
        return self._agents.get(name)

    def list_names(self) -> list[str]:
        return list(self._agents.keys())

    def clear(self) -> None:
        self._agents.clear()
