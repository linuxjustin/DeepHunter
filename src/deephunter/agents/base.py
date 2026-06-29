"""Base agent interface and registry.

Agents are composable units of work that perform a specific task
in the research pipeline — parsing, reasoning, retrieval, reporting.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Type
from uuid import uuid4


@dataclass
class AgentResult:
    """Result produced by an agent execution."""

    agent_name: str
    success: bool
    data: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    result_id: str = field(default_factory=lambda: f"res-{uuid4().hex[:12]}")
    created: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class Agent(ABC):
    """Abstract base for all agents.

    Each agent has a name, description, and implements ``execute``.
    Agents are registered globally and can be discovered by the
    orchestrator.
    """

    def __init__(self, name: Optional[str] = None) -> None:
        self._name = name or self.__class__.__name__
        self._description = ""

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @abstractmethod
    def execute(self, context: Dict[str, Any]) -> AgentResult:
        """Execute the agent's task.

        Args:
            context: A dictionary of input parameters and shared state.

        Returns:
            An AgentResult with the output.
        """


class AgentRegistry:
    """Registry of available agent classes."""

    _agents: Dict[str, Type[Agent]] = {}

    @classmethod
    def register(cls, agent_cls: Type[Agent]) -> Type[Agent]:
        """Register an agent class by its name.

        Can be used as a decorator::

            @AgentRegistry.register
            class MyAgent(Agent): ...
        """
        name = agent_cls.__name__
        if name in cls._agents:
            raise ValueError(f"Agent '{name}' is already registered")
        cls._agents[name] = agent_cls
        return agent_cls

    @classmethod
    def get(cls, name: str) -> Optional[Type[Agent]]:
        return cls._agents.get(name)

    @classmethod
    def list_names(cls) -> List[str]:
        return list(cls._agents.keys())

    @classmethod
    def clear(cls) -> None:
        cls._agents.clear()