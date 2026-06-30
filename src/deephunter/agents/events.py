"""Event bus for the Agent Orchestration Framework v2.

Follows the same pattern as ``PlanningEventBus``, ``ReasoningEventBus``,
and other event buses in the DeepHunter platform.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from deephunter.agents.models import AgentResponse


@dataclass
class AgentEvent:
    """Base event for all agent pipeline events."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    agent_name: str = ""
    plan_id: str = ""


@dataclass
class AgentRegisteredEvent(AgentEvent):
    """Emitted when an agent is registered."""


@dataclass
class AgentDeregisteredEvent(AgentEvent):
    """Emitted when an agent is deregistered."""


@dataclass
class AgentExecutionStartedEvent(AgentEvent):
    """Emitted when an agent begins execution."""

    request_id: str = ""
    task_type: str = ""


@dataclass
class AgentExecutionCompletedEvent(AgentEvent):
    """Emitted when an agent completes execution."""

    request_id: str = ""
    success: bool = True
    execution_time_ms: float = 0.0


@dataclass
class AgentExecutionFailedEvent(AgentEvent):
    """Emitted when an agent execution fails."""

    request_id: str = ""
    error: str = ""


@dataclass
class AgentExecutionRetryingEvent(AgentEvent):
    """Emitted when an agent execution is retried."""

    request_id: str = ""
    attempt: int = 0
    error: str = ""


@dataclass
class PlanExecutionStartedEvent(AgentEvent):
    """Emitted when an execution plan begins."""

    strategy: str = ""


@dataclass
class PlanExecutionCompletedEvent(AgentEvent):
    """Emitted when a plan finishes successfully."""

    strategy: str = ""
    total_agents: int = 0
    successful: int = 0
    failed: int = 0
    elapsed_seconds: float = 0.0


@dataclass
class PlanExecutionFailedEvent(AgentEvent):
    """Emitted when a plan execution fails."""

    strategy: str = ""
    error: str = ""


@dataclass
class AgentBlockedEvent(AgentEvent):
    """Emitted when an agent is blocked by unmet dependencies."""

    dependency: str = ""


AgentEventHandler = Callable[[AgentEvent], None]


class AgentEventBus:
    """Synchronous event bus for agent pipeline events."""

    def __init__(self) -> None:
        self._handlers: dict[type[AgentEvent], list[AgentEventHandler]] = {}

    def subscribe(
        self, event_type: type[AgentEvent], handler: AgentEventHandler
    ) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def unsubscribe(
        self, event_type: type[AgentEvent], handler: AgentEventHandler
    ) -> None:
        handlers = self._handlers.get(event_type)
        if handlers:
            try:
                handlers.remove(handler)
            except ValueError:
                pass

    def emit(self, event: AgentEvent) -> None:
        handlers = self._handlers.get(type(event), [])
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                import logging

                logging.getLogger(__name__).exception(
                    "Agent event handler %r failed for %s",
                    handler,
                    type(event).__name__,
                )

    def clear(self) -> None:
        self._handlers.clear()
