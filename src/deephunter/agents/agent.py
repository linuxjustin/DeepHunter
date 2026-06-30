"""Extended agent base class with capabilities, metadata, and dependencies.

``BaseAgent`` extends the legacy ``Agent`` ABC with richer metadata,
capability discovery, dependency declarations, health checks, and
lifecycle hooks — while remaining backward-compatible.
"""

from __future__ import annotations

from typing import Any

from deephunter.agents.base import Agent, AgentResult
from deephunter.agents.models import (
    AgentCapability,
    AgentDependency,
    AgentRequest,
    AgentResponse,
    AgentStatus,
)


class BaseAgent(Agent):
    """Extended agent with capabilities, dependencies, and lifecycle hooks.

    Subclasses must implement ``execute`` (from ``Agent``) and
    optionally override lifecycle hooks for richer orchestration.
    """

    def __init__(self, name: str | None = None) -> None:
        super().__init__(name)
        self._version = "1.0.0"
        self._capabilities: list[AgentCapability] = []
        self._dependencies: list[AgentDependency] = []
        self._supported_tasks: list[str] = []
        self._priority: int = 50
        self._status: AgentStatus = AgentStatus.IDLE
        self._tags: list[str] = []
        self._max_retries: int = 3
        self._timeout_seconds: float = 300.0

    # --- Properties -----------------------------------------------------------

    @property
    def version(self) -> str:
        return self._version

    @property
    def capabilities(self) -> list[AgentCapability]:
        return self._capabilities

    @property
    def dependencies(self) -> list[AgentDependency]:
        return self._dependencies

    @property
    def supported_tasks(self) -> list[str]:
        return self._supported_tasks

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def status(self) -> AgentStatus:
        return self._status

    @property
    def tags(self) -> list[str]:
        return self._tags

    @property
    def max_retries(self) -> int:
        return self._max_retries

    @property
    def timeout_seconds(self) -> float:
        return self._timeout_seconds

    # --- Lifecycle hooks ------------------------------------------------------

    def on_start(self, request: AgentRequest) -> None:
        """Called before execution begins."""
        self._status = AgentStatus.RUNNING

    def on_completed(self, request: AgentRequest, response: AgentResponse) -> None:
        """Called after successful execution."""
        self._status = AgentStatus.COMPLETED

    def on_failed(self, request: AgentRequest, response: AgentResponse) -> None:
        """Called after failed execution."""
        self._status = AgentStatus.FAILED

    def on_retry(self, request: AgentRequest, attempt: int, error: str) -> None:
        """Called when execution is being retried."""
        self._status = AgentStatus.RUNNING

    # --- Capability & task discovery ------------------------------------------

    def can_execute(self, task: str) -> bool:
        if not self._supported_tasks:
            return True
        return task in self._supported_tasks

    def has_capability(self, name: str) -> bool:
        return any(c.name == name for c in self._capabilities)

    # --- Request/Response lifecycle -------------------------------------------

    def validate_request(self, request: AgentRequest) -> bool:
        return True

    def prepare_response(self, result: AgentResult) -> AgentResponse:
        return AgentResponse(
            agent_name=self.name,
            success=result.success,
            output_data=result.data if isinstance(result.data, dict) else {"result": result.data},
            error=result.error or "",
            execution_time_ms=result.execution_time_ms,
        )

    # --- Health & metadata ----------------------------------------------------

    def health(self) -> bool:
        return self._status not in (AgentStatus.FAILED, AgentStatus.CANCELLED)

    def metadata(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self._description,
            "version": self._version,
            "status": self._status.value,
            "priority": self._priority,
            "supported_tasks": self._supported_tasks,
            "tags": self._tags,
            "capabilities": [c.model_dump() for c in self._capabilities],
            "dependencies": [d.model_dump() for d in self._dependencies],
            "max_retries": self._max_retries,
            "timeout_seconds": self._timeout_seconds,
        }
