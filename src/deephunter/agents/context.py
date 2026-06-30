"""Execution context for the Agent Orchestration Framework v2.

Provides typed shared state that flows through agent executions,
similar to ``PlannerContext`` in the planning module.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from deephunter.agents.models import AgentResponse


class AgentExecutionContext(BaseModel):
    """Shared context passed through agent executions.

    Carries input data, accumulated results, and optional references
    to the Context Engine and Prompt Builder.
    """

    id: str = Field(default_factory=lambda: f"ctx-{uuid4().hex[:12]}")
    shared_data: dict[str, Any] = Field(default_factory=dict)
    agent_results: dict[str, AgentResponse] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def get_output(self, agent_name: str, key: str, default: Any = None) -> Any:
        result = self.agent_results.get(agent_name)
        if result is not None and result.success:
            return result.output_data.get(key, default)
        return default

    def set_output(self, agent_name: str, response: AgentResponse) -> None:
        self.agent_results[agent_name] = response

    def all_successful(self) -> bool:
        return all(r.success for r in self.agent_results.values())

    def failed_agents(self) -> list[str]:
        return [name for name, r in self.agent_results.items() if not r.success]

    def merge(self, agent_name: str, data: dict[str, Any]) -> None:
        self.shared_data.update(data)
        self.metadata[f"merged_from_{agent_name}"] = list(data.keys())
