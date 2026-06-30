"""Instance-based agent registry for the Agent Orchestration Framework v2.

Unlike the class-based ``AgentRegistry`` in ``base.py``, this registry
holds live agent instances with lifecycle support.
"""

from __future__ import annotations

from typing import Any

from deephunter.agents.models import AgentCapability


class AgentRegistryV2:
    """Registry of live agent instances."""

    def __init__(self) -> None:
        self._agents: dict[str, Any] = {}

    def register(self, agent: Any) -> None:
        name = getattr(agent, "name", agent.__class__.__name__)
        if name in self._agents:
            raise ValueError(f"Agent '{name}' is already registered")
        self._agents[name] = agent

    def deregister(self, name: str) -> None:
        self._agents.pop(name, None)

    def get(self, name: str) -> Any | None:
        return self._agents.get(name)

    def list_agents(self) -> list[Any]:
        return list(self._agents.values())

    def list_names(self) -> list[str]:
        return list(self._agents.keys())

    def clear(self) -> None:
        self._agents.clear()

    def find_by_task(self, task_type: str) -> list[Any]:
        results: list[Any] = []
        for agent in self._agents.values():
            capabilities: list[AgentCapability] = getattr(
                agent, "capabilities", []
            )
            if isinstance(capabilities, AgentCapability):
                capabilities = [capabilities]
            for cap in capabilities:
                if task_type in cap.supported_tasks:
                    results.append(agent)
                    break
        return results

    def find_by_capability(self, capability_name: str) -> list[Any]:
        results: list[Any] = []
        for agent in self._agents.values():
            capabilities: list[AgentCapability] = getattr(
                agent, "capabilities", []
            )
            if isinstance(capabilities, AgentCapability):
                capabilities = [capabilities]
            for cap in capabilities:
                if cap.name == capability_name:
                    results.append(agent)
                    break
        return results

    def __len__(self) -> int:
        return len(self._agents)

    def __contains__(self, name: str) -> bool:
        return name in self._agents
