"""Tests for the agent framework."""

from __future__ import annotations

from typing import Any

import pytest

from deephunter.agents.base import Agent, AgentRegistry, AgentResult
from deephunter.agents.orchestrator import AgentOrchestrator


class TestAgent(Agent):
    def execute(self, context: dict[str, Any]) -> AgentResult:
        data = context.get("data", "default")
        return AgentResult(
            agent_name=self.name,
            success=True,
            data={"processed": data},
        )


class FailingTestAgent(Agent):
    def execute(self, context: dict[str, Any]) -> AgentResult:
        raise ValueError("Intentional failure")


@pytest.fixture
def agent_registry() -> AgentRegistry:
    reg = AgentRegistry()
    reg.register(TestAgent)
    reg.register(FailingTestAgent)
    return reg


class TestAgentResult:
    def test_create_success(self) -> None:
        result = AgentResult(agent_name="TestAgent", success=True, data={"key": "val"})
        assert result.result_id.startswith("res-")
        assert result.data == {"key": "val"}
        assert result.error is None

    def test_create_failure(self) -> None:
        result = AgentResult(agent_name="BadAgent", success=False, error="Something broke")
        assert result.success is False
        assert result.error == "Something broke"


class TestAgentRegistry:
    def test_register_and_get(self, agent_registry: AgentRegistry) -> None:
        cls = agent_registry.get("TestAgent")
        assert cls is TestAgent

        cls = agent_registry.get("Nonexistent")
        assert cls is None

    def test_duplicate_register(self, agent_registry: AgentRegistry) -> None:
        with pytest.raises(ValueError, match="already registered"):
            agent_registry.register(TestAgent)

    def test_list_names(self, agent_registry: AgentRegistry) -> None:
        names = agent_registry.list_names()
        assert "TestAgent" in names
        assert "FailingTestAgent" in names

    def test_clear(self, agent_registry: AgentRegistry) -> None:
        agent_registry.clear()
        assert agent_registry.list_names() == []


class TestAgentOrchestrator:
    def test_run_sequential_success(self, agent_registry: AgentRegistry) -> None:
        orch = AgentOrchestrator(agent_registry=agent_registry)
        results = orch.run_sequential(
            ["TestAgent"],
            {"data": "hello"},
        )
        assert len(results) == 1
        assert results[0].success is True
        assert results[0].data == {"processed": "hello"}

    def test_run_sequential_multiple(self, agent_registry: AgentRegistry) -> None:
        orch = AgentOrchestrator(agent_registry=agent_registry)
        results = orch.run_sequential(
            ["TestAgent", "TestAgent"],
            {"data": "start"},
        )
        assert len(results) == 2
        assert results[0].success is True
        assert results[1].success is True

    def test_run_sequential_unknown_agent(self) -> None:
        reg = AgentRegistry()
        orch = AgentOrchestrator(agent_registry=reg)
        with pytest.raises(ValueError, match="Unknown agent"):
            orch.run_sequential(["NonexistentAgent"], {})

    def test_run_sequential_failure(self, agent_registry: AgentRegistry) -> None:
        orch = AgentOrchestrator(agent_registry=agent_registry)
        results = orch.run_sequential(["FailingTestAgent"], {})
        assert len(results) == 1
        assert results[0].success is False
        assert "Intentional failure" in results[0].error

    def test_get_result(self, agent_registry: AgentRegistry) -> None:
        orch = AgentOrchestrator(agent_registry=agent_registry)
        results = orch.run_sequential(["TestAgent"], {"data": "x"})
        result_id = results[0].result_id

        retrieved = orch.get_result(result_id)
        assert retrieved is not None
        assert retrieved.agent_name == "TestAgent"

        assert orch.get_result("nonexistent") is None

    def test_clear_results(self, agent_registry: AgentRegistry) -> None:
        orch = AgentOrchestrator(agent_registry=agent_registry)
        orch.run_sequential(["TestAgent"], {})
        orch.clear_results()
        assert list(orch._results.keys()) == []
