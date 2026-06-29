"""Agent orchestrator — coordinates multi-agent research workflows.

The orchestrator manages sequential and parallel execution of agents,
shared context propagation, and result aggregation.
"""

from __future__ import annotations

import time
from typing import Any

from deephunter.agents.base import AgentRegistry, AgentResult
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class AgentOrchestrator:
    """Coordinates execution of multiple agents in a research pipeline.

    Supports running agents sequentially (each output feeds the next)
    or in parallel groups.

    Usage::

        orch = AgentOrchestrator()
        context = {"target": "https://example.com", "tags": ["jwt"]}
        results = orch.run_sequential(["KnowledgeAgent", "ReasoningAgent"], context)
    """

    def __init__(self, agent_registry: AgentRegistry | None = None) -> None:
        self._agent_registry = agent_registry or AgentRegistry()
        self._results: dict[str, AgentResult] = {}

    def run_sequential(
        self,
        agent_names: list[str],
        context: dict[str, Any],
    ) -> list[AgentResult]:
        """Run agents one after another, passing context forward.

        Args:
            agent_names: Ordered list of agent names to execute.
            context: Initial shared context dictionary.

        Returns:
            List of AgentResult objects in execution order.

        Raises:
            ValueError: If an agent name is not registered.
        """
        results: list[AgentResult] = []
        current_context = dict(context)

        for name in agent_names:
            agent_cls = self._agent_registry.get(name)
            if agent_cls is None:
                raise ValueError(f"Unknown agent: {name}")

            agent = agent_cls()
            logger.info("Running agent: %s", name)

            try:
                start = time.monotonic()
                result = agent.execute(current_context)
                elapsed = (time.monotonic() - start) * 1000
                result.execution_time_ms = elapsed
            except Exception as exc:
                result = AgentResult(
                    agent_name=name,
                    success=False,
                    error=str(exc),
                )
                logger.error("Agent %s failed: %s", name, exc)

            self._results[result.result_id] = result
            results.append(result)

            if result.success and isinstance(result.data, dict):
                current_context.update(result.data)

        return results

    def run_parallel(
        self,
        agent_names: list[str],
        context: dict[str, Any],
    ) -> list[AgentResult]:
        """Run agents in parallel (sequentially in current implementation).

        Args:
            agent_names: List of agent names to execute.
            context: Shared context for all agents.

        Returns:
            List of AgentResult objects.

        Note:
            Currently executes sequentially. A future version may use
            concurrent.futures for true parallelism.
        """
        return self.run_sequential(agent_names, context)

    def get_result(self, result_id: str) -> AgentResult | None:
        """Retrieve a stored result by its ID."""
        return self._results.get(result_id)

    def clear_results(self) -> None:
        self._results.clear()
