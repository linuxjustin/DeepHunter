"""Agent Orchestrator v2 — coordinates multi-agent execution with strategies,
event bus, dependency graph, and platform integration.

Builds on the legacy ``AgentOrchestrator`` with typed execution plans,
strategy selection, and integrated event bus.
"""

from __future__ import annotations

import time
from typing import Any

from deephunter.agents.agent import BaseAgent
from deephunter.agents.context import AgentExecutionContext
from deephunter.agents.dependency_graph import DependencyGraph
from deephunter.agents.events import (
    AgentEventBus,
    PlanExecutionCompletedEvent,
    PlanExecutionFailedEvent,
    PlanExecutionStartedEvent,
)
from deephunter.agents.models import (
    AgentExecutionPlan,
    AgentResponse,
    ExecutionStrategyType,
)
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
from deephunter.core.config import AgentConfig


class AgentOrchestratorV2:
    """Coordinates agent execution with strategies, events, and dependency management.

    Usage::

        orch = AgentOrchestratorV2()
        orch.register_agent(MyAgent())
        context = AgentExecutionContext(shared_data={"target": "https://example.com"})
        results = orch.execute_sequential(["MyAgent"], context)
    """

    def __init__(
        self,
        registry: AgentRegistryV2 | None = None,
        config: AgentConfig | None = None,
        event_bus: AgentEventBus | None = None,
        dependency_graph: DependencyGraph | None = None,
    ) -> None:
        self._registry = registry or AgentRegistryV2()
        self._config = config or AgentConfig()
        self._event_bus = event_bus or AgentEventBus()
        self._dependency_graph = dependency_graph or DependencyGraph()

    # --- Properties -----------------------------------------------------------

    @property
    def registry(self) -> AgentRegistryV2:
        return self._registry

    @property
    def config(self) -> AgentConfig:
        return self._config

    @property
    def event_bus(self) -> AgentEventBus:
        return self._event_bus

    @property
    def dependency_graph(self) -> DependencyGraph:
        return self._dependency_graph

    # --- Agent lifecycle ------------------------------------------------------

    def register_agent(self, agent: BaseAgent) -> None:
        self._registry.register(agent)
        for dep in agent.dependencies:
            self._dependency_graph.add_dependency(agent.name, dep.agent_name)

    def deregister_agent(self, name: str) -> None:
        self._registry.deregister(name)
        self._dependency_graph.remove_node(name)

    def get_agent(self, name: str) -> BaseAgent | None:
        return self._registry.get(name)

    def list_agents(self) -> list[BaseAgent]:
        return self._registry.list_agents()

    # --- Strategy resolution --------------------------------------------------

    def _resolve_strategy(
        self, strategy_type: str | ExecutionStrategyType
    ) -> ExecutionStrategy:
        if isinstance(strategy_type, str):
            strategy_type = ExecutionStrategyType(strategy_type)

        strategies: dict[ExecutionStrategyType, type[ExecutionStrategy]] = {
            ExecutionStrategyType.SEQUENTIAL: SequentialStrategy,
            ExecutionStrategyType.PARALLEL: ParallelStrategy,
            ExecutionStrategyType.CONDITIONAL: ConditionalStrategy,
            ExecutionStrategyType.PIPELINE: PipelineStrategy,
            ExecutionStrategyType.FAN_OUT: FanOutStrategy,
            ExecutionStrategyType.FAN_IN: FanInStrategy,
        }

        cls = strategies.get(strategy_type)
        if cls is None:
            raise ValueError(f"Unknown strategy: {strategy_type}")

        return cls()

    # --- Single agent execution -----------------------------------------------

    def execute(
        self,
        agent_name: str,
        context: AgentExecutionContext | None = None,
    ) -> AgentResponse:
        """Execute a single agent by name."""
        agent = self._registry.get(agent_name)
        if agent is None:
            raise ValueError(f"Unknown agent: {agent_name}")

        ctx = context or AgentExecutionContext()
        strategy = SequentialStrategy()
        results = strategy.execute([agent], ctx, self._event_bus)
        return results[0] if results else AgentResponse(agent_name=agent_name, success=False, error="No result")

    # --- Multi-agent execution ------------------------------------------------

    def execute_sequential(
        self,
        agent_names: list[str],
        context: AgentExecutionContext,
    ) -> list[AgentResponse]:
        agents = self._resolve_agents(agent_names)
        strategy = SequentialStrategy()
        return strategy.execute(agents, context, self._event_bus)

    def execute_parallel(
        self,
        agent_names: list[str],
        context: AgentExecutionContext,
    ) -> list[AgentResponse]:
        agents = self._resolve_agents(agent_names)
        strategy = ParallelStrategy(max_workers=self._config.max_concurrency)
        return strategy.execute(agents, context, self._event_bus)

    def execute_pipeline(
        self,
        agent_names: list[str],
        context: AgentExecutionContext,
    ) -> list[AgentResponse]:
        agents = self._resolve_agents(agent_names)
        strategy = PipelineStrategy()
        return strategy.execute(agents, context, self._event_bus)

    def execute_fan_out(
        self,
        agent_names: list[str],
        context: AgentExecutionContext,
    ) -> list[AgentResponse]:
        agents = self._resolve_agents(agent_names)
        strategy = FanOutStrategy()
        return strategy.execute(agents, context, self._event_bus)

    def execute_fan_in(
        self,
        agent_names: list[str],
        context: AgentExecutionContext,
        merge_fn: Any = None,
    ) -> list[AgentResponse]:
        agents = self._resolve_agents(agent_names)
        strategy = FanInStrategy(merge_fn=merge_fn)
        return strategy.execute(agents, context, self._event_bus)

    # --- Plan-based execution -------------------------------------------------

    def execute_plan(
        self,
        plan: AgentExecutionPlan,
        context: AgentExecutionContext | None = None,
    ) -> list[AgentResponse]:
        if plan.strategy == ExecutionStrategyType.SEQUENTIAL:
            return self.execute_sequential(plan.agent_names, context or AgentExecutionContext())
        elif plan.strategy == ExecutionStrategyType.PARALLEL:
            return self.execute_parallel(plan.agent_names, context or AgentExecutionContext())
        elif plan.strategy == ExecutionStrategyType.PIPELINE:
            return self.execute_pipeline(plan.agent_names, context or AgentExecutionContext())
        elif plan.strategy == ExecutionStrategyType.FAN_OUT:
            return self.execute_fan_out(plan.agent_names, context or AgentExecutionContext())
        elif plan.strategy == ExecutionStrategyType.FAN_IN:
            return self.execute_fan_in(plan.agent_names, context or AgentExecutionContext())
        else:
            raise ValueError(f"Unsupported plan strategy: {plan.strategy}")

    # --- Dependency-aware execution -------------------------------------------

    def execute_with_dependencies(
        self,
        agent_names: list[str] | None = None,
        context: AgentExecutionContext | None = None,
    ) -> list[AgentResponse]:
        """Execute agents respecting the dependency graph.

        Agents in the same topological level run in parallel.
        Levels run sequentially.
        """
        names = agent_names or self._dependency_graph.nodes
        ctx = context or AgentExecutionContext()
        levels = self._dependency_graph.execution_order(names)
        all_responses: list[AgentResponse] = []

        for level in levels:
            agents = self._resolve_agents(level)
            strategy = ParallelStrategy(max_workers=self._config.max_concurrency)
            responses = strategy.execute(agents, ctx, self._event_bus)
            for resp in responses:
                if resp.success and resp.output_data:
                    ctx.shared_data.update(resp.output_data)
            all_responses.extend(responses)

        return all_responses

    # --- Internal helpers -----------------------------------------------------

    def _resolve_agents(self, names: list[str]) -> list[BaseAgent]:
        agents: list[BaseAgent] = []
        for name in names:
            agent = self._registry.get(name)
            if agent is None:
                raise ValueError(f"Unknown agent: {name}")
            agents.append(agent)
        return agents
