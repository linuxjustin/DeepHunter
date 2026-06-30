"""Execution strategies for the Agent Orchestration Framework v2.

Each strategy implements a different coordination pattern:
sequential, parallel, conditional branching, pipeline (chain),
fan-out (same input), and fan-in (merge results).
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from deephunter.agents.agent import BaseAgent
from deephunter.agents.context import AgentExecutionContext
from deephunter.agents.events import (
    AgentBlockedEvent,
    AgentEventBus,
    AgentExecutionCompletedEvent,
    AgentExecutionFailedEvent,
    AgentExecutionStartedEvent,
    AgentExecutionRetryingEvent,
)
from deephunter.agents.models import AgentRequest, AgentResponse


class ExecutionStrategy(ABC):
    """Abstract base for all execution strategies."""

    @abstractmethod
    def execute(
        self,
        agents: list[BaseAgent],
        context: AgentExecutionContext,
        event_bus: AgentEventBus,
        plan_id: str = "",
        **kwargs: Any,
    ) -> list[AgentResponse]:
        ...


def _run_single_agent(
    agent: BaseAgent,
    context: AgentExecutionContext,
    event_bus: AgentEventBus,
    plan_id: str = "",
    input_data: dict[str, Any] | None = None,
) -> AgentResponse:
    """Execute a single agent with lifecycle hooks and retries."""
    request = AgentRequest(
        agent_name=agent.name,
        task_type="",
        input_data=input_data or {},
        context_id=context.id,
        timeout_seconds=agent.timeout_seconds,
    )

    event_bus.emit(
        AgentExecutionStartedEvent(
            agent_name=agent.name,
            plan_id=plan_id,
            request_id=request.id,
            task_type=request.task_type,
        )
    )

    agent.on_start(request)
    start = time.perf_counter()
    max_retries = getattr(agent, "max_retries", 0)

    for attempt in range(max_retries + 1):
        try:
            result = agent.execute(input_data or dict(context.shared_data))
            elapsed = (time.perf_counter() - start) * 1000
            response = AgentResponse(
                agent_name=agent.name,
                success=result.success,
                output_data=result.data if isinstance(result.data, dict) else {"result": result.data},
                error=result.error or "",
                execution_time_ms=elapsed,
                retry_attempt=attempt,
            )
            if result.success:
                agent.on_completed(request, response)
                event_bus.emit(
                    AgentExecutionCompletedEvent(
                        agent_name=agent.name,
                        plan_id=plan_id,
                        request_id=request.id,
                        success=True,
                        execution_time_ms=elapsed,
                    )
                )
            else:
                agent.on_failed(request, response)
                event_bus.emit(
                    AgentExecutionFailedEvent(
                        agent_name=agent.name,
                        plan_id=plan_id,
                        request_id=request.id,
                        error=result.error or "Unknown error",
                    )
                )
            return response
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            error = str(exc)
            if attempt < max_retries:
                agent.on_retry(request, attempt + 1, error)
                event_bus.emit(
                    AgentExecutionRetryingEvent(
                        agent_name=agent.name,
                        plan_id=plan_id,
                        request_id=request.id,
                        attempt=attempt + 1,
                        error=error,
                    )
                )
                time.sleep(1.0)
                continue
            response = AgentResponse(
                agent_name=agent.name,
                success=False,
                error=error,
                execution_time_ms=elapsed,
                retry_attempt=attempt,
            )
            agent.on_failed(request, response)
            event_bus.emit(
                AgentExecutionFailedEvent(
                    agent_name=agent.name,
                    plan_id=plan_id,
                    request_id=request.id,
                    error=error,
                )
            )
            return response

    return AgentResponse(
        agent_name=agent.name,
        success=False,
        error="Max retries exceeded",
    )


class SequentialStrategy(ExecutionStrategy):
    """Run agents one after another, each receiving the full context."""

    def execute(
        self,
        agents: list[BaseAgent],
        context: AgentExecutionContext,
        event_bus: AgentEventBus,
        plan_id: str = "",
        **kwargs: Any,
    ) -> list[AgentResponse]:
        responses: list[AgentResponse] = []
        for agent in agents:
            response = _run_single_agent(agent, context, event_bus, plan_id)
            context.set_output(agent.name, response)
            if response.success and response.output_data:
                context.shared_data.update(response.output_data)
            responses.append(response)
        return responses


class ParallelStrategy(ExecutionStrategy):
    """Run agents concurrently using threading."""

    def __init__(self, max_workers: int = 4) -> None:
        self._max_workers = max_workers

    def execute(
        self,
        agents: list[BaseAgent],
        context: AgentExecutionContext,
        event_bus: AgentEventBus,
        plan_id: str = "",
        **kwargs: Any,
    ) -> list[AgentResponse]:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        responses: list[AgentResponse] = []
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            fut_to_agent = {
                executor.submit(
                    _run_single_agent, agent, context, event_bus, plan_id
                ): agent
                for agent in agents
            }
            for future in as_completed(fut_to_agent):
                agent = fut_to_agent[future]
                try:
                    response = future.result(timeout=agent.timeout_seconds)
                except Exception as exc:
                    response = AgentResponse(
                        agent_name=agent.name,
                        success=False,
                        error=str(exc),
                    )
                context.set_output(agent.name, response)
                if response.success and response.output_data:
                    context.shared_data.update(response.output_data)
                responses.append(response)
        return responses


class ConditionalStrategy(ExecutionStrategy):
    """Execute a subset of agents based on a condition function.

    The condition receives the context and should return the index
    (or name) of the agent to run.  If it returns None, no agent runs.
    """

    def __init__(self, condition_fn: Callable[[AgentExecutionContext], str | int | None]) -> None:
        self._condition_fn = condition_fn

    def execute(
        self,
        agents: list[BaseAgent],
        context: AgentExecutionContext,
        event_bus: AgentEventBus,
        plan_id: str = "",
        **kwargs: Any,
    ) -> list[AgentResponse]:
        selected = self._condition_fn(context)
        if selected is None:
            return []
        if isinstance(selected, int):
            agent = agents[selected]
        else:
            matched = [a for a in agents if a.name == selected]
            if not matched:
                return []
            agent = matched[0]
        response = _run_single_agent(agent, context, event_bus, plan_id)
        context.set_output(agent.name, response)
        if response.success and response.output_data:
            context.shared_data.update(response.output_data)
        return [response]


class PipelineStrategy(ExecutionStrategy):
    """Chain agents so each receives the previous agent's output as input."""

    def execute(
        self,
        agents: list[BaseAgent],
        context: AgentExecutionContext,
        event_bus: AgentEventBus,
        plan_id: str = "",
        **kwargs: Any,
    ) -> list[AgentResponse]:
        responses: list[AgentResponse] = []
        current_input: dict[str, Any] = dict(context.shared_data)

        for agent in agents:
            response = _run_single_agent(
                agent, context, event_bus, plan_id, input_data=current_input
            )
            context.set_output(agent.name, response)
            responses.append(response)
            if response.success:
                current_input = dict(response.output_data)
            else:
                break

        return responses


class FanOutStrategy(ExecutionStrategy):
    """Run all agents with the same input in parallel."""

    def execute(
        self,
        agents: list[BaseAgent],
        context: AgentExecutionContext,
        event_bus: AgentEventBus,
        plan_id: str = "",
        **kwargs: Any,
    ) -> list[AgentResponse]:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        input_data = dict(context.shared_data)
        responses: list[AgentResponse] = []

        with ThreadPoolExecutor() as executor:
            fut_to_agent = {
                executor.submit(
                    _run_single_agent, agent, context, event_bus, plan_id, input_data
                ): agent
                for agent in agents
            }
            for future in as_completed(fut_to_agent):
                agent = fut_to_agent[future]
                try:
                    response = future.result(timeout=agent.timeout_seconds)
                except Exception as exc:
                    response = AgentResponse(
                        agent_name=agent.name,
                        success=False,
                        error=str(exc),
                    )
                context.set_output(agent.name, response)
                if response.success and response.output_data:
                    context.shared_data.update(response.output_data)
                responses.append(response)
        return responses


class FanInStrategy(ExecutionStrategy):
    """Run all agents with the same input, then merge results.

    The merge function receives a dict of ``{agent_name: AgentResponse}``
    and returns a merged ``dict[str, Any]`` that is stored in context.
    """

    def __init__(
        self,
        merge_fn: Callable[
            [dict[str, AgentResponse]], dict[str, Any]
        ] | None = None,
    ) -> None:
        self._merge_fn = merge_fn or self._default_merge

    @staticmethod
    def _default_merge(
        responses: dict[str, AgentResponse],
    ) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for name, resp in responses.items():
            if resp.success:
                merged[name] = resp.output_data
        return merged

    def execute(
        self,
        agents: list[BaseAgent],
        context: AgentExecutionContext,
        event_bus: AgentEventBus,
        plan_id: str = "",
        **kwargs: Any,
    ) -> list[AgentResponse]:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        input_data = dict(context.shared_data)
        responses: dict[str, AgentResponse] = {}

        with ThreadPoolExecutor() as executor:
            fut_map = {
                executor.submit(
                    _run_single_agent, agent, context, event_bus, plan_id, input_data
                ): agent
                for agent in agents
            }
            for future in as_completed(fut_map):
                agent = fut_map[future]
                try:
                    resp = future.result(timeout=agent.timeout_seconds)
                except Exception as exc:
                    resp = AgentResponse(
                        agent_name=agent.name,
                        success=False,
                        error=str(exc),
                    )
                responses[agent.name] = resp
                context.set_output(agent.name, resp)

        merged = self._merge_fn(responses)
        context.shared_data.update(merged)
        return list(responses.values())
