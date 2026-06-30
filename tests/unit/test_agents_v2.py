"""Tests for the Agent Orchestration Framework v2."""

from __future__ import annotations

from typing import Any

import pytest

from deephunter.agents import (
    AgentEventBus,
    AgentExecutionCompletedEvent,
    AgentExecutionFailedEvent,
    AgentExecutionStartedEvent,
    AgentExecutionContext,
    AgentOrchestratorV2,
    AgentRegistryV2,
    AgentStatus,
    BaseAgent,
    ConditionalStrategy,
    DependencyGraph,
    ExecutionStrategyType,
    FanInStrategy,
    FanOutStrategy,
    ParallelStrategy,
    PipelineStrategy,
    SequentialStrategy,
)
from deephunter.agents.base import AgentResult
from deephunter.agents.models import (
    AgentCapability,
    AgentDependency,
    AgentExecutionPlan,
    AgentMessage,
    AgentRequest,
    AgentResponse,
)
from deephunter.core.config import AgentConfig
from deephunter.core.exceptions import AgentError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class PassthroughAgent(BaseAgent):
    """Agent that returns its input unchanged."""
    def execute(self, context: dict[str, Any]) -> AgentResult:
        return AgentResult(
            agent_name=self.name,
            success=True,
            data=dict(context),
        )


class FailingAgent(BaseAgent):
    """Agent that always fails."""
    def execute(self, context: dict[str, Any]) -> AgentResult:
        raise ValueError("Intentional failure")


class TransformingAgent(BaseAgent):
    """Agent that transforms input data."""
    def execute(self, context: dict[str, Any]) -> AgentResult:
        data = dict(context)
        data["transformed"] = data.get("value", 0) * 2
        return AgentResult(
            agent_name=self.name,
            success=True,
            data=data,
        )


class ConditionAgent(BaseAgent):
    """Agent with a custom condition."""
    def execute(self, context: dict[str, Any]) -> AgentResult:
        return AgentResult(
            agent_name=self.name,
            success=True,
            data={"condition": context.get("branch", "none")},
        )


class SlowAgent(BaseAgent):
    """Agent that simulates latency."""
    def __init__(self, name: str | None = None, delay: float = 0.05) -> None:
        super().__init__(name)
        self._delay = delay

    def execute(self, context: dict[str, Any]) -> AgentResult:
        import time
        time.sleep(self._delay)
        return AgentResult(
            agent_name=self.name,
            success=True,
            data={"slept": True},
        )


@pytest.fixture
def pass_agent() -> PassthroughAgent:
    return PassthroughAgent("PassAgent")


@pytest.fixture
def fail_agent() -> FailingAgent:
    return FailingAgent("FailAgent")


@pytest.fixture
def transform_agent() -> TransformingAgent:
    return TransformingAgent("TransformAgent")


@pytest.fixture
def condition_agent() -> ConditionAgent:
    return ConditionAgent("ConditionAgent")


@pytest.fixture
def slow_agent_a() -> SlowAgent:
    return SlowAgent("SlowA", delay=0.02)


@pytest.fixture
def slow_agent_b() -> SlowAgent:
    return SlowAgent("SlowB", delay=0.02)


@pytest.fixture
def event_bus() -> AgentEventBus:
    return AgentEventBus()


@pytest.fixture
def context() -> AgentExecutionContext:
    return AgentExecutionContext(shared_data={"value": 5})


@pytest.fixture
def registry(
    pass_agent: PassthroughAgent,
    fail_agent: FailingAgent,
    transform_agent: TransformingAgent,
) -> AgentRegistryV2:
    reg = AgentRegistryV2()
    reg.register(pass_agent)
    reg.register(fail_agent)
    reg.register(transform_agent)
    return reg


@pytest.fixture
def orchestrator(registry: AgentRegistryV2) -> AgentOrchestratorV2:
    return AgentOrchestratorV2(registry=registry)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TestAgentModels:
    def test_agent_status_values(self) -> None:
        assert AgentStatus.IDLE.value == "idle"
        assert AgentStatus.RUNNING.value == "running"
        assert AgentStatus.COMPLETED.value == "completed"
        assert AgentStatus.FAILED.value == "failed"
        assert AgentStatus.CANCELLED.value == "cancelled"
        assert AgentStatus.BLOCKED.value == "blocked"

    def test_execution_strategy_type_values(self) -> None:
        assert ExecutionStrategyType.SEQUENTIAL.value == "sequential"
        assert ExecutionStrategyType.PARALLEL.value == "parallel"
        assert ExecutionStrategyType.PIPELINE.value == "pipeline"

    def test_agent_capability(self) -> None:
        cap = AgentCapability(
            name="search",
            description="Search knowledge base",
            supported_tasks=["search", "query"],
        )
        assert cap.name == "search"
        assert "query" in cap.supported_tasks

    def test_agent_dependency(self) -> None:
        dep = AgentDependency(agent_name="ParserAgent", required=True)
        assert dep.agent_name == "ParserAgent"
        assert dep.required is True

    def test_agent_message(self) -> None:
        msg = AgentMessage(agent_name="TestAgent", content="hello")
        assert msg.id.startswith("msg-")
        assert msg.agent_name == "TestAgent"
        assert msg.message_type == "info"

    def test_agent_request(self) -> None:
        req = AgentRequest(agent_name="TestAgent", task_type="parse")
        assert req.id.startswith("req-")
        assert req.task_type == "parse"
        assert req.timeout_seconds == 300.0

    def test_agent_response_success(self) -> None:
        resp = AgentResponse(
            agent_name="TestAgent",
            success=True,
            output_data={"key": "val"},
        )
        assert resp.id.startswith("res-")
        assert resp.success is True
        assert resp.output_data == {"key": "val"}

    def test_agent_response_failure(self) -> None:
        resp = AgentResponse(
            agent_name="TestAgent",
            success=False,
            error="Something went wrong",
        )
        assert resp.success is False
        assert resp.error == "Something went wrong"

    def test_agent_execution_plan(self) -> None:
        plan = AgentExecutionPlan(
            strategy=ExecutionStrategyType.PARALLEL,
            agent_names=["A", "B"],
        )
        assert plan.id.startswith("plan-")
        assert len(plan.agent_names) == 2
        assert plan.strategy == ExecutionStrategyType.PARALLEL


# ---------------------------------------------------------------------------
# Event Bus
# ---------------------------------------------------------------------------

class TestAgentEventBus:
    def test_subscribe_and_emit(self) -> None:
        bus = AgentEventBus()
        received: list[AgentExecutionStartedEvent] = []

        def handler(event: AgentExecutionStartedEvent) -> None:
            received.append(event)

        bus.subscribe(AgentExecutionStartedEvent, handler)
        bus.emit(AgentExecutionStartedEvent(agent_name="TestAgent"))
        assert len(received) == 1
        assert received[0].agent_name == "TestAgent"

    def test_unsubscribe(self) -> None:
        bus = AgentEventBus()
        received: list[AgentExecutionStartedEvent] = []

        def handler(event: AgentExecutionStartedEvent) -> None:
            received.append(event)

        bus.subscribe(AgentExecutionStartedEvent, handler)
        bus.unsubscribe(AgentExecutionStartedEvent, handler)
        bus.emit(AgentExecutionStartedEvent(agent_name="TestAgent"))
        assert len(received) == 0

    def test_no_handlers_does_not_crash(self) -> None:
        bus = AgentEventBus()
        bus.emit(AgentExecutionStartedEvent(agent_name="TestAgent"))

    def test_multiple_handlers(self) -> None:
        bus = AgentEventBus()
        count: list[int] = [0]

        def h1(event: AgentExecutionStartedEvent) -> None:
            count[0] += 1

        def h2(event: AgentExecutionStartedEvent) -> None:
            count[0] += 1

        bus.subscribe(AgentExecutionStartedEvent, h1)
        bus.subscribe(AgentExecutionStartedEvent, h2)
        bus.emit(AgentExecutionStartedEvent(agent_name="TestAgent"))
        assert count[0] == 2

    def test_handler_exception_is_caught(self) -> None:
        bus = AgentEventBus()

        def bad_handler(event: AgentExecutionStartedEvent) -> None:
            raise RuntimeError("handler error")

        ok_count: list[int] = [0]

        def ok_handler(event: AgentExecutionStartedEvent) -> None:
            ok_count[0] += 1

        bus.subscribe(AgentExecutionStartedEvent, bad_handler)
        bus.subscribe(AgentExecutionStartedEvent, ok_handler)
        bus.emit(AgentExecutionStartedEvent(agent_name="TestAgent"))
        assert ok_count[0] == 1

    def test_clear(self) -> None:
        bus = AgentEventBus()
        received: list[AgentExecutionStartedEvent] = []

        def handler(event: AgentExecutionStartedEvent) -> None:
            received.append(event)

        bus.subscribe(AgentExecutionStartedEvent, handler)
        bus.clear()
        bus.emit(AgentExecutionStartedEvent(agent_name="TestAgent"))
        assert len(received) == 0

    def test_subscribe_wrong_type_no_callback(self) -> None:
        bus = AgentEventBus()
        received: list[AgentExecutionCompletedEvent] = []

        def handler(event: AgentExecutionCompletedEvent) -> None:
            received.append(event)

        bus.subscribe(AgentExecutionCompletedEvent, handler)
        bus.emit(AgentExecutionStartedEvent(agent_name="TestAgent"))
        assert len(received) == 0


# ---------------------------------------------------------------------------
# Execution Context
# ---------------------------------------------------------------------------

class TestAgentExecutionContext:
    def test_get_output(self) -> None:
        ctx = AgentExecutionContext()
        resp = AgentResponse(agent_name="A", success=True, output_data={"x": 10})
        ctx.set_output("A", resp)
        assert ctx.get_output("A", "x") == 10
        assert ctx.get_output("A", "y", "default") == "default"

    def test_all_successful(self) -> None:
        ctx = AgentExecutionContext()
        ctx.set_output("A", AgentResponse(agent_name="A", success=True))
        ctx.set_output("B", AgentResponse(agent_name="B", success=True))
        assert ctx.all_successful() is True

    def test_all_successful_false(self) -> None:
        ctx = AgentExecutionContext()
        ctx.set_output("A", AgentResponse(agent_name="A", success=True))
        ctx.set_output("B", AgentResponse(agent_name="B", success=False, error="fail"))
        assert ctx.all_successful() is False

    def test_failed_agents(self) -> None:
        ctx = AgentExecutionContext()
        ctx.set_output("A", AgentResponse(agent_name="A", success=True))
        ctx.set_output("B", AgentResponse(agent_name="B", success=False, error="fail"))
        ctx.set_output("C", AgentResponse(agent_name="C", success=False, error="err"))
        assert ctx.failed_agents() == ["B", "C"]

    def test_merge(self) -> None:
        ctx = AgentExecutionContext()
        ctx.merge("TestAgent", {"key": "val"})
        assert ctx.shared_data["key"] == "val"
        assert ctx.metadata.get("merged_from_TestAgent") == ["key"]

    def test_get_output_nonexistent_agent(self) -> None:
        ctx = AgentExecutionContext()
        assert ctx.get_output("Nonexistent", "key") is None

    def test_get_output_failed_agent(self) -> None:
        ctx = AgentExecutionContext()
        ctx.set_output("A", AgentResponse(agent_name="A", success=False, error="fail"))
        assert ctx.get_output("A", "anything") is None


# ---------------------------------------------------------------------------
# Dependency Graph
# ---------------------------------------------------------------------------

class TestDependencyGraph:
    def test_add_node(self) -> None:
        g = DependencyGraph()
        g.add_node("A")
        assert g.has_node("A")
        assert g.nodes == ["A"]

    def test_add_dependency(self) -> None:
        g = DependencyGraph()
        g.add_dependency("B", "A")
        assert g.get_dependencies("B") == ["A"]
        assert g.get_dependents("A") == ["B"]

    def test_add_dependencies(self) -> None:
        g = DependencyGraph()
        g.add_dependencies("C", ["A", "B"])
        deps = g.get_dependencies("C")
        assert "A" in deps
        assert "B" in deps

    def test_remove_node(self) -> None:
        g = DependencyGraph()
        g.add_dependency("B", "A")
        g.remove_node("A")
        assert not g.has_node("A")
        assert g.get_dependencies("B") == []
        assert g.edge_count == 0

    def test_has_cycle_no_cycle(self) -> None:
        g = DependencyGraph()
        g.add_dependency("B", "A")
        g.add_dependency("C", "B")
        assert g.has_cycle() is False

    def test_has_cycle_detected(self) -> None:
        g = DependencyGraph()
        g.add_dependency("A", "B")
        g.add_dependency("B", "C")
        g.add_dependency("C", "A")
        assert g.has_cycle() is True

    def test_has_cycle_self_loop(self) -> None:
        g = DependencyGraph()
        g.add_dependency("A", "A")
        assert g.has_cycle() is True

    def test_execution_order_linear(self) -> None:
        g = DependencyGraph()
        g.add_dependency("C", "B")
        g.add_dependency("B", "A")
        levels = g.execution_order(["A", "B", "C"])
        assert levels == [["A"], ["B"], ["C"]]

    def test_execution_order_parallel(self) -> None:
        g = DependencyGraph()
        g.add_dependency("C", "A")
        g.add_dependency("D", "B")
        levels = g.execution_order(["A", "B", "C", "D"])
        assert levels[0] == ["A", "B"] or levels[0] == ["B", "A"]
        assert set(levels[0]) == {"A", "B"}
        assert set(levels[1]) == {"C", "D"}

    def test_execution_order_all_nodes(self) -> None:
        g = DependencyGraph()
        g.add_dependency("B", "A")
        levels = g.execution_order()
        assert levels == [["A"], ["B"]]

    def test_clear(self) -> None:
        g = DependencyGraph()
        g.add_dependency("B", "A")
        g.clear()
        assert g.nodes == []
        assert g.edge_count == 0


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TestAgentRegistryV2:
    def test_register_and_get(self, pass_agent: PassthroughAgent) -> None:
        reg = AgentRegistryV2()
        reg.register(pass_agent)
        assert reg.get("PassAgent") is pass_agent

    def test_register_duplicate(self, pass_agent: PassthroughAgent) -> None:
        reg = AgentRegistryV2()
        reg.register(pass_agent)
        with pytest.raises(ValueError, match="already registered"):
            reg.register(pass_agent)

    def test_deregister(self, pass_agent: PassthroughAgent) -> None:
        reg = AgentRegistryV2()
        reg.register(pass_agent)
        reg.deregister("PassAgent")
        assert reg.get("PassAgent") is None

    def test_list_names(self, pass_agent: PassthroughAgent, fail_agent: FailingAgent) -> None:
        reg = AgentRegistryV2()
        reg.register(pass_agent)
        reg.register(fail_agent)
        names = reg.list_names()
        assert "PassAgent" in names
        assert "FailAgent" in names

    def test_list_agents(self, pass_agent: PassthroughAgent) -> None:
        reg = AgentRegistryV2()
        reg.register(pass_agent)
        agents = reg.list_agents()
        assert pass_agent in agents

    def test_len(self) -> None:
        reg = AgentRegistryV2()
        assert len(reg) == 0
        reg.register(PassthroughAgent("A"))
        assert len(reg) == 1

    def test_contains(self) -> None:
        reg = AgentRegistryV2()
        reg.register(PassthroughAgent("A"))
        assert "A" in reg
        assert "B" not in reg

    def test_clear(self, pass_agent: PassthroughAgent) -> None:
        reg = AgentRegistryV2()
        reg.register(pass_agent)
        reg.clear()
        assert len(reg) == 0

    def test_find_by_task(self) -> None:
        reg = AgentRegistryV2()
        agent_a = PassthroughAgent("A")
        agent_a._supported_tasks = ["search"]
        agent_a._capabilities = [
            AgentCapability(name="search", supported_tasks=["search"])
        ]
        agent_b = PassthroughAgent("B")
        agent_b._supported_tasks = ["parse"]
        agent_b._capabilities = [
            AgentCapability(name="parse", supported_tasks=["parse"])
        ]
        reg.register(agent_a)
        reg.register(agent_b)
        found = reg.find_by_task("search")
        assert agent_a in found
        assert agent_b not in found

    def test_find_by_capability(self) -> None:
        reg = AgentRegistryV2()
        agent_a = PassthroughAgent("A")
        agent_a._capabilities = [AgentCapability(name="search")]
        agent_b = PassthroughAgent("B")
        agent_b._capabilities = [AgentCapability(name="parse")]
        reg.register(agent_a)
        reg.register(agent_b)
        found = reg.find_by_capability("search")
        assert agent_a in found
        assert agent_b not in found


# ---------------------------------------------------------------------------
# BaseAgent
# ---------------------------------------------------------------------------

class TestBaseAgent:
    def test_name_default(self) -> None:
        agent = PassthroughAgent()
        assert agent.name == "PassthroughAgent"

    def test_name_custom(self) -> None:
        agent = PassthroughAgent("Custom")
        assert agent.name == "Custom"

    def test_status_default(self) -> None:
        agent = PassthroughAgent()
        assert agent.status == AgentStatus.IDLE

    def test_version_default(self) -> None:
        agent = PassthroughAgent()
        assert agent.version == "1.0.0"

    def test_priority_default(self) -> None:
        agent = PassthroughAgent()
        assert agent.priority == 50

    def test_capabilities_default(self) -> None:
        agent = PassthroughAgent()
        assert agent.capabilities == []

    def test_dependencies_default(self) -> None:
        agent = PassthroughAgent()
        assert agent.dependencies == []

    def test_supported_tasks_default(self) -> None:
        agent = PassthroughAgent()
        assert agent.supported_tasks == []

    def test_can_execute_no_tasks(self) -> None:
        agent = PassthroughAgent()
        assert agent.can_execute("anything") is True

    def test_can_execute_with_tasks(self) -> None:
        agent = PassthroughAgent()
        agent._supported_tasks = ["search", "query"]
        assert agent.can_execute("search") is True
        assert agent.can_execute("delete") is False

    def test_has_capability(self) -> None:
        agent = PassthroughAgent()
        agent._capabilities = [AgentCapability(name="search")]
        assert agent.has_capability("search") is True
        assert agent.has_capability("parse") is False

    def test_lifecycle_hooks(self) -> None:
        agent = PassthroughAgent()
        req = AgentRequest(agent_name="TestAgent")

        assert agent.status == AgentStatus.IDLE
        agent.on_start(req)
        assert agent.status == AgentStatus.RUNNING

        resp = AgentResponse(agent_name="TestAgent", success=True)
        agent.on_completed(req, resp)
        assert agent.status == AgentStatus.COMPLETED

    def test_on_failed(self) -> None:
        agent = PassthroughAgent()
        req = AgentRequest(agent_name="TestAgent")
        resp = AgentResponse(agent_name="TestAgent", success=False, error="fail")
        agent.on_failed(req, resp)
        assert agent.status == AgentStatus.FAILED

    def test_health_healthy(self) -> None:
        agent = PassthroughAgent()
        assert agent.health() is True

    def test_health_unhealthy(self) -> None:
        agent = PassthroughAgent()
        agent._status = AgentStatus.FAILED
        assert agent.health() is False

    def test_metadata(self) -> None:
        agent = PassthroughAgent("MetaAgent")
        meta = agent.metadata()
        assert meta["name"] == "MetaAgent"
        assert meta["version"] == "1.0.0"
        assert meta["status"] == "idle"
        assert meta["priority"] == 50
        assert "capabilities" in meta
        assert "dependencies" in meta

    def test_validate_request_returns_true(self) -> None:
        agent = PassthroughAgent()
        req = AgentRequest(agent_name="TestAgent")
        assert agent.validate_request(req) is True

    def test_prepare_response(self) -> None:
        agent = PassthroughAgent()
        result = AgentResult(agent_name="TestAgent", success=True, data={"key": "val"})
        resp = agent.prepare_response(result)
        assert resp.success is True
        assert resp.output_data == {"key": "val"}

    def test_prepare_response_with_non_dict_data(self) -> None:
        agent = PassthroughAgent()
        result = AgentResult(agent_name="TestAgent", success=True, data="string_result")
        resp = agent.prepare_response(result)
        assert resp.output_data == {"result": "string_result"}


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

class TestSequentialStrategy:
    def test_execute_agents_in_order(self, orchestrator: AgentOrchestratorV2) -> None:
        ctx = AgentExecutionContext(shared_data={"value": 5})
        results = orchestrator.execute_sequential(["PassAgent", "TransformAgent"], ctx)
        assert len(results) == 2
        assert results[0].success is True
        assert results[1].success is True
        assert results[1].output_data.get("transformed") == 10

    def test_failure_does_not_stop(self, orchestrator: AgentOrchestratorV2) -> None:
        ctx = AgentExecutionContext()
        results = orchestrator.execute_sequential(["PassAgent", "FailAgent", "PassAgent"], ctx)
        assert len(results) == 3
        assert results[0].success is True
        assert results[1].success is False
        assert "Intentional failure" in results[1].error
        assert results[2].success is True

    def test_empty_agent_list(self, orchestrator: AgentOrchestratorV2) -> None:
        ctx = AgentExecutionContext()
        results = orchestrator.execute_sequential([], ctx)
        assert results == []

    def test_context_updated(self, orchestrator: AgentOrchestratorV2) -> None:
        ctx = AgentExecutionContext(shared_data={"value": 5})
        orchestrator.execute_sequential(["TransformAgent"], ctx)
        assert ctx.shared_data.get("transformed") == 10


class TestSequentialStrategyDirect:
    def test_direct(self, event_bus: AgentEventBus) -> None:
        agent = PassthroughAgent("Test")
        strategy = SequentialStrategy()
        ctx = AgentExecutionContext(shared_data={"key": "val"})
        results = strategy.execute([agent], ctx, event_bus)
        assert len(results) == 1
        assert results[0].agent_name == "Test"
        assert results[0].success is True
        assert results[0].output_data.get("key") == "val"


class TestParallelStrategy:
    def test_all_agents_run(self, orchestrator: AgentOrchestratorV2) -> None:
        ctx = AgentExecutionContext(shared_data={"value": 1})
        results = orchestrator.execute_parallel(["PassAgent", "TransformAgent"], ctx)
        assert len(results) == 2
        successes = [r.success for r in results]
        assert all(successes)

    def test_failure_isolated(self, orchestrator: AgentOrchestratorV2) -> None:
        ctx = AgentExecutionContext()
        results = orchestrator.execute_parallel(["PassAgent", "FailAgent"], ctx)
        successes = [r.success for r in results]
        assert successes.count(True) == 1
        assert successes.count(False) == 1


class TestPipelineStrategy:
    def test_output_chains(self) -> None:
        class DoublerAgent(BaseAgent):
            def execute(self, context: dict[str, Any]) -> AgentResult:
                ctx = dict(context)
                ctx["value"] = ctx.get("value", 1) * 2
                return AgentResult(agent_name=self.name, success=True, data=ctx)

        reg = AgentRegistryV2()
        a1 = DoublerAgent("Double1")
        a2 = DoublerAgent("Double2")
        reg.register(a1)
        reg.register(a2)
        orch = AgentOrchestratorV2(registry=reg)

        ctx = AgentExecutionContext(shared_data={"value": 3})
        results = orch.execute_pipeline(["Double1", "Double2"], ctx)
        assert len(results) == 2
        assert results[0].output_data.get("value") == 6
        assert results[1].output_data.get("value") == 12

    def test_stops_on_failure(self, orchestrator: AgentOrchestratorV2) -> None:
        ctx = AgentExecutionContext(shared_data={"value": 1})
        results = orchestrator.execute_pipeline(["TransformAgent", "FailAgent", "TransformAgent"], ctx)
        assert len(results) == 2
        assert results[0].success is True
        assert results[1].success is False


class TestFanOutStrategy:
    def test_all_agents_receive_same_input(self, orchestrator: AgentOrchestratorV2) -> None:
        ctx = AgentExecutionContext(shared_data={"value": 42})
        results = orchestrator.execute_fan_out(["PassAgent", "TransformAgent"], ctx)
        assert len(results) == 2
        assert all(r.success for r in results)
        # Both received same input; TransformAgent should double the value
        transform_result = [r for r in results if r.output_data.get("transformed") == 84]
        assert len(transform_result) == 1


class TestFanInStrategy:
    def test_all_agents_run_and_merge(self, orchestrator: AgentOrchestratorV2) -> None:
        ctx = AgentExecutionContext(shared_data={"value": 7})
        results = orchestrator.execute_fan_in(["PassAgent", "TransformAgent"], ctx)
        assert len(results) == 2
        assert all(r.success for r in results)
        # Merge should have added both agent outputs to shared_data
        assert "PassAgent" in ctx.shared_data or ctx.shared_data.get("transformed") == 14

    def test_custom_merge(self, event_bus: AgentEventBus) -> None:
        agent_a = PassthroughAgent("A")
        agent_b = TransformingAgent("B")

        def custom_merge(responses: dict[str, AgentResponse]) -> dict[str, Any]:
            return {"custom_merged": True}

        reg = AgentRegistryV2()
        reg.register(agent_a)
        reg.register(agent_b)
        orch = AgentOrchestratorV2(registry=reg)
        ctx = AgentExecutionContext(shared_data={"value": 1})
        results = orch.execute_fan_in(["A", "B"], ctx, merge_fn=custom_merge)
        assert len(results) == 2
        assert ctx.shared_data.get("custom_merged") is True


class TestConditionalStrategy:
    def test_select_by_index(self, event_bus: AgentEventBus) -> None:
        agent_a = PassthroughAgent("A")
        agent_b = PassthroughAgent("B")

        def condition(ctx: AgentExecutionContext) -> int:
            return 1

        strategy = ConditionalStrategy(condition)
        ctx = AgentExecutionContext()
        results = strategy.execute([agent_a, agent_b], ctx, event_bus)
        assert len(results) == 1
        assert results[0].agent_name == "B"

    def test_select_by_name(self, event_bus: AgentEventBus) -> None:
        agent_a = PassthroughAgent("A")
        agent_b = PassthroughAgent("B")

        def condition(ctx: AgentExecutionContext) -> str | None:
            return "A"

        strategy = ConditionalStrategy(condition)
        ctx = AgentExecutionContext()
        results = strategy.execute([agent_a, agent_b], ctx, event_bus)
        assert len(results) == 1
        assert results[0].agent_name == "A"

    def test_none_returns_empty(self, event_bus: AgentEventBus) -> None:
        agent_a = PassthroughAgent("A")

        def condition(ctx: AgentExecutionContext) -> None:
            return None

        strategy = ConditionalStrategy(condition)
        ctx = AgentExecutionContext()
        results = strategy.execute([agent_a], ctx, event_bus)
        assert results == []

    def test_unknown_name_returns_empty(self, event_bus: AgentEventBus) -> None:
        agent_a = PassthroughAgent("A")

        def condition(ctx: AgentExecutionContext) -> str | None:
            return "Nonexistent"

        strategy = ConditionalStrategy(condition)
        ctx = AgentExecutionContext()
        results = strategy.execute([agent_a], ctx, event_bus)
        assert results == []


# ---------------------------------------------------------------------------
# Retry Logic
# ---------------------------------------------------------------------------

class TestRetryLogic:
    def test_retry_on_failure(self, event_bus: AgentEventBus) -> None:
        call_count: list[int] = [0]

        class FlakyAgent(BaseAgent):
            def execute(self, context: dict[str, Any]) -> AgentResult:
                call_count[0] += 1
                if call_count[0] < 3:
                    raise ValueError(f"Attempt {call_count[0]} failed")
                return AgentResult(
                    agent_name=self.name,
                    success=True,
                    data={"result": "success"},
                )

        agent = FlakyAgent("Flaky")
        agent._max_retries = 3
        strategy = SequentialStrategy()
        ctx = AgentExecutionContext()
        results = strategy.execute([agent], ctx, event_bus)
        assert len(results) == 1
        assert results[0].success is True
        assert call_count[0] == 3

    def test_retry_exhausted(self, event_bus: AgentEventBus) -> None:
        call_count: list[int] = [0]

        class AlwaysFailsAgent(BaseAgent):
            def execute(self, context: dict[str, Any]) -> AgentResult:
                call_count[0] += 1
                raise ValueError("Always fails")

        agent = AlwaysFailsAgent("Bad")
        agent._max_retries = 2
        strategy = SequentialStrategy()
        ctx = AgentExecutionContext()
        results = strategy.execute([agent], ctx, event_bus)
        assert len(results) == 1
        assert results[0].success is False
        assert call_count[0] == 3  # initial + 2 retries


# ---------------------------------------------------------------------------
# Orchestrator v2
# ---------------------------------------------------------------------------

class TestAgentOrchestratorV2:
    def test_register_agent(self, pass_agent: PassthroughAgent) -> None:
        orch = AgentOrchestratorV2()
        orch.register_agent(pass_agent)
        assert orch.get_agent("PassAgent") is pass_agent

    def test_deregister_agent(self, pass_agent: PassthroughAgent) -> None:
        orch = AgentOrchestratorV2()
        orch.register_agent(pass_agent)
        orch.deregister_agent("PassAgent")
        assert orch.get_agent("PassAgent") is None

    def test_list_agents(self, pass_agent: PassthroughAgent, fail_agent: FailingAgent) -> None:
        orch = AgentOrchestratorV2()
        orch.register_agent(pass_agent)
        orch.register_agent(fail_agent)
        agents = orch.list_agents()
        assert len(agents) == 2

    def test_execute_single(self, orchestrator: AgentOrchestratorV2) -> None:
        result = orchestrator.execute("PassAgent")
        assert result.success is True

    def test_execute_unknown_agent(self, orchestrator: AgentOrchestratorV2) -> None:
        with pytest.raises(ValueError, match="Unknown agent"):
            orchestrator.execute("NonexistentAgent")

    def test_execute_plan_sequential(self, orchestrator: AgentOrchestratorV2) -> None:
        plan = AgentExecutionPlan(
            strategy=ExecutionStrategyType.SEQUENTIAL,
            agent_names=["PassAgent", "TransformAgent"],
        )
        ctx = AgentExecutionContext(shared_data={"value": 10})
        results = orchestrator.execute_plan(plan, ctx)
        assert len(results) == 2
        assert results[0].success is True
        assert results[1].success is True

    def test_execute_plan_parallel(self, orchestrator: AgentOrchestratorV2) -> None:
        plan = AgentExecutionPlan(
            strategy=ExecutionStrategyType.PARALLEL,
            agent_names=["PassAgent", "TransformAgent"],
        )
        ctx = AgentExecutionContext(shared_data={"value": 5})
        results = orchestrator.execute_plan(plan, ctx)
        assert len(results) == 2

    def test_execute_plan_unsupported(self, orchestrator: AgentOrchestratorV2) -> None:
        plan = AgentExecutionPlan(
            strategy=ExecutionStrategyType.CONDITIONAL,
            agent_names=[],
        )
        with pytest.raises(ValueError, match="Unsupported plan strategy"):
            orchestrator.execute_plan(plan)

    def test_registry_property(self, registry: AgentRegistryV2) -> None:
        orch = AgentOrchestratorV2(registry=registry)
        assert orch.registry is registry

    def test_config_property(self) -> None:
        config = AgentConfig()
        orch = AgentOrchestratorV2(config=config)
        assert orch.config is config

    def test_event_bus_property(self, event_bus: AgentEventBus) -> None:
        orch = AgentOrchestratorV2(event_bus=event_bus)
        assert orch.event_bus is event_bus

    def test_execute_with_dependencies(self) -> None:
        agent_a = PassthroughAgent("A")
        agent_b = PassthroughAgent("B")
        agent_c = PassthroughAgent("C")

        agent_b._dependencies = [AgentDependency(agent_name="A")]
        agent_c._dependencies = [AgentDependency(agent_name="A")]

        orch = AgentOrchestratorV2()
        orch.register_agent(agent_a)
        orch.register_agent(agent_b)
        orch.register_agent(agent_c)

        ctx = AgentExecutionContext(shared_data={"task": "test"})
        results = orch.execute_with_dependencies(
            agent_names=["A", "B", "C"],
            context=ctx,
        )
        assert len(results) == 3
        assert all(r.success for r in results)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

class TestAgentConfig:
    def test_default_values(self) -> None:
        config = AgentConfig()
        assert config.enabled is True
        assert config.default_execution_strategy == "sequential"
        assert config.max_concurrency == 4
        assert config.default_timeout == 300.0
        assert config.max_retries == 3
        assert config.enabled_agents == []
        assert config.disabled_agents == []
        assert config.enable_event_bus is True

    def test_can_be_nested_in_deephunter_config(self) -> None:
        from deephunter.core.config import DeepHunterConfig
        cfg = DeepHunterConfig.default()
        assert cfg.agent.enabled is True
        assert cfg.agent.max_concurrency == 4


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TestAgentException:
    def test_agent_error_is_deephunter_error(self) -> None:
        err = AgentError("test")
        from deephunter.core.exceptions import DeepHunterError
        assert isinstance(err, DeepHunterError)

    def test_agent_error_message(self) -> None:
        err = AgentError("Something went wrong")
        assert str(err) == "Something went wrong"
