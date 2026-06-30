# Agent Orchestration Framework v1

Coordinates multi-agent execution with typed plans, pluggable
strategies, event bus, dependency graphs, and retry logic.

## Architecture

```
AgentOrchestratorV2
    │
    ├── AgentRegistryV2      ── instance-based registry
    ├── AgentConfig           ── configuration
    ├── AgentEventBus         ── typed event pub/sub
    ├── DependencyGraph       ── topological ordering
    └── ExecutionStrategy     ── coordination pattern
            │
      Sequential / Parallel / Pipeline / FanOut / FanIn / Conditional
```

## Core Models

| Model | ID prefix | Purpose |
|-------|-----------|---------|
| `AgentRequest` | `req-` | What the agent should do |
| `AgentResponse` | `res-` | Execution result |
| `AgentMessage` | `msg-` | Typed message within a response |
| `AgentExecutionPlan` | `plan-` | Declarative execution plan |
| `AgentExecutionContext` | `ctx-` | Typed shared context |

## Execution Strategy

```
Sequential ──→ [A]→[B]→[C]   each agent sees full context
Parallel   ──→ [A,B,C]        concurrent (thread pool)
Pipeline   ──→ A→B→C          each receives previous output
FanOut     ──→ A,A,A          same input, concurrent
FanIn      ──→ A,B,C          concurrent + merge results
Conditional─→ A | B | C       one agent based on condition
```

## Quick Start

```python
from deephunter.agents import (
    BaseAgent, AgentOrchestratorV2,
    AgentExecutionContext, AgentExecutionPlan,
    ExecutionStrategyType,
)
from deephunter.agents.base import AgentResult

class MyAgent(BaseAgent):
    def execute(self, context):
        return AgentResult(
            agent_name=self.name,
            success=True,
            data={"processed": context.get("input")},
        )

orch = AgentOrchestratorV2()
orch.register_agent(MyAgent("AgentA"))
orch.register_agent(MyAgent("AgentB"))

ctx = AgentExecutionContext(shared_data={"input": "hello"})
results = orch.execute_sequential(["AgentA", "AgentB"], ctx)
```

## Dependency Graph

Agents declare `dependencies` and the orchestrator resolves them:

```python
from deephunter.agents.models import AgentDependency

agent_b._dependencies = [AgentDependency(agent_name="AgentA")]
orch.register_agent(agent_a)
orch.register_agent(agent_b)

ctx = AgentExecutionContext(shared_data={"task": "test"})
results = orch.execute_with_dependencies(context=ctx)
# AgentA runs first, then AgentB
```

The `DependencyGraph` produces topological levels — agents in the
same level run in parallel; levels run sequentially.

## Event Bus

Subscribe to typed events for metrics, logging, UI:

```python
from deephunter.agents import (
    AgentEventBus, AgentExecutionCompletedEvent,
    AgentExecutionFailedEvent,
)

bus = AgentEventBus()
bus.subscribe(AgentExecutionCompletedEvent, lambda e: print(f"Done: {e.agent_name}"))
bus.subscribe(AgentExecutionFailedEvent, lambda e: print(f"Failed: {e.agent_name}"))
```

## Retry Logic

Each `BaseAgent` has `max_retries` (default 3). On exception,
the strategy retries with a 1-second delay. Lifecycle hooks
track retry state:

```python
agent._max_retries = 5   # override
# on_retry() is called between attempts
```

## Lifecycle Hooks

| Hook | When |
|------|------|
| `on_start(request)` | Before `execute` |
| `on_completed(request, response)` | After success |
| `on_failed(request, response)` | After failure |
| `on_retry(request, attempt, error)` | Before retry |

## File Layout

| File | Role |
|------|------|
| `models.py` | Pydantic v2 models |
| `agent.py` | `BaseAgent` with capabilities, deps, hooks |
| `base.py` | Legacy `Agent` ABC (unchanged) |
| `registry.py` | `AgentRegistryV2` instance-based |
| `strategies.py` | 6 execution strategy implementations |
| `orchestrator_v2.py` | Main `AgentOrchestratorV2` |
| `dependency_graph.py` | `DependencyGraph` with cycle detection |
| `context.py` | `AgentExecutionContext` shared state |
| `events.py` | `AgentEventBus` + typed events |
| `orchestrator.py` | Legacy orchestrator (unchanged) |
