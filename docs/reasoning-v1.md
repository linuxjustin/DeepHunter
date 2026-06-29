# Reasoning Engine v1 — Investigation Pipeline

The Reasoning Engine models how an experienced security researcher
investigates a target.  It is **completely model-independent** — no
LLM calls, no embeddings, no RAG, no AI.

## Architecture

```
Observation → Evidence → Hypothesis → Experiment → Result → Pivot → Finding
```

Each arrow is a **stage** in the reasoning pipeline.  Stages run in
sequence; each reads and mutates the shared ``InvestigationState``.

### Core Concepts

| Concept       | Model              | Description                                        |
|---------------|--------------------|----------------------------------------------------|
| Observation   | ``Observation``    | Something noticed about the target                 |
| Evidence      | ``Evidence``       | Data supporting an observation                     |
| Hypothesis    | ``dict``           | A testable theory about a vulnerability (stored as dict for flexibility) |
| Experiment    | ``Experiment``     | A manual test designed to validate/refute a hypothesis |
| Pivot         | ``Pivot``          | A new direction triggered by experiment results     |
| Finding       | ``Finding``        | A confirmed vulnerability                           |

### Why Hypotheses Are Dicts

Hypotheses use ``dict[str, Any]`` instead of a Pydantic model to allow
free-form key-value pairs that future stages or AI integrations can
extend without schema changes.  The graph tracks only Pydantic model
instances, so hypotheses are referenced by ID but not stored as nodes.

## Pipeline Stages

1. **Observation** — Seeds observations from the target description
2. **Evidence Collection** — Adds basic evidence for each observation
3. **Hypothesis Generation** — Creates initial hypotheses from technology fingerprints
4. **Prioritization** — Sorts hypotheses by bug class severity and confidence
5. **Experiment Planning** — Creates experiments for high-confidence hypotheses
6. **Result Recording** — Placeholder for CLI/AI result entry
7. **Confidence Update** — Recalculates confidence from experiment outcomes
8. **Pivot Generation** — Creates pivots from refuted/inconclusive experiments
9. **Finding Creation** — Promotes confirmed hypotheses to findings
10. **Report Hook** — Logs final state, future hook for report generation

### Error Handling

- Every stage is wrapped in ``try/except`` so a single stage failure
  never crashes the pipeline
- ``PipelineReport`` captures per-stage timing
- ``add_evidence``, ``create_experiment``, ``record_result`` return
  ``None``/``False`` on failure instead of raising

## Confidence Scoring

The ``WeightedEvidenceScorer`` uses three inputs:

| Input        | Max contribution | Notes                                    |
|--------------|------------------|------------------------------------------|
| Observations | 0.10             | Diminishing returns after 3              |
| Evidence     | 0.15             | Diminishing returns after 5              |
| Experiments  | ±0.20 / -0.30    | Pass = +0.20, Fail = -0.30              |

Score is clamped to ``[0.0, 1.0]``.

``HypothesisStatusScorer.determine_status()`` maps confidence + experiment
outcomes to a status: ``proposed`` → ``investigating`` → ``confirmed`` /
``refuted``.

### Pluggable Scorers

Implement ``ConfidenceScorer`` and pass it to ``InvestigationSession``:

```python
class MyScorer(ConfidenceScorer):
    def score(self, observations, evidence, experiments) -> float:
        return min(1.0, len(evidence) * 0.1)

session = InvestigationSession(
    investigation=inv,
    confidence_scorer=MyScorer(),
)
```

## Investigation Graph

The ``ReasoningGraph`` is an in-memory DAG that tracks relationships:

```
Observation ──suggests──→ Experiment ──tests──→ Hypothesis
     ↑                       │
  supports                   ├──produces──→ Result
  Evidence                   │
                             └──generates──→ Pivot
                                            │
                                            └──leads_to──→ Finding (confirmed)
```

- Nodes are Pydantic model instances (Observation, Evidence, Experiment,
  Pivot, Finding)
- Edges use ``EdgeType`` enum (SUPPORTS, SUGGESTS, TESTS, GENERATES, CONFIRMS, etc.)
- Serializes to JSON alongside the investigation for persistence
- Supports BFS traversal, predecessors/successors, and edge filtering

## Session Lifecycle

```python
from deephunter.reasoning import InvestigationSession

# Create
session = InvestigationSession.new("https://example.com")

# Add observations and evidence
obs = session.create_observation("endpoint", description="Login page")
session.add_evidence(observation_id=obs.id, content="200 OK", source="curl")

# Create hypotheses and experiments
hyp = session.create_hypothesis(title="SQLi", description="Test SQL injection")
exp = session.create_experiment(
    hypothesis_id=hyp["id"],
    description="Send SQLi payloads",
    procedure="sqlmap -u ...",
    expected_result="Database error",
)

# Record results
session.record_result(experiment_id=exp.id, status="completed", actual_result="SQLi confirmed")

# Promote to finding
fnd = session.create_finding(
    title="SQL Injection in Login",
    hypothesis_id=hyp["id"],
    bug_classes=["sql_injection"],
    severity="high",
    experiment_ids=[exp.id],
)

# Run pipeline
from deephunter.reasoning import ReasoningPipeline
pipeline = ReasoningPipeline()
report = pipeline.run(session)
print(f"Completed in {report.total_seconds:.2f}s")

# Persist
session.save("/tmp/investigation.json")
loaded = InvestigationSession.load("/tmp/investigation.json")
```

## Event Bus

All mutations emit typed events via ``ReasoningEventBus``:

| Event                      | When                            |
|----------------------------|---------------------------------|
| ``ObservationCreatedEvent``  | A new observation is added      |
| ``EvidenceAddedEvent``       | Evidence is attached            |
| ``HypothesisCreatedEvent``   | A hypothesis is generated       |
| ``HypothesisUpdatedEvent``   | Confidence/status changes       |
| ``ExperimentCreatedEvent``   | An experiment is planned        |
| ``ExperimentCompletedEvent`` | An experiment finishes          |
| ``ConfidenceChangedEvent``   | Confidence changes significantly |
| ``PivotCreatedEvent``        | A pivot is created              |
| ``FindingCreatedEvent``      | A finding is confirmed          |
| ``HypothesisStatusChangedEvent`` | Hypothesis status transitions |

```python
session.events.subscribe(FindingCreatedEvent, lambda e: print(f"Finding: {e.finding.title}"))
```

## Prompt Builder Interface

The ``PromptBuilderContext`` and ``PromptBuilderContextBuilder`` provide
a structured snapshot of the investigation state for future prompt
generation.  No prompts are generated in v1 — only the data contract.

```python
from deephunter.reasoning import PromptBuilderContextBuilder
context = PromptBuilderContextBuilder.build(session)
print(context.summary)
# "2 observations, 1 hypothesis, 1 experiment, 1 finding"
```

## Extension Points

- **ConfidenceScorer** — Replace the scoring algorithm
- **HypothesisStatusScorer** — Custom status determination
- **ReasoningStage** — Define custom pipeline stages
- **ReasoningEventBus** — Subscribe to any event for metrics, logging, UI
- **PromptBuilderContext** — Feed investigation state to an LLM prompt builder

## File Layout

```
src/deephunter/reasoning/
├── __init__.py          # Public API (preserves legacy Hypothesis + HypothesisGenerator)
├── models.py            # Pydantic models (Observation, Evidence, Experiment, Pivot, Finding, etc.)
├── graph.py             # In-memory DAG (ReasoningGraph, GraphNode, GraphEdge)
├── confidence.py        # WeightedEvidenceScorer + HypothesisStatusScorer
├── events.py            # ReasoningEventBus + 10 typed events
├── session.py           # InvestigationSession (full CRUD + persistence)
├── pipeline.py          # ReasoningPipeline (10-stage stage-based pipeline)
└── prompt_builder.py    # PromptBuilderContext + PromptBuilderContextBuilder
```

## Testing

```bash
# Run all reasoning tests
python -m pytest tests/unit/test_reasoning_*.py -v

# Run full suite
python -m pytest tests/
```

148 tests cover the reasoning engine across 7 test files:

| Test file                       | Tests | Scope               |
|---------------------------------|-------|---------------------|
| ``test_reasoning_models.py``    | 17    | Core Pydantic models |
| ``test_reasoning_graph.py``     | 16    | In-memory DAG       |
| ``test_reasoning_confidence.py`` | 19    | Scoring algorithms  |
| ``test_reasoning_events.py``    | 20    | Event bus + events  |
| ``test_reasoning_session.py``   | 25    | Full Session CRUD   |
| ``test_reasoning_pipeline.py``  | 33    | Pipeline stages     |
| ``test_reasoning_integration.py`` | 5   | End-to-end lifecycle |

All 448 tests pass (205 SKO v1 + 95 ingestion + 148 reasoning).
