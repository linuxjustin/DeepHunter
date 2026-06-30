"""Reasoning engine — investigation pipeline and hypothesis management."""

from deephunter.reasoning.hypothesis import (
    HypothesisGenerator,
)
from deephunter.reasoning.models import (
    Evidence,
    EvidenceType,
    Experiment,
    ExperimentStatus,
    Finding,
    Hypothesis,
    HypothesisPriority,
    Investigation,
    InvestigationState,
    Observation,
    ObservationType,
    Pivot,
    PivotReason,
    TechnologyFingerprint,
)
from deephunter.reasoning.graph import (
    GraphEdge,
    GraphNode,
    ReasoningGraph,
)
from deephunter.reasoning.confidence import (
    ConfidenceScorer,
    HypothesisStatusScorer,
    WeightedEvidenceScorer,
)
from deephunter.reasoning.events import (
    ConfidenceChangedEvent,
    EvidenceAddedEvent,
    ExperimentCompletedEvent,
    ExperimentCreatedEvent,
    FindingCreatedEvent,
    HypothesisCreatedEvent,
    HypothesisStatusChangedEvent,
    HypothesisUpdatedEvent,
    ObservationCreatedEvent,
    PivotCreatedEvent,
    ReasoningEvent,
    ReasoningEventBus,
)
from deephunter.reasoning.session import (
    InvestigationSession,
)
from deephunter.reasoning.pipeline import (
    PipelineReport,
    ReasoningPipeline,
    ReasoningStage,
)
from deephunter.reasoning.prompt_builder import (
    HypothesisContext,
    PromptBuilderContext,
    PromptBuilderContextBuilder,
)

__all__ = [
    # Legacy
    "Hypothesis",
    "HypothesisGenerator",
    "HypothesisPriority",
    # Models
    "Evidence",
    "EvidenceType",
    "Experiment",
    "ExperimentStatus",
    "Finding",
    "Investigation",
    "InvestigationState",
    "Observation",
    "ObservationType",
    "Pivot",
    "PivotReason",
    "TechnologyFingerprint",
    # Graph
    "GraphEdge",
    "GraphNode",
    "ReasoningGraph",
    # Confidence
    "ConfidenceScorer",
    "HypothesisStatusScorer",
    "WeightedEvidenceScorer",
    # Events
    "ConfidenceChangedEvent",
    "EvidenceAddedEvent",
    "ExperimentCompletedEvent",
    "ExperimentCreatedEvent",
    "FindingCreatedEvent",
    "HypothesisCreatedEvent",
    "HypothesisStatusChangedEvent",
    "HypothesisUpdatedEvent",
    "ObservationCreatedEvent",
    "PivotCreatedEvent",
    "ReasoningEvent",
    "ReasoningEventBus",
    # Session
    "InvestigationSession",
    # Pipeline
    "PipelineReport",
    "ReasoningPipeline",
    "ReasoningStage",
    # Prompt Builder
    "HypothesisContext",
    "PromptBuilderContext",
    "PromptBuilderContextBuilder",
]
