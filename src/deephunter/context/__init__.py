"""Context Engine — structured context assembly for AI models.

Gathers and organizes information from Knowledge Store, Reasoning
Engine, Investigation Planner, user input, and future sources into
a single structured ``Context`` object.

Independent of any LLM.  No AI, no embeddings, no RAG.
"""

from deephunter.context.budget import apply_budget, estimate_tokens
from deephunter.context.config import ContextConfig
from deephunter.context.engine import ContextEngine
from deephunter.context.events import (
    ContextBudgetExceededEvent,
    ContextCreatedEvent,
    ContextDeduplicatedEvent,
    ContextEvent,
    ContextEventBus,
    ContextMergeEvent,
    ContextTrimmedEvent,
    ContextUpdatedEvent,
)
from deephunter.context.models import (
    Context,
    ContextBlock,
    ContextBudget,
    ContextImportance,
    ContextMetadata,
    ContextReference,
    ContextSection,
    ContextSource,
    ContextSourceType,
    ContextStatistics,
)
from deephunter.context.pipeline import (
    BudgetStage,
    CollectPlanStage,
    CollectSessionStage,
    CollectUserInputStage,
    ContextPipeline,
    ContextPipelineReport,
    ContextStage,
    DeduplicateStage,
    InitContextStage,
    PrioritizeStage,
    RecalculateStage,
)
from deephunter.context.sources import (
    collect_from_constraints,
    collect_from_plan,
    collect_from_query,
    collect_from_session,
    merge_contexts,
)

__all__ = [
    # Config
    "ContextConfig",
    # Models
    "Context",
    "ContextBlock",
    "ContextBudget",
    "ContextImportance",
    "ContextMetadata",
    "ContextReference",
    "ContextSection",
    "ContextSource",
    "ContextSourceType",
    "ContextStatistics",
    # Events
    "ContextBudgetExceededEvent",
    "ContextCreatedEvent",
    "ContextDeduplicatedEvent",
    "ContextEvent",
    "ContextEventBus",
    "ContextMergeEvent",
    "ContextTrimmedEvent",
    "ContextUpdatedEvent",
    # Pipeline
    "BudgetStage",
    "CollectPlanStage",
    "CollectSessionStage",
    "CollectUserInputStage",
    "ContextPipeline",
    "ContextPipelineReport",
    "ContextStage",
    "DeduplicateStage",
    "InitContextStage",
    "PrioritizeStage",
    "RecalculateStage",
    # Budget
    "apply_budget",
    "estimate_tokens",
    # Source collectors
    "collect_from_constraints",
    "collect_from_plan",
    "collect_from_query",
    "collect_from_session",
    "merge_contexts",
    # Engine
    "ContextEngine",
]
