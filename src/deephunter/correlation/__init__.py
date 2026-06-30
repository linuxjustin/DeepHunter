"""Recon Correlation Engine — orchestrates the full intelligence pipeline.

Chains: subdomain enumeration → HTTP probing → technology intelligence →
framework intelligence → attack surface graph → investigation hints.
"""

from deephunter.correlation.engine import CorrelationEngine, CorrelationResult
from deephunter.correlation.events import (
    CorrelationCompletedEvent,
    CorrelationEvent,
    CorrelationEventBus,
    CorrelationFailedEvent,
    CorrelationStartedEvent,
    PipelineStageCompletedEvent,
    PipelineStageStartedEvent,
)

__all__ = [
    "CorrelationEngine",
    "CorrelationResult",
    "CorrelationEventBus",
    "CorrelationEvent",
    "CorrelationStartedEvent",
    "CorrelationCompletedEvent",
    "CorrelationFailedEvent",
    "PipelineStageStartedEvent",
    "PipelineStageCompletedEvent",
]
