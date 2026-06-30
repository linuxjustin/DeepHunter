"""Intelligence module for DeepHunter.

Implements the intelligence lifecycle with evidence quality, hypothesis
enhancement, learning suggestions, pattern discovery, knowledge curation,
and reasoning quality traces.
"""

from deephunter.intelligence.manager import IntelligenceManager
from deephunter.intelligence.models import (
    CurationStatus,
    DiscoveredPattern,
    EnhancedHypothesisLinks,
    EvidenceQuality,
    EvidenceQualityLevel,
    EvidenceSource,
    EvidenceVerificationStatus,
    HypothesisEnhancement,
    HypothesisOutcome,
    HypothesisReviewStatus,
    IntelligenceState,
    KnowledgeCurationEntry,
    LearningSuggestion,
    LearningSuggestionType,
    PatternConfidence,
    PatternType,
    ReasoningStep,
    ReasoningStepType,
    ReasoningTrace,
)

__all__ = [
    "IntelligenceManager",
    "IntelligenceState",
    "HypothesisEnhancement",
    "EnhancedHypothesisLinks",
    "AnalystNotes",
    "HypothesisOutcome",
    "HypothesisReviewStatus",
    "EvidenceQuality",
    "EvidenceQualityLevel",
    "EvidenceSource",
    "EvidenceVerificationStatus",
    "LearningSuggestion",
    "LearningSuggestionType",
    "DiscoveredPattern",
    "PatternType",
    "PatternConfidence",
    "KnowledgeCurationEntry",
    "CurationStatus",
    "ReasoningTrace",
    "ReasoningStep",
    "ReasoningStepType",
]