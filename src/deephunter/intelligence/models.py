"""Intelligence models for DeepHunter.

Implements the intelligence lifecycle with evidence quality, hypothesis
enhancement, pattern discovery, knowledge curation, and reasoning traces.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class EvidenceQualityLevel(str, Enum):
    """Quality level for evidence."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"


class EvidenceVerificationStatus(str, Enum):
    """Verification status of evidence."""

    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    CONFLICTING = "conflicting"
    DISPROVEN = "disproven"


class EvidenceSource(str, Enum):
    """Source type of evidence."""

    RECON = "recon"
    MANUAL_TESTING = "manual_testing"
    TOOL_OUTPUT = "tool_output"
    AI_GENERATED = "ai_generated"
    KNOWLEDGE_BASE = "knowledge_base"
    REFERENCE = "reference"
    OTHER = "other"


class EvidenceQuality(BaseModel):
    """Quality scoring and metadata for evidence."""

    quality_level: EvidenceQualityLevel = Field(default=EvidenceQualityLevel.MEDIUM)
    verification_status: EvidenceVerificationStatus = Field(default=EvidenceVerificationStatus.UNVERIFIED)
    source_type: EvidenceSource = Field(default=EvidenceSource.OTHER)
    reliability_score: float = Field(default=0.5, ge=0.0, le=1.0)
    freshness_score: float = Field(default=1.0, ge=0.0, le=1.0)
    relevance_score: float = Field(default=0.5, ge=0.0, le=1.0)
    provenance_chain: list[str] = Field(default_factory=list, description="IDs forming provenance chain")
    verification_notes: str = Field(default="")
    verified_by: str = Field(default="")
    verified_at: datetime | None = None
    conflicting_evidence_ids: list[str] = Field(default_factory=list)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    overall_score: float = Field(default=0.5, ge=0.0, le=1.0)

    def compute_overall_score(self) -> float:
        w_quality = {"high": 1.0, "medium": 0.7, "low": 0.3, "unverified": 0.1}
        q_score = w_quality.get(self.quality_level, 0.5)
        return round(
            q_score * 0.3
            + self.reliability_score * 0.25
            + self.freshness_score * 0.15
            + self.relevance_score * 0.3,
            3,
        )


class HypothesisOutcome(str, Enum):
    """Outcome of a hypothesis investigation."""

    PENDING = "pending"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    SUPERSEDED = "superseded"


class HypothesisReviewStatus(str, Enum):
    """Review status for hypothesis quality."""

    DRAFT = "draft"
    REVIEWED = "reviewed"
    APPROVED = "approved"
    REJECTED = "rejected"


class EnhancedHypothesisLinks(BaseModel):
    """Enhanced relationship links for hypotheses."""

    related_hypothesis_ids: list[str] = Field(default_factory=list)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    alternative_hypothesis_ids: list[str] = Field(default_factory=list)
    derived_from_hypothesis_ids: list[str] = Field(default_factory=list)
    supersedes_hypothesis_ids: list[str] = Field(default_factory=list)


class AnalystNotes(BaseModel):
    """Analyst notes on a hypothesis."""

    initial_notes: str = Field(default="")
    review_notes: str = Field(default="")
    final_notes: str = Field(default="")
    feedback: str = Field(default="")
    lessons_learned: str = Field(default="")
    updated_by: str = Field(default="")
    updated_at: datetime | None = None


class HypothesisEnhancement(BaseModel):
    """Enhanced hypothesis with full lifecycle tracking."""

    id: str = Field(default_factory=lambda: f"hype-{uuid4().hex[:12]}")
    base_hypothesis_id: str = Field(default="", description="Links to core Hypothesis.id")
    target_id: str = Field(default="")
    investigation_session_id: str = Field(default="")

    outcome: HypothesisOutcome = Field(default=HypothesisOutcome.PENDING)
    review_status: HypothesisReviewStatus = Field(default=HypothesisReviewStatus.DRAFT)

    links: EnhancedHypothesisLinks = Field(default_factory=EnhancedHypothesisLinks)
    analyst_notes: AnalystNotes = Field(default_factory=AnalystNotes)

    ai_suggestions: list[str] = Field(default_factory=list, description="AI-generated alternatives")
    alternative_hypotheses: list[str] = Field(default_factory=list, description="Alternative explanations")

    related_asset_ids: list[str] = Field(default_factory=list)
    related_technology_ids: list[str] = Field(default_factory=list)
    related_sko_ids: list[str] = Field(default_factory=list)
    related_planner_task_ids: list[str] = Field(default_factory=list)

    confidence_history: list[dict[str, Any]] = Field(default_factory=list)
    decision_history: list[dict[str, Any]] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    reviewed_at: datetime | None = None
    resolved_at: datetime | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)


class CurationStatus(str, Enum):
    """Knowledge curation workflow status."""

    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


class LearningSuggestionType(str, Enum):
    """Types of learning suggestions."""

    PLANNER_IMPROVEMENT = "planner_improvement"
    METHODOLOGY_ADJUSTMENT = "methodology_adjustment"
    KNOWLEDGE_PACK_SUGGESTION = "knowledge_pack_suggestion"
    WORKFLOW_REFINEMENT = "workflow_refinement"
    NEW_PATTERN = "new_pattern"
    RULE_IMPROVEMENT = "rule_improvement"
    HYPOTHESIS_TEMPLATE = "hypothesis_template"


class LearningSuggestion(BaseModel):
    """Project-level learning suggestion requiring analyst review."""

    id: str = Field(default_factory=lambda: f"ls-{uuid4().hex[:12]}")
    suggestion_type: LearningSuggestionType
    title: str = Field(description="Brief title of the suggestion")
    description: str = Field(description="Detailed description")
    rationale: str = Field(default="", description="Why this suggestion was generated")
    evidence: str = Field(default="", description="Supporting evidence for this suggestion")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    project_id: str = Field(default="")
    target_id: str = Field(default="")
    investigation_session_id: str = Field(default="")

    generated_by: str = Field(default="ai", description="ai or analyst")
    curator_id: str = Field(default="")

    curation_status: CurationStatus = Field(default=CurationStatus.DRAFT)
    reviewer_id: str = Field(default="")
    review_notes: str = Field(default="")
    reviewed_at: datetime | None = None

    applied_to_project: bool = Field(default=False)
    applied_to_global: bool = Field(default=False)

    priority: int = Field(default=0, ge=0, le=10)
    tags: list[str] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    metadata: dict[str, Any] = Field(default_factory=dict)


class PatternType(str, Enum):
    """Types of discovered patterns."""

    AUTHENTICATION_FLOW = "authentication_flow"
    FRAMEWORK_STRUCTURE = "framework_structure"
    API_DESIGN = "api_design"
    TECHNOLOGY_COMBINATION = "technology_combination"
    TRUST_BOUNDARY = "trust_boundary"
    AUTHORIZATION_PATTERN = "authorization_pattern"
    DATA_FLOW = "data_flow"
    SESSION_MANAGEMENT = "session_management"
    ERROR_HANDLING = "error_handling"
    INPUT_VALIDATION = "input_validation"
    OTHER = "other"


class PatternConfidence(str, Enum):
    """Confidence in a discovered pattern."""

    SPECULATIVE = "speculative"
    LIKELY = "likely"
    CONFIRMED = "confirmed"


class DiscoveredPattern(BaseModel):
    """A pattern discovered during investigation."""

    id: str = Field(default_factory=lambda: f"pat-{uuid4().hex[:12]}")
    pattern_type: PatternType
    name: str = Field(description="Pattern name")
    description: str = Field(description="Pattern description")
    pattern_data: dict[str, Any] = Field(default_factory=dict, description="Pattern specifics")

    confidence: PatternConfidence = Field(default=PatternConfidence.SPECULATIVE)
    occurrence_count: int = Field(default=1)
    locations: list[str] = Field(default_factory=list, description="Where observed")

    related_technology_ids: list[str] = Field(default_factory=list)
    related_sko_ids: list[str] = Field(default_factory=list)
    related_hypothesis_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)

    project_id: str = Field(default="")
    target_id: str = Field(default="")

    curator_id: str = Field(default="")
    curation_status: CurationStatus = Field(default=CurationStatus.DRAFT)
    reviewed_at: datetime | None = None

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeCurationEntry(BaseModel):
    """Entry in the knowledge curation workflow."""

    id: str = Field(default_factory=lambda: f"kc-{uuid4().hex[:12]}")
    content_type: str = Field(description="Type: sko, hypothesis_template, pattern, etc.")
    content_id: str = Field(description="ID of the content being curated")
    content_summary: str = Field(default="", description="Brief summary for review")

    status: CurationStatus = Field(default=CurationStatus.DRAFT)
    previous_status: CurationStatus | None = None

    change_description: str = Field(default="", description="What changed")
    change_rationale: str = Field(default="", description="Why the change is suggested")

    proposed_by: str = Field(default="ai")
    proposed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    reviewer_id: str = Field(default="")
    review_notes: str = Field(default="")
    reviewed_at: datetime | None = None

    project_id: str = Field(default="")
    investigation_session_id: str = Field(default="")

    metadata: dict[str, Any] = Field(default_factory=dict)


class ReasoningStepType(str, Enum):
    """Types of reasoning steps in a trace."""

    HYPOTHESIS = "hypothesis"
    EVIDENCE = "evidence"
    DECISION = "decision"
    NEXT_ACTION = "next_action"
    ALTERNATIVE = "alternative"
    FEEDBACK = "feedback"


class ReasoningStep(BaseModel):
    """A single step in a reasoning trace."""

    step_type: ReasoningStepType
    content: str = Field(description="Step content")
    reasoning: str = Field(default="", description="Why this step was taken")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    alternatives: list[str] = Field(default_factory=list, description="Alternative options considered")
    selected_alternative: str = Field(default="")
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReasoningTrace(BaseModel):
    """Complete reasoning trace for quality recording."""

    id: str = Field(default_factory=lambda: f"trace-{uuid4().hex[:12]}")
    investigation_session_id: str = Field(default="")
    target_id: str = Field(default="")
    hypothesis_id: str = Field(default="", description="Hypothesis this trace relates to")

    steps: list[ReasoningStep] = Field(default_factory=list)
    conclusion: str = Field(default="")
    quality_score: float = Field(default=0.5, ge=0.0, le=1.0)

    analyst_id: str = Field(default="")
    feedback: str = Field(default="")
    feedback_rating: int = Field(default=0, ge=0, le=5)

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    metadata: dict[str, Any] = Field(default_factory=dict)


class IntelligenceState(BaseModel):
    """Complete intelligence state for an investigation/project."""

    target_id: str = Field(default="")
    investigation_session_id: str = Field(default="")
    project_id: str = Field(default="")

    hypothesis_enhancements: list[HypothesisEnhancement] = Field(default_factory=list)
    evidence_qualities: dict[str, EvidenceQuality] = Field(default_factory=dict)

    learning_suggestions: list[LearningSuggestion] = Field(default_factory=list)
    discovered_patterns: list[DiscoveredPattern] = Field(default_factory=list)

    curation_queue: list[KnowledgeCurationEntry] = Field(default_factory=list)
    reasoning_traces: list[ReasoningTrace] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class InvestigationIntelligenceSummary(BaseModel):
    """Summary of intelligence metrics for an investigation."""

    target_id: str = Field(default="")
    investigation_session_id: str = Field(default="")

    total_hypotheses: int = 0
    confirmed_hypotheses: int = 0
    refuted_hypotheses: int = 0
    inconclusive_hypotheses: int = 0

    avg_evidence_quality: float = 0.0
    high_quality_evidence_count: int = 0
    unverified_evidence_count: int = 0

    learning_suggestions_generated: int = 0
    learning_suggestions_approved: int = 0
    patterns_discovered: int = 0
    patterns_promoted: int = 0

    reasoning_traces_recorded: int = 0
    avg_reasoning_quality: float = 0.0
    analyst_feedback_avg: float = 0.0