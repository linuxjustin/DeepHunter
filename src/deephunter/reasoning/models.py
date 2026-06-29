"""Core data models for the Reasoning Engine v1.

Models how experienced security researchers think:
observations → evidence → hypotheses → experiments → results → pivots → findings.

Every model is a Pydantic BaseModel for validation, serialization,
and future schema migration support.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from deephunter.core.types import BugClass, Technology


# ── Enums ────────────────────────────────────────────────────────────────────


class ObservationType(str, Enum):
    """Categories of things a researcher can observe about a target."""

    TECHNOLOGY = "technology"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    HEADER = "header"
    BUSINESS_LOGIC = "business_logic"
    CLOUD = "cloud"
    FRAMEWORK = "framework"
    BEHAVIOR = "behavior"
    OTHER = "other"


class EvidenceType(str, Enum):
    """Types of evidence supporting an observation."""

    RAW = "raw"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    CODE_SNIPPET = "code_snippet"
    CONFIG = "config"
    SCREENSHOT = "screenshot"
    LOG = "log"
    DOCUMENTATION = "documentation"
    OTHER = "other"


class ExperimentStatus(str, Enum):
    """Status of a manual test experiment."""

    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class HypothesisStatus(str, Enum):
    """Lifecycle status of a hypothesis."""

    PROPOSED = "proposed"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    SUPERSEDED = "superseded"


class FindingSeverity(str, Enum):
    """Severity of a confirmed finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PivotReason(str, Enum):
    """Why a pivot occurred."""

    NEW_OBSERVATION = "new_observation"
    HYPOTHESIS_REFUTED = "hypothesis_refuted"
    PARTIAL_CONFIRMATION = "partial_confirmation"
    NEW_TECHNOLOGY = "new_technology"
    UNEXPECTED_BEHAVIOR = "unexpected_behavior"
    RESEARCHER_INPUT = "researcher_input"
    OTHER = "other"


class NodeType(str, Enum):
    """Types of nodes in the reasoning graph."""

    OBSERVATION = "observation"
    EVIDENCE = "evidence"
    HYPOTHESIS = "hypothesis"
    EXPERIMENT = "experiment"
    RESULT = "result"
    PIVOT = "pivot"
    FINDING = "finding"


class EdgeType(str, Enum):
    """Types of edges in the reasoning graph."""

    SUPPORTS = "supports"               # Evidence → Observation
    SUGGESTS = "suggests"               # Observation → Hypothesis
    TESTS = "tests"                     # Hypothesis → Experiment
    PRODUCES = "produces"               # Experiment → Result
    UPDATES = "updates"                 # Result → Hypothesis (confidence update)
    GENERATES = "generates"             # Result → Pivot
    LEADS_TO = "leads_to"               # Pivot → Hypothesis
    CONFIRMS = "confirms"               # Hypothesis → Finding
    REFERENCES = "references"           # Node → SKO (external)
    DERIVED_FROM = "derived_from"       # Hypothesis → Observation


# ── Core models ──────────────────────────────────────────────────────────────


class Observation(BaseModel):
    """Something noticed about the target application.

    Observations are the atomic unit of the reasoning process.
    They come from manual inspection, tool output, or knowledge review.
    """

    id: str = Field(
        default_factory=lambda: f"obs-{uuid4().hex[:12]}",
        description="Unique identifier (obs-<12 hex chars>)",
    )
    type: ObservationType = Field(description="Category of observation")
    description: str = Field(description="Human-readable description")
    detail: str = Field(default="", description="Technical detail or payload")
    source: str = Field(default="", description="Where this was observed (URL, tool, etc.)")
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Evidence(BaseModel):
    """Supporting data for an observation.

    Could be an HTTP response, code snippet, configuration, etc.
    """

    id: str = Field(
        default_factory=lambda: f"ev-{uuid4().hex[:12]}",
        description="Unique identifier (ev-<12 hex chars>)",
    )
    observation_id: str = Field(description="The observation this supports")
    content: str = Field(description="The evidence data")
    source: str = Field(default="", description="Origin of this evidence")
    type: EvidenceType = Field(default=EvidenceType.RAW)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Experiment(BaseModel):
    """A manual test designed to validate or refute a hypothesis."""

    id: str = Field(
        default_factory=lambda: f"exp-{uuid4().hex[:12]}",
        description="Unique identifier (exp-<12 hex chars>)",
    )
    hypothesis_id: str = Field(description="The hypothesis being tested")
    description: str = Field(description="What this test does")
    procedure: str = Field(default="", description="Step-by-step instructions")
    expected_result: str = Field(default="", description="What should happen if vulnerable")
    actual_result: str = Field(default="", description="What actually happened")
    status: ExperimentStatus = Field(default=ExperimentStatus.PLANNED)
    duration_ms: float = Field(default=0.0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = Field(default=None)


class Pivot(BaseModel):
    """A new direction for the investigation.

    Generated when an experiment result suggests a different approach
    or a new area to explore.
    """

    id: str = Field(
        default_factory=lambda: f"pvt-{uuid4().hex[:12]}",
        description="Unique identifier (pvt-<12 hex chars>)",
    )
    description: str = Field(description="What new direction to take")
    rationale: str = Field(default="", description="Why this pivot makes sense")
    reason: PivotReason = Field(default=PivotReason.OTHER)
    source_experiment_id: str | None = Field(default=None)
    new_hypothesis_id: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Finding(BaseModel):
    """A confirmed vulnerability discovered during investigation."""

    id: str = Field(
        default_factory=lambda: f"fnd-{uuid4().hex[:12]}",
        description="Unique identifier (fnd-<12 hex chars>)",
    )
    title: str = Field(description="Human-readable title of the finding")
    description: str = Field(default="", description="Detailed description")
    bug_classes: list[BugClass] = Field(default_factory=list)
    severity: FindingSeverity = Field(default=FindingSeverity.MEDIUM)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cwe_ids: list[str] = Field(default_factory=list)
    hypothesis_id: str = Field(description="The hypothesis this finding confirms")
    evidence_ids: list[str] = Field(default_factory=list)
    experiment_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TechnologyFingerprint(BaseModel):
    """Detected technologies for the target being investigated."""

    technologies: list[Technology] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    programming_languages: list[str] = Field(default_factory=list)
    operating_systems: list[str] = Field(default_factory=list)
    cloud_providers: list[str] = Field(default_factory=list)
    auth_mechanisms: list[str] = Field(default_factory=list)

    def merge(self, other: TechnologyFingerprint) -> None:
        for field in ("technologies", "frameworks", "programming_languages",
                      "operating_systems", "cloud_providers", "auth_mechanisms"):
            ours: set[str] = {getattr(v, "value", v) for v in getattr(self, field)}
            theirs: set[str] = {getattr(v, "value", v) for v in getattr(other, field)}
            merged = sorted(ours | theirs)
            setattr(self, field, merged)


class InvestigationState(BaseModel):
    """Full mutable state of an investigation.

    This is the single source of truth for everything known and
    everything done during an investigation.
    """

    target: str = Field(default="", description="Target description (URL, app name, scope)")
    technology_fingerprint: TechnologyFingerprint = Field(
        default_factory=TechnologyFingerprint,
    )
    observations: list[Observation] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    experiments: list[Experiment] = Field(default_factory=list)
    pivots: list[Pivot] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    interesting_endpoints: list[str] = Field(default_factory=list)
    interesting_parameters: list[str] = Field(default_factory=list)
    pending_actions: list[str] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    overall_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def add_observation(self, obs: Observation) -> None:
        self.observations.append(obs)
        self.updated_at = datetime.now(UTC)

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)
        self.updated_at = datetime.now(UTC)


class Investigation(BaseModel):
    """Top-level container for a security investigation.

    Wraps state, metadata, and provides the public API for the
    reasoning engine.
    """

    id: str = Field(
        default_factory=lambda: f"inv-{uuid4().hex[:12]}",
        description="Unique identifier (inv-<12 hex chars>)",
    )
    name: str = Field(default="", description="Human-readable name")
    target: str = Field(description="Target being investigated")
    state: InvestigationState = Field(default_factory=InvestigationState)
    sko_ids: list[str] = Field(
        default_factory=list,
        description="SKOs retrieved for this investigation",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def model_dump_for_storage(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Investigation:
        return cls(**data)
