"""Data models for the Bug Bounty Methodology Engine.

Each model captures a specific aspect of manual security testing methodology
as structured, versioned data objects.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from deephunter.core.types import BugClass


class RiskCategory(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Reference(BaseModel):
    """A reference to external documentation or methodology."""
    source: str  # OWASP, CWE, CAPEC, ASVS, etc.
    ref_id: str = ""
    title: str = ""
    url: str = ""
    description: str = ""


class TestingObjective(BaseModel):
    """A specific testing objective within a methodology phase."""

    id: str = Field(default_factory=lambda: f"tobj-{uuid4().hex[:12]}")
    name: str
    description: str = ""
    bug_classes: list[BugClass] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class TestingTechnique(BaseModel):
    """A specific technique used to achieve a testing objective."""

    id: str = Field(default_factory=lambda: f"ttech-{uuid4().hex[:12]}")
    name: str
    description: str = ""
    procedure: str = ""
    tools: list[str] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    bug_classes: list[BugClass] = Field(default_factory=list)
    risk: RiskCategory = RiskCategory.MEDIUM
    tags: list[str] = Field(default_factory=list)


class Methodology(BaseModel):
    """A complete testing methodology with versioned phases."""

    id: str = Field(default_factory=lambda: f"meth-{uuid4().hex[:12]}")
    name: str
    version: str = "1.0.0"
    description: str = ""
    objectives: list[TestingObjective] = Field(default_factory=list)
    techniques: list[TestingTechnique] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    attack_surface_areas: list[str] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class MethodologySelection(BaseModel):
    """The result of selecting a methodology for a given context."""

    methodology: Methodology
    confidence: Confidence
    relevance_score: float = Field(default=0.0, ge=0.0, le=1.0)
    matched_technologies: list[str] = Field(default_factory=list)
    matched_frameworks: list[str] = Field(default_factory=list)
    matched_areas: list[str] = Field(default_factory=list)


class FrameworkProfile(BaseModel):
    """Security profile for a specific framework, guiding methodology."""

    id: str = Field(default_factory=lambda: f"fp-{uuid4().hex[:12]}")
    framework_name: str
    version: str = ""
    architecture_notes: list[str] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    common_components: list[str] = Field(default_factory=list)
    auth_patterns: list[str] = Field(default_factory=list)
    deployment_patterns: list[str] = Field(default_factory=list)
    investigation_areas: list[str] = Field(default_factory=list)
    testing_workflows: list[str] = Field(default_factory=list)
    related_methodologies: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceRequirement(BaseModel):
    """Required evidence for a checklist item or finding."""

    id: str = Field(default_factory=lambda: f"ev-{uuid4().hex[:12]}")
    description: str
    evidence_type: str = ""  # screenshot, request, response, log, code, config
    required: bool = True
    tags: list[str] = Field(default_factory=list)


class ChecklistItem(BaseModel):
    """A single item in a testing checklist."""

    id: str = Field(default_factory=lambda: f"ci-{uuid4().hex[:12]}")
    objective: str
    description: str = ""
    procedure: str = ""
    required_evidence: list[EvidenceRequirement] = Field(default_factory=list)
    priority: Priority = Priority.MEDIUM
    expected_outcome: str = ""
    dependencies: list[str] = Field(default_factory=list)
    related_technologies: list[str] = Field(default_factory=list)
    related_frameworks: list[str] = Field(default_factory=list)
    bug_classes: list[BugClass] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    completed: bool = False
    evidence_collected: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class Checklist(BaseModel):
    """A generated checklist for an investigation."""

    id: str = Field(default_factory=lambda: f"cl-{uuid4().hex[:12]}")
    methodology_id: str = ""
    framework_profile_id: str = ""
    items: list[ChecklistItem] = Field(default_factory=list)
    total_items: int = 0
    completed_items: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def recalculate(self) -> None:
        self.total_items = len(self.items)
        self.completed_items = sum(1 for i in self.items if i.completed)


class WorkflowStep(BaseModel):
    """A single step in an investigation workflow."""

    id: str = Field(default_factory=lambda: f"ws-{uuid4().hex[:12]}")
    order: int = 0
    title: str
    description: str = ""
    technique: str = ""
    expected_findings: str = ""
    required_evidence: list[str] = Field(default_factory=list)
    estimated_time_minutes: int = 0
    risk: RiskCategory = RiskCategory.MEDIUM
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class InvestigationBranch(BaseModel):
    """A branch from a decision point in a workflow."""

    id: str = Field(default_factory=lambda: f"ib-{uuid4().hex[:12]}")
    condition: str
    description: str = ""
    next_step_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class DecisionPoint(BaseModel):
    """A branching decision in an investigation workflow."""

    id: str = Field(default_factory=lambda: f"dp-{uuid4().hex[:12]}")
    step_id: str = ""
    question: str
    branches: list[InvestigationBranch] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class InvestigationWorkflow(BaseModel):
    """A structured investigation workflow with optional branching."""

    id: str = Field(default_factory=lambda: f"iw-{uuid4().hex[:12]}")
    name: str = ""
    description: str = ""
    steps: list[WorkflowStep] = Field(default_factory=list)
    decision_points: list[DecisionPoint] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Observation(BaseModel):
    """An observation made during manual testing."""

    id: str = Field(default_factory=lambda: f"mo-{uuid4().hex[:12]}")
    step_id: str = ""
    description: str
    detail: str = ""
    evidence: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class FindingTemplate(BaseModel):
    """Template for reporting a security finding."""

    id: str = Field(default_factory=lambda: f"ft-{uuid4().hex[:12]}")
    title: str
    description: str = ""
    impact: str = ""
    remediation: str = ""
    references: list[Reference] = Field(default_factory=list)
    bug_classes: list[BugClass] = Field(default_factory=list)
    risk: RiskCategory = RiskCategory.MEDIUM
    tags: list[str] = Field(default_factory=list)


class ManualTest(BaseModel):
    """A manual test procedure with methodology context.

    Maps to planning.models.ManualTest but includes methodology
    provenance for traceability.
    """

    id: str = Field(default_factory=lambda: f"mmt-{uuid4().hex[:12]}")
    description: str
    procedure: str = ""
    expected_result: str = ""
    bug_classes: list[BugClass] = Field(default_factory=list)
    priority: float = Field(default=0.0, ge=0.0, le=1.0)
    estimated_effort_hours: float = Field(default=0.0, ge=0.0)
    methodology_id: str = ""
    checklist_item_id: str = ""
    framework_profile_id: str = ""
    references: list[Reference] = Field(default_factory=list)
    risk: RiskCategory = RiskCategory.MEDIUM

    def to_planning_manual_test(self) -> Any:
        from deephunter.planning.models import ManualTest as PlanningManualTest

        return PlanningManualTest(
            description=self.description,
            procedure=self.procedure,
            expected_result=self.expected_result,
            bug_classes=[bc.value for bc in self.bug_classes],
            priority=self.priority,
            estimated_effort_hours=self.estimated_effort_hours,
        )


class MethodologyResult(BaseModel):
    """Complete result of the methodology pipeline."""

    id: str = Field(default_factory=lambda: f"mr-{uuid4().hex[:12]}")
    selections: list[MethodologySelection] = Field(default_factory=list)
    checklists: list[Checklist] = Field(default_factory=list)
    workflows: list[InvestigationWorkflow] = Field(default_factory=list)
    manual_tests: list[ManualTest] = Field(default_factory=list)
    framework_profiles: list[FrameworkProfile] = Field(default_factory=list)
    total_selected: int = 0
    total_checklist_items: int = 0
    total_workflow_steps: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
