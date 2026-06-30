"""Core data models for the Investigation Planning Engine.

Represents an investigation plan as an ordered series of steps
grouped by phases.  Every model is a Pydantic BaseModel for
validation, serialization, and schema migration.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


class PlanningPhase(str, Enum):
    """Phases of a security investigation, executed in order."""

    RECON = "recon"
    FINGERPRINT = "fingerprint"
    FRAMEWORK_DETECTION = "framework_detection"
    AUTHENTICATION_ANALYSIS = "authentication_analysis"
    AUTHORIZATION_ANALYSIS = "authorization_analysis"
    BUSINESS_LOGIC_ANALYSIS = "business_logic_analysis"
    INPUT_VALIDATION = "input_validation"
    API_ANALYSIS = "api_analysis"
    FILE_UPLOAD_ANALYSIS = "file_upload_analysis"
    CLOUD_ANALYSIS = "cloud_analysis"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    EXPLOIT_CHAIN_ANALYSIS = "exploit_chain_analysis"
    REPORT_PREPARATION = "report_preparation"


class StepStatus(str, Enum):
    """Status of a single investigation step."""

    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class RiskScore(BaseModel):
    """Risk assessment for a step or the overall plan."""

    overall: float = Field(default=0.0, ge=0.0, le=10.0)
    likelihood: float = Field(default=0.0, ge=0.0, le=10.0)
    impact: float = Field(default=0.0, ge=0.0, le=10.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    def calculate_overall(self) -> float:
        self.overall = round((self.likelihood * self.impact) / 10.0, 2)
        return self.overall


class PriorityWeights(BaseModel):
    """Configurable weights for priority calculation.

    All weights should sum to approximately 1.0.
    """

    likelihood: float = 0.30
    impact: float = 0.25
    confidence: float = 0.15
    complexity_inverted: float = 0.10
    effort_inverted: float = 0.10
    reward: float = 0.10

    def normalize(self) -> None:
        total = sum(
            [
                self.likelihood,
                self.impact,
                self.confidence,
                self.complexity_inverted,
                self.effort_inverted,
                self.reward,
            ]
        )
        if total > 0:
            factor = 1.0 / total
            self.likelihood *= factor
            self.impact *= factor
            self.confidence *= factor
            self.complexity_inverted *= factor
            self.effort_inverted *= factor
            self.reward *= factor


class ManualTest(BaseModel):
    """A recommended manual test as part of an investigation step."""

    id: str = Field(
        default_factory=lambda: f"mt-{uuid4().hex[:12]}",
    )
    description: str
    procedure: str = ""
    expected_result: str = ""
    bug_classes: list[str] = Field(default_factory=list)
    priority: float = Field(default=0.0, ge=0.0, le=1.0)
    estimated_effort_hours: float = Field(default=0.0, ge=0.0)
    methodology_id: str = ""
    checklist_item_id: str = ""


class InvestigationStep(BaseModel):
    """A single step in an investigation plan."""

    id: str = Field(
        default_factory=lambda: f"step-{uuid4().hex[:12]}",
    )
    phase: PlanningPhase
    title: str
    description: str = ""
    rationale: str = ""
    priority_score: float = Field(default=0.0, ge=0.0, le=1.0)
    risk: RiskScore = Field(default_factory=RiskScore)
    estimated_cost_hours: float = Field(default=0.0, ge=0.0)
    complexity: float = Field(default=0.5, ge=0.0, le=1.0)
    status: StepStatus = Field(default=StepStatus.PLANNED)
    depends_on: list[str] = Field(default_factory=list)
    recommended_tests: list[ManualTest] = Field(default_factory=list)
    bug_classes: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    observation_ids: list[str] = Field(default_factory=list)
    hypothesis_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class InvestigationPlan(BaseModel):
    """Complete investigation plan with ordered steps and metadata."""

    id: str = Field(
        default_factory=lambda: f"plan-{uuid4().hex[:12]}",
    )
    title: str = ""
    description: str = ""
    target: str = ""
    investigation_id: str = ""
    steps: list[InvestigationStep] = Field(default_factory=list)
    total_estimated_hours: float = Field(default=0.0, ge=0.0)
    risk: RiskScore = Field(default_factory=RiskScore)
    overall_priority: float = Field(default=0.0, ge=0.0, le=1.0)
    phases_covered: list[PlanningPhase] = Field(default_factory=list)
    version: int = Field(default=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def recalculate(self) -> None:
        if not self.steps:
            self.total_estimated_hours = 0.0
            self.overall_priority = 0.0
            self.phases_covered = []
            return

        self.total_estimated_hours = sum(s.estimated_cost_hours for s in self.steps)
        self.overall_priority = round(
            sum(s.priority_score for s in self.steps) / len(self.steps), 4
        )
        phases = {s.phase for s in self.steps}
        self.phases_covered = sorted(phases, key=lambda p: list(PlanningPhase).index(p))
        self.updated_at = datetime.now(UTC)

    def steps_by_phase(self, phase: PlanningPhase) -> list[InvestigationStep]:
        return [s for s in self.steps if s.phase == phase]

    def steps_by_status(self, status: StepStatus) -> list[InvestigationStep]:
        return [s for s in self.steps if s.status == status]

    def model_dump_for_storage(self) -> dict:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict) -> InvestigationPlan:
        return cls(**data)


class PlannerContext(BaseModel):
    """Complete context for the planning engine.

    This is the single input to every planning rule.
    """

    target: str = ""
    investigation_id: str = ""
    technologies: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    bug_classes: list[str] = Field(default_factory=list)
    auth_mechanisms: list[str] = Field(default_factory=list)
    cloud_providers: list[str] = Field(default_factory=list)
    interesting_endpoints: list[str] = Field(default_factory=list)
    interesting_parameters: list[str] = Field(default_factory=list)
    observation_types: list[str] = Field(default_factory=list)
    existing_findings: list[str] = Field(default_factory=list)
    existing_hypotheses: list[str] = Field(default_factory=list)
    os: list[str] = Field(default_factory=list)
    programming_languages: list[str] = Field(default_factory=list)
    user_constraints: list[str] = Field(default_factory=list)
    attack_surface_areas: list[str] = Field(default_factory=list)
    methodology_result: dict | None = None

    @classmethod
    def from_session(cls, session: object) -> PlannerContext:
        from deephunter.reasoning.session import InvestigationSession

        if not isinstance(session, InvestigationSession):
            raise TypeError(f"Expected InvestigationSession, got {type(session).__name__}")

        inv = session.investigation
        state = inv.state
        fp = state.technology_fingerprint

        tech_strs: list[str] = []
        for t in fp.technologies:
            tech_strs.append(t.value if hasattr(t, "value") else str(t))

        return cls(
            target=inv.target,
            investigation_id=inv.id,
            technologies=tech_strs,
            frameworks=fp.frameworks,
            auth_mechanisms=fp.auth_mechanisms,
            cloud_providers=fp.cloud_providers,
            interesting_endpoints=state.interesting_endpoints,
            interesting_parameters=state.interesting_parameters,
            bug_classes=list(
                set(
                    str(bc)
                    for hyp in state.hypotheses
                    for bc in hyp.bug_classes
                )
            ),
            os=fp.operating_systems,
            programming_languages=fp.programming_languages,
            observation_types=[o.type.value for o in state.observations],
            existing_findings=[f.title for f in state.findings],
            existing_hypotheses=[h.title for h in state.hypotheses],
        )


class PlannerMetrics(BaseModel):
    """Metrics from a planning run."""

    total_rules_evaluated: int = 0
    total_candidates_generated: int = 0
    total_steps_produced: int = 0
    phases_covered: int = 0
    estimated_total_hours: float = 0.0
    average_priority: float = 0.0
    risk_score: float = 0.0
    elapsed_seconds: float = 0.0


class PlannerResult(BaseModel):
    """Complete result of a planning run."""

    plan: InvestigationPlan
    metrics: PlannerMetrics = Field(default_factory=PlannerMetrics)
    warnings: list[str] = Field(default_factory=list)
