"""Research Dashboard Models.

Provides overview, progress, coverage, and health metrics for an investigation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class HealthStatus(str, Enum):
    """Overall investigation health."""

    HEALTHY = "healthy"
    AT_RISK = "at_risk"
    BLOCKED = "blocked"
    STALLED = "stalled"
    COMPLETED = "completed"


class CoverageLevel(str, Enum):
    """Coverage assessment levels."""

    NONE = "none"
    MINIMAL = "minimal"
    PARTIAL = "partial"
    GOOD = "good"
    COMPREHENSIVE = "comprehensive"


class DashboardOverview(BaseModel):
    """High-level overview of an investigation."""

    target_id: str
    target_name: str = ""
    target_url: str = ""
    project_name: str = ""

    investigation_id: str = ""
    investigation_status: str = ""

    start_time: datetime | None = None
    last_activity_time: datetime | None = None
    total_duration_minutes: float = 0.0

    health_status: HealthStatus = Field(default=HealthStatus.HEALTHY)
    progress_pct: float = Field(default=0.0, ge=0.0, le=100.0)

    active_researchers: int = 0
    ai_conversations_count: int = 0


class HypothesisSummary(BaseModel):
    """Summary of hypothesis tracking."""

    total: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    by_priority: dict[str, int] = Field(default_factory=dict)
    by_bug_class: dict[str, int] = Field(default_factory=dict)
    avg_confidence: float = 0.0
    confirmed_findings: int = 0
    refuted: int = 0


class EvidenceSummary(BaseModel):
    """Summary of evidence collected."""

    total: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    http_exchanges: int = 0
    screenshots: int = 0
    code_snippets: int = 0
    recon_artifacts: int = 0
    manual_notes: int = 0


class TaskBoardSummary(BaseModel):
    """Summary of task board."""

    total_cards: int = 0
    backlog: int = 0
    planned: int = 0
    in_progress: int = 0
    needs_verification: int = 0
    completed: int = 0
    archived: int = 0

    by_priority: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    completion_rate: float = 0.0
    overdue_cards: int = 0


class TechnologySummary(BaseModel):
    """Summary of detected technologies."""

    total: int = 0
    by_category: dict[str, int] = Field(default_factory=dict)
    technologies: list[dict[str, Any]] = Field(default_factory=list)


class AttackSurfaceSummary(BaseModel):
    """Summary of the attack surface."""

    total_endpoints: int = 0
    total_parameters: int = 0
    total_hosts: int = 0
    total_technologies: int = 0
    total_auth_flows: int = 0
    total_apis: int = 0

    by_category: dict[str, int] = Field(default_factory=dict)
    by_http_method: dict[str, int] = Field(default_factory=dict)
    by_auth_required: dict[str, int] = Field(default_factory=dict)


class NotebookSummary(BaseModel):
    """Summary of investigation notebook."""

    total_entries: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    flagged: int = 0
    archived: int = 0


class FindingSummary(BaseModel):
    """Summary of confirmed findings."""

    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    cvss_scores: list[float] = Field(default_factory=list)
    avg_cvss: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0


class TimelineActivitySummary(BaseModel):
    """Summary of timeline activity."""

    total_events: int = 0
    events_today: int = 0
    events_this_week: int = 0
    events_this_month: int = 0
    by_event_type: dict[str, int] = Field(default_factory=dict)
    avg_events_per_day: float = 0.0


class CoverageAssessment(BaseModel):
    """Assessment of investigation coverage."""

    recon_coverage: CoverageLevel = Field(default=CoverageLevel.NONE)
    auth_coverage: CoverageLevel = Field(default=CoverageLevel.NONE)
    authz_coverage: CoverageLevel = Field(default=CoverageLevel.NONE)
    input_validation_coverage: CoverageLevel = Field(default=CoverageLevel.NONE)
    business_logic_coverage: CoverageLevel = Field(default=CoverageLevel.NONE)
    api_coverage: CoverageLevel = Field(default=CoverageLevel.NONE)
    session_coverage: CoverageLevel = Field(default=CoverageLevel.NONE)
    cloud_coverage: CoverageLevel = Field(default=CoverageLevel.NONE)
    overall: CoverageLevel = Field(default=CoverageLevel.NONE)

    coverage_by_endpoint: float = 0.0
    coverage_by_parameter: float = 0.0
    coverage_by_technology: float = 0.0


class ResearchDashboard(BaseModel):
    """Complete research dashboard for a target/investigation."""

    id: str = Field(default_factory=lambda: f"dash-{uuid4().hex[:12]}")
    target_id: str
    investigation_session_id: str = Field(default="")

    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    overview: DashboardOverview | None = None
    hypothesis: HypothesisSummary | None = None
    evidence: EvidenceSummary | None = None
    tasks: TaskBoardSummary | None = None
    technologies: TechnologySummary | None = None
    attack_surface: AttackSurfaceSummary | None = None
    notebook: NotebookSummary | None = None
    findings: FindingSummary | None = None
    timeline_activity: TimelineActivitySummary | None = None
    coverage: CoverageAssessment | None = None

    health_status: HealthStatus = Field(default=HealthStatus.HEALTHY)
    health_messages: list[str] = Field(default_factory=list)

    def model_dump_for_storage(self) -> dict[str, Any]:
        return self.model_dump(mode="json")