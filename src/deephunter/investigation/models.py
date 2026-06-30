"""Data models for the investigation workflow layer.

These models extend the existing ``InvestigationSession`` with workflow-level
concepts: tasks, scope, evidence records, reports, and checkpoint state.

They are agnostic about which AI provider, planner, or agent is used.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ── Task Engine ──────────────────────────────────────────────────────────────


class TaskPriority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TaskStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class TaskCategory(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    BUSINESS_LOGIC = "business_logic"
    JAVASCRIPT = "javascript"
    API = "api"
    CLOUD = "cloud"
    FILE_UPLOAD = "file_upload"
    GRAPHQL = "graphql"
    SESSION = "session"
    SSRF = "ssrf"
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    RCE = "rce"
    LFI = "lfi"
    IDOR = "idor"
    RATE_LIMIT = "rate_limit"
    RECON = "recon"
    OTHER = "other"


class Task(BaseModel):
    """A single unit of investigation work."""

    id: str = Field(default_factory=lambda: f"task-{__import__('uuid').uuid4().hex[:12]}")
    title: str
    description: str = ""
    category: TaskCategory = TaskCategory.OTHER
    priority: TaskPriority = TaskPriority.MEDIUM
    status: TaskStatus = TaskStatus.PENDING
    confidence: float = 0.0
    dependencies: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    owner: str = ""
    references: list[str] = Field(default_factory=list)
    notes: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    completed_at: str | None = None

    def complete(self) -> None:
        self.status = TaskStatus.COMPLETED
        self.completed_at = datetime.now(UTC).isoformat()
        self.updated_at = self.completed_at

    def fail(self, reason: str = "") -> None:
        self.status = TaskStatus.FAILED
        self.notes = reason
        self.completed_at = datetime.now(UTC).isoformat()
        self.updated_at = self.completed_at

    def block(self, reason: str = "") -> None:
        self.status = TaskStatus.BLOCKED
        self.notes = reason
        self.updated_at = datetime.now(UTC).isoformat()


# ── Scope ────────────────────────────────────────────────────────────────────


class ScopeEntryType(StrEnum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    WILD_CARD = "wild_card"


class ScopeEntry(BaseModel):
    """A single scope entry (domain, URL, CIDR, etc.)."""

    value: str
    entry_type: ScopeEntryType = ScopeEntryType.IN_SCOPE
    description: str = ""
    source: str = ""


class ScopeInfo(BaseModel):
    """Target scope definition."""

    target: str
    entries: list[ScopeEntry] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    rate_limits: str = ""
    auth_requirements: str = ""
    notes: str = ""


# ── Evidence Records ─────────────────────────────────────────────────────────


class EvidenceType(StrEnum):
    HTTP_RESPONSE = "http_response"
    HEADER = "header"
    COOKIE = "cookie"
    SCREENSHOT = "screenshot"
    MANUAL_NOTE = "manual_note"
    RECON_ARTIFACT = "recon_artifact"
    OBSERVATION = "observation"
    REASONING_STEP = "reasoning_step"
    PLANNER_DECISION = "planner_decision"
    REFERENCE = "reference"
    CODE_SNIPPET = "code_snippet"
    OTHER = "other"


class EvidenceRecord(BaseModel):
    """Structured evidence captured during an investigation."""

    id: str = Field(default_factory=lambda: f"ev-{__import__('uuid').uuid4().hex[:12]}")
    title: str
    evidence_type: EvidenceType = EvidenceType.OTHER
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_step: str = ""
    source_task: str = ""
    tags: list[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


# ── Manual Notes ─────────────────────────────────────────────────────────────


class ManualNote(BaseModel):
    """A researcher's manual observation or note."""

    id: str = Field(default_factory=lambda: f"note-{__import__('uuid').uuid4().hex[:12]}")
    content: str
    tags: list[str] = Field(default_factory=list)
    source_step: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


# ── Investigation Session State ──────────────────────────────────────────────


class InvestigationStatus(StrEnum):
    CREATED = "created"
    SCOPE_LOADED = "scope_loaded"
    RECON_COMPLETED = "recon_completed"
    GRAPH_BUILT = "graph_built"
    TECHNOLOGIES_IDENTIFIED = "technologies_identified"
    KNOWLEDGE_PACKS_SELECTED = "knowledge_packs_selected"
    METHODOLOGY_SELECTED = "methodology_selected"
    PLAN_GENERATED = "plan_generated"
    CONTEXT_BUILT = "context_built"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class InvestigationSessionState(BaseModel):
    """Persistent state for a full investigation workflow session.

    Complements the existing ``InvestigationSession`` (which tracks
    reasoning-graph state) with workflow-level tracking.
    """

    session_id: str = Field(default_factory=lambda: f"inv-{__import__('uuid').uuid4().hex[:12]}")
    target: str = ""
    name: str = ""
    status: InvestigationStatus = InvestigationStatus.CREATED
    scope: ScopeInfo = Field(default_factory=lambda: ScopeInfo(target=""))
    tasks: list[Task] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    notes: list[ManualNote] = Field(default_factory=list)
    selected_knowledge_packs: list[str] = Field(default_factory=list)
    selected_methodology_packs: list[str] = Field(default_factory=list)
    current_step: str = ""
    completed_steps: list[str] = Field(default_factory=list)
    checkpoint_data: dict[str, Any] = Field(default_factory=dict)
    reasoning_session_id: str = ""
    planner_result_id: str = ""
    report_id: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def in_scope(self) -> list[ScopeEntry]:
        return [e for e in self.scope.entries if e.entry_type == ScopeEntryType.IN_SCOPE]

    @property
    def out_of_scope(self) -> list[ScopeEntry]:
        return [e for e in self.scope.entries if e.entry_type == ScopeEntryType.OUT_OF_SCOPE]

    def get_tasks_by_status(self, status: TaskStatus) -> list[Task]:
        return [t for t in self.tasks if t.status == status]

    def get_tasks_by_category(self, category: TaskCategory) -> list[Task]:
        return [t for t in self.tasks if t.category == category]


# ── Workflow DSL Types ───────────────────────────────────────────────────────


class WorkflowStepType(StrEnum):
    BUILTIN = "builtin"
    AI = "ai"
    APPROVAL = "approval"
    CONDITIONAL = "conditional"
    SUB_WORKFLOW = "sub_workflow"


class WorkflowStepDefinition(BaseModel):
    """A single step in a YAML workflow definition."""

    id: str
    name: str = ""
    description: str = ""
    step_type: WorkflowStepType = Field(
        default=WorkflowStepType.BUILTIN, alias="type"
    )
    action: str = ""
    task_type: str = ""
    prompt_template: str = ""
    depends_on: list[str] = Field(default_factory=list)
    condition: str = ""
    branches: dict[str, list[str]] = Field(default_factory=dict)
    sub_workflow: str = ""
    approval_message: str = ""
    timeout_seconds: int = 300
    retry_count: int = 0
    config: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)


class WorkflowDefinition(BaseModel):
    """A complete YAML workflow definition."""

    name: str
    description: str = ""
    version: str = "1.0"
    steps: list[WorkflowStepDefinition] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)


class WorkflowStepResult(BaseModel):
    """Result of executing a single workflow step."""

    step_id: str
    success: bool
    data: dict[str, Any] = Field(default_factory=dict)
    error: str = ""
    execution_time_ms: float = 0.0


class WorkflowResult(BaseModel):
    """Result of executing an entire workflow."""

    workflow_name: str
    success: bool
    step_results: list[WorkflowStepResult] = Field(default_factory=list)
    total_execution_time_ms: float = 0.0
    error: str = ""


# ── Investigation Report ─────────────────────────────────────────────────────


class InvestigationReport(BaseModel):
    """A complete structured investigation report."""

    title: str
    target: str
    executive_summary: str = ""
    scope_summary: str = ""
    recon_summary: str = ""
    technology_profile: str = ""
    attack_surface_summary: str = ""
    methodology_applied: str = ""
    timeline: str = ""
    evidence_summary: list[EvidenceRecord] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    suggested_manual_tests: list[str] = Field(default_factory=list)
    draft_findings: list[dict[str, Any]] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    completed_tasks: list[Task] = Field(default_factory=list)
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_markdown(self) -> str:
        """Render the report as Markdown."""
        lines = [
            f"# Investigation Report: {self.title}",
            "",
            f"**Target:** {self.target}",
            f"**Generated:** {self.generated_at}",
            "",
            "## Executive Summary",
            "",
            self.executive_summary or "*No summary provided.*",
            "",
            "## Scope",
            "",
            self.scope_summary or "*No scope defined.*",
            "",
            "## Recon Summary",
            "",
            self.recon_summary or "*No recon data.*",
            "",
            "## Technology Profile",
            "",
            self.technology_profile or "*No technologies identified.*",
            "",
            "## Attack Surface Summary",
            "",
            self.attack_surface_summary or "*No attack surface data.*",
            "",
            "## Methodology Applied",
            "",
            self.methodology_applied or "*No methodology selected.*",
            "",
            "## Investigation Timeline",
            "",
            self.timeline or "*No timeline data.*",
            "",
            "## Evidence",
            "",
        ]
        if self.evidence_summary:
            for ev in self.evidence_summary:
                lines.append(f"- **{ev.title}** ({ev.evidence_type.value}): {ev.content[:200]}")
        else:
            lines.append("*No evidence collected.*")

        lines += [
            "",
            "## Open Questions",
            "",
        ]
        if self.open_questions:
            for q in self.open_questions:
                lines.append(f"- {q}")
        else:
            lines.append("*No open questions.*")

        lines += [
            "",
            "## Suggested Manual Tests",
            "",
        ]
        if self.suggested_manual_tests:
            for test in self.suggested_manual_tests:
                lines.append(f"- {test}")
        else:
            lines.append("*No manual tests suggested.*")

        lines += [
            "",
            "## Draft Findings",
            "",
        ]
        if self.draft_findings:
            for f in self.draft_findings:
                lines.append(f"- **{f.get('title', 'Untitled')}** ({f.get('severity', 'info')})")
                lines.append(f"  {f.get('description', '')[:200]}")
        else:
            lines.append("*No findings drafted.*")

        return "\n".join(lines)
