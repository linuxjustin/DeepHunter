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


class WorkflowVariableType(StrEnum):
    STRING = "string"
    LIST = "list"
    BOOL = "bool"
    INTEGER = "integer"


class WorkflowVariable(BaseModel):
    """A typed workflow variable resolved from context or input."""

    name: str
    type: WorkflowVariableType = WorkflowVariableType.STRING
    default: Any = ""
    description: str = ""
    required: bool = False


class WorkflowVariables(BaseModel):
    """Runtime values for workflow variables."""

    framework: str = ""
    technologies: list[str] = Field(default_factory=list)
    cloud_provider: str = ""
    auth_method: str = ""
    graphql_enabled: bool = False
    api_present: bool = False
    websocket_enabled: bool = False
    sso_enabled: bool = False
    admin_panel_detected: bool = False
    planner_confidence: float = 0.0
    attack_surface_metadata: dict[str, Any] = Field(default_factory=dict)
    extra: dict[str, Any] = Field(default_factory=dict)


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


# ── Workflow Metrics ─────────────────────────────────────────────────────────


class WorkflowMetrics(BaseModel):
    """Real-time tracking metrics for a running workflow."""

    total_phases: int = 0
    completed_phases: int = 0
    total_steps: int = 0
    completed_steps: int = 0
    estimated_remaining_minutes: float = 0.0
    evidence_count: int = 0
    evidence_coverage: float = 0.0
    checklist_coverage: float = 0.0
    planner_confidence: float = 0.0
    outstanding_tasks: int = 0
    phase_metrics: dict[str, "PhaseMetrics"] = Field(default_factory=dict)


class PhaseMetrics(BaseModel):
    """Metrics for a single phase."""

    phase_id: str
    total_steps: int = 0
    completed_steps: int = 0
    estimated_minutes: int = 0
    evidence_collected: int = 0
    evidence_required: int = 0
    completion_pct: float = 0.0


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
    completed_phases: list[str] = Field(default_factory=list)
    variables: WorkflowVariables = Field(default_factory=WorkflowVariables)
    metrics: WorkflowMetrics = Field(default_factory=WorkflowMetrics)
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


# ── Workflow Phases ──────────────────────────────────────────────────────────


class PhaseResourceRef(BaseModel):
    """Reference to a knowledge pack, methodology pack, or planner rule."""

    name: str
    type: str = "knowledge_pack"  # knowledge_pack, methodology_pack, planner_rule
    config: dict[str, Any] = Field(default_factory=dict)


class PhaseEvidenceRequirement(BaseModel):
    """Expected evidence to be collected during a phase."""

    description: str
    evidence_type: str = "observation"
    required: bool = True


class WorkflowStepType(StrEnum):
    BUILTIN = "builtin"
    AI = "ai"
    APPROVAL = "approval"
    CONDITIONAL = "conditional"
    SUB_WORKFLOW = "sub_workflow"


class PhaseStep(BaseModel):
    """A step definition within a workflow phase."""

    id: str
    name: str = ""
    description: str = ""
    objective: str = ""
    step_type: WorkflowStepType = Field(default=WorkflowStepType.BUILTIN, alias="type")
    action: str = ""
    task_type: str = ""
    prompt_template: str = ""
    depends_on: list[str] = Field(default_factory=list)
    condition: str = ""
    branches: dict[str, list[str]] = Field(default_factory=dict)
    approval_message: str = ""
    timeout_seconds: int = 600
    retry_count: int = 0
    estimated_time_minutes: int = 15
    priority: str = "medium"
    difficulty: str = "medium"
    required_inputs: list[str] = Field(default_factory=list)
    expected_outputs: list[str] = Field(default_factory=list)
    evidence_requirements: list[PhaseEvidenceRequirement] = Field(default_factory=list)
    completion_criteria: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)


class WorkflowPhase(BaseModel):
    """A named phase containing multiple steps."""

    id: str
    name: str = ""
    description: str = ""
    steps: list[PhaseStep] = Field(default_factory=list)
    resources: list[PhaseResourceRef] = Field(default_factory=list)
    methodology_packs: list[str] = Field(default_factory=list)
    knowledge_packs: list[str] = Field(default_factory=list)
    planner_rules: list[str] = Field(default_factory=list)
    checkpoints: list[str] = Field(default_factory=list)
    evidence_requirements: list[PhaseEvidenceRequirement] = Field(default_factory=list)


class WorkflowCheckpoint(BaseModel):
    """A named checkpoint that can be used for pause/resume."""

    id: str
    name: str = ""
    description: str = ""
    phase_id: str = ""
    requires_approval: bool = False
    approval_message: str = ""


# ── Workflow Templates ───────────────────────────────────────────────────────


class WorkflowTemplate(BaseModel):
    """A reusable template that can be referenced by workflows."""

    name: str
    description: str = ""
    phases: list[WorkflowPhase] = Field(default_factory=list)
    variables: list[WorkflowVariable] = Field(default_factory=list)
    inputs: dict[str, str] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)


# ── Conditional Phase ────────────────────────────────────────────────────────


class ConditionalPhase(BaseModel):
    """A phase that is conditionally executed based on a condition."""

    phase: WorkflowPhase
    condition: str = ""
    framework_match: list[str] = Field(default_factory=list)
    technology_match: list[str] = Field(default_factory=list)
    variable_match: dict[str, Any] = Field(default_factory=dict)


# ── Expanded Workflow Definition ──────────────────────────────────────────────


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
    phases: list[WorkflowPhase] = Field(default_factory=list)
    conditional_phases: list[ConditionalPhase] = Field(default_factory=list)
    templates: list[WorkflowTemplate] = Field(default_factory=list)
    variables: list[WorkflowVariable] = Field(default_factory=list)
    checkpoints: list[WorkflowCheckpoint] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)

    def get_phase(self, phase_id: str) -> WorkflowPhase | None:
        for p in self.phases:
            if p.id == phase_id:
                return p
        return None


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
    metrics: WorkflowMetrics | None = None


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
            "# " + self.title,
            "",
            "## Metadata",
            "",
            f"- **Target:** {self.target}",
            f"- **Generated:** {self.generated_at}",
            f"- **Report ID:** {self.report_id if hasattr(self, 'report_id') else 'N/A'}",
            "",
            "---\n",
            "## Executive Summary",
            "",
        ]
        exec_summary = self.executive_summary or "*No summary provided.*"
        lines.append(exec_summary)

        lines.extend([
            "",
            "---\n",
            "## Scope",
            "",
        ])
        lines.append(self.scope_summary or "*No scope defined.*")

        lines.extend([
            "",
            "---\n",
            "## Reconnaissance Summary",
            "",
        ])
        lines.append(self.recon_summary or "*No recon data.*")

        lines.extend([
            "",
            "---\n",
            "## Technology Profile",
            "",
        ])
        lines.append(self.technology_profile or "*No technologies identified.*")

        lines.extend([
            "",
            "---\n",
            "## Attack Surface Summary",
            "",
        ])
        lines.append(self.attack_surface_summary or "*No attack surface data.*")

        lines.extend([
            "",
            "---\n",
            "## Methodology Applied",
            "",
        ])
        lines.append(self.methodology_applied or "*No methodology selected.*")

        lines.extend([
            "",
            "---\n",
            "## Investigation Timeline",
            "",
        ])
        lines.append(self.timeline or "*No timeline data.*")

        lines.extend([
            "",
            "---\n",
            "## Evidence Collected",
            "",
        ])
        if self.evidence_summary:
            by_type: dict[str, list[EvidenceRecord]] = {}
            for ev in self.evidence_summary:
                by_type.setdefault(ev.evidence_type.value, []).append(ev)

            for ev_type, records in sorted(by_type.items()):
                lines.append(f"### {ev_type.replace('_', ' ').title()} ({len(records)})")
                for ev in records[:10]:
                    content = ev.content[:300].replace("\n", " ")
                    lines.append(f"- **{ev.title}**: {content}...")
                if len(records) > 10:
                    lines.append(f"  _... and {len(records) - 10} more {ev_type}_")
                lines.append("")
        else:
            lines.append("*No evidence collected.*\n")

        lines.extend([
            "",
            "---\n",
            "## Draft Findings",
            "",
        ])
        if self.draft_findings:
            severity_order = ["critical", "high", "medium", "low", "info"]
            by_severity: dict[str, list[dict]] = {s: [] for s in severity_order}
            for f in self.draft_findings:
                sev = f.get("severity", "info")
                by_severity.setdefault(sev, []).append(f)

            for sev in severity_order:
                findings = by_severity.get(sev, [])
                if not findings:
                    continue
                sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}.get(sev, "⚪")
                lines.append(f"### {sev_icon} {sev.upper()} Severity ({len(findings)})")
                for f in findings:
                    title = f.get("title", "Untitled")
                    desc = f.get("description", "")[:200]
                    category = f.get("category", "other")
                    confidence = f.get("confidence", 0)
                    lines.append(f"#### {title}")
                    lines.append(f"- **Category:** {category}")
                    lines.append(f"- **Severity:** {sev}")
                    lines.append(f"- **Confidence:** {confidence:.0%}")
                    if f.get("evidence_count"):
                        lines.append(f"- **Evidence Count:** {f['evidence_count']}")
                    if desc:
                        lines.append(f"- **Description:** {desc}")
                    if f.get("sample_evidence"):
                        lines.append(f"- **Sample Evidence:** {f['sample_evidence']}...")
                    lines.append("")
        else:
            lines.append("*No findings drafted.*\n")

        lines.extend([
            "",
            "---\n",
            "## Open Questions",
            "",
        ])
        if self.open_questions:
            for q in self.open_questions:
                lines.append(f"- {q}")
        else:
            lines.append("*No open questions.*\n")

        lines.extend([
            "",
            "---\n",
            "## Suggested Manual Tests",
            "",
        ])
        if self.suggested_manual_tests:
            for test in self.suggested_manual_tests:
                lines.append(f"- {test}")
        else:
            lines.append("*No manual tests suggested.*\n")

        if self.references:
            lines.extend([
                "",
                "---\n",
                "## References",
                "",
            ])
            for ref in self.references:
                lines.append(f"- {ref}")

        lines.extend([
            "",
            "---\n",
            f"*Report generated by DeepHunter on {self.generated_at}*",
        ])

        return "\n".join(lines)
