"""Investigation Workflow — end-to-end coordination of all DeepHunter subsystems.

This module composes existing components (Planner, AgentOrchestratorV2,
ModelRouter, InvestigationSession, ContextEngine, etc.) into complete,
repeatable investigation workflows driven by YAML DSL definitions.

It does NOT introduce new architectural layers — it orchestrates what exists.
"""

from __future__ import annotations

from deephunter.investigation.evidence import EvidenceManager
from deephunter.investigation.models import (
    EvidenceRecord,
    InvestigationReport,
    InvestigationSessionState,
    InvestigationStatus,
    ManualNote,
    ScopeEntry,
    ScopeEntryType,
    ScopeInfo,
    Task,
    TaskCategory,
    TaskPriority,
    TaskStatus,
    WorkflowDefinition,
    WorkflowResult,
    WorkflowStepDefinition,
    WorkflowStepResult,
    WorkflowStepType,
)
from deephunter.investigation.models import (
    EvidenceType as InvestigationEvidenceType,
)
from deephunter.investigation.orchestrator import InvestigationOrchestrator
from deephunter.investigation.report import ReportGenerator
from deephunter.investigation.workflow import (
    WorkflowLoader,
    WorkflowStepHandler,
)

__all__ = [
    "EvidenceManager",
    "EvidenceRecord",
    "InvestigationEvidenceType",
    "InvestigationOrchestrator",
    "InvestigationReport",
    "InvestigationSessionState",
    "InvestigationStatus",
    "ManualNote",
    "ReportGenerator",
    "ScopeEntry",
    "ScopeEntryType",
    "ScopeInfo",
    "Task",
    "TaskCategory",
    "TaskPriority",
    "TaskStatus",
    "WorkflowDefinition",
    "WorkflowLoader",
    "WorkflowResult",
    "WorkflowStepDefinition",
    "WorkflowStepHandler",
    "WorkflowStepResult",
    "WorkflowStepType",
]
