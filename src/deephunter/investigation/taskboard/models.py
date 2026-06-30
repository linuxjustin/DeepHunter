"""Task Board Models.

Kanban-style task tracking integrated with Planner, Methodology Packs,
Knowledge Packs, and Evidence.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class BoardColumn(str, Enum):
    """Standard Kanban columns."""

    BACKLOG = "backlog"
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    NEEDS_VERIFICATION = "needs_verification"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class TaskPriority(str, Enum):
    """Task priority levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TaskCategory(str, Enum):
    """Task categories matching methodology packs."""

    RECON = "recon"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    BUSINESS_LOGIC = "business_logic"
    INPUT_VALIDATION = "input_validation"
    API_ANALYSIS = "api_analysis"
    FILE_UPLOAD = "file_upload"
    CLOUD_ANALYSIS = "cloud_analysis"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SESSION_MANAGEMENT = "session_management"
    CRYPTO_ISSUES = "crypto_issues"
    INFORMATION_DISCLOSURE = "information_disclosure"
    CLIENT_SIDE = "client_side"
    NETWORK = "network"
    REPORTING = "reporting"
    OTHER = "other"


class TaskStatus(str, Enum):
    """Task execution status."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class BoardCard(BaseModel):
    """A single task card on the Kanban board."""

    id: str = Field(default_factory=lambda: f"card-{uuid4().hex[:12]}")
    target_id: str = Field(description="Associated target")
    investigation_session_id: str = Field(default="", description="Linked investigation session")

    title: str = Field(description="Task title")
    description: str = Field(default="", description="Detailed description (markdown)")

    column: BoardColumn = Field(default=BoardColumn.BACKLOG)
    status: TaskStatus = Field(default=TaskStatus.PENDING)
    priority: TaskPriority = Field(default=TaskPriority.MEDIUM)
    category: TaskCategory = Field(default=TaskCategory.OTHER)

    assigned_to: str = Field(default="", description="User ID assigned to this task")
    estimated_minutes: int = Field(default=0)
    actual_minutes: int = Field(default=0)

    tags: list[str] = Field(default_factory=list)

    linked_evidence_ids: list[str] = Field(default_factory=list)
    linked_hypothesis_ids: list[str] = Field(default_factory=list)
    linked_knowledge_pack_ids: list[str] = Field(default_factory=list)
    linked_methodology_pack_ids: list[str] = Field(default_factory=list)
    linked_planner_step_ids: list[str] = Field(default_factory=list)
    linked_notebook_entry_ids: list[str] = Field(default_factory=list)

    depends_on: list[str] = Field(default_factory=list, description="Card IDs this depends on")
    blocking: list[str] = Field(default_factory=list, description="Card IDs blocked by this")

    notes: str = Field(default="", description="Working notes")
    findings: str = Field(default="", description="Findings from this task")

    parent_card_id: str = Field(default="", description="Parent card if subtask")
    order_in_column: int = Field(default=0)

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    archived_at: datetime | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    def model_dump_for_storage(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ColumnConfig(BaseModel):
    """Configuration for a Kanban column."""

    column: BoardColumn
    wip_limit: int = Field(default=0, description="Max cards in column, 0=unlimited")
    collapsed: bool = Field(default=False)
    color: str = Field(default="#6366f1")


class BoardState(BaseModel):
    """Complete state of a task board."""

    target_id: str
    investigation_session_id: str = Field(default="")

    cards: list[BoardCard] = Field(default_factory=list)
    column_configs: list[ColumnConfig] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class BoardSummary(BaseModel):
    """Summary statistics for a task board."""

    total_cards: int = 0
    cards_by_column: dict[str, int] = Field(default_factory=dict)
    cards_by_status: dict[str, int] = Field(default_factory=dict)
    cards_by_priority: dict[str, int] = Field(default_factory=dict)
    cards_by_category: dict[str, int] = Field(default_factory=dict)
    completion_rate: float = 0.0
    avg_time_to_complete_minutes: float = 0.0
    overdue_cards: int = 0