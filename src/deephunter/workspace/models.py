"""Workspace model for DeepHunter.

The workspace is the top-level organizational unit containing projects,
targets, investigation sessions, evidence, reports, and AI conversations.

Every asset, target, investigation, and report belongs to a workspace.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────────


class ProjectStatus(str, Enum):
    """Status of a project."""

    ACTIVE = "active"
    ARCHIVED = "archived"
    DELETED = "deleted"


class TargetType(str, Enum):
    """Type of target."""

    WEB_APPLICATION = "web_application"
    API = "api"
    MOBILE = "mobile"
    INFRASTRUCTURE = "infrastructure"
    CLOUD = "cloud"
    SOURCE_CODE = "source_code"
    COMPILED_BINARY = "compiled_binary"
    IOT = "iot"
    OTHER = "other"


class TargetStatus(str, Enum):
    """Status of a target in the workflow."""

    CREATED = "created"
    SCOPE_DEFINED = "scope_defined"
    RECON_IN_PROGRESS = "recon_in_progress"
    RECON_COMPLETED = "recon_completed"
    INVESTIGATION_IN_PROGRESS = "investigation_in_progress"
    INVESTIGATION_COMPLETED = "investigation_completed"
    REPORT_IN_PROGRESS = "report_in_progress"
    REPORT_COMPLETED = "report_completed"
    ARCHIVED = "archived"


class AttachmentType(str, Enum):
    """Type of attachment."""

    SCREENSHOT = "screenshot"
    HAR_FILE = "har_file"
    BURP_STATE = "burp_state"
    OPENAPI_SPEC = "openapi_spec"
    DOCUMENTATION = "documentation"
    CODE_SNIPPET = "code_snippet"
    PCAP = "pcap"
    LOG_FILE = "log_file"
    OTHER = "other"


class ReportFormat(str, Enum):
    """Available report formats."""

    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    SARIF = "sarif"
    PDF = "pdf"


class ConversationRole(str, Enum):
    """Role in an AI conversation."""

    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"


# ── Core Models ──────────────────────────────────────────────────────────────


class WorkspaceUser(BaseModel):
    """A user with access to the workspace."""

    user_id: str = Field(default_factory=lambda: f"usr-{uuid4().hex[:12]}")
    email: str = ""
    name: str = ""
    role: str = "viewer"
    added_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Project(BaseModel):
    """A top-level project containing targets and investigations.

    Represents a bug bounty program, pentest engagement, or security review.
    """

    id: str = Field(default_factory=lambda: f"prj-{uuid4().hex[:12]}")
    name: str = Field(description="Project name")
    description: str = Field(default="")
    status: ProjectStatus = Field(default=ProjectStatus.ACTIVE)
    owner_id: str = Field(default="")
    team_members: list[WorkspaceUser] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    archived_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    def model_dump_for_storage(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class Target(BaseModel):
    """A single target within a project.

    Can be a web application, API, mobile app, infrastructure, etc.
    """

    id: str = Field(default_factory=lambda: f"tgt-{uuid4().hex[:12]}")
    project_id: str = Field(description="Parent project ID")
    name: str = Field(description="Human-readable target name")
    target_type: TargetType = Field(default=TargetType.WEB_APPLICATION)
    status: TargetStatus = Field(default=TargetStatus.CREATED)
    url: str = Field(default="", description="Primary URL")
    description: str = Field(default="")
    scope: TargetScope = Field(default_factory=lambda: TargetScope())
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    def model_dump_for_storage(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class TargetScope(BaseModel):
    """Scope entries for a target."""

    in_scope: list[ScopeEntry] = Field(default_factory=list)
    out_of_scope: list[ScopeEntry] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    note: str = ""


class ScopeEntry(BaseModel):
    """A single scope entry (URL pattern, asset, etc.)."""

    entry_type: str = Field(default="url", description="Type: url, asset, cidr, domain")
    value: str = Field(description="The scope value (URL, asset, etc.)")
    comment: str = ""
    wildcards_allowed: bool = True


class Tag(BaseModel):
    """A tag for organizing workspace entities."""

    id: str = Field(default_factory=lambda: f"tag-{uuid4().hex[:12]}")
    name: str = Field(description="Tag name")
    color: str = Field(default="#6366f1", description="Hex color code")
    description: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Note(BaseModel):
    """A note attached to any workspace entity."""

    id: str = Field(default_factory=lambda: f"note-{uuid4().hex[:12]}")
    entity_type: str = Field(description="Type of entity: project, target, investigation, finding")
    entity_id: str = Field(description="ID of the entity")
    content: str = Field(description="Note content (markdown)")
    author_id: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Attachment(BaseModel):
    """A file attachment."""

    id: str = Field(default_factory=lambda: f"att-{uuid4().hex[:12]}")
    entity_type: str = Field(description="Type of entity this is attached to")
    entity_id: str = Field(description="ID of the entity")
    name: str = Field(description="Original filename")
    attachment_type: AttachmentType = Field(default=AttachmentType.OTHER)
    size_bytes: int = Field(default=0)
    mime_type: str = ""
    storage_path: str = Field(description="Path to stored file")
    uploaded_by: str = ""
    uploaded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)


class Asset(BaseModel):
    """A discovered asset within a target."""

    id: str = Field(default_factory=lambda: f"ast-{uuid4().hex[:12]}")
    target_id: str = Field(description="Parent target ID")
    asset_type: str = Field(description="Type: subdomain, host, endpoint, parameter")
    value: str = Field(description="Asset value")
    source: str = Field(default="", description="Discovery source")
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class InvestigationLink(BaseModel):
    """Links an investigation to a target."""

    id: str = Field(default_factory=lambda: f"inv-{uuid4().hex[:12]}")
    target_id: str = Field(description="Parent target ID")
    investigation_session_id: str = Field(description="Reasoning session ID")
    investigation_name: str = ""
    status: str = Field(default="in_progress")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None


class Report(BaseModel):
    """A generated security report."""

    id: str = Field(default_factory=lambda: f"rpt-{uuid4().hex[:12]}")
    target_id: str = Field(description="Parent target ID")
    title: str = Field(description="Report title")
    format: ReportFormat = Field(default=ReportFormat.MARKDOWN)
    content: str = Field(default="", description="Report content")
    findings_count: int = Field(default=0)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    generated_by: str = Field(default="", description="User or AI that generated")
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)

    def model_dump_for_storage(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ConversationMessage(BaseModel):
    """A single message in an AI conversation."""

    id: str = Field(default_factory=lambda: f"msg-{uuid4().hex[:12]}")
    role: ConversationRole = Field(description="User, assistant, or system")
    content: str = Field(description="Message content")
    model: str = Field(default="", description="Model used for assistant messages")
    tokens_used: int = Field(default=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)


class AIConversation(BaseModel):
    """A persistent AI conversation session."""

    id: str = Field(default_factory=lambda: f"cnv-{uuid4().hex[:12]}")
    target_id: str = Field(description="Associated target")
    title: str = Field(default="New Conversation", description="Conversation title")
    messages: list[ConversationMessage] = Field(default_factory=list)
    context_summary: str = Field(default="", description="Summarized context for this conversation")
    investigation_session_id: str = Field(default="", description="Linked investigation")
    evidence_references: list[str] = Field(default_factory=list, description="Evidence IDs referenced")
    knowledge_references: list[str] = Field(default_factory=list, description="SKO IDs referenced")
    model_preference: str = Field(default="", description="Preferred model for this conversation")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_message_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TimelineEvent(BaseModel):
    """An event in the project timeline."""

    id: str = Field(default_factory=lambda: f"evt-{uuid4().hex[:12]}")
    project_id: str = Field(description="Parent project ID")
    target_id: str | None = Field(default=None)
    event_type: str = Field(description="Event type: created, updated, finding, etc.")
    title: str = Field(description="Event title")
    description: str = Field(default="")
    severity: str = Field(default="info", description="info, low, medium, high, critical")
    entity_type: str = Field(default="", description="Related entity type")
    entity_id: str = Field(default="", description="Related entity ID")
    created_by: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)


class WorkspaceState(BaseModel):
    """Complete state of a workspace.

    This is the root container for all workspace data and serves
    as the serialization boundary for persistence.
    """

    workspace_id: str = Field(default_factory=lambda: f"ws-{uuid4().hex[:12]}")
    name: str = Field(default="Default Workspace", description="Workspace name")
    description: str = Field(default="")
    version: str = Field(default="1.0")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    projects: list[Project] = Field(default_factory=list)
    targets: list[Target] = Field(default_factory=list)
    tags: list[Tag] = Field(default_factory=list)
    notes: list[Note] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    investigation_links: list[InvestigationLink] = Field(default_factory=list)
    reports: list[Report] = Field(default_factory=list)
    conversations: list[AIConversation] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)

    metadata: dict[str, Any] = Field(default_factory=dict)

    def model_dump_for_storage(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorkspaceState:
        return cls(**data)


class Workspace(BaseModel):
    """Top-level workspace container.

    Wraps WorkspaceState and provides the public API for workspace
    operations including persistence and event emission.
    """

    id: str = Field(default_factory=lambda: f"ws-{uuid4().hex[:12]}")
    name: str = Field(default="Default Workspace")
    description: str = Field(default="")
    state: WorkspaceState = Field(default_factory=WorkspaceState)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def model_dump_for_storage(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "description": self.description, "state": self.state.model_dump_for_storage(), "created_at": self.created_at.isoformat(), "updated_at": self.updated_at.isoformat()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Workspace:
        return cls(**data)