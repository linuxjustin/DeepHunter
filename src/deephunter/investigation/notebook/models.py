"""Investigation Notebook Models.

The notebook provides a structured, unified view of all research artifacts
produced during an investigation. It supports notes, observations, questions,
hypotheses, evidence references, and more - all queryable and exportable.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class NoteType(str, Enum):
    """Types of notebook entries."""

    RESEARCH_NOTE = "research_note"
    OBSERVATION = "observation"
    QUESTION = "question"
    HYPOTHESIS = "hypothesis"
    EVIDENCE_REF = "evidence_ref"
    INTERESTING_URL = "interesting_url"
    INTERESTING_PARAMETER = "interesting_parameter"
    INTERESTING_TECHNOLOGY = "interesting_technology"
    INTERESTING_AUTH_FLOW = "interesting_auth_flow"
    INTERESTING_API = "interesting_api"
    MANUAL_FINDING = "manual_finding"
    REFERENCE = "reference"
    CHECKLIST = "checklist"
    CODE_SNIPPET = "code_snippet"
    SCREENSHOT = "screenshot"
    TODO = "todo"


class NoteStatus(str, Enum):
    """Status of a notebook entry."""

    ACTIVE = "active"
    ARCHIVED = "archived"
    FLAGGED = "flagged"
    RESOLVED = "resolved"


class EvidenceRefType(str, Enum):
    """Type of evidence reference."""

    HTTP_EXCHANGE = "http_exchange"
    RECON_ARTIFACT = "recon_artifact"
    SCREENSHOT = "screenshot"
    CODE_SNIPPET = "code_snippet"
    MANUAL_NOTE = "manual_note"
    AI_GENERATED = "ai_generated"


class NotebookEntry(BaseModel):
    """A single entry in the investigation notebook.

    Supports all research artifact types unified under one model.
    """

    id: str = Field(default_factory=lambda: f"nb-{uuid4().hex[:12]}")
    target_id: str = Field(description="Associated target")
    investigation_session_id: str = Field(default="", description="Linked investigation session")
    entry_type: NoteType = Field(description="Type of this entry")
    title: str = Field(default="", description="Brief title")
    content: str = Field(default="", description="Entry content (markdown)")
    status: NoteStatus = Field(default=NoteStatus.ACTIVE)
    author_id: str = Field(default="", description="Author user ID")

    tags: list[str] = Field(default_factory=list)
    linked_evidence_ids: list[str] = Field(default_factory=list)
    linked_hypothesis_ids: list[str] = Field(default_factory=list)
    linked_task_ids: list[str] = Field(default_factory=list)
    linked_finding_ids: list[str] = Field(default_factory=list)
    linked_endpoint_ids: list[str] = Field(default_factory=list)
    linked_parameter_ids: list[str] = Field(default_factory=list)
    linked_technology_ids: list[str] = Field(default_factory=list)
    linked_auth_flow_ids: list[str] = Field(default_factory=list)
    linked_api_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list, description="URLs or literature refs")

    severity: str = Field(default="", description="Severity if a finding")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    archived_at: datetime | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    def model_dump_for_storage(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class NotebookChecklistItem(BaseModel):
    """A single item in a checklist."""

    id: str = Field(default_factory=lambda: f"cli-{uuid4().hex[:12]}")
    text: str = Field(description="Checklist item text")
    checked: bool = Field(default=False)
    priority: str = Field(default="medium")
    assignee: str = Field(default="")


class NotebookChecklist(BaseModel):
    """A checklist within a notebook entry."""

    id: str = Field(default_factory=lambda: f"cl-{uuid4().hex[:12]}")
    title: str = Field(default="Checklist")
    items: list[NotebookChecklistItem] = Field(default_factory=list)


class HypothesisRef(BaseModel):
    """Reference to a hypothesis from the reasoning engine."""

    hypothesis_id: str
    title: str
    status: str
    confidence: float = 0.0
    priority: str = "medium"
    bug_classes: list[str] = Field(default_factory=list)


class EvidenceRef(BaseModel):
    """Reference to evidence from any source."""

    evidence_id: str
    ref_type: EvidenceRefType
    title: str
    source: str = ""
    description: str = ""
    tags: list[str] = Field(default_factory=list)


class EndpointRef(BaseModel):
    """Reference to an interesting endpoint."""

    endpoint_id: str = Field(default="", description="Recon endpoint ID")
    url: str = Field(description="Full URL")
    method: str = Field(default="GET")
    path: str = Field(description="URL path")
    category: str = Field(default="")
    description: str = Field(default="")
    auth_required: bool = False
    tags: list[str] = Field(default_factory=list)


class ParameterRef(BaseModel):
    """Reference to an interesting parameter."""

    parameter_id: str = Field(default="", description="Recon parameter ID")
    name: str = Field(description="Parameter name")
    location: str = Field(description="query, path, header, body, cookie")
    param_type: str = Field(default="", description="string, int, bool, etc.")
    endpoint_url: str = Field(default="")
    description: str = Field(default="")
    tags: list[str] = Field(default_factory=list)


class TechnologyRef(BaseModel):
    """Reference to an interesting technology."""

    technology_id: str = Field(default="", description="Recon technology ID")
    name: str = Field(description="Technology name")
    category: str = Field(default="", description="frontend, backend, framework, library, etc.")
    version: str = Field(default="")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    description: str = Field(default="")
    tags: list[str] = Field(default_factory=list)


class AuthFlowRef(BaseModel):
    """Reference to an interesting authentication flow."""

    auth_flow_id: str = Field(default="", description="Recon auth flow ID")
    flow_type: str = Field(default="", description="oauth2, saml, jwt, session, api_key, etc.")
    description: str = Field(default="")
    endpoints_involved: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class APIRef(BaseModel):
    """Reference to an interesting API or API endpoint."""

    api_id: str = Field(default="", description="Recon API ID")
    name: str = Field(description="API name")
    base_url: str = Field(default="")
    description: str = Field(default="")
    endpoints: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class NotebookState(BaseModel):
    """Complete notebook state for an investigation."""

    target_id: str
    investigation_session_id: str = Field(default="")
    entries: list[NotebookEntry] = Field(default_factory=list)

    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    endpoint_refs: list[EndpointRef] = Field(default_factory=list)
    parameter_refs: list[ParameterRef] = Field(default_factory=list)
    technology_refs: list[TechnologyRef] = Field(default_factory=list)
    auth_flow_refs: list[AuthFlowRef] = Field(default_factory=list)
    api_refs: list[APIRef] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class NotebookSummary(BaseModel):
    """Summary statistics for a notebook."""

    total_entries: int = 0
    entries_by_type: dict[str, int] = Field(default_factory=dict)
    entries_by_status: dict[str, int] = Field(default_factory=dict)
    total_evidence_refs: int = 0
    total_endpoint_refs: int = 0
    total_parameter_refs: int = 0
    total_technology_refs: int = 0
    total_auth_flow_refs: int = 0
    total_api_refs: int = 0
    flagged_entries: int = 0
    archived_entries: int = 0