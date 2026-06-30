"""Security Knowledge Object (SKO) model — v1.

Every ingested document becomes a structured SKO with typed fields
for classification, relationships, provenance tracking, and
future compatibility.

Versioning
----------
``schema_version`` is incremented when backward-incompatible changes
are made.  Parsers should always populate ``schema_version`` to the
latest known version.  Consumers should assert a minimum supported
version when reading SKOs.

Migration
---------
New fields are added with defaults so old SKOs deserialize cleanly.
When removing fields, add a ``model_validator`` that strips them.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

from deephunter.core.types import (
    AttackSurfaceEntry,
    AuthMechanism,
    AuthorizationModel,
    BugClass,
    BusinessLogicConcern,
    CloudProvider,
    Confidence,
    DocumentType,
    Framework,
    ManualTestChecklistItem,
    Metadata,
    PayloadReference,
    RelatedReference,
    SourceType,
    Technology,
    TestingIdea,
    TrustBoundary,
)

_SKO_ID_PATTERN = re.compile(r"^sko-[a-f0-9]{12}$")
_URL_OR_PATH_PATTERN = re.compile(r"^(https?://|file://|/|[a-zA-Z]:\\).+")
_SCHEMA_VERSION = 1


class SKOCurationStatus(str, Enum):
    """Curation workflow states for a Security Knowledge Object."""

    DRAFT = "draft"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


class SecurityKnowledgeObject(BaseModel):
    """A structured Security Knowledge Object (SKO v1).

    Stores parsed and classified security knowledge extracted from
    documents, along with provenance, relationships, and testing
    guidance metadata.
    """

    # ── Identity & versioning ──────────────────────────────────────
    schema_version: int = Field(
        default=_SCHEMA_VERSION,
        ge=1,
        description="SKO schema version for migration support",
    )
    id: str = Field(
        default_factory=lambda: f"sko-{uuid4().hex[:12]}",
        pattern=r"^sko-[a-f0-9]{12}$",
        description="Unique identifier (sko-<12 hex chars>)",
    )

    # ── Core content ───────────────────────────────────────────────
    title: str = Field(description="Human-readable title")
    summary: str = Field(default="", description="Brief summary of the content")
    description: str = Field(
        default="",
        description="Full description or analysis (longer than summary)",
    )

    # ── Provenance ─────────────────────────────────────────────────
    source: str = Field(description="Original source URL or file path")
    source_type: SourceType = Field(
        default=SourceType.OTHER,
        description="Classification of the source",
    )
    document_type: DocumentType = Field(
        default=DocumentType.UNKNOWN,
        description="Format of the source document",
    )
    author: str | None = Field(default=None, description="Original author or publisher")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this SKO was created",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this SKO was last updated",
    )

    # ── Classification ─────────────────────────────────────────────
    tags: list[str] = Field(
        default_factory=list,
        description="Free-form tags for categorization",
    )

    technology: list[Technology] = Field(
        default_factory=list,
        description="Technologies detected (e.g. Node.js, React)",
    )
    framework: list[Framework] = Field(
        default_factory=list,
        description="Security or development frameworks referenced",
    )
    programming_language: list[str] = Field(
        default_factory=list,
        description="Programming languages mentioned (e.g. Python, Go)",
    )
    operating_system: list[str] = Field(
        default_factory=list,
        description="Operating systems targeted (e.g. Linux, Windows)",
    )
    cloud_provider: list[CloudProvider] = Field(
        default_factory=list,
        description="Cloud providers referenced",
    )

    # ── Vulnerability classification ───────────────────────────────
    bug_classes: list[BugClass] = Field(
        default_factory=list,
        description="Detected bug classes (e.g. SQL injection, XSS)",
    )

    # ── Authentication & authorization ─────────────────────────────
    authentication: list[AuthMechanism] = Field(
        default_factory=list,
        description="Authentication mechanisms discussed",
    )
    authorization: list[AuthorizationModel] = Field(
        default_factory=list,
        description="Authorization models or checks described",
    )

    # ── Architecture analysis ──────────────────────────────────────
    business_logic: list[BusinessLogicConcern] = Field(
        default_factory=list,
        description="Business logic concerns or flaw patterns",
    )
    attack_surface: list[AttackSurfaceEntry] = Field(
        default_factory=list,
        description="Attack surface entry points identified",
    )
    trust_boundaries: list[TrustBoundary] = Field(
        default_factory=list,
        description="Trust boundaries in the target application",
    )

    # ── Interesting findings ───────────────────────────────────────
    interesting_headers: list[str] = Field(
        default_factory=list,
        description="Notable HTTP headers",
    )
    interesting_parameters: list[str] = Field(
        default_factory=list,
        description="Notable request parameters",
    )
    interesting_endpoints: list[str] = Field(
        default_factory=list,
        description="Notable API endpoints or routes",
    )

    # ── Testing guidance ───────────────────────────────────────────
    high_level_testing_ideas: list[TestingIdea] = Field(
        default_factory=list,
        description="High-level testing ideas derived from analysis",
    )
    manual_test_checklist: list[ManualTestChecklistItem] = Field(
        default_factory=list,
        description="Step-by-step manual penetration test checklist",
    )
    payload_references: list[PayloadReference] = Field(
        default_factory=list,
        description="Specific payload strings for testing",
    )

    # ── Relationships ──────────────────────────────────────────────
    related_cves: list[RelatedReference] = Field(
        default_factory=list,
        description="Related CVE entries",
    )
    related_cwes: list[str] = Field(
        default_factory=list,
        description="Related CWE identifiers (e.g. 'CWE-79', 'CWE-89')",
    )
    related_writeups: list[RelatedReference] = Field(
        default_factory=list,
        description="Related writeups or blog posts",
    )
    related_frameworks: list[Framework] = Field(
        default_factory=list,
        description="Related security frameworks or standards",
    )
    references: list[RelatedReference] = Field(
        default_factory=list,
        description="General references (URLs, papers, tools)",
    )

    # ── Confidence ─────────────────────────────────────────────────
    confidence: Confidence = Field(
        default=Confidence.UNKNOWN,
        description="Confidence in the SKO's accuracy and relevance",
    )

    # ── Curation workflow ──────────────────────────────────────────
    curation_status: SKOCurationStatus = Field(
        default=SKOCurationStatus.DRAFT,
        description="Curation workflow state",
    )
    curator: str | None = Field(
        default=None,
        description="User who curated this SKO",
    )
    curation_notes: str = Field(
        default="",
        description="Notes from the curation review",
    )
    reviewed_by: str | None = Field(
        default=None,
        description="User who approved/deprecated this SKO",
    )
    reviewed_at: datetime | None = Field(
        default=None,
        description="When this SKO was reviewed",
    )

    # ── Raw & processed content ────────────────────────────────────
    raw_content: str | None = Field(
        default=None,
        description="Original document text, retained for RAG embedding",
    )
    normalized_content: str | None = Field(
        default=None,
        description="Cleaned/normalized version of raw_content for dedup",
    )

    # ── Extensible metadata ────────────────────────────────────────
    metadata: list[Metadata] = Field(
        default_factory=list,
        description="Extensible key-value metadata for future fields",
    )

    # ────────────────────────────────────────────────────────────────
    # Validators
    # ────────────────────────────────────────────────────────────────

    @field_validator("title")
    @classmethod
    def _title_non_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("title must not be empty")
        return stripped

    @field_validator("source")
    @classmethod
    def _source_valid(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("source must not be empty")
        if not _URL_OR_PATH_PATTERN.match(stripped):
            raise ValueError(
                f"source must be a valid URL or absolute path, got: {stripped!r}"
            )
        return stripped

    @field_validator("id")
    @classmethod
    def _id_format(cls, v: str) -> str:
        if not _SKO_ID_PATTERN.match(v):
            raise ValueError(
                f"id must match pattern sko-<12 hex chars>, got: {v!r}"
            )
        return v

    @field_validator("related_cwes")
    @classmethod
    def _cwe_format(cls, v: list[str]) -> list[str]:
        for entry in v:
            if not re.match(r"^CWE-\d+$", entry.strip()):
                raise ValueError(
                    f"CWE entries must match 'CWE-<number>', got: {entry!r}"
                )
        return [e.strip() for e in v]

    @model_validator(mode="after")
    def _sync_updated(self) -> SecurityKnowledgeObject:
        self.updated_at = datetime.now(UTC)
        return self

    @model_validator(mode="after")
    def _version_check(self) -> SecurityKnowledgeObject:
        if self.schema_version < 1:
            raise ValueError(
                f"schema_version must be >= 1, got: {self.schema_version}"
            )
        return self

    # ────────────────────────────────────────────────────────────────
    # Serialization
    # ────────────────────────────────────────────────────────────────

    def model_dump_for_storage(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict for persistence."""
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityKnowledgeObject:
        """Deserialize from a dict (e.g. loaded from JSON storage)."""
        return cls(**data)

    @classmethod
    def current_schema_version(cls) -> int:
        """Return the latest schema version this code understands."""
        return _SCHEMA_VERSION
