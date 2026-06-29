"""Security Knowledge Object (SKO) model.

Every ingested document becomes a structured SKO with typed fields
for classification, relationships, and provenance tracking.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

from deephunter.core.types import (
    AuthMechanism,
    BugClass,
    CloudProvider,
    Confidence,
    DocumentType,
    Framework,
    Metadata,
    RelatedReference,
    SourceType,
    Technology,
    TestingIdea,
    TrustBoundary,
)


class SecurityKnowledgeObject(BaseModel):
    """A structured Security Knowledge Object.

    Stores parsed and classified security knowledge extracted from
    documents, along with provenance and relationship metadata.
    """

    id: str = Field(
        default_factory=lambda: f"sko-{uuid4().hex[:12]}",
        description="Unique identifier for this SKO",
    )
    title: str = Field(description="Human-readable title")
    summary: str = Field(default="", description="Brief summary of the content")
    source: str = Field(description="Original source (URL or file path)")
    source_type: SourceType = Field(
        default=SourceType.OTHER, description="Classification of the source"
    )
    document_type: DocumentType = Field(
        default=DocumentType.UNKNOWN, description="Format of the source document"
    )
    author: str | None = Field(default=None)
    created: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this SKO was created",
    )
    updated: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this SKO was last updated",
    )

    tags: list[str] = Field(default_factory=list)

    technology: list[Technology] = Field(default_factory=list)
    framework: list[Framework] = Field(default_factory=list)
    language: list[str] = Field(default_factory=list)
    cloud_provider: list[CloudProvider] = Field(default_factory=list)

    bug_classes: list[BugClass] = Field(default_factory=list)
    authentication: list[AuthMechanism] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)

    interesting_headers: list[str] = Field(default_factory=list)
    interesting_parameters: list[str] = Field(default_factory=list)

    high_level_testing_ideas: list[TestingIdea] = Field(default_factory=list)

    related_frameworks: list[Framework] = Field(default_factory=list)
    related_bug_classes: list[BugClass] = Field(default_factory=list)
    related_writeups: list[RelatedReference] = Field(default_factory=list)
    related_cves: list[RelatedReference] = Field(default_factory=list)

    references: list[RelatedReference] = Field(default_factory=list)

    confidence: Confidence = Field(default=Confidence.UNKNOWN)

    raw_content: str | None = Field(
        default=None,
        description="Original document text, retained for RAG embedding",
    )

    metadata: list[Metadata] = Field(default_factory=list)

    @field_validator("title")
    @classmethod
    def _title_non_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("title must not be empty")
        return stripped

    @model_validator(mode="after")
    def _sync_updated(self) -> SecurityKnowledgeObject:
        self.updated = datetime.now(UTC)
        return self

    def model_dump_for_storage(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict for persistence."""
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityKnowledgeObject:
        """Deserialize from a dict (e.g. loaded from JSON storage)."""
        return cls(**data)
