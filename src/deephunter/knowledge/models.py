"""Security Knowledge Object (SKO) model.

Every ingested document becomes a structured SKO with typed fields
for classification, relationships, and provenance tracking.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
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
    author: Optional[str] = Field(default=None)
    created: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this SKO was created",
    )
    updated: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this SKO was last updated",
    )

    tags: List[str] = Field(default_factory=list)

    technology: List[Technology] = Field(default_factory=list)
    framework: List[Framework] = Field(default_factory=list)
    language: List[str] = Field(default_factory=list)
    cloud_provider: List[CloudProvider] = Field(default_factory=list)

    bug_classes: List[BugClass] = Field(default_factory=list)
    authentication: List[AuthMechanism] = Field(default_factory=list)
    trust_boundaries: List[TrustBoundary] = Field(default_factory=list)

    interesting_headers: List[str] = Field(default_factory=list)
    interesting_parameters: List[str] = Field(default_factory=list)

    high_level_testing_ideas: List[TestingIdea] = Field(default_factory=list)

    related_frameworks: List[Framework] = Field(default_factory=list)
    related_bug_classes: List[BugClass] = Field(default_factory=list)
    related_writeups: List[RelatedReference] = Field(default_factory=list)
    related_cves: List[RelatedReference] = Field(default_factory=list)

    references: List[RelatedReference] = Field(default_factory=list)

    confidence: Confidence = Field(default=Confidence.UNKNOWN)

    raw_content: Optional[str] = Field(
        default=None,
        description="Original document text, retained for RAG embedding",
    )

    metadata: List[Metadata] = Field(default_factory=list)

    @field_validator("title")
    @classmethod
    def _title_non_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("title must not be empty")
        return stripped

    @model_validator(mode="after")
    def _sync_updated(self) -> SecurityKnowledgeObject:
        self.updated = datetime.now(timezone.utc)
        return self

    def model_dump_for_storage(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict for persistence."""
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SecurityKnowledgeObject:
        """Deserialize from a dict (e.g. loaded from JSON storage)."""
        return cls(**data)


class SKOBuilder:
    """Fluent builder for constructing SecurityKnowledgeObject instances.

    Usage::

        sko = (
            SKOBuilder()
            .title("JWT Attack Vectors")
            .source("https://example.com/jwt-attacks")
            .source_type(SourceType.OWASP)
            .add_bug_class(BugClass.AUTH_BYPASS)
            .add_technology(Technology.NODEJS)
            .build()
        )
    """

    def __init__(self) -> None:
        self._data: Dict[str, Any] = {
            "tags": [],
            "technology": [],
            "framework": [],
            "language": [],
            "cloud_provider": [],
            "bug_classes": [],
            "authentication": [],
            "trust_boundaries": [],
            "interesting_headers": [],
            "interesting_parameters": [],
            "high_level_testing_ideas": [],
            "related_frameworks": [],
            "related_bug_classes": [],
            "related_writeups": [],
            "related_cves": [],
            "references": [],
            "metadata": [],
        }

    def title(self, value: str) -> SKOBuilder:
        self._data["title"] = value
        return self

    def summary(self, value: str) -> SKOBuilder:
        self._data["summary"] = value
        return self

    def source(self, value: str) -> SKOBuilder:
        self._data["source"] = value
        return self

    def source_type(self, value: SourceType) -> SKOBuilder:
        self._data["source_type"] = value
        return self

    def document_type(self, value: DocumentType) -> SKOBuilder:
        self._data["document_type"] = value
        return self

    def author(self, value: str) -> SKOBuilder:
        self._data["author"] = value
        return self

    def raw_content(self, value: str) -> SKOBuilder:
        self._data["raw_content"] = value
        return self

    def confidence(self, value: Confidence) -> SKOBuilder:
        self._data["confidence"] = value
        return self

    def add_tag(self, tag: str) -> SKOBuilder:
        self._data["tags"].append(tag)
        return self

    def add_bug_class(self, bc: BugClass) -> SKOBuilder:
        self._data["bug_classes"].append(bc)
        return self

    def add_technology(self, tech: Technology) -> SKOBuilder:
        self._data["technology"].append(tech)
        return self

    def add_reference(self, ref: RelatedReference) -> SKOBuilder:
        self._data["references"].append(ref)
        return self

    def add_testing_idea(self, idea: TestingIdea) -> SKOBuilder:
        self._data["high_level_testing_ideas"].append(idea)
        return self

    def build(self) -> SecurityKnowledgeObject:
        """Construct the SKO, or raise if validation fails."""
        return SecurityKnowledgeObject(**self._data)