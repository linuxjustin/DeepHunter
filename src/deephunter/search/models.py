"""Unified Search Module.

Provides cross-entity search across notes, evidence, endpoints, tasks,
knowledge packs, methodology packs, and reports.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class SearchScope(str, Enum):
    """Scopes available for search."""

    ALL = "all"
    NOTEBOOK = "notebook"
    EVIDENCE = "evidence"
    ENDPOINTS = "endpoints"
    PARAMETERS = "parameters"
    TECHNOLOGIES = "technologies"
    TASKS = "tasks"
    FINDINGS = "findings"
    HYPOTHESES = "hypotheses"
    REPORTS = "reports"
    KNOWLEDGE_PACKS = "knowledge_packs"
    METHODOLOGY_PACKS = "methodology_packs"
    CONVERSATIONS = "conversations"


class SearchResultType(str, Enum):
    """Types of search results."""

    NOTEBOOK_ENTRY = "notebook_entry"
    EVIDENCE = "evidence"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    TECHNOLOGY = "technology"
    TASK = "task"
    FINDING = "finding"
    HYPOTHESIS = "hypothesis"
    REPORT = "report"
    KNOWLEDGE_PACK = "knowledge_pack"
    METHODOLOGY_PACK = "methodology_pack"
    CONVERSATION = "conversation"
    NOTE = "note"
    ASSET = "asset"


class SearchResult(BaseModel):
    """A single search result."""

    result_type: SearchResultType
    result_id: str

    title: str = Field(description="Result title")
    description: str = Field(default="", description="Brief description/summary")
    content_snippet: str = Field(default="", description="Matching content snippet")

    relevance_score: float = Field(default=0.0, ge=0.0, le=1.0)

    target_id: str = Field(default="")
    investigation_session_id: str = Field(default="")

    url_path: str = Field(default="", description="API URL path to this result")

    created_at: datetime | None = None
    updated_at: datetime | None = None

    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SearchQuery(BaseModel):
    """A search query with filters."""

    query: str = Field(description="Search query string")
    scopes: list[SearchScope] = Field(default_factory=lambda: [SearchScope.ALL])
    target_id: str = Field(default="")
    investigation_session_id: str = Field(default="")

    limit: int = Field(default=20, ge=1, le=100)
    offset: int = Field(default=0, ge=0)

    tags: list[str] = Field(default_factory=list, description="Filter by tags")
    date_from: datetime | None = None
    date_to: datetime | None = None

    include_archived: bool = Field(default=False)

    metadata: dict[str, Any] = Field(default_factory=dict)


class SearchResponse(BaseModel):
    """Response from a search query."""

    query: str = Field(description="Original query")
    total_results: int = Field(default=0)
    results: list[SearchResult] = Field(default_factory=list)

    execution_time_ms: float = 0.0

    pagination: dict[str, Any] = Field(default_factory=dict)

    suggestions: list[str] = Field(default_factory=list, description="Alternative queries")


class SearchIndexEntry(BaseModel):
    """An entry in the search index."""

    id: str = Field(default_factory=lambda: f"idx-{uuid4().hex[:12]}")
    entity_type: SearchResultType
    entity_id: str

    title: str = Field(default="")
    content: str = Field(default="", description="Full text content to search")
    summary: str = Field(default="")

    target_id: str = Field(default="")
    investigation_session_id: str = Field(default="")

    indexed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime | None = None

    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SearchFilter(BaseModel):
    """A filter for refining search."""

    field: str = Field(description="Field to filter on")
    operator: str = Field(default="equals", description="equals, contains, gt, lt, in")
    value: Any = Field(description="Filter value")