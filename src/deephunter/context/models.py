"""Pydantic models for the Context Engine."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


class ContextSourceType(str, Enum):
    """Where context data originates."""

    KNOWLEDGE_STORE = "knowledge_store"
    REASONING_SESSION = "reasoning_session"
    INVESTIGATION_PLAN = "investigation_plan"
    USER_QUERY = "user_query"
    USER_CONSTRAINTS = "user_constraints"
    TECHNOLOGY_FINGERPRINT = "technology_fingerprint"
    FRAMEWORK_DETECTION = "framework_detection"
    AUTHENTICATION_STATE = "authentication_state"
    AUTHORIZATION_STATE = "authorization_state"
    BUSINESS_LOGIC = "business_logic"
    CLOUD_INFORMATION = "cloud_information"
    INTERESTING_HEADERS = "interesting_headers"
    INTERESTING_COOKIES = "interesting_cookies"
    INTERESTING_PARAMETERS = "interesting_parameters"
    INTERESTING_ENDPOINTS = "interesting_endpoints"
    PREVIOUS_FINDINGS = "previous_findings"
    PREVIOUS_EVIDENCE = "previous_evidence"
    USER_NOTES = "user_notes"
    RELATED_CVES = "related_cves"
    RELATED_CWES = "related_cwes"
    RELATED_WRITEUPS = "related_writeups"
    RELATED_PAYLOADS = "related_payloads"
    FRAMEWORK_DOCUMENTATION = "framework_documentation"
    TOOL_RESULTS = "tool_results"
    SCANNER_RESULTS = "scanner_results"
    BURP_INTEGRATION = "burp_integration"
    MCP_TOOLS = "mcp_tools"
    OTHER = "other"


class ContextImportance(str, Enum):
    """Importance level of a context block or section."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ContextBlock(BaseModel):
    """A single block of structured context data."""

    id: str = Field(default_factory=lambda: f"cb-{uuid4().hex[:12]}")
    section_id: str = ""
    source_type: ContextSourceType = ContextSourceType.OTHER
    importance: ContextImportance = ContextImportance.MEDIUM
    priority: float = 0.5
    content: str = ""
    summary: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    references: list[ContextReference] = Field(default_factory=list)
    estimated_tokens: int = 0
    created_at: datetime = Field(default_factory=utcnow)
    dedup_key: str = ""

    def model_dump_for_storage(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContextBlock:
        return cls(**data)


class ContextSection(BaseModel):
    """A named section containing context blocks."""

    id: str = Field(default_factory=lambda: f"cs-{uuid4().hex[:12]}")
    name: str = ""
    description: str = ""
    blocks: list[ContextBlock] = Field(default_factory=list)
    importance: ContextImportance = ContextImportance.MEDIUM
    priority: float = 0.5
    estimated_tokens: int = 0

    def add_block(self, block: ContextBlock) -> None:
        block.section_id = self.id
        self.blocks.append(block)

    def recalculate(self) -> None:
        self.estimated_tokens = sum(b.estimated_tokens for b in self.blocks)
        if self.blocks:
            self.importance = max(self.blocks, key=lambda b: _importance_rank(b.importance)).importance
            self.priority = max(b.priority for b in self.blocks)

    def model_dump_for_storage(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContextSection:
        return cls(**data)


class ContextSource(BaseModel):
    """Information about where context was sourced from."""

    type: ContextSourceType = ContextSourceType.OTHER
    name: str = ""
    description: str = ""
    record_count: int = 0
    query_time_ms: float = 0.0
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ContextReference(BaseModel):
    """A reference (CVE, CWE, writeup, payload, etc.)."""

    reference_type: str = "other"
    identifier: str = ""
    title: str = ""
    url: str = ""
    description: str = ""
    source: str = ""


class ContextStatistics(BaseModel):
    """Statistics about the context object."""

    total_sections: int = 0
    total_blocks: int = 0
    total_sources: int = 0
    total_references: int = 0
    total_characters: int = 0
    estimated_tokens: int = 0
    estimated_cost: float = 0.0
    sources_by_type: dict[str, int] = Field(default_factory=dict)
    importance_distribution: dict[str, int] = Field(default_factory=dict)


class ContextBudget(BaseModel):
    """Token budget configuration for context."""

    max_tokens: int = 8192
    reserved_system_tokens: int = 512
    reserved_user_tokens: int = 256
    min_important_tokens: int = 1024
    compression_enabled: bool = True
    summaries_enabled: bool = True
    priority_threshold: float = 0.0


class ContextMetadata(BaseModel):
    """Flexible metadata for context objects."""

    model_config = ConfigDict(extra="allow")

    name: str = ""
    version: str = "1"
    created_at: datetime = Field(default_factory=utcnow)
    tags: list[str] = Field(default_factory=list)


class Context(BaseModel):
    """The complete context object produced by the ContextEngine."""

    id: str = Field(default_factory=lambda: f"ctx-{uuid4().hex[:12]}")
    investigation_id: str = ""
    plan_id: str = ""
    sections: list[ContextSection] = Field(default_factory=list)
    sources: list[ContextSource] = Field(default_factory=list)
    metadata: ContextMetadata = Field(default_factory=ContextMetadata)
    statistics: ContextStatistics = Field(default_factory=ContextStatistics)
    budget: ContextBudget = Field(default_factory=ContextBudget)
    references: list[ContextReference] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)

    def get_section(self, name: str) -> ContextSection | None:
        for section in self.sections:
            if section.name == name:
                return section
        return None

    def add_section(self, section: ContextSection) -> None:
        self.sections.append(section)

    def remove_section(self, section_id: str) -> None:
        self.sections = [s for s in self.sections if s.id != section_id]

    def get_blocks_by_importance(self, importance: ContextImportance) -> list[ContextBlock]:
        return [b for s in self.sections for b in s.blocks if b.importance == importance]

    def get_blocks_by_source(self, source_type: ContextSourceType) -> list[ContextBlock]:
        return [b for s in self.sections for b in s.blocks if b.source_type == source_type]

    def get_total_tokens(self) -> int:
        return sum(s.estimated_tokens for s in self.sections)

    def recalculate(self) -> None:
        for section in self.sections:
            section.recalculate()
        self.statistics.total_sections = len(self.sections)
        self.statistics.total_blocks = sum(len(s.blocks) for s in self.sections)
        self.statistics.total_sources = len(self.sources)
        self.statistics.total_references = len(self.references)
        self.statistics.total_characters = sum(
            len(b.content) for s in self.sections for b in s.blocks
        )
        self.statistics.estimated_tokens = self.get_total_tokens()

        self.statistics.sources_by_type = {}
        for s in self.sections:
            for b in s.blocks:
                key = b.source_type.value
                self.statistics.sources_by_type[key] = self.statistics.sources_by_type.get(key, 0) + 1

        self.statistics.importance_distribution = {}
        for s in self.sections:
            for b in s.blocks:
                key = b.importance.value
                self.statistics.importance_distribution[key] = self.statistics.importance_distribution.get(key, 0) + 1

    def model_dump_for_storage(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Context:
        return cls(**data)


def _importance_rank(importance: ContextImportance) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(importance.value, 0)
