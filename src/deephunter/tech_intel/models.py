"""Data models for the Technology Intelligence Engine."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from deephunter.core.types import BugClass
from deephunter.recon.models import TechCategory


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class AttackSurfaceImplication(BaseModel):
    """A potential attack surface area introduced by a technology."""

    area: str
    description: str
    bug_classes: list[BugClass] = Field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM


class AuthMechanismClue(BaseModel):
    """A clue about what authentication mechanisms a technology may use."""

    mechanism: str
    description: str
    likelihood: Confidence = Confidence.MEDIUM


class InvestigationSuggestion(BaseModel):
    """A suggestion for manual investigation."""

    title: str
    description: str
    references: list[str] = Field(default_factory=list)
    priority: int = Field(default=50, ge=0, le=100)


class TechnologyKnowledgeEntry(BaseModel):
    """Structured security knowledge about a specific technology."""

    technology_name: str
    aliases: list[str] = Field(default_factory=list)
    category: TechCategory = TechCategory.UNKNOWN
    version: str = ""
    description: str = ""
    tags: list[str] = Field(default_factory=list)

    related_technologies: list[str] = Field(default_factory=list)
    potential_auth_mechanisms: list[AuthMechanismClue] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    attack_surface_implications: list[AttackSurfaceImplication] = Field(default_factory=list)
    investigation_suggestions: list[InvestigationSuggestion] = Field(default_factory=list)

    metadata: dict[str, Any] = Field(default_factory=dict)


class TechnologyKnowledge(BaseModel):
    """The full knowledge interpretation for a set of technologies.

    Produced by TechnologyIntelEngine.interpret().
    """

    id: str = Field(default_factory=lambda: f"tk-{uuid4().hex[:12]}")
    source_technologies: list[str] = Field(default_factory=list)
    entries: list[TechnologyKnowledgeEntry] = Field(default_factory=list)
    all_related_technologies: list[str] = Field(default_factory=list)
    all_auth_mechanisms: list[AuthMechanismClue] = Field(default_factory=list)
    all_trust_boundaries: list[str] = Field(default_factory=list)
    all_attack_surface_implications: list[AttackSurfaceImplication] = Field(default_factory=list)
    all_investigation_suggestions: list[InvestigationSuggestion] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
