"""Data models for the Framework Intelligence module."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from deephunter.core.types import BugClass
from deephunter.recon.models import TechCategory, ApplicationType
from deephunter.tech_intel.models import (
    AttackSurfaceImplication,
    AuthMechanismClue,
    InvestigationSuggestion,
    TechnologyKnowledgeEntry,
)


class FrameworkStack(BaseModel):
    """A correlated framework stack — an ordered set of technologies that
    together form a coherent application platform."""

    id: str = Field(default_factory=lambda: f"fs-{uuid4().hex[:12]}")
    name: str
    description: str = ""
    technologies: list[str] = Field(default_factory=list)
    confidence: str = "medium"
    tags: list[str] = Field(default_factory=list)


class StackCorrelation(BaseModel):
    """The result of correlating detected technologies into framework stacks."""

    id: str = Field(default_factory=lambda: f"sc-{uuid4().hex[:12]}")
    source_technologies: list[str] = Field(default_factory=list)
    stacks: list[FrameworkStack] = Field(default_factory=list)
    unmatched_technologies: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ApplicationProfile(BaseModel):
    """A full application profile derived from its framework stack."""

    id: str = Field(default_factory=lambda: f"ap-{uuid4().hex[:12]}")
    name: str
    app_type: ApplicationType = ApplicationType.WEB_APP
    technologies: list[TechnologyKnowledgeEntry] = Field(default_factory=list)
    stacks: list[FrameworkStack] = Field(default_factory=list)
    combined_attack_surface: list[AttackSurfaceImplication] = Field(default_factory=list)
    combined_auth_mechanisms: list[AuthMechanismClue] = Field(default_factory=list)
    combined_trust_boundaries: list[str] = Field(default_factory=list)
    combined_investigation_suggestions: list[InvestigationSuggestion] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AttackSurfaceProfile(BaseModel):
    """A structured attack surface profile generated from framework intelligence."""

    id: str = Field(default_factory=lambda: f"asp-{uuid4().hex[:12]}")
    application_profiles: list[ApplicationProfile] = Field(default_factory=list)
    total_attack_surface_areas: int = 0
    total_auth_mechanisms: int = 0
    total_trust_boundaries: int = 0
    total_suggestions: int = 0
    priority_areas: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
