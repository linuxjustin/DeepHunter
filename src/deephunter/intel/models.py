"""Data models for Investigation Hints."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class HintCategory(str, Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFIGURATION = "configuration"
    INPUT_VALIDATION = "input_validation"
    BUSINESS_LOGIC = "business_logic"
    EXPOSURE = "exposure"
    FRAMEWORK_SPECIFIC = "framework_specific"
    CLOUD = "cloud"
    GENERAL = "general"


class HintPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class InvestigationHint(BaseModel):
    """A structured investigation hint — NOT a vulnerability claim."""

    id: str = Field(default_factory=lambda: f"hint-{uuid4().hex[:12]}")
    title: str
    description: str
    category: HintCategory = HintCategory.GENERAL
    priority: HintPriority = HintPriority.MEDIUM
    source_technology: str = ""
    rationale: str = ""
    investigation_steps: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
