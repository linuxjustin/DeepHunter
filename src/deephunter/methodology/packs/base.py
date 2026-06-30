"""Core data models for Expert Methodology Packs.

Each pack encodes structured expert knowledge about investigating a specific
technology, framework, protocol, or attack surface.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field

from deephunter.core.types import BugClass


class PackCategory(str, Enum):
    FRAMEWORK = "framework"
    CROSS_CUTTING = "cross_cutting"
    PROTOCOL = "protocol"
    ATTACK_SURFACE = "attack_surface"
    INFRASTRUCTURE = "infrastructure"


class InvestigationGoal(BaseModel):
    """A specific goal within a methodology pack investigation."""

    id: str = Field(default_factory=lambda: f"ig-{uuid4().hex[:12]}")
    name: str
    description: str = ""
    priority: int = Field(default=50, ge=0, le=100)
    bug_classes: list[BugClass] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class PackFrameworkProfile(BaseModel):
    """Extended framework security profile for methodology packs."""

    architecture_description: str = ""
    request_lifecycle: str = ""
    authentication_components: list[str] = Field(default_factory=list)
    authorization_components: list[str] = Field(default_factory=list)
    routing: str = ""
    middleware: str = ""
    template_engine: str = ""
    api_layer: str = ""
    storage_layer: str = ""
    caching: str = ""
    queues: str = ""
    background_jobs: str = ""
    deployment_patterns: list[str] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    typical_components: list[str] = Field(default_factory=list)
    technology_relationships: dict[str, list[str]] = Field(default_factory=dict)
    investigation_areas: list[str] = Field(default_factory=list)


class PackChecklist(BaseModel):
    """A single checklist item within a methodology pack."""

    id: str = Field(default_factory=lambda: f"pc-{uuid4().hex[:12]}")
    objective: str
    description: str = ""
    procedure: str = ""
    priority: str = "medium"  # critical, high, medium, low
    difficulty: str = "medium"  # easy, medium, hard
    required_evidence: list[str] = Field(default_factory=list)
    expected_result: str = ""
    related_technologies: list[str] = Field(default_factory=list)
    related_methodology: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    bug_classes: list[BugClass] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    def to_checklist_item(self) -> object:
        from deephunter.methodology.models import (
            ChecklistItem as EngineChecklistItem,
            EvidenceRequirement,
            Priority as EnginePriority,
            Reference,
        )

        priority_map: dict[str, EnginePriority] = {
            "critical": EnginePriority.CRITICAL,
            "high": EnginePriority.HIGH,
            "medium": EnginePriority.MEDIUM,
            "low": EnginePriority.LOW,
        }

        return EngineChecklistItem(
            objective=self.objective,
            description=self.description,
            procedure=self.procedure,
            priority=priority_map.get(self.priority, EnginePriority.MEDIUM),
            required_evidence=[
                EvidenceRequirement(description=ev) for ev in self.required_evidence
            ],
            expected_outcome=self.expected_result,
            dependencies=self.dependencies,
            related_technologies=self.related_technologies,
            bug_classes=self.bug_classes,
            tags=self.tags,
        )


class DecisionTreeNode(BaseModel):
    """A node in an investigation decision tree."""

    id: str = Field(default_factory=lambda: f"dn-{uuid4().hex[:12]}")
    question: str
    description: str = ""
    branches: list[DecisionTreeBranch] = Field(default_factory=list)
    conclusion: str = ""
    checklist_items: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class DecisionTreeBranch(BaseModel):
    """A branch from a decision tree node."""

    id: str = Field(default_factory=lambda: f"db-{uuid4().hex[:12]}")
    condition: str
    description: str = ""
    child: DecisionTreeNode | None = None
    conclusion: str = ""
    tags: list[str] = Field(default_factory=list)


class PackPlannerRule(BaseModel):
    """A planner rule modifier from a methodology pack."""

    id: str = Field(default_factory=lambda: f"ppr-{uuid4().hex[:12]}")
    technology: str = ""
    framework: str = ""
    attack_surface: str = ""
    description: str = ""
    priority_modifier: float = Field(default=0.0, ge=-1.0, le=1.0)
    phase: str = ""
    tags: list[str] = Field(default_factory=list)


class MethodologyPack(BaseModel):
    """A complete, self-contained methodology pack.

    Encodes expert bug bounty methodology for investigating a specific
    technology, framework, protocol, or attack surface.
    """

    name: str
    version: str = "1.0.0"
    category: PackCategory = PackCategory.CROSS_CUTTING
    description: str = ""
    author: str = "DeepHunter Methodology Engine"

    supported_technologies: list[str] = Field(default_factory=list)
    supported_frameworks: list[str] = Field(default_factory=list)
    supported_languages: list[str] = Field(default_factory=list)
    attack_surface_areas: list[str] = Field(default_factory=list)

    investigation_goals: list[InvestigationGoal] = Field(default_factory=list)
    investigation_priority: int = Field(default=50, ge=0, le=100)

    dependencies: list[str] = Field(default_factory=list)
    related_packs: list[str] = Field(default_factory=list)

    profile: PackFrameworkProfile | None = None
    workflow: list[str] = Field(default_factory=list)  # ordered phase names
    checklists: list[PackChecklist] = Field(default_factory=list)
    decision_trees: list[DecisionTreeNode] = Field(default_factory=list)
    planner_rules: list[PackPlannerRule] = Field(default_factory=list)
    references: list[dict[str, str]] = Field(default_factory=list)

    tags: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now().isoformat())

    def get_checklist_items(self, engine_checklist: bool = True) -> list:
        """Return checklist items, optionally as engine ChecklistItem objects."""
        if engine_checklist:
            return [c.to_checklist_item() for c in self.checklists]
        return self.checklists


class MethodologyPackSet(BaseModel):
    """A collection of methodology packs active for an investigation."""

    packs: list[MethodologyPack] = Field(default_factory=list)
    total_checklist_items: int = 0
    total_goals: int = 0
    total_planner_rules: int = 0
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())

    def recalculate(self) -> None:
        self.total_checklist_items = sum(len(p.checklists) for p in self.packs)
        self.total_goals = sum(len(p.investigation_goals) for p in self.packs)
        self.total_planner_rules = sum(len(p.planner_rules) for p in self.packs)
