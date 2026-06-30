"""Expert Methodology Packs Framework.

Encodes 20+ years of collective bug bounty methodology into reusable,
versioned, structured Methodology Packs that plug into the Methodology
Engine and Investigation Planner.

Each pack represents how experienced security researchers investigate
a specific technology, framework, protocol, or attack surface.
"""

from __future__ import annotations

from deephunter.methodology.packs.base import (
    DecisionTreeNode,
    InvestigationGoal,
    MethodologyPack,
    MethodologyPackSet,
    PackCategory,
    PackChecklist,
    PackFrameworkProfile,
    PackPlannerRule,
)
from deephunter.methodology.packs.registry import (
    PackLoadError,
    PackRegistry,
    PackValidationError,
    get_pack,
    get_packs_by_category,
    get_packs_by_technology,
    list_all_packs,
    load_all_packs,
    register_pack,
)
from deephunter.methodology.packs.integration import MethodologyPackRule

__all__ = [
    "DecisionTreeNode",
    "InvestigationGoal",
    "MethodologyPack",
    "MethodologyPackSet",
    "MethodologyPackRule",
    "PackCategory",
    "PackChecklist",
    "PackFrameworkProfile",
    "PackLoadError",
    "PackPlannerRule",
    "PackRegistry",
    "PackValidationError",
    "get_pack",
    "get_packs_by_category",
    "get_packs_by_technology",
    "list_all_packs",
    "load_all_packs",
    "register_pack",
]
