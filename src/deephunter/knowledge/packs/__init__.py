"""Knowledge Pack Ecosystem.

First-class structured knowledge about technologies, frameworks, protocols,
and attack surfaces. Each Knowledge Pack integrates with every DeepHunter
subsystem: Planner, Reasoning, Methodology, Context Engine, Prompt Builder,
Technology Intelligence, and the Attack Surface Graph.
"""

from __future__ import annotations

from deephunter.knowledge.packs.base import (
    AttackSurfaceProfile,
    FingerprintProfile,
    KnowledgePack,
    KnowledgePackCategory,
    KnowledgePackIndex,
    KnowledgeRelationship,
    KnowledgeRelationshipGraph,
    KnowledgeRelationshipType,
    ReconProfile,
    TechnologyComponentProfile,
    TechnologyProfile,
)
from deephunter.knowledge.packs.registry import (
    KnowledgePackRegistry,
    get_kp,
    get_kp_by_technology,
    get_kp_by_vendor,
    get_knowledge_packs_by_category,
    list_all_knowledge_packs,
    load_all_knowledge_packs,
    register_knowledge_pack,
)

__all__ = [
    "AttackSurfaceProfile",
    "FingerprintProfile",
    "KnowledgePack",
    "KnowledgePackCategory",
    "KnowledgePackIndex",
    "KnowledgePackRegistry",
    "KnowledgeRelationship",
    "KnowledgeRelationshipGraph",
    "KnowledgeRelationshipType",
    "ReconProfile",
    "TechnologyComponentProfile",
    "TechnologyProfile",
    "get_kp",
    "get_kp_by_technology",
    "get_kp_by_vendor",
    "get_knowledge_packs_by_category",
    "list_all_knowledge_packs",
    "load_all_knowledge_packs",
    "register_knowledge_pack",
]
