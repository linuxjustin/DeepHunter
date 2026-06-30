"""Knowledge module — SKO models, storage backends, and Knowledge Pack Ecosystem."""

from deephunter.knowledge.json_store import JSONKnowledgeStore
from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.knowledge.store import KnowledgeStore

from deephunter.knowledge.packs.base import (
    AttackSurfaceProfile,
    FingerprintProfile,
    KnowledgePack,
    KnowledgePackCategory,
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
from deephunter.knowledge.packs.integration import (
    KnowledgePackRule,
    KnowledgePackReasoningAdapter,
    enrich_context_with_knowledge_packs,
    enrich_tech_intel,
    get_prompt_context_enrichment,
)

__all__ = [
    "AttackSurfaceProfile",
    "enrich_context_with_knowledge_packs",
    "enrich_tech_intel",
    "FingerprintProfile",
    "get_kp",
    "get_kp_by_technology",
    "get_kp_by_vendor",
    "get_knowledge_packs_by_category",
    "get_prompt_context_enrichment",
    "JSONKnowledgeStore",
    "KnowledgePack",
    "KnowledgePackCategory",
    "KnowledgePackRegistry",
    "KnowledgePackReasoningAdapter",
    "KnowledgePackRule",
    "KnowledgeRelationship",
    "KnowledgeRelationshipGraph",
    "KnowledgeRelationshipType",
    "KnowledgeStore",
    "list_all_knowledge_packs",
    "load_all_knowledge_packs",
    "ReconProfile",
    "register_knowledge_pack",
    "SecurityKnowledgeObject",
    "TechnologyComponentProfile",
    "TechnologyProfile",
]
