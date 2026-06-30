"""Technology Intelligence Engine — interprets detected technologies.

This module does NOT detect technologies.
It interprets already-detected technologies and provides security-relevant
knowledge about what each technology means for the target's attack surface.
"""

from deephunter.tech_intel.engine import TechnologyIntelEngine
from deephunter.tech_intel.knowledge_base import KB as TechnologyKnowledgeBase
from deephunter.tech_intel.models import (
    AttackSurfaceImplication,
    AuthMechanismClue,
    InvestigationSuggestion,
    TechnologyKnowledge,
    TechnologyKnowledgeEntry,
)

__all__ = [
    "TechnologyIntelEngine",
    "TechnologyKnowledgeBase",
    "TechnologyKnowledge",
    "TechnologyKnowledgeEntry",
    "AttackSurfaceImplication",
    "AuthMechanismClue",
    "InvestigationSuggestion",
]
