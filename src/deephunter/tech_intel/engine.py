"""Technology Intelligence Engine.

Interprets detected technologies and provides security-relevant knowledge.
This module does NOT detect technologies — it interprets them.
"""

from __future__ import annotations

from typing import Any

from deephunter.recon.models import Technology as ReconTechnology
from deephunter.tech_intel.knowledge_base import KB
from deephunter.tech_intel.models import (
    AttackSurfaceImplication,
    AuthMechanismClue,
    InvestigationSuggestion,
    TechnologyKnowledge,
    TechnologyKnowledgeEntry,
)


class TechnologyIntelEngine:
    """Interprets detected technologies into security-relevant knowledge."""

    def __init__(self, knowledge_base: dict[str, TechnologyKnowledgeEntry] | None = None) -> None:
        self._kb = knowledge_base or KB

    def lookup(self, tech_name: str) -> TechnologyKnowledgeEntry | None:
        key = tech_name.lower().strip()
        if key in self._kb:
            return self._kb[key]
        for entry in self._kb.values():
            if tech_name.lower() in entry.aliases:
                return entry
        return None

    def interpret(self, technologies: list[str | ReconTechnology]) -> TechnologyKnowledge:
        """Interpret a list of detected technologies.

        Args:
            technologies: List of technology names or ReconTechnology objects.

        Returns:
            TechnologyKnowledge with aggregated intelligence.
        """
        tech_names: list[str] = []
        for t in technologies:
            if isinstance(t, ReconTechnology):
                tech_names.append(t.name)
            else:
                tech_names.append(str(t))

        entries: list[TechnologyKnowledgeEntry] = []
        seen_entries: set[str] = set()

        for name in tech_names:
            entry = self.lookup(name)
            if entry and entry.technology_name.lower() not in seen_entries:
                seen_entries.add(entry.technology_name.lower())
                entries.append(entry)

        if not entries:
            entries = self._make_unknown_entry(tech_names)

        all_related: list[str] = []
        all_auth: list[AuthMechanismClue] = []
        all_boundaries: list[str] = []
        all_implications: list[AttackSurfaceImplication] = []
        all_suggestions: list[InvestigationSuggestion] = []

        for e in entries:
            all_related.extend(e.related_technologies)
            all_auth.extend(e.potential_auth_mechanisms)
            all_boundaries.extend(e.trust_boundaries)
            all_implications.extend(e.attack_surface_implications)
            all_suggestions.extend(e.investigation_suggestions)

        return TechnologyKnowledge(
            source_technologies=tech_names,
            entries=entries,
            all_related_technologies=_dedupe(all_related),
            all_auth_mechanisms=_dedupe_auth(all_auth),
            all_trust_boundaries=_dedupe(all_boundaries),
            all_attack_surface_implications=_dedupe_implications(all_implications),
            all_investigation_suggestions=_dedupe_suggestions(all_suggestions),
        )

    def interpret_recon_technologies(self, recon_technologies: list[ReconTechnology]) -> TechnologyKnowledge:
        return self.interpret(recon_technologies)

    @staticmethod
    def _make_unknown_entry(tech_names: list[str]) -> list[TechnologyKnowledgeEntry]:
        return [TechnologyKnowledgeEntry(
            technology_name=" | ".join(tech_names),
            description="No specific intelligence available for these technologies",
        )]

    def list_known_technologies(self) -> list[str]:
        return sorted({e.technology_name for e in self._kb.values()})


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item.lower().strip() not in seen:
            seen.add(item.lower().strip())
            result.append(item)
    return result


def _dedupe_auth(items: list[AuthMechanismClue]) -> list[AuthMechanismClue]:
    seen: set[str] = set()
    result: list[AuthMechanismClue] = []
    for item in items:
        key = item.mechanism.lower().strip()
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _dedupe_implications(items: list[AttackSurfaceImplication]) -> list[AttackSurfaceImplication]:
    seen: set[str] = set()
    result: list[AttackSurfaceImplication] = []
    for item in items:
        key = item.area.lower().strip()
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _dedupe_suggestions(items: list[InvestigationSuggestion]) -> list[InvestigationSuggestion]:
    seen: set[str] = set()
    result: list[InvestigationSuggestion] = []
    for item in items:
        key = item.title.lower().strip()
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result
