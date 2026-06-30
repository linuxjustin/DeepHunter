"""Subsystem integration adapters for Knowledge Packs.

Connects Knowledge Packs to every DeepHunter subsystem:
  - Planner       → KnowledgePackRule (priority 35)
  - Reasoning     → knowledge pack hypothesis enrichment
  - Context       → context enrichment with tech profiles
  - Tech Intel    → TechnologyKnowledgeEntry generation
  - Prompt        → context injection for prompt building
"""

from __future__ import annotations

from typing import Any

from deephunter.knowledge.packs.registry import (
    _REGISTRY,
    get_kp,
    get_kp_by_technology,
    get_knowledge_packs_by_category,
    list_all_knowledge_packs,
    load_all_knowledge_packs,
)
from deephunter.knowledge.packs.base import KnowledgePack, KnowledgePackCategory


# =============================================================================
# Planner Integration
# =============================================================================


class KnowledgePackRule:
    """Planning rule that generates steps from Knowledge Packs.

    Runs at priority 35 (after BugClassRule at 30, before EndpointAnalysisRule
    at 40). Each active Knowledge Pack injects its workflow steps, attack
    surface investigation areas, and checklists as planning steps.
    """

    name = "knowledge_packs"
    description = "Generates deep investigation steps from Knowledge Pack profiles"
    phase = "fingerprint"
    priority = 35

    def evaluate(self, context: Any) -> list[Any]:
        registry = _REGISTRY
        if registry.count() == 0:
            load_all_knowledge_packs()

        steps: list[InvestigationStep] = []

        technologies = context.technologies
        frameworks = context.frameworks
        attack_surface_areas = context.attack_surface_areas

        matched: set[str] = set()

        # Match by technology name
        for tech in technologies:
            packs = get_kp_by_technology(tech)
            for pack in packs:
                if pack.name not in matched:
                    matched.add(pack.name)
                    steps.extend(self._pack_to_steps(pack))

        # Match by framework (fallback)
        for fw in frameworks:
            packs = get_kp_by_technology(fw)
            for pack in packs:
                if pack.name not in matched:
                    matched.add(pack.name)
                    steps.extend(self._pack_to_steps(pack))

        # If nothing matched, include universal packs
        if not matched:
            for cat in (
                KnowledgePackCategory.API,
                KnowledgePackCategory.AUTHENTICATION,
                KnowledgePackCategory.AUTHORIZATION,
                KnowledgePackCategory.BUSINESS_LOGIC,
            ):
                for pack in get_knowledge_packs_by_category(cat):
                    if pack.name not in matched:
                        matched.add(pack.name)
                        steps.extend(self._pack_to_steps(pack))

        return steps

    def _pack_to_steps(self, pack: KnowledgePack) -> list[Any]:
        from deephunter.planning.models import InvestigationStep, ManualTest, PlanningPhase, RiskScore

        steps: list[InvestigationStep] = []

        phase_map = {
            KnowledgePackCategory.API: PlanningPhase.API_ANALYSIS,
            KnowledgePackCategory.AUTHENTICATION: PlanningPhase.AUTHENTICATION_ANALYSIS,
            KnowledgePackCategory.AUTHORIZATION: PlanningPhase.AUTHENTICATION_ANALYSIS,
            KnowledgePackCategory.CLOUD: PlanningPhase.CLOUD_ANALYSIS,
            KnowledgePackCategory.DATABASE: PlanningPhase.INPUT_VALIDATION,
        }
        inferred_phase = phase_map.get(pack.category, PlanningPhase.FINGERPRINT)

        # First step: comprehensive pack-level analysis
        steps.append(
            InvestigationStep(
                phase=inferred_phase,
                title=f"[{pack.name}] Knowledge Pack Analysis",
                description=pack.description,
                priority_score=0.85,
                risk=RiskScore(likelihood=7.0, impact=8.0, confidence=0.7),
                estimated_cost_hours=1.0,
                complexity=0.3,
                technologies=[pack.technology.name],
                bug_classes=pack.cwe_ids,
                metadata={
                    "pack_name": pack.name,
                    "pack_version": pack.version,
                    "pack_category": pack.category.value,
                    "technology": pack.technology.name,
                    "cwe_ids": ", ".join(pack.cwe_ids),
                },
            )
        )

        # Step per attack surface area
        for area in pack.attack_surface.attack_surface_areas:
            steps.append(
                InvestigationStep(
                    phase=PlanningPhase.INPUT_VALIDATION,
                    title=f"[{pack.name}] {area}",
                    description=f"Investigate {area.lower()} in {pack.technology.name} context.",
                    priority_score=0.75,
                    risk=RiskScore(likelihood=7.0, impact=8.0, confidence=0.6),
                    estimated_cost_hours=1.0,
                    complexity=0.4,
                    technologies=[pack.technology.name],
                    metadata={"pack_name": pack.name, "area": area},
                )
            )

        # Step per workflow item
        for i, wf in enumerate(pack.workflow):
            steps.append(
                InvestigationStep(
                    phase=inferred_phase,
                    title=f"[{pack.name}] Workflow {i + 1}: {wf[:60]}",
                    description=wf,
                    priority_score=0.70,
                    risk=RiskScore(likelihood=6.0, impact=7.0, confidence=0.5),
                    estimated_cost_hours=0.5,
                    complexity=0.3,
                    technologies=[pack.technology.name],
                    metadata={"pack_name": pack.name, "workflow_index": str(i)},
                )
            )

        # Manual test per checklist item
        for item in pack.checklists:
            steps.append(
                InvestigationStep(
                    phase=PlanningPhase.INPUT_VALIDATION,
                    title=f"[{pack.name}] {item.category}: {item.description[:60]}",
                    description=item.description,
                    priority_score=0.80,
                    risk=RiskScore(likelihood=7.0, impact=8.0, confidence=0.6),
                    estimated_cost_hours=1.0,
                    complexity=0.4,
                    technologies=[pack.technology.name],
                    metadata={
                        "pack_name": pack.name,
                        "checklist_id": item.step_id,
                        "category": item.category,
                    },
                    recommended_tests=[
                        ManualTest(
                            description=item.description,
                            procedure=item.description,
                            expected_result=item.expected_result,
                            bug_classes=[],
                            priority=0.8,
                            estimated_effort_hours=1.0,
                        )
                    ],
                )
            )

        return steps


# =============================================================================
# Context Engine Enrichment
# =============================================================================


def enrich_context_with_knowledge_packs(context: Any) -> dict[str, Any]:
    """Enrich a context object with knowledge pack data.

    Returns a dict of enrichment data suitable for merging into
    PlannerContext, ReasoningContext, or PromptContext.
    """
    registry = _REGISTRY
    if registry.count() == 0:
        load_all_knowledge_packs()

    enrichment: dict[str, Any] = {
        "knowledge_packs": {},
        "technology_profiles": [],
        "attack_surface_profiles": [],
        "fingerprint_signatures": [],
        "technology_stack": [],
    }

    for pack in registry.list_all():
        enrichment["knowledge_packs"][pack.name] = {
            "name": pack.name,
            "category": pack.category.value,
            "description": pack.description,
            "technology": pack.technology.name,
            "vendor": pack.technology.vendor,
            "dependencies": pack.dependencies,
            "cwe_ids": pack.cwe_ids,
        }
        enrichment["technology_profiles"].append(
            {
                "name": pack.technology.name,
                "vendor": pack.technology.vendor,
                "language": pack.technology.language,
                "description": pack.technology.description,
            }
        )
        enrichment["attack_surface_profiles"].extend(
            pack.attack_surface.attack_surface_areas
        )
        enrichment["fingerprint_signatures"].extend(
            list(pack.fingerprints.http_headers.keys())
            + pack.fingerprints.cookies
            + pack.fingerprints.server_signatures
        )

    return enrichment


# =============================================================================
# Reasoning Engine Integration
# =============================================================================


class KnowledgePackReasoningAdapter:
    """Provides knowledge pack data for the Reasoning Engine.

    Reasoning Engine can query this adapter to get hypothesis-relevant
    knowledge about specific technologies.
    """

    def __init__(self) -> None:
        if _REGISTRY.count() == 0:
            load_all_knowledge_packs()

    def get_hypotheses_for_tech(self, tech_name: str) -> list[dict[str, str]]:
        """Get hypothesis-generating data for a technology."""
        packs = get_kp_by_technology(tech_name)
        hypotheses: list[dict[str, str]] = []
        for pack in packs:
            for area in pack.attack_surface.attack_surface_areas:
                hypotheses.append({
                    "technology": tech_name,
                    "hypothesis": f"{pack.technology.name} may be vulnerable via {area.lower()}",
                    "pack_name": pack.name,
                    "supporting_cwe": ", ".join(pack.cwe_ids[:3]),
                })
            for concern in pack.business_logic_concerns:
                hypotheses.append({
                    "technology": tech_name,
                    "hypothesis": f"Business logic: {concern.description}",
                    "pack_name": pack.name,
                    "attack_scenario": concern.attack_scenario,
                    "complexity": concern.complexity,
                })
        return hypotheses

    def get_attack_scenarios(self, tech_name: str) -> list[dict[str, str]]:
        packs = get_kp_by_technology(tech_name)
        scenarios: list[dict[str, str]] = []
        for pack in packs:
            for concern in pack.business_logic_concerns:
                scenarios.append({
                    "technology": tech_name,
                    "description": concern.description,
                    "impact": concern.impact,
                    "attack_scenario": concern.attack_scenario,
                    "complexity": concern.complexity,
                })
        return scenarios


# =============================================================================
# Technology Intelligence Integration
# =============================================================================


def enrich_tech_intel(tech_name: str) -> dict[str, Any] | None:
    """Enrich Technology Intelligence with Knowledge Pack data."""
    packs = get_kp_by_technology(tech_name)
    if not packs:
        return None
    pack = packs[0]
    return {
        "technology": pack.technology.name,
        "aliases": pack.technology.common_aliases,
        "vendor": pack.technology.vendor,
        "description": pack.technology.description,
        "fingerprints": {
            "headers": pack.fingerprints.http_headers,
            "cookies": pack.fingerprints.cookies,
            "server_signatures": pack.fingerprints.server_signatures,
            "error_pages": pack.fingerprints.error_page_signatures,
            "default_paths": pack.fingerprints.default_paths,
            "default_files": pack.fingerprints.default_files,
        },
        "attack_surface": pack.attack_surface.attack_surface_areas,
        "investigation_areas": pack.attack_surface.investigation_areas,
        "relationships": [
            {
                "target": r.target_pack_name,
                "type": r.relationship_type.value,
                "description": r.description,
            }
            for r in pack.relationships
        ],
    }


# =============================================================================
# Prompt Builder Integration
# =============================================================================


def get_prompt_context_enrichment() -> dict[str, Any]:
    """Get knowledge pack data for prompt building context injection."""
    if _REGISTRY.count() == 0:
        load_all_knowledge_packs()
    return {
        "available_knowledge_packs": [
            {
                "name": p.name,
                "category": p.category.value,
                "description": p.description,
                "technology": p.technology.name,
                "components": [
                    {"name": c.name, "security_relevance": c.security_relevance}
                    for c in p.components
                ],
                "attack_surface_count": len(p.attack_surface.attack_surface_areas),
                "checklist_count": len(p.checklists),
                "cwe_count": len(p.cwe_ids),
            }
            for p in _REGISTRY.list_all()
        ],
        "knowledge_pack_count": _REGISTRY.count(),
    }
