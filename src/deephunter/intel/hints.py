"""Investigation Hint Generator — produces structured, non-vulnerability
investigation guidance from technology and framework intelligence.

Hints NEVER claim vulnerabilities. They only suggest investigation areas.
"""

from __future__ import annotations

from deephunter.intel.models import HintCategory, HintPriority, InvestigationHint
from deephunter.tech_intel.models import (
    AttackSurfaceImplication,
    InvestigationSuggestion,
    TechnologyKnowledge,
)


class InvestigationHintGenerator:
    """Generates structured investigation hints from intelligence data."""

    def generate_from_knowledge(self, knowledge: TechnologyKnowledge) -> list[InvestigationHint]:
        hints: list[InvestigationHint] = []

        for impl in knowledge.all_attack_surface_implications:
            hints.append(self._implication_to_hint(impl, knowledge.source_technologies))

        for suggestion in knowledge.all_investigation_suggestions:
            hints.append(self._suggestion_to_hint(suggestion, knowledge.source_technologies))

        if not hints:
            hints.append(InvestigationHint(
                title="General Reconnaissance",
                description="No specific framework intelligence available. Conduct general reconnaissance.",
                category=HintCategory.GENERAL,
                priority=HintPriority.LOW,
            ))

        return hints

    def _implication_to_hint(
        self,
        impl: AttackSurfaceImplication,
        source_techs: list[str],
    ) -> InvestigationHint:
        areas = ", ".join(source_techs)
        return InvestigationHint(
            title=f"Investigate: {impl.area}",
            description=impl.description,
            category=self._classify_implication(impl),
            priority=self._confidence_to_priority(impl.confidence),
            source_technology=areas,
            rationale=f"Detected {areas} technology; known attack surface area: {impl.area}",
            investigation_steps=self._generate_steps(impl.area),
            tags=[impl.area, impl.confidence.value] + [bc.value for bc in impl.bug_classes],
        )

    def _suggestion_to_hint(
        self,
        suggestion: InvestigationSuggestion,
        source_techs: list[str],
    ) -> InvestigationHint:
        return InvestigationHint(
            title=suggestion.title,
            description=suggestion.description,
            category=HintCategory.FRAMEWORK_SPECIFIC,
            priority=self._score_to_priority(suggestion.priority),
            source_technology=", ".join(source_techs),
            rationale=f"Framework intelligence suggests investigating: {suggestion.title}",
            investigation_steps=[
                f"Investigate: {suggestion.title}",
                f"Description: {suggestion.description}",
            ],
            references=suggestion.references,
            tags=[suggestion.title],
        )

    def _classify_implication(self, impl: AttackSurfaceImplication) -> HintCategory:
        bc_names = [bc.value for bc in impl.bug_classes]
        if any(k in " ".join(bc_names) for k in ("auth", "bypass")):
            return HintCategory.AUTHENTICATION
        if any(k in " ".join(bc_names) for k in ("privilege", "access")):
            return HintCategory.AUTHORIZATION
        if any(k in " ".join(bc_names) for k in ("xss", "injection", "ssti")):
            return HintCategory.INPUT_VALIDATION
        if "disclosure" in " ".join(bc_names):
            return HintCategory.EXPOSURE
        return HintCategory.FRAMEWORK_SPECIFIC

    def _confidence_to_priority(self, confidence) -> HintPriority:
        if confidence and confidence.value == "high":
            return HintPriority.HIGH
        if confidence and confidence.value == "medium":
            return HintPriority.MEDIUM
        return HintPriority.LOW

    @staticmethod
    def _score_to_priority(score: int) -> HintPriority:
        if score >= 80:
            return HintPriority.HIGH
        if score >= 50:
            return HintPriority.MEDIUM
        return HintPriority.LOW

    @staticmethod
    def _generate_steps(area: str) -> list[str]:
        return [
            f"Identify all endpoints related to {area}",
            f"Review configuration for {area}",
            f"Document findings for {area} in investigation report",
        ]
