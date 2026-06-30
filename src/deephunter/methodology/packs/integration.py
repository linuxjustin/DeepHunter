"""Planner integration for Methodology Packs.

Connects methodology packs to the Investigation Planner via a dedicated
PlanningRule that loads packs and generates steps.
"""

from __future__ import annotations

from deephunter.planning.models import InvestigationStep, ManualTest, PlannerContext, PlanningPhase, RiskScore
from deephunter.planning.rules import PlanningRule

from deephunter.methodology.packs.registry import (
    _REGISTRY,
    get_packs_by_technology,
    get_packs_by_category,
    list_all_packs,
    load_all_packs,
)
from deephunter.methodology.packs.base import PackCategory, MethodologyPack


class MethodologyPackRule(PlanningRule):
    """Planning rule that loads methodology packs and generates investigation steps.

    Integrates at priority 45 (just before the original MethodologyRule at 50),
    so pack-driven steps are generated before the generic methodology pipeline.
    """

    name = "methodology_packs"
    description = "Generates investigation steps from loaded expert methodology packs"
    phase = PlanningPhase.FINGERPRINT
    priority = 45

    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        registry = _REGISTRY
        if registry.count() == 0:
            load_all_packs()

        steps: list[InvestigationStep] = []

        technologies = context.technologies
        frameworks = context.frameworks
        attack_surface_areas = context.attack_surface_areas

        matched_packs: set[str] = set()

        # Match by technology
        for tech in technologies:
            for pack in registry.get_by_technology(tech):
                if pack.name not in matched_packs:
                    matched_packs.add(pack.name)
                    steps.extend(self._pack_to_steps(pack, context))

        # Match by framework
        for fw in frameworks:
            for pack in registry.get_by_framework(fw):
                if pack.name not in matched_packs:
                    matched_packs.add(pack.name)
                    steps.extend(self._pack_to_steps(pack, context))

        # Match by attack surface
        for area in attack_surface_areas:
            for pack in registry.get_by_attack_surface(area):
                if pack.name not in matched_packs:
                    matched_packs.add(pack.name)
                    steps.extend(self._pack_to_steps(pack, context))

        # If nothing matched, include all cross-cutting packs (they are universal)
        if not matched_packs:
            for pack in registry.get_by_category(PackCategory.CROSS_CUTTING):
                if pack.name not in matched_packs:
                    matched_packs.add(pack.name)
                    steps.extend(self._pack_to_steps(pack, context))

        return steps

    def _pack_to_steps(
        self, pack: MethodologyPack, context: PlannerContext
    ) -> list[InvestigationStep]:
        steps: list[InvestigationStep] = []
        for checklist_item in pack.checklists:
            phase = self._infer_phase(checklist_item.objective, pack)

            priority_map: dict[str, float] = {
                "critical": 0.95,
                "high": 0.80,
                "medium": 0.55,
                "low": 0.30,
            }
            priority_score = priority_map.get(checklist_item.priority, 0.55)

            difficulty_map: dict[str, float] = {
                "easy": 0.3,
                "medium": 0.5,
                "hard": 0.8,
            }
            complexity = difficulty_map.get(checklist_item.difficulty, 0.5)

            step = InvestigationStep(
                phase=phase,
                title=f"[{pack.name}] {checklist_item.objective}",
                description=checklist_item.description,
                priority_score=priority_score,
                risk=RiskScore(likelihood=7.0, impact=8.0, confidence=0.7),
                estimated_cost_hours=1.0,
                complexity=complexity,
                technologies=list(checklist_item.related_technologies),
                bug_classes=[bc.value for bc in checklist_item.bug_classes],
                metadata={
                    "pack_name": pack.name,
                    "pack_version": pack.version,
                    "checklist_item_id": checklist_item.id,
                    "checklist_objective": checklist_item.objective,
                },
            )

            # Add a manual test from the checklist item
            step.recommended_tests.append(
                ManualTest(
                    description=checklist_item.objective,
                    procedure=checklist_item.procedure,
                    expected_result=checklist_item.expected_result,
                    bug_classes=[bc.value for bc in checklist_item.bug_classes],
                    priority=priority_score,
                    estimated_effort_hours=1.0,
                )
            )

            steps.append(step)

        return steps

    @staticmethod
    def _infer_phase(objective: str, pack: MethodologyPack) -> PlanningPhase:
        objective_lower = objective.lower()

        if any(kw in objective_lower for kw in ["recon", "enumeration", "discover", "detect"]):
            return PlanningPhase.RECON
        if any(kw in objective_lower for kw in ["fingerprint", "version", "tech", "framework"]):
            return PlanningPhase.FINGERPRINT
        if any(kw in objective_lower for kw in ["authori", "access control", "rbac", "permission"]):
            return PlanningPhase.AUTHORIZATION_ANALYSIS
        if any(kw in objective_lower for kw in ["auth", "login", "oauth", "jwt", "session", "sso", "oidc"]):
            return PlanningPhase.AUTHENTICATION_ANALYSIS
        if any(kw in objective_lower for kw in ["business", "logic", "workflow", "race"]):
            return PlanningPhase.BUSINESS_LOGIC_ANALYSIS
        if any(kw in objective_lower for kw in ["api", "graphql", "rest", "endpoint"]):
            return PlanningPhase.API_ANALYSIS
        if any(kw in objective_lower for kw in ["upload", "file"]):
            return PlanningPhase.FILE_UPLOAD_ANALYSIS
        if any(kw in objective_lower for kw in ["cloud", "aws", "azure", "gcp", "k8s", "kubernetes"]):
            return PlanningPhase.CLOUD_ANALYSIS
        if any(kw in objective_lower for kw in ["privilege", "escalation", "idor"]):
            return PlanningPhase.PRIVILEGE_ESCALATION
        if any(kw in objective_lower for kw in ["input", "injection", "xss", "sql", "ssti"]):
            return PlanningPhase.INPUT_VALIDATION
        if any(kw in objective_lower for kw in ["report", "documentation", "evidence"]):
            return PlanningPhase.REPORT_PREPARATION

        # Fall back to framework detection phase for framework packs
        if pack.category == PackCategory.FRAMEWORK:
            return PlanningPhase.FRAMEWORK_DETECTION

        return PlanningPhase.INPUT_VALIDATION
