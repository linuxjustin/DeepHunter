"""Planner integration for Methodology Packs.

Connects methodology packs to the Investigation Planner via a dedicated
PlanningRule that loads packs and generates steps.

Features:
- Decision tree evaluation for adaptive investigation paths
- PackPlannerRule priority modifiers applied to matching steps
- Manual test guidance from checklist items with full procedures
"""

from __future__ import annotations

from deephunter.planning.models import InvestigationStep, ManualTest, PlannerContext, PlanningPhase, RiskScore
from deephunter.planning.rules import PlanningRule

from deephunter.methodology.packs.base import PackCategory, MethodologyPack, PackPlannerRule
from deephunter.methodology.packs.registry import (
    _REGISTRY,
    get_packs_by_technology,
    get_packs_by_category,
    load_all_packs,
)
from deephunter.methodology.tree_engine import DecisionTreeEngine


class MethodologyPackRule(PlanningRule):
    """Planning rule that loads methodology packs and generates investigation steps.

    Integrates at priority 45 (just before the original MethodologyRule at 50),
    so pack-driven steps are generated before the generic methodology pipeline.

    Enhancements:
    - Decision tree evaluation for context-sensitive investigation paths
    - PackPlannerRule priority modifiers applied to matching steps
    - Decision tree conclusions added as high-priority steps
    """

    name = "methodology_packs"
    description = "Generates investigation steps from loaded expert methodology packs"
    phase = PlanningPhase.FINGERPRINT
    priority = 45

    def __init__(self) -> None:
        self._tree_engine = DecisionTreeEngine()

    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        registry = _REGISTRY
        if registry.count() == 0:
            load_all_packs()

        steps: list[InvestigationStep] = []

        technologies = context.technologies
        frameworks = context.frameworks
        attack_surface_areas = context.attack_surface_areas

        tree_ctx = {
            "technologies": technologies,
            "frameworks": frameworks,
            "bug_classes": context.bug_classes,
            "auth_mechanisms": context.auth_mechanisms,
            "cloud_providers": context.cloud_providers,
            "attack_surface_areas": attack_surface_areas,
            "observation_types": context.observation_types,
            "programming_languages": context.programming_languages,
            "os": context.os,
        }

        matched_packs: set[str] = set()

        for tech in technologies:
            for pack in registry.get_by_technology(tech):
                if pack.name not in matched_packs:
                    matched_packs.add(pack.name)
                    steps.extend(self._pack_to_steps(pack, context, tree_ctx))

        for fw in frameworks:
            for pack in registry.get_by_framework(fw):
                if pack.name not in matched_packs:
                    matched_packs.add(pack.name)
                    steps.extend(self._pack_to_steps(pack, context, tree_ctx))

        for area in attack_surface_areas:
            for pack in registry.get_by_attack_surface(area):
                if pack.name not in matched_packs:
                    matched_packs.add(pack.name)
                    steps.extend(self._pack_to_steps(pack, context, tree_ctx))

        if not matched_packs:
            for pack in registry.get_by_category(PackCategory.CROSS_CUTTING):
                if pack.name not in matched_packs:
                    matched_packs.add(pack.name)
                    steps.extend(self._pack_to_steps(pack, context, tree_ctx))

        return steps

    def _pack_to_steps(
        self, pack: MethodologyPack, context: PlannerContext, tree_ctx: dict,
    ) -> list[InvestigationStep]:
        steps: list[InvestigationStep] = []
        priority_modifiers: dict[str, float] = {}

        for rule in pack.planner_rules:
            key = self._pack_rule_target_key(rule)
            if key:
                priority_modifiers[key] = rule.priority_modifier

        for checklist_item in pack.checklists:
            phase = self._infer_phase(checklist_item.objective, pack)

            priority_map: dict[str, float] = {
                "critical": 0.95,
                "high": 0.80,
                "medium": 0.55,
                "low": 0.30,
            }
            base_priority = priority_map.get(checklist_item.priority, 0.55)
            modifier = priority_modifiers.get(checklist_item.id, 0.0)
            priority_score = max(0.0, min(1.0, base_priority + modifier))

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
                rationale=checklist_item.procedure or f"Investigate {checklist_item.objective} for {pack.name}",
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
                    "checklist_priority": checklist_item.priority,
                    "checklist_difficulty": checklist_item.difficulty,
                },
            )

            step.recommended_tests.append(
                ManualTest(
                    description=checklist_item.objective,
                    procedure=checklist_item.procedure or self._default_procedure(checklist_item),
                    expected_result=checklist_item.expected_result or "Evidence of vulnerability or secure implementation",
                    bug_classes=[bc.value for bc in checklist_item.bug_classes],
                    priority=priority_score,
                    estimated_effort_hours=1.0,
                    methodology_id=pack.name,
                    checklist_item_id=checklist_item.id,
                )
            )

            steps.append(step)

        evaluation = self._tree_engine.evaluate_trees([pack], tree_ctx)
        for result in evaluation.results:
            for conclusion in result.conclusions:
                phase = self._phase_from_tree_path(result.path_taken, pack)
                step = InvestigationStep(
                    phase=phase,
                    title=f"[{pack.name}] Decision: {conclusion[:80]}",
                    description=conclusion,
                    rationale=f"Path: {' → '.join(result.path_taken)}",
                    priority_score=max(0.5, 0.8 + result.priority_modifier),
                    risk=RiskScore(
                        likelihood=7.0,
                        impact=8.0,
                        confidence=result.confidence,
                    ),
                    estimated_cost_hours=0.5,
                    complexity=0.3,
                    technologies=context.technologies,
                    metadata={
                        "pack_name": pack.name,
                        "tree_id": result.tree_id,
                        "path": " → ".join(result.path_taken),
                        "is_decision_tree_conclusion": True,
                    },
                )
                steps.append(step)

        return steps

    def _pack_rule_target_key(self, rule: PackPlannerRule) -> str:
        if rule.phase:
            return f"{rule.phase}:{rule.attack_surface}"
        if rule.attack_surface:
            return rule.attack_surface
        if rule.framework:
            return f"framework:{rule.framework}"
        return ""

    def _default_procedure(self, checklist_item) -> str:
        """Generate a default test procedure from checklist item metadata."""
        return (
            f"1. Identify relevant attack surface for: {checklist_item.objective}\n"
            f"2. Review configuration and implementation\n"
            f"3. Test for the specific vulnerability class\n"
            f"4. Document findings and evidence\n"
            f"5. Verify with a safe PoC if confirmed"
        )

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

        if pack.category == PackCategory.FRAMEWORK:
            return PlanningPhase.FRAMEWORK_DETECTION

        return PlanningPhase.INPUT_VALIDATION

    @staticmethod
    def _phase_from_tree_path(path: list[str], pack: MethodologyPack) -> PlanningPhase:
        if not path:
            return PlanningPhase.INPUT_VALIDATION

        combined = " ".join(path).lower()

        if any(kw in combined for kw in ["auth", "jwt", "oauth", "session"]):
            return PlanningPhase.AUTHENTICATION_ANALYSIS
        if any(kw in combined for kw in ["authori", "access", "rbac"]):
            return PlanningPhase.AUTHORIZATION_ANALYSIS
        if any(kw in combined for kw in ["sql", "xss", "inject", "input"]):
            return PlanningPhase.INPUT_VALIDATION
        if any(kw in combined for kw in ["api", "graphql", "rest"]):
            return PlanningPhase.API_ANALYSIS
        if any(kw in combined for kw in ["business", "logic", "race"]):
            return PlanningPhase.BUSINESS_LOGIC_ANALYSIS
        if any(kw in combined for kw in ["file", "upload"]):
            return PlanningPhase.FILE_UPLOAD_ANALYSIS
        if any(kw in combined for kw in ["cloud", "aws", "azure", "gcp"]):
            return PlanningPhase.CLOUD_ANALYSIS
        if any(kw in combined for kw in ["privilege", "escalation"]):
            return PlanningPhase.PRIVILEGE_ESCALATION

        if pack.category == PackCategory.FRAMEWORK:
            return PlanningPhase.FRAMEWORK_DETECTION
        return PlanningPhase.INPUT_VALIDATION