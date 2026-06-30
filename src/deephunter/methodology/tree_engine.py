"""Decision Tree Engine — evaluates methodology pack decision trees.

Decision trees enable adaptive investigation paths: the engine walks
from a root node, evaluates branch conditions against the current
investigation context, and returns a set of conclusions with associated
checklist items and priority guidance.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from deephunter.methodology.packs.base import (
    DecisionTreeBranch,
    DecisionTreeNode,
    PackChecklist,
)


@dataclass
class DecisionTreeResult:
    """Result of evaluating a single decision tree."""

    tree_id: str
    root_question: str
    path_taken: list[str] = field(default_factory=list)
    conclusions: list[str] = field(default_factory=list)
    triggered_checklist_item_ids: list[str] = field(default_factory=list)
    priority_modifier: float = 0.0
    recommended_phases: list[str] = field(default_factory=list)
    confidence: float = 0.5


@dataclass
class DecisionTreeEvaluation:
    """Result of evaluating all decision trees from matched packs."""

    results: list[DecisionTreeResult] = field(default_factory=list)
    all_conclusions: list[str] = field(default_factory=list)
    all_checklist_ids: list[str] = field(default_factory=list)
    combined_priority_modifier: float = 0.0
    recommended_phases: list[str] = field(default_factory=list)


class DecisionTreeEngine:
    """Evaluates decision trees against an investigation context.

    Usage::

        engine = DecisionTreeEngine()
        ctx = {
            "technologies": ["django", "postgresql"],
            "bug_classes": ["sql_injection", "auth_bypass"],
            "attack_surface_areas": ["API endpoints", "Authentication"],
        }
        packs = registry.get_by_technology("django")
        evaluation = engine.evaluate_trees(packs, ctx)
    """

    def evaluate_trees(
        self,
        packs: list,
        context: dict,
    ) -> DecisionTreeEvaluation:
        """Evaluate all decision trees from the given methodology packs.

        Args:
            packs: List of matched MethodologyPack objects.
            context: PlannerContext-style dict with technologies, bug_classes,
                attack_surface_areas, observation_types, etc.

        Returns:
            A DecisionTreeEvaluation with combined results from all trees.
        """
        results: list[DecisionTreeResult] = []
        all_conclusions: list[str] = []
        all_checklist_ids: list[str] = []
        combined_priority = 0.0
        recommended_phases: set[str] = set()

        for pack in packs:
            for tree in pack.decision_trees:
                result = self._evaluate_node(tree, tree, context, pack)
                results.append(result)
                all_conclusions.extend(result.conclusions)
                all_checklist_ids.extend(result.triggered_checklist_item_ids)
                combined_priority += result.priority_modifier
                recommended_phases.update(result.recommended_phases)

        return DecisionTreeEvaluation(
            results=results,
            all_conclusions=all_conclusions,
            all_checklist_ids=all_checklist_ids,
            combined_priority_modifier=combined_priority,
            recommended_phases=list(recommended_phases),
        )

    def _evaluate_node(
        self,
        root: DecisionTreeNode,
        node: DecisionTreeNode | None,
        context: dict,
        pack,
    ) -> DecisionTreeResult:
        """Recursively evaluate a decision tree node.

        Walks the tree by evaluating branch conditions against the context.
        Returns when a conclusion is reached or no more branches match.
        """
        if node is None:
            return self._make_result(root, [])

        path: list[str] = []
        result = DecisionTreeResult(
            tree_id=node.id,
            root_question=root.question,
        )

        for branch in node.branches:
            if self._condition_matches(branch.condition, context):
                path.append(branch.condition)
                result.path_taken = path.copy()

                if branch.conclusion and not branch.child:
                    result.conclusions.append(branch.conclusion)
                    result.triggered_checklist_item_ids.extend(
                        branch.checklist_items
                    )
                    result.priority_modifier = self._priority_from_condition(
                        branch.condition
                    )
                    result.recommended_phases.extend(
                        self._phases_from_condition(branch.condition)
                    )
                    result.confidence = 0.8
                    return result

                if branch.child:
                    sub_result = self._evaluate_node(root, branch.child, context, pack)
                    result.conclusions.extend(sub_result.conclusions)
                    result.triggered_checklist_item_ids.extend(
                        sub_result.triggered_checklist_item_ids
                    )
                    result.priority_modifier += sub_result.priority_modifier
                    result.recommended_phases.extend(sub_result.recommended_phases)
                    result.confidence = max(result.confidence, sub_result.confidence)
                    return result

        if node.conclusion and not node.branches:
            result.conclusions.append(node.conclusion)
            result.triggered_checklist_item_ids.extend(node.checklist_items)
            result.confidence = 0.6

        return result

    def _make_result(
        self, root: DecisionTreeNode, path: list[str]
    ) -> DecisionTreeResult:
        return DecisionTreeResult(
            tree_id=root.id,
            root_question=root.question,
            path_taken=path,
        )

    CONDITION_PREFIXES = frozenset(["has:", "tech:", "area:", "auth:", "cloud:", "phase:", "lang:", "os:"])

    def _condition_matches(self, condition: str, context: dict) -> bool:
        """Evaluate a branch condition against the investigation context.

        Supports patterns like:
          - "has:sql_injection" — check if bug_classes contains sql_injection
          - "tech:django" — check if technologies contains django
          - "area:API" — check if attack_surface_areas contains API
          - "auth:jwt" — check if auth_mechanisms contains jwt
          - "cloud:aws" — check if cloud_providers contains aws
          - "phase:authentication" — check if observation_types contains auth-related
          - "has:XSS AND tech:nodejs" — compound with AND (requires prefixed tokens)
          - "tech:python OR tech:nodejs" — OR compound (requires prefixed tokens)

        Natural language conditions without a prefix (e.g., "Sanctum or
        Passport authentication") is matched as a plain string lookup.
        """
        condition = condition.strip()
        if not condition:
            return False

        is_compound = (
            (condition.upper().startswith("HAS:") or condition.upper().startswith("TECH:"))
            or (condition.upper().startswith("AREA:") or condition.upper().startswith("AUTH:"))
            or (condition.upper().startswith("CLOUD:") or condition.upper().startswith("PHASE:"))
            or (condition.upper().startswith("LANG:") or condition.upper().startswith("OS:"))
        )

        if is_compound and " AND " in condition.upper():
            return all(
                self._condition_matches(c.strip(), context)
                for c in condition.split(" AND ")
            )

        if is_compound and " OR " in condition.upper():
            return any(
                self._condition_matches(c.strip(), context)
                for c in condition.split(" OR ")
            )

        if condition.startswith("has:"):
            key = condition[4:].lower()
            bug_classes = [bc.lower() for bc in context.get("bug_classes", [])]
            return key in bug_classes

        if condition.startswith("tech:"):
            tech = condition[4:].lower()
            technologies = [t.lower() for t in context.get("technologies", [])]
            frameworks = [f.lower() for f in context.get("frameworks", [])]
            return tech in technologies or tech in frameworks

        if condition.startswith("area:"):
            area = condition[5:].lower()
            areas = [a.lower() for a in context.get("attack_surface_areas", [])]
            return any(area in a.lower() for a in areas)

        if condition.startswith("auth:"):
            auth = condition[5:].lower()
            auths = [a.lower() for a in context.get("auth_mechanisms", [])]
            return auth in auths

        if condition.startswith("cloud:"):
            cloud = condition[6:].lower()
            clouds = [c.lower() for c in context.get("cloud_providers", [])]
            return cloud in clouds

        if condition.startswith("phase:"):
            phase = condition[6:].lower()
            phases = [p.lower() for p in context.get("observation_types", [])]
            return phase in phases

        if condition.startswith("lang:"):
            lang = condition[5:].lower()
            langs = [l.lower() for l in context.get("programming_languages", [])]
            return lang in langs

        if condition.startswith("os:"):
            os_name = condition[3:].lower()
            oss = [o.lower() for o in context.get("os", [])]
            return os_name in oss

        plain_lower = condition.lower()
        bug_classes = [bc.lower() for bc in context.get("bug_classes", [])]
        technologies = [t.lower() for t in context.get("technologies", [])]
        frameworks = [f.lower() for f in context.get("frameworks", [])]
        areas = [a.lower() for a in context.get("attack_surface_areas", [])]
        return (
            plain_lower in bug_classes
            or plain_lower in technologies
            or plain_lower in frameworks
            or any(plain_lower in a for a in areas)
        )

    def _priority_from_condition(self, condition: str) -> float:
        """Extract priority modifier from a condition string.

        Conditions can embed priority hints like "critical:", "high:",
        or just return a default modifier based on the condition type.
        """
        lower = condition.lower()
        if lower.startswith("critical:") or "critical" in lower:
            return 0.15
        if lower.startswith("high:") or "high" in lower:
            return 0.10
        if lower.startswith("medium:"):
            return 0.05
        return 0.05

    def _phases_from_condition(self, condition: str) -> list[str]:
        """Infer recommended phases from a condition string."""
        lower = condition.lower()
        phases: list[str] = []

        if any(kw in lower for kw in ["auth", "jwt", "oauth", "sso", "login", "session"]):
            phases.append("authentication_analysis")
        if any(kw in lower for kw in ["authori", "rbac", "access", "permission"]):
            phases.append("authorization_analysis")
        if any(kw in lower for kw in ["sql", "xss", "inject", "input", "validation"]):
            phases.append("input_validation")
        if any(kw in lower for kw in ["api", "graphql", "rest", "endpoint"]):
            phases.append("api_analysis")
        if any(kw in lower for kw in ["business", "logic", "workflow"]):
            phases.append("business_logic_analysis")
        if any(kw in lower for kw in ["upload", "file"]):
            phases.append("file_upload_analysis")
        if any(kw in lower for kw in ["cloud", "aws", "azure", "gcp", "k8s"]):
            phases.append("cloud_analysis")
        if any(kw in lower for kw in ["recon", "enum"]):
            phases.append("recon")
        if any(kw in lower for kw in ["fingerprint", "tech", "version"]):
            phases.append("fingerprint")
        if any(kw in lower for kw in ["privilege", "escalation", "idor"]):
            phases.append("privilege_escalation")

        return phases if phases else ["input_validation"]
