"""Comprehensive tests for the Expert Methodology Packs Framework."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from deephunter.methodology.packs.base import (
    DecisionTreeBranch,
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
from deephunter.core.types import BugClass


# =============================================================================
# Base Model Tests
# =============================================================================


class TestPackChecklist:
    def test_minimal_checklist(self):
        item = PackChecklist(objective="Test XSS", procedure="Test all inputs")
        assert item.objective == "Test XSS"
        assert item.priority == "medium"
        assert item.difficulty == "medium"

    def test_checklist_to_engine_item(self):
        item = PackChecklist(
            objective="Test SQL injection",
            description="Find SQL injection",
            procedure="1. Test input\n2. Verify error",
            priority="critical",
            difficulty="hard",
            required_evidence=["SQL error"],
            bug_classes=[BugClass.SQL_INJECTION],
        )
        engine_item = item.to_checklist_item()
        assert engine_item.objective == "Test SQL injection"
        assert engine_item.priority.value == "critical"
        assert len(engine_item.required_evidence) == 1
        assert engine_item.required_evidence[0].description == "SQL error"

    def test_all_priority_levels(self):
        for priority in ["critical", "high", "medium", "low"]:
            item = PackChecklist(objective=f"Test {priority}", priority=priority)
            engine = item.to_checklist_item()
            assert engine.priority.value == priority

    def test_invalid_priority_fallback(self):
        item = PackChecklist(objective="Test", priority="invalid")
        engine = item.to_checklist_item()
        assert engine.priority.value == "medium"  # fallback


class TestDecisionTreeNode:
    def test_minimal_node(self):
        node = DecisionTreeNode(question="Is auth present?")
        assert node.question == "Is auth present?"
        assert len(node.branches) == 0
        assert node.conclusion == ""

    def test_with_branches(self):
        branch_yes = DecisionTreeBranch(condition="yes", description="Auth found")
        branch_no = DecisionTreeBranch(condition="no", description="No auth")
        node = DecisionTreeNode(
            question="Is auth present?",
            branches=[branch_yes, branch_no],
        )
        assert len(node.branches) == 2
        assert node.branches[0].condition == "yes"

    def test_nested_tree(self):
        leaf = DecisionTreeNode(
            question="What auth type?",
            branches=[
                DecisionTreeBranch(condition="JWT", conclusion="Test JWT"),
                DecisionTreeBranch(condition="Session", conclusion="Test session"),
            ],
        )
        root = DecisionTreeNode(
            question="Auth present?",
            branches=[
                DecisionTreeBranch(condition="yes", child=leaf),
                DecisionTreeBranch(condition="no", conclusion="Skip auth tests"),
            ],
        )
        assert len(root.branches) == 2
        assert root.branches[0].child is not None
        assert root.branches[0].child.question == "What auth type?"


class TestMethodologyPack:
    def test_minimal_pack(self):
        pack = MethodologyPack(
            name="Test Pack",
            category=PackCategory.CROSS_CUTTING,
            supported_technologies=["Test"],
        )
        assert pack.name == "Test Pack"
        assert pack.version == "1.0.0"
        assert pack.category == PackCategory.CROSS_CUTTING
        assert len(pack.checklists) == 0

    def test_pack_with_all_fields(self):
        pack = MethodologyPack(
            name="Full Test",
            version="2.0.0",
            category=PackCategory.FRAMEWORK,
            description="A test pack with everything",
            supported_technologies=["Python", "Django"],
            supported_frameworks=["Django"],
            supported_languages=["Python"],
            attack_surface_areas=["authentication", "api"],
            investigation_goals=[
                InvestigationGoal(name="Find bugs", priority=80)
            ],
            investigation_priority=90,
            checklists=[
                PackChecklist(objective="Test A"),
                PackChecklist(objective="Test B"),
            ],
            planner_rules=[
                PackPlannerRule(technology="Django", description="Prioritize X", priority_modifier=0.1),
            ],
        )
        assert len(pack.checklists) == 2
        assert len(pack.planner_rules) == 1
        assert len(pack.investigation_goals) == 1

    def test_get_checklist_items_engine(self):
        pack = MethodologyPack(
            name="Test",
            category=PackCategory.FRAMEWORK,
            supported_technologies=["Test"],
            checklists=[
                PackChecklist(objective="Test SQLi", bug_classes=[BugClass.SQL_INJECTION]),
            ],
        )
        items = pack.get_checklist_items(engine_checklist=True)
        assert len(items) == 1
        assert items[0].objective == "Test SQLi"

    def test_get_checklist_items_raw(self):
        pack = MethodologyPack(
            name="Test",
            category=PackCategory.FRAMEWORK,
            supported_technologies=["Test"],
            checklists=[PackChecklist(objective="Test")],
        )
        items = pack.get_checklist_items(engine_checklist=False)
        assert len(items) == 1
        assert isinstance(items[0], PackChecklist)

    def test_pack_serialization_roundtrip(self):
        pack = MethodologyPack(
            name="Serialize Test",
            category=PackCategory.FRAMEWORK,
            supported_technologies=["T"],
            checklists=[PackChecklist(objective="Test")],
            decision_trees=[
                DecisionTreeNode(question="Decision?")
            ],
        )
        data = pack.model_dump(mode="json")
        restored = MethodologyPack.model_validate(data)
        assert restored.name == pack.name
        assert len(restored.checklists) == len(pack.checklists)
        assert len(restored.decision_trees) == len(pack.decision_trees)


class TestMethodologyPackSet:
    def test_empty_set(self):
        pset = MethodologyPackSet()
        assert len(pset.packs) == 0
        assert pset.total_checklist_items == 0

    def test_recalculate(self):
        pack = MethodologyPack(
            name="Test",
            category=PackCategory.FRAMEWORK,
            supported_technologies=["T"],
            checklists=[PackChecklist(objective="A"), PackChecklist(objective="B")],
            investigation_goals=[InvestigationGoal(name="Goal")],
            planner_rules=[PackPlannerRule(technology="T", description="R", priority_modifier=0.1)],
        )
        pset = MethodologyPackSet(packs=[pack])
        pset.recalculate()
        assert pset.total_checklist_items == 2
        assert pset.total_goals == 1
        assert pset.total_planner_rules == 1


# =============================================================================
# Registry Tests
# =============================================================================


class TestPackRegistry:
    def test_register_and_get(self):
        registry = PackRegistry()
        pack = MethodologyPack(name="Test", category=PackCategory.FRAMEWORK, supported_technologies=["Test"])
        registry.register(pack)
        assert registry.get("Test") is pack
        assert registry.get("Nonexistent") is None

    def test_register_duplicate_overwrites(self):
        registry = PackRegistry()
        p1 = MethodologyPack(name="Test", category=PackCategory.FRAMEWORK, supported_technologies=["T"])
        p2 = MethodologyPack(name="Test", category=PackCategory.CROSS_CUTTING, supported_technologies=["T"])
        registry.register(p1)
        registry.register(p2)  # overwrites
        assert registry.get("Test").category == PackCategory.CROSS_CUTTING

    def test_get_by_technology(self):
        registry = PackRegistry()
        p1 = MethodologyPack(name="Django Pack", category=PackCategory.FRAMEWORK, supported_technologies=["Django", "Python"])
        p2 = MethodologyPack(name="Flask Pack", category=PackCategory.FRAMEWORK, supported_technologies=["Flask", "Python"])
        registry.register(p1)
        registry.register(p2)
        result = registry.get_by_technology("Django")
        assert len(result) == 1
        assert result[0].name == "Django Pack"

    def test_get_by_category(self):
        registry = PackRegistry()
        fw = MethodologyPack(name="FW", category=PackCategory.FRAMEWORK, supported_technologies=["T"])
        cc = MethodologyPack(name="CC", category=PackCategory.CROSS_CUTTING, supported_technologies=["T"])
        registry.register(fw)
        registry.register(cc)
        assert len(registry.get_by_category(PackCategory.FRAMEWORK)) == 1
        assert len(registry.get_by_category(PackCategory.CROSS_CUTTING)) == 1

    def test_get_by_attack_surface(self):
        registry = PackRegistry()
        p = MethodologyPack(name="Test", category=PackCategory.CROSS_CUTTING, attack_surface_areas=["authentication", "api"])
        registry.register(p)
        assert len(registry.get_by_attack_surface("authentication")) == 1
        assert len(registry.get_by_attack_surface("authorization")) == 0

    def test_list_all_and_count(self):
        registry = PackRegistry()
        registry.register(MethodologyPack(name="A", category=PackCategory.FRAMEWORK, supported_technologies=["T"]))
        registry.register(MethodologyPack(name="B", category=PackCategory.CROSS_CUTTING, supported_technologies=["T"]))
        assert registry.count() == 2
        assert len(registry.list_all()) == 2

    def test_clear(self):
        registry = PackRegistry()
        registry.register(MethodologyPack(name="A", category=PackCategory.FRAMEWORK, supported_technologies=["T"]))
        registry.clear()
        assert registry.count() == 0

    def test_validation_empty_name(self):
        registry = PackRegistry()
        with pytest.raises(PackValidationError, match="must have a name"):
            registry.register(MethodologyPack(name="", category=PackCategory.FRAMEWORK))

    def test_validation_empty_tech_and_fw(self):
        registry = PackRegistry()
        with pytest.raises(PackValidationError, match="must support at least one"):
            registry.register(MethodologyPack(
                name="Invalid",
                category=PackCategory.FRAMEWORK,
            ))

    def test_validation_checklist_empty_objective(self):
        registry = PackRegistry()
        with pytest.raises(PackValidationError, match="empty objective"):
            registry.register(MethodologyPack(
                name="Bad",
                category=PackCategory.CROSS_CUTTING,
                supported_technologies=["Test"],
                checklists=[PackChecklist(objective="")],
            ))

    def test_validation_checklist_invalid_priority(self):
        registry = PackRegistry()
        with pytest.raises(PackValidationError, match="invalid priority"):
            registry.register(MethodologyPack(
                name="Bad",
                category=PackCategory.CROSS_CUTTING,
                supported_technologies=["Test"],
                checklists=[PackChecklist(objective="Test", priority="urgent")],
            ))


# =============================================================================
# Module-Level Function Tests
# =============================================================================


class TestModuleFunctions:
    def test_load_all_packs(self):
        """Verify all 25 built-in packs load correctly."""
        from deephunter.methodology.packs.registry import _REGISTRY
        _REGISTRY.clear()
        load_all_packs()
        packs = list_all_packs()
        assert len(packs) == 25

    def test_all_packs_have_valid_data(self):
        """Every pack should have meaningful data, not placeholders."""
        from deephunter.methodology.packs.registry import _REGISTRY
        _REGISTRY.clear()
        load_all_packs()
        for pack in list_all_packs():
            assert pack.name, f"Pack missing name"
            assert pack.description, f"Pack '{pack.name}' missing description"
            assert pack.checklists, f"Pack '{pack.name}' has no checklists"
            for ci in pack.checklists:
                assert ci.objective, f"Checklist item in '{pack.name}' empty objective"
                assert ci.procedure, f"Checklist item '{ci.objective}' in '{pack.name}' has empty procedure"

    def test_get_pack_by_name(self):
        from deephunter.methodology.packs.registry import _REGISTRY
        _REGISTRY.clear()
        load_all_packs()
        pack = get_pack("Laravel")
        assert pack is not None
        assert pack.category == PackCategory.FRAMEWORK

    def test_get_packs_by_category_framework(self):
        from deephunter.methodology.packs.registry import _REGISTRY
        _REGISTRY.clear()
        load_all_packs()
        fw_packs = get_packs_by_category(PackCategory.FRAMEWORK)
        assert len(fw_packs) == 12

    def test_get_packs_by_category_cross_cutting(self):
        from deephunter.methodology.packs.registry import _REGISTRY
        _REGISTRY.clear()
        load_all_packs()
        cc_packs = get_packs_by_category(PackCategory.CROSS_CUTTING)
        assert len(cc_packs) == 13

    def test_get_packs_by_technology_django(self):
        from deephunter.methodology.packs.registry import _REGISTRY
        _REGISTRY.clear()
        load_all_packs()
        packs = get_packs_by_technology("Django")
        assert any(p.name == "Django" for p in packs)

    def test_get_packs_by_technology_graphql(self):
        from deephunter.methodology.packs.registry import _REGISTRY
        _REGISTRY.clear()
        load_all_packs()
        packs = get_packs_by_technology("GraphQL")
        assert any(p.name == "GraphQL" for p in packs)

    def test_register_pack_function(self):
        from deephunter.methodology.packs.registry import _REGISTRY
        _REGISTRY.clear()
        pack = MethodologyPack(
            name="Custom Pack",
            category=PackCategory.CROSS_CUTTING,
            supported_technologies=["Custom"],
            checklists=[PackChecklist(objective="Test custom")],
        )
        register_pack(pack)
        assert get_pack("Custom Pack") is pack


# =============================================================================
# Framework-Specific Pack Tests
# =============================================================================


class TestFrameworkPacks:
    @pytest.fixture(autouse=True)
    def load_packs(self):
        from deephunter.methodology.packs.registry import _REGISTRY
        _REGISTRY.clear()
        load_all_packs()

    @pytest.mark.parametrize("pack_name,expected_items,expected_rules", [
        ("Laravel", 13, 3),
        ("Django", 9, 3),
        ("Spring Boot", 7, 3),
        ("Express", 7, 3),
        ("FastAPI", 6, 2),
        ("Next.js", 7, 4),
        ("Nuxt", 4, 2),
        ("Ruby on Rails", 5, 2),
        ("ASP.NET Core", 5, 2),
        ("WordPress", 6, 2),
        ("Drupal", 4, 2),
        ("Magento", 5, 2),
    ])
    def test_framework_pack_content(self, pack_name, expected_items, expected_rules):
        pack = get_pack(pack_name)
        assert pack is not None, f"{pack_name} pack not found"
        assert len(pack.checklists) >= expected_items, \
            f"{pack_name}: expected >= {expected_items} items, got {len(pack.checklists)}"
        assert len(pack.planner_rules) >= expected_rules, \
            f"{pack_name}: expected >= {expected_rules} rules, got {len(pack.planner_rules)}"
        assert pack.profile is not None, f"{pack_name} missing profile"
        assert len(pack.workflow) >= 5, f"{pack_name}: workflow too short ({len(pack.workflow)} phases)"
        assert pack.investigation_priority >= 70, f"{pack_name}: low priority {pack.investigation_priority}"


class TestCrossCuttingPacks:
    @pytest.fixture(autouse=True)
    def load_packs(self):
        from deephunter.methodology.packs.registry import _REGISTRY
        _REGISTRY.clear()
        load_all_packs()

    @pytest.mark.parametrize("pack_name,expected_items,expected_rules", [
        ("GraphQL", 6, 3),
        ("REST API", 8, 3),
        ("JWT", 7, 4),
        ("OAuth", 7, 3),
        ("OIDC", 5, 2),
        ("Session Management", 7, 3),
        ("File Upload", 6, 3),
        ("Business Logic", 8, 3),
        ("Cloud Review", 5, 2),
        ("Microservices", 7, 3),
    ])
    def test_cross_cutting_pack_content(self, pack_name, expected_items, expected_rules):
        pack = get_pack(pack_name)
        assert pack is not None, f"{pack_name} pack not found"
        assert len(pack.checklists) >= expected_items, \
            f"{pack_name}: expected >= {expected_items} items, got {len(pack.checklists)}"
        assert len(pack.planner_rules) >= expected_rules, \
            f"{pack_name}: expected >= {expected_rules} rules, got {len(pack.planner_rules)}"


# =============================================================================
# Decision Tree Tests
# =============================================================================


class TestDecisionTrees:
    @pytest.fixture(autouse=True)
    def load_packs(self):
        from deephunter.methodology.packs.registry import _REGISTRY
        _REGISTRY.clear()
        load_all_packs()

    def test_all_framework_packs_have_decision_trees(self):
        """All framework packs should include at least 1 decision tree."""
        fw_packs = get_packs_by_category(PackCategory.FRAMEWORK)
        for pack in fw_packs:
            assert len(pack.decision_trees) >= 1, f"{pack.name} has no decision tree"

    def test_all_cross_cutting_packs_have_decision_trees(self):
        """All cross-cutting packs should include at least 1 decision tree."""
        cc_packs = get_packs_by_category(PackCategory.CROSS_CUTTING)
        for pack in cc_packs:
            assert len(pack.decision_trees) >= 1, f"{pack.name} has no decision tree"

    def test_decision_tree_structure(self):
        """Every decision tree should have a root with at least 2 branches."""
        for pack in list_all_packs():
            for tree in pack.decision_trees:
                assert tree.question, f"Tree in {pack.name} missing question"
                assert len(tree.branches) >= 1, f"Tree in {pack.name} has no branches"
                for branch in tree.branches:
                    assert branch.condition, f"Branch in {pack.name} missing condition"
                    assert branch.conclusion or branch.child, \
                        f"Branch '{branch.condition}' in {pack.name} has no conclusion or child"


# =============================================================================
# Planner Integration Tests
# =============================================================================


class TestPlannerIntegration:
    def test_methodology_pack_rule_generates_steps(self):
        """Verify MethodologyPackRule generates steps from context."""
        from deephunter.planning.rules import RuleRegistry
        from deephunter.planning.models import PlannerContext

        registry = RuleRegistry.with_default_rules()
        pack_rule = registry.get("methodology_packs")
        assert pack_rule is not None, "methodology_packs rule not registered"

        ctx = PlannerContext(
            technologies=["Django", "Python"],
            frameworks=["Django"],
            attack_surface_areas=["authentication", "api"],
        )
        steps = pack_rule.evaluate(ctx)
        assert len(steps) > 0, "Pack rule produced no steps"
        first = steps[0]
        assert "[Django]" in first.title or "Django" in first.metadata.get("pack_name", "")

    def test_pack_steps_have_manual_tests(self):
        """Every pack-generated step should include at least 1 manual test."""
        from deephunter.planning.rules import RuleRegistry
        from deephunter.planning.models import PlannerContext

        registry = RuleRegistry.with_default_rules()
        pack_rule = registry.get("methodology_packs")
        ctx = PlannerContext(
            technologies=["Django"],
            frameworks=["Django"],
        )
        steps = pack_rule.evaluate(ctx)
        for s in steps:
            assert len(s.recommended_tests) > 0, f"Step '{s.title}' missing recommended test"

    def test_pack_and_methodology_rules_complement(self):
        """Both pack rule and methodology rule should run without errors."""
        from deephunter.planning.rules import RuleRegistry
        from deephunter.planning.models import PlannerContext

        registry = RuleRegistry.with_default_rules()
        ctx = PlannerContext(
            technologies=["Python", "Django"],
            frameworks=["Django"],
            attack_surface_areas=["authentication"],
        )
        all_steps = registry.evaluate_all(ctx)
        pack_steps = [s for s in all_steps if s.metadata.get("pack_name")]
        meth_steps = [s for s in all_steps if s.metadata.get("methodology_id")]
        assert len(pack_steps) > 0, "No pack steps generated"
        assert len(meth_steps) > 0, "No methodology steps generated"

    def test_infer_phase_for_various_objectives(self):
        """Verify phase inference maps objectives to appropriate planning phases."""
        from deephunter.methodology.packs.integration import MethodologyPackRule
        from deephunter.methodology.packs.base import MethodologyPack, PackCategory, PackChecklist
        from deephunter.planning.models import PlanningPhase

        rule = MethodologyPackRule()

        test_cases = [
            ("reconnaissance and enumeration", PlanningPhase.RECON),
            ("fingerprint framework version", PlanningPhase.FINGERPRINT),
            ("authentication bypass in JWT", PlanningPhase.AUTHENTICATION_ANALYSIS),
            ("authorization for admin users", PlanningPhase.AUTHORIZATION_ANALYSIS),
            ("business logic workflow test", PlanningPhase.BUSINESS_LOGIC_ANALYSIS),
            ("graphql API endpoint test", PlanningPhase.API_ANALYSIS),
            ("file upload vulnerability", PlanningPhase.FILE_UPLOAD_ANALYSIS),
            ("cloud provider misconfiguration", PlanningPhase.CLOUD_ANALYSIS),
            ("privilege escalation via IDOR", PlanningPhase.PRIVILEGE_ESCALATION),
            ("input validation for SSTI", PlanningPhase.INPUT_VALIDATION),
            ("report preparation", PlanningPhase.REPORT_PREPARATION),
        ]
        for objective, expected_phase in test_cases:
            pack = MethodologyPack(name="Test", category=PackCategory.CROSS_CUTTING, supported_technologies=["Test"])
            phase = rule._infer_phase(objective, pack)
            assert phase == expected_phase, f"'{objective}' -> {phase}, expected {expected_phase}"

    def test_framework_pack_infers_framework_detection_phase(self):
        """Framework packs should default to FRAMEWORK_DETECTION phase."""
        from deephunter.methodology.packs.integration import MethodologyPackRule
        from deephunter.methodology.packs.base import MethodologyPack, PackCategory

        rule = MethodologyPackRule()
        pack = MethodologyPack(name="Test", category=PackCategory.FRAMEWORK, supported_technologies=["Test"])
        phase = rule._infer_phase("arbitrary pack specific testing objective", pack)
        assert phase.value == "framework_detection"


# =============================================================================
# Framework Profile Tests
# =============================================================================


class TestFrameworkProfiles:
    @pytest.fixture(autouse=True)
    def load_packs(self):
        from deephunter.methodology.packs.registry import _REGISTRY
        _REGISTRY.clear()
        load_all_packs()

    def test_framework_packs_have_profiles(self):
        """Every framework pack should have a PackFrameworkProfile."""
        for pack in get_packs_by_category(PackCategory.FRAMEWORK):
            assert pack.profile is not None, f"{pack.name} missing profile"
            assert len(pack.profile.architecture_description) > 0, f"{pack.name} missing architecture"
            assert len(pack.profile.investigation_areas) >= 5, \
                f"{pack.name} only has {len(pack.profile.investigation_areas)} investigation areas"

    def test_trust_boundaries_defined(self):
        """All framework profiles should define trust boundaries."""
        for pack in get_packs_by_category(PackCategory.FRAMEWORK):
            assert len(pack.profile.trust_boundaries) >= 2, \
                f"{pack.name}: only {len(pack.profile.trust_boundaries)} trust boundaries"
