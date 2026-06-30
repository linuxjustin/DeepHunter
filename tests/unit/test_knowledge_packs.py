"""Comprehensive tests for the Knowledge Pack Ecosystem (Epic #014).

Tests cover:
  1. Data model construction & validation
  2. Registry operations (CRUD, load, query)
  3. Relationship graph traversal & tech stack
  4. All 35 built-in packs load correctly
  5. Subsystem integration (Planner, Reasoning, Context, Prompt)
  6. Edge cases (empty, malformed, duplicates)
  7. Cross-subsystem data flow
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from deephunter.core.types import AttackSurfaceEntry, BugClass, ManualTestChecklistItem, TrustBoundary

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
from deephunter.knowledge.packs.integration import (
    KnowledgePackRule,
    KnowledgePackReasoningAdapter,
    enrich_context_with_knowledge_packs,
    enrich_tech_intel,
    get_prompt_context_enrichment,
)


# =============================================================================
# 1. Data Model Construction
# =============================================================================


class TestKnowledgePackConstruction:
    def test_minimal_pack(self):
        pack = KnowledgePack(
            name="test",
            description="A test pack",
            technology=TechnologyProfile(name="Test"),
        )
        assert pack.name == "test"
        assert pack.version == "1.0.0"
        assert pack.category == KnowledgePackCategory.FRAMEWORK
        assert pack.technology.name == "Test"

    def test_full_pack(self):
        pack = KnowledgePack(
            name="fullpack",
            version="2.0.0",
            category=KnowledgePackCategory.API,
            description="Full test pack",
            technology=TechnologyProfile(
                name="Full API",
                vendor="Acme",
                language="Python",
                common_aliases=["full-api", "api-v2"],
                dependencies=["lib1"],
                tags=["api"],
            ),
            components=[
                TechnologyComponentProfile(
                    name="Auth Module",
                    description="Handles auth",
                    security_relevance="high",
                    common_vulnerabilities=["Bypass"],
                    investigation_priority=90,
                    tags=["auth"],
                ),
            ],
            attack_surface=AttackSurfaceProfile(
                endpoints=["/api/v1"],
                parameters=["id"],
                authentication=["JWT"],
                attack_surface_areas=["Injection", "Bypass"],
                investigation_areas=["Test auth bypass"],
                tags=["api"],
            ),
            fingerprints=FingerprintProfile(
                http_headers={"X-API": "v2"},
                cookies=["session"],
                tags=["fingerprint"],
            ),
            recon=ReconProfile(
                endpoints_to_scan=["/api/v1"],
                tags=["recon"],
            ),
            relationships=[
                KnowledgeRelationship(
                    target_pack_name="target",
                    relationship_type=KnowledgeRelationshipType.DEPENDS_ON,
                    description="Depends on target",
                    confidence="high",
                ),
            ],
            workflow=[
                "Step 1: Test",
                "Step 2: Verify",
            ],
            checklists=[
                ManualTestChecklistItem(
                    step_id="API-01",
                    category="Auth",
                    description="Test auth bypass",
                    expected_result="No bypass",
                    tools=["curl"],
                    references=["https://example.com"],
                ),
            ],
            references=[{"title": "Docs", "url": "https://docs.example.com"}],
            cwe_ids=["CWE-1", "CWE-2"],
            tags=["test", "full"],
        )
        assert pack.name == "fullpack"
        assert len(pack.components) == 1
        assert len(pack.attack_surface.attack_surface_areas) == 2
        assert len(pack.relationships) == 1
        assert len(pack.checklists) == 1
        assert len(pack.cwe_ids) == 2

    def test_pack_without_name_succeeds(self):
        """Empty name is accepted (no validation constraint on str length)."""
        pack = KnowledgePack(
            name="",
            description="test",
            technology=TechnologyProfile(name="Test tech"),
        )
        assert pack.name == ""

    def test_default_values(self):
        pack = KnowledgePack(
            name="defaults",
            description="Defaults test",
            technology=TechnologyProfile(name="Default Tech"),
        )
        assert pack.components == []
        assert pack.relationships == []
        assert pack.dependencies == []
        assert pack.cwe_ids == []
        assert pack.fingerprints.http_headers == {}
        assert pack.fingerprints.cookies == []


class TestSubProfileModels:
    def test_technology_profile(self):
        tp = TechnologyProfile(
            name="Laravel",
            vendor="Laravel LLC",
            language="PHP",
            common_aliases=["laravel", "lumen"],
            tags=["php", "mvc"],
        )
        assert tp.name == "Laravel"
        assert len(tp.common_aliases) == 2

    def test_component_profile(self):
        cp = TechnologyComponentProfile(
            name="ORM",
            description="Object relational mapper",
            security_relevance="high",
            common_vulnerabilities=["SQL Injection", "Mass Assignment"],
            investigation_priority=95,
            tags=["orm", "sql"],
        )
        assert cp.security_relevance == "high"
        assert cp.investigation_priority == 95

    def test_attack_surface_profile(self):
        asp = AttackSurfaceProfile(
            entry_points=[
                AttackSurfaceEntry(
                    name="Login",
                    description="Login endpoint",
                    protocol="HTTPS",
                    method="POST",
                    path="/login",
                    parameters=["username", "password"],
                    authentication_required=False,
                    authorization_required=False,
                    bug_classes=[BugClass.SQL_INJECTION.value],
                ),
            ],
            endpoints=["/login", "/admin"],
            authentication=["Session"],
            authorization=["RBAC"],
            trust_boundaries=[
                TrustBoundary(
                    name="Web-to-App",
                    description="External to internal",
                    direction="inbound",
                    sensitivity="high",
                ),
            ],
            attack_surface_areas=["SQL Injection", "Auth Bypass"],
            investigation_areas=["Test login bypass"],
            tags=["web"],
        )
        assert len(asp.entry_points) == 1
        assert len(asp.trust_boundaries) == 1
        assert len(asp.attack_surface_areas) == 2

    def test_fingerprint_profile(self):
        fp = FingerprintProfile(
            http_headers={"X-Powered-By": "PHP"},
            cookies=["laravel_session"],
            server_signatures=["Laravel"],
            error_page_signatures=["Whoops!"],
            default_paths=["/login"],
            tags=["fingerprint", "laravel"],
        )
        assert fp.http_headers["X-Powered-By"] == "PHP"
        assert len(fp.server_signatures) == 1

    def test_recon_profile(self):
        rp = ReconProfile(
            directories_to_check=["/admin", "/storage"],
            files_to_check=[".env", "artisan"],
            endpoints_to_scan=["/login", "/api"],
            version_detection_paths=["/version"],
            tags=["recon", "laravel"],
        )
        assert len(rp.directories_to_check) == 2


# =============================================================================
# 2. Registry Operations
# =============================================================================


class TestKnowledgePackRegistry:
    def setup_method(self):
        self.registry = KnowledgePackRegistry()

    def make_pack(self, name: str, **kwargs) -> KnowledgePack:
        return KnowledgePack(
            name=name,
            description=f"Pack {name}",
            technology=TechnologyProfile(
                name=kwargs.pop("tech_name", name.title()),
                vendor=kwargs.pop("vendor", ""),
            ),
            category=kwargs.pop("category", KnowledgePackCategory.FRAMEWORK),
            relationships=kwargs.pop("relationships", []),
            **kwargs,
        )

    def test_register_and_get(self):
        pack = self.make_pack("testpack")
        self.registry.register(pack)
        assert self.registry.get("testpack") is pack
        assert self.registry.count() == 1

    def test_register_multiple_packs(self):
        for name in ["alpha", "beta", "gamma"]:
            self.registry.register(self.make_pack(name))
        assert self.registry.count() == 3
        assert self.registry.get("alpha") is not None
        assert self.registry.get("missing") is None

    def test_register_duplicate_overwrites(self):
        self.registry.register(self.make_pack("dup"))
        p1 = self.registry.get("dup")
        self.registry.register(self.make_pack("dup"))
        p2 = self.registry.get("dup")
        assert p1 is not p2  # Different object, same name

    def test_get_by_technology(self):
        pack = self.make_pack("techpack", tech_name="MyTech")
        self.registry.register(pack)
        results = self.registry.get_by_technology("MyTech")
        assert len(results) == 1
        assert results[0].name == "techpack"

    def test_get_by_technology_case_insensitive(self):
        pack = self.make_pack("tp", tech_name="MyTech", common_aliases=["MT-Alias"])
        self.registry.register(pack)
        assert len(self.registry.get_by_technology("mytech")) == 1
        assert len(self.registry.get_by_technology("MYTECH")) == 1

    def test_get_by_technology_alias(self):
        pack = KnowledgePack(
            name="aliaspack",
            description="Packs with aliases",
            technology=TechnologyProfile(
                name="Original",
                common_aliases=["alias1", "alias2"],
            ),
        )
        self.registry.register(pack)
        ts = self.registry.get_by_technology("alias1")
        assert len(ts) == 1
        assert ts[0].name == "aliaspack"

    def test_get_by_vendor(self):
        pack = self.make_pack("vpack", tech_name="VT", vendor="Acme Corp")
        self.registry.register(pack)
        assert len(self.registry.get_by_vendor("Acme")) == 1
        assert len(self.registry.get_by_vendor("acme")) == 1
        assert len(self.registry.get_by_vendor("Missing")) == 0

    def test_get_by_category(self):
        infra = self.make_pack("infra1", category=KnowledgePackCategory.INFRASTRUCTURE)
        api = self.make_pack("api1", category=KnowledgePackCategory.API)
        self.registry.register(infra)
        self.registry.register(api)
        assert len(self.registry.get_by_category(KnowledgePackCategory.INFRASTRUCTURE)) == 1
        assert len(self.registry.get_by_category(KnowledgePackCategory.API)) == 1

    def test_list_all(self):
        for n in range(5):
            self.registry.register(self.make_pack(f"pack{n}"))
        assert len(self.registry.list_all()) == 5

    def test_clear(self):
        self.registry.register(self.make_pack("p1"))
        self.registry.register(self.make_pack("p2"))
        assert self.registry.count() == 2
        self.registry.clear()
        assert self.registry.count() == 0

    def test_index_generation(self):
        for name in ["a", "b", "c"]:
            pack = self.make_pack(name)
            if name == "a":
                pack.relationships.append(
                    KnowledgeRelationship(
                        target_pack_name="b",
                        relationship_type=KnowledgeRelationshipType.DEPENDS_ON,
                    )
                )
            self.registry.register(pack)
        idx = self.registry.to_index()
        assert idx.total_packs == 3
        assert idx.total_categories >= 1
        assert idx.total_relationships >= 1

    def test_technology_stack(self):
        self.registry.register(self.make_pack("app"))
        self.registry.register(self.make_pack("db"))
        self.registry.register(self.make_pack("cache"))
        app = self.registry.get("app")
        app.relationships.append(
            KnowledgeRelationship(
                target_pack_name="db",
                relationship_type=KnowledgeRelationshipType.STORES_DATA_IN,
            )
        )
        app.relationships.append(
            KnowledgeRelationship(
                target_pack_name="cache",
                relationship_type=KnowledgeRelationshipType.CACHES_WITH,
            )
        )
        # Re-register to rebuild graph
        self.registry.register(app)
        stack = self.registry.get_technology_stack("app", depth=3)
        assert "app" in stack
        assert "db" in stack


# =============================================================================
# 3. Relationship Graph
# =============================================================================


class TestKnowledgeRelationshipGraph:
    def setup_method(self):
        self.graph = KnowledgeRelationshipGraph()

    def test_add_relationship(self):
        rel = KnowledgeRelationship(
            target_pack_name="target",
            relationship_type=KnowledgeRelationshipType.DEPENDS_ON,
            description="A depends on B",
        )
        self.graph.add_relationship("source", rel)
        assert "source" in self.graph.nodes
        assert "target" in self.graph.nodes["source"]

    def test_get_related(self):
        rel1 = KnowledgeRelationship(
            target_pack_name="B",
            relationship_type=KnowledgeRelationshipType.DEPENDS_ON,
        )
        rel2 = KnowledgeRelationship(
            target_pack_name="C",
            relationship_type=KnowledgeRelationshipType.INTEGRATES_WITH,
        )
        self.graph.add_relationship("A", rel1)
        self.graph.add_relationship("A", rel2)
        related = self.graph.get_related("A")
        assert len(related) == 2

    def test_tech_stack_bfs(self):
        self.graph.add_relationship(
            "Frontend", KnowledgeRelationship(
                target_pack_name="Backend",
                relationship_type=KnowledgeRelationshipType.INTEGRATES_WITH,
            )
        )
        self.graph.add_relationship(
            "Backend", KnowledgeRelationship(
                target_pack_name="Database",
                relationship_type=KnowledgeRelationshipType.STORES_DATA_IN,
            )
        )
        self.graph.add_relationship(
            "Database", KnowledgeRelationship(
                target_pack_name="Cache",
                relationship_type=KnowledgeRelationshipType.CACHES_WITH,
            )
        )
        stack = self.graph.get_technology_stack("Frontend", depth=3)
        assert "Frontend" in stack
        assert "Backend" in stack
        assert "Database" in stack
        assert len(stack) == 3

    def test_tech_stack_max_depth(self):
        self.graph.add_relationship(
            "A", KnowledgeRelationship(
                target_pack_name="B",
                relationship_type=KnowledgeRelationshipType.DEPENDS_ON,
            )
        )
        self.graph.add_relationship(
            "B", KnowledgeRelationship(
                target_pack_name="C",
                relationship_type=KnowledgeRelationshipType.DEPENDS_ON,
            )
        )
        self.graph.add_relationship(
            "C", KnowledgeRelationship(
                target_pack_name="D",
                relationship_type=KnowledgeRelationshipType.DEPENDS_ON,
            )
        )
        stack = self.graph.get_technology_stack("A", depth=2)
        assert len(stack) == 2

    def test_bidirectional_graph(self):
        rel = KnowledgeRelationship(
            target_pack_name="Laravel",
            relationship_type=KnowledgeRelationshipType.RUNS_ON,
            description="Laravel runs on PHP",
        )
        self.graph.add_relationship("PHP", rel)
        reverse_rel = KnowledgeRelationship(
            target_pack_name="PHP",
            relationship_type=KnowledgeRelationshipType.RUNS_ON,
            description="PHP runs Laravel",
        )
        self.graph.add_relationship("Laravel", reverse_rel)
        assert len(self.graph.get_related("PHP")) == 1
        assert len(self.graph.get_related("Laravel")) == 1


# =============================================================================
# 4. Built-in Pack Loading
# =============================================================================


class TestBuiltInPacks:
    def test_all_packs_load(self):
        registry = load_all_knowledge_packs()
        assert registry.count() >= 5

    def test_specific_packs_exist(self):
        load_all_knowledge_packs()
        for pack_name in [
            "laravel", "django", "rails", "spring_boot", "express",
            "fastapi", "flask", "nextjs", "nuxt", "nestjs",
            "phoenix", "symfony", "aspnet",
            "wordpress", "drupal", "magento",
            "nginx", "apache", "redis", "rabbitmq",
            "kubernetes", "docker",
            "aws", "azure", "gcp", "cloudflare",
            "postgresql", "mysql", "mongodb",
            "graphql", "rest", "jwt", "oauth", "oidc", "saml",
        ]:
            assert get_kp(pack_name) is not None, f"Missing pack: {pack_name}"

    def test_all_packs_have_components(self):
        load_all_knowledge_packs()
        for pack in list_all_knowledge_packs():
            assert len(pack.components) >= 1, f"Pack {pack.name} has no components"

    def test_all_packs_have_checklists(self):
        load_all_knowledge_packs()
        for pack in list_all_knowledge_packs():
            assert len(pack.checklists) >= 1, f"Pack {pack.name} has no checklists"

    def test_all_packs_have_relationships(self):
        load_all_knowledge_packs()
        for pack in list_all_knowledge_packs():
            assert len(pack.relationships) >= 1, f"Pack {pack.name} has no relationships"

    def test_all_packs_have_attack_surface(self):
        load_all_knowledge_packs()
        for pack in list_all_knowledge_packs():
            assert len(pack.attack_surface.attack_surface_areas) >= 1, \
                f"Pack {pack.name} has no attack surface areas"

    def test_all_packs_have_workflow_steps(self):
        load_all_knowledge_packs()
        for pack in list_all_knowledge_packs():
            assert len(pack.workflow) >= 1, f"Pack {pack.name} has no workflow"

    def test_all_packs_have_fingerprints(self):
        load_all_knowledge_packs()
        for pack in list_all_knowledge_packs():
            fp = pack.fingerprints
            assert (
                fp.http_headers
                or fp.cookies
                or fp.server_signatures
                or fp.error_page_signatures
                or fp.default_paths
            ), f"Pack {pack.name} has no fingerprints"

    def test_all_packs_have_recon(self):
        load_all_knowledge_packs()
        for pack in list_all_knowledge_packs():
            recon = pack.recon
            assert (
                recon.directories_to_check
                or recon.files_to_check
                or recon.endpoints_to_scan
                or recon.version_detection_paths
            ), f"Pack {pack.name} has no recon data"

    def test_category_distribution(self):
        load_all_knowledge_packs()
        categories = set(p.category for p in list_all_knowledge_packs())
        assert KnowledgePackCategory.FRAMEWORK in categories
        assert KnowledgePackCategory.CMS in categories
        assert KnowledgePackCategory.WEBSERVER in categories
        assert KnowledgePackCategory.CLOUD in categories
        assert KnowledgePackCategory.DATABASE in categories
        assert KnowledgePackCategory.API in categories
        assert KnowledgePackCategory.AUTHENTICATION in categories

    def test_version_format(self):
        load_all_knowledge_packs()
        for pack in list_all_knowledge_packs():
            parts = pack.version.split(".")
            assert len(parts) == 3, f"Pack {pack.name} has non-semver version: {pack.version}"
            for part in parts:
                assert part.isdigit(), f"Pack {pack.name} version part not numeric: {part}"


# =============================================================================
# 5. Subsystem Integration
# =============================================================================


class TestPlannerIntegration:
    def test_knowledge_pack_rule_exists(self):
        rule = KnowledgePackRule()
        assert rule.name == "knowledge_packs"
        assert rule.priority == 35
        assert rule.phase == "fingerprint"

    def test_knowledge_pack_rule_in_default_registry(self):
        from deephunter.planning.rules import RuleRegistry
        reg = RuleRegistry.with_default_rules()
        rule = reg.get("knowledge_packs")
        assert rule is not None
        assert rule.priority == 35

    def test_knowledge_pack_rule_priority_order(self):
        from deephunter.planning.rules import RuleRegistry
        reg = RuleRegistry.with_default_rules()
        rules = reg.list_rules()
        priorities = [r.priority for r in rules]
        assert priorities == sorted(priorities)

    def test_full_planning_pipeline_loads(self):
        from deephunter.planning.models import PlannerContext
        load_all_knowledge_packs()
        rule = KnowledgePackRule()
        context = PlannerContext(
            target_url="https://example.com",
            technologies=["Laravel", "PHP"],
            frameworks=["laravel"],
            attack_surface_areas=["Authentication", "SQL Injection"],
        )
        steps = rule.evaluate(context)
        assert len(steps) >= 1
        assert any("laravel" in s.title.lower() for s in steps)

    def test_universal_packs_applied_when_no_tech_match(self):
        from deephunter.planning.models import PlannerContext
        load_all_knowledge_packs()
        rule = KnowledgePackRule()
        context = PlannerContext(
            target_url="https://example.com",
            technologies=["UnknownTechXYZ"],
            frameworks=[],
        )
        steps = rule.evaluate(context)
        assert len(steps) >= 1


class TestReasoningIntegration:
    def test_reasoning_adapter_creates_hypotheses(self):
        load_all_knowledge_packs()
        adapter = KnowledgePackReasoningAdapter()
        hyps = adapter.get_hypotheses_for_tech("Laravel")
        assert len(hyps) >= 5
        for h in hyps:
            assert "hypothesis" in h
            assert "technology" in h
            assert h["technology"] == "Laravel"

    def test_reasoning_adapter_unknown_tech(self):
        load_all_knowledge_packs()
        adapter = KnowledgePackReasoningAdapter()
        hyps = adapter.get_hypotheses_for_tech("UnknownTech123")
        assert hyps == []

    def test_reasoning_adapter_attack_scenarios(self):
        load_all_knowledge_packs()
        adapter = KnowledgePackReasoningAdapter()
        scenarios = adapter.get_attack_scenarios("Laravel")
        assert len(scenarios) >= 1
        for s in scenarios:
            assert "attack_scenario" in s

    def test_reasoning_adapter_multiple_techs(self):
        load_all_knowledge_packs()
        adapter = KnowledgePackReasoningAdapter()
        for tech in ["Laravel", "Django", "Express", "Redis"]:
            hyps = adapter.get_hypotheses_for_tech(tech)
            assert len(hyps) >= 1, f"No hypotheses for {tech}"


class TestContextEnrichment:
    def test_context_enrichment_returns_all_packs(self):
        load_all_knowledge_packs()
        env = enrich_context_with_knowledge_packs(None)
        assert "knowledge_packs" in env
        assert "technology_profiles" in env
        assert "attack_surface_profiles" in env
        assert "fingerprint_signatures" in env
        assert len(env["knowledge_packs"]) >= 5

    def test_context_enrichment_has_fingerprints(self):
        load_all_knowledge_packs()
        env = enrich_context_with_knowledge_packs(None)
        assert len(env["fingerprint_signatures"]) >= 10

    def test_context_enrichment_has_attack_surface(self):
        load_all_knowledge_packs()
        env = enrich_context_with_knowledge_packs(None)
        assert len(env["attack_surface_profiles"]) >= 10


class TestTechIntelIntegration:
    def test_enrich_tech_intel_found(self):
        load_all_knowledge_packs()
        intel = enrich_tech_intel("Laravel")
        assert intel is not None
        assert intel["vendor"] == "Laravel LLC"

    def test_enrich_tech_intel_not_found(self):
        load_all_knowledge_packs()
        intel = enrich_tech_intel("NonexistentTech")
        assert intel is None

    def test_enrich_tech_intel_has_fingerprints(self):
        load_all_knowledge_packs()
        intel = enrich_tech_intel("Laravel")
        assert "fingerprints" in intel
        assert "cookies" in intel["fingerprints"]
        assert "headers" in intel["fingerprints"]

    def test_enrich_tech_intel_has_relationships(self):
        load_all_knowledge_packs()
        intel = enrich_tech_intel("Laravel")
        assert len(intel["relationships"]) >= 5


class TestPromptIntegration:
    def test_prompt_context_enrichment(self):
        load_all_knowledge_packs()
        prompt = get_prompt_context_enrichment()
        assert prompt["knowledge_pack_count"] >= 5
        assert len(prompt["available_knowledge_packs"]) >= 5

    def test_prompt_context_has_component_details(self):
        load_all_knowledge_packs()
        prompt = get_prompt_context_enrichment()
        for pack in prompt["available_knowledge_packs"]:
            assert "components" in pack
            assert "attack_surface_count" in pack
            assert "checklist_count" in pack


# =============================================================================
# 6. Edge Cases
# =============================================================================


class TestEdgeCases:
    def test_empty_registry(self):
        registry = KnowledgePackRegistry()
        assert registry.count() == 0
        assert registry.list_all() == []
        assert registry.get("anything") is None

    def test_empty_graph(self):
        graph = KnowledgeRelationshipGraph()
        assert graph.get_related("nonexistent") == []
        assert graph.get_technology_stack("nonexistent") == ["nonexistent"]

    def test_registry_with_relationships_across_packs(self):
        registry = KnowledgePackRegistry()
        a = KnowledgePack(
            name="pack_a",
            description="Pack A",
            technology=TechnologyProfile(name="Tech A"),
            relationships=[
                KnowledgeRelationship(
                    target_pack_name="pack_b",
                    relationship_type=KnowledgeRelationshipType.DEPENDS_ON,
                ),
            ],
        )
        b = KnowledgePack(
            name="pack_b",
            description="Pack B",
            technology=TechnologyProfile(name="Tech B"),
        )
        registry.register(a)
        registry.register(b)
        # Graph should have both directions
        graph = registry.get_graph()
        related_to_a = graph.get_related("pack_a")
        related_to_b = graph.get_related("pack_b")
        assert len(related_to_a) == 1
        assert len(related_to_b) == 1  # reverse relationship

    def test_pack_with_no_components(self):
        pack = KnowledgePack(
            name="empty",
            description="Empty test pack",
            technology=TechnologyProfile(name="Empty Tech"),
            components=[],
        )
        assert len(pack.components) == 0

    def test_pack_with_no_attack_surface(self):
        pack = KnowledgePack(
            name="nope",
            description="No attack surface",
            technology=TechnologyProfile(name="Nope"),
        )
        assert pack.attack_surface.endpoints == []

    def test_multiple_packs_same_category(self):
        registry = KnowledgePackRegistry()
        for i in range(5):
            pack = KnowledgePack(
                name=f"api_pack_{i}",
                description=f"API pack {i}",
                category=KnowledgePackCategory.API,
                technology=TechnologyProfile(name=f"API {i}"),
            )
            registry.register(pack)
        assert len(registry.get_by_category(KnowledgePackCategory.API)) == 5

    def test_rich_technology_stack(self):
        load_all_knowledge_packs()
        # Laravel depends on PHP, MySQL, Redis
        stack = list_all_knowledge_packs()[0].relationships
        assert len(stack) >= 1

    def test_pack_to_tech_knowledge_entry(self):
        pack = KnowledgePack(
            name="TestTech",
            description="Tech for conversion test",
            technology=TechnologyProfile(
                name="TestTech",
                common_aliases=["tt"],
            ),
            attack_surface=AttackSurfaceProfile(
                attack_surface_areas=["Area 1"],
            ),
        )
        entry = pack.to_technology_knowledge_entry()
        assert entry.technology_name == "TestTech"
        assert entry.aliases == ["tt"]

    def test_pack_to_planning_enrichment(self):
        pack = KnowledgePack(
            name="EnrichPack",
            description="Enrichment test pack",
            technology=TechnologyProfile(name="Enrichment"),
            category=KnowledgePackCategory.CLOUD,
            attack_surface=AttackSurfaceProfile(
                authentication=["OAuth"],
                attack_surface_areas=["Metadata SSRF"],
            ),
        )
        enriched = pack.to_planning_context_enrichment()
        assert enriched["pack_name"] == "EnrichPack"
        assert enriched["pack_category"] == "cloud"
        assert "Metadata SSRF" in enriched["attack_surface_areas"]


# =============================================================================
# 7. Cross-subsystem Data Flow
# =============================================================================


class TestCrossSubsystemFlow:
    def test_tech_intel_to_planning_flow(self):
        """Knowledge Pack feeds tech_intel which feeds planning."""
        load_all_knowledge_packs()
        intel = enrich_tech_intel("Laravel")
        assert intel is not None
        assert intel["vendor"] == "Laravel LLC"
        # Planning rule uses the same pack
        from deephunter.planning.models import PlannerContext
        rule = KnowledgePackRule()
        context = PlannerContext(
            target_url="https://example.com",
            technologies=["Laravel"],
        )
        steps = rule.evaluate(context)
        assert len(steps) >= 1

    def test_context_enrichment_to_reasoning_flow(self):
        """Context enrichment data informs reasoning hypotheses."""
        load_all_knowledge_packs()
        ctx = enrich_context_with_knowledge_packs(None)
        adapter = KnowledgePackReasoningAdapter()
        all_hyps = 0
        for tech in ["Laravel", "Django", "Redis", "Kubernetes"]:
            if tech.lower() in ctx["knowledge_packs"]:
                hyps = adapter.get_hypotheses_for_tech(tech)
                all_hyps += len(hyps)
            else:
                # Try fuzzy match
                for kp_name in ctx["knowledge_packs"]:
                    if tech.lower() in kp_name:
                        hyps = adapter.get_hypotheses_for_tech(tech)
                        all_hyps += len(hyps)
                        break
        assert all_hyps >= 10

    def test_prompt_to_planning_flow(self):
        """Prompt context correctly reports pack counts."""
        load_all_knowledge_packs()
        prompt = get_prompt_context_enrichment()
        planning_packs = list_all_knowledge_packs()
        assert prompt["knowledge_pack_count"] == len(planning_packs)

    def test_relationship_graph_connects_ecosystem(self):
        load_all_knowledge_packs()
        # Count intra-ecosystem relationships (those referencing names that exist)
        resolved = 0
        unresolved = 0
        for pack in list_all_knowledge_packs():
            for rel in pack.relationships:
                target = get_kp(rel.target_pack_name)
                if target is not None:
                    resolved += 1
                else:
                    unresolved += 1
        # Most relationships should resolve within the ecosystem
        assert resolved >= 10, f"Only {resolved} of {resolved + unresolved} relationships resolved"

    def test_all_relationship_types_used(self):
        load_all_knowledge_packs()
        used_types = set()
        for pack in list_all_knowledge_packs():
            for rel in pack.relationships:
                used_types.add(rel.relationship_type)
        # Verify a diverse set of relationship types
        assert KnowledgeRelationshipType.DEPENDS_ON in used_types, \
            "DEPENDS_ON relationship type not used"
        assert KnowledgeRelationshipType.INTEGRATES_WITH in used_types, \
            "INTEGRATES_WITH not used"
        assert KnowledgeRelationshipType.RUNS_ON in used_types, \
            "RUNS_ON not used"

    def test_knowledge_pack_rule_executes_without_error(self):
        load_all_knowledge_packs()
        rule = KnowledgePackRule()
        from deephunter.planning.models import PlannerContext
        context = PlannerContext(
            target_url="https://test.com",
            technologies=["PHP"],
            frameworks=["laravel"],
        )
        steps = rule.evaluate(context)
        assert isinstance(steps, list)
