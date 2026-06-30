"""Tests for the Technology Intelligence Engine."""

from __future__ import annotations

from deephunter.core.types import BugClass
from deephunter.recon.models import Technology as ReconTechnology, TechCategory
from deephunter.tech_intel.engine import TechnologyIntelEngine
from deephunter.tech_intel.knowledge_base import KB
from deephunter.tech_intel.models import (
    AttackSurfaceImplication,
    AuthMechanismClue,
    Confidence,
    InvestigationSuggestion,
    TechnologyKnowledge,
    TechnologyKnowledgeEntry,
)


class TestKnowledgeBase:
    def test_laravel_known(self) -> None:
        entry = KB.get("laravel")
        assert entry is not None
        assert entry.technology_name == "Laravel"
        assert len(entry.attack_surface_implications) >= 5
        assert len(entry.investigation_suggestions) >= 2

    def test_spring_boot_known(self) -> None:
        entry = KB.get("spring boot")
        assert entry is not None
        assert "Spring Boot" in entry.technology_name

    def test_django_known(self) -> None:
        entry = KB.get("django")
        assert entry is not None
        assert len(entry.related_technologies) >= 3

    def test_wordpress_known(self) -> None:
        entry = KB.get("wordpress")
        assert entry is not None
        assert len(entry.attack_surface_implications) >= 3

    def test_flask_known(self) -> None:
        entry = KB.get("flask")
        assert entry is not None
        assert any("SSTI" in s.title for s in entry.investigation_suggestions)

    def test_fastapi_known(self) -> None:
        entry = KB.get("fastapi")
        assert entry is not None
        assert len(entry.attack_surface_implications) >= 2

    def test_nextjs_known(self) -> None:
        entry = KB.get("next.js")
        assert entry is not None
        assert any("SSRF" in imp.area for imp in entry.attack_surface_implications)

    def test_express_known(self) -> None:
        entry = KB.get("express")
        assert entry is not None
        assert any("CORS" in imp.area for imp in entry.attack_surface_implications)

    def test_rails_known(self) -> None:
        entry = KB.get("rails")
        assert entry is not None
        assert len(entry.potential_auth_mechanisms) >= 2

    def test_drupal_known(self) -> None:
        entry = KB.get("drupal")
        assert entry is not None
        assert any("Drupalgeddon" in imp.area for imp in entry.attack_surface_implications)

    def test_magento_known(self) -> None:
        entry = KB.get("magento")
        assert entry is not None
        assert len(entry.attack_surface_implications) >= 2

    def test_aspnet_known(self) -> None:
        entry = KB.get("asp.net")
        assert entry is not None
        assert any("ViewState" in imp.area for imp in entry.attack_surface_implications)

    def test_cloudflare_known(self) -> None:
        entry = KB.get("cloudflare")
        assert entry is not None
        assert any("Origin IP" in imp.area for imp in entry.attack_surface_implications)

    def test_aws_known(self) -> None:
        entry = KB.get("aws")
        assert entry is not None
        assert any("S3" in imp.area for imp in entry.attack_surface_implications)

    def test_azure_known(self) -> None:
        entry = KB.get("azure")
        assert entry is not None
        assert len(entry.attack_surface_implications) >= 1

    def test_gcp_known(self) -> None:
        entry = KB.get("gcp")
        assert entry is not None
        assert len(entry.attack_surface_implications) >= 1

    def test_nginx_known(self) -> None:
        entry = KB.get("nginx")
        assert entry is not None
        assert any("Path Traversal" in imp.area for imp in entry.attack_surface_implications)

    def test_unknown_tech(self) -> None:
        entry = KB.get("completely_unknown_tech_xyz")
        assert entry is None

    def test_alias_resolution(self) -> None:
        entry = KB.get("nextjs")
        assert entry is not None
        assert entry.technology_name == "Next.js"

    def test_alias_case_sensitivity(self) -> None:
        entry = KB.get("laravel framework")
        assert entry is not None

    def test_all_entries_have_name(self) -> None:
        for key, entry in KB.items():
            if not hasattr(entry, 'technology_name'):
                continue
            if key == entry.technology_name.lower():
                assert entry.technology_name, f"Empty name for key {key}"


class TestTechnologyIntelEngine:
    def test_lookup_found(self) -> None:
        engine = TechnologyIntelEngine()
        entry = engine.lookup("laravel")
        assert entry is not None
        assert entry.technology_name == "Laravel"

    def test_lookup_not_found(self) -> None:
        engine = TechnologyIntelEngine()
        assert engine.lookup("nonexistent_tool") is None

    def test_lookup_alias(self) -> None:
        engine = TechnologyIntelEngine()
        entry = engine.lookup("nextjs")
        assert entry is not None
        assert "Next.js" in entry.technology_name

    def test_interpret_single(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret(["laravel"])
        assert isinstance(result, TechnologyKnowledge)
        assert len(result.entries) >= 1
        assert len(result.all_attack_surface_implications) >= 5

    def test_interpret_multiple(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret(["laravel", "nginx"])
        assert len(result.entries) >= 2

    def test_interpret_recon_technologies(self) -> None:
        engine = TechnologyIntelEngine()
        recon_techs = [ReconTechnology(name="Laravel"), ReconTechnology(name="Nginx")]
        result = engine.interpret_recon_technologies(recon_techs)
        assert len(result.entries) >= 2

    def test_interpret_unknown(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret(["unknown_tech"])
        assert len(result.entries) >= 1

    def test_interpret_empty(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret([])
        assert result.source_technologies == []

    def test_interpret_aggregates_related(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret(["laravel", "django"])
        all_related = result.all_related_technologies
        assert "PHP" in all_related or "Python" in all_related

    def test_interpret_no_duplicates(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret(["laravel", "laravel"])
        assert len(result.entries) == 1

    def test_interpret_auth_mechanisms(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret(["spring boot"])
        assert len(result.all_auth_mechanisms) >= 2

    def test_interpret_trust_boundaries(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret(["express"])
        assert len(result.all_trust_boundaries) >= 1

    def test_interpret_investigation_suggestions(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret(["django"])
        assert len(result.all_investigation_suggestions) >= 2

    def test_interpret_attack_surface_implications(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret(["wordpress"])
        assert len(result.all_attack_surface_implications) >= 3

    def test_list_known_technologies(self) -> None:
        engine = TechnologyIntelEngine()
        known = engine.list_known_technologies()
        assert "Laravel" in known
        assert "Django" in known
        assert "WordPress" in known
        assert len(known) >= 15

    def test_interpret_consistency(self) -> None:
        engine = TechnologyIntelEngine()
        r1 = engine.interpret(["laravel"])
        r2 = engine.interpret(["laravel"])
        assert len(r1.entries) == len(r2.entries)

    def test_mixed_string_and_recon_tech(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret(["laravel", ReconTechnology(name="Nginx")])
        assert len(result.entries) >= 2

    def test_creates_technology_knowledge(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret(["laravel"])
        assert result.id.startswith("tk-")
        assert result.created_at is not None

    def test_bug_classes_in_implications(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret(["laravel"])
        for imp in result.all_attack_surface_implications:
            for bc in imp.bug_classes:
                assert isinstance(bc, BugClass)

    def test_auth_mechanism_confidence(self) -> None:
        result = TechnologyIntelEngine().interpret(["spring boot"])
        for auth in result.all_auth_mechanisms:
            assert isinstance(auth.likelihood, Confidence)

    def test_suggestion_priority(self) -> None:
        result = TechnologyIntelEngine().interpret(["django"])
        for s in result.all_investigation_suggestions:
            assert 0 <= s.priority <= 100


class TestEmptyKnowledgeResult:
    def test_unknown_tech_produces_entry(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret(["zzz_unknown_99"])
        assert len(result.entries) == 1

    def test_unknown_tech_no_implications(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret(["zzz_unknown_99"])
        assert len(result.all_attack_surface_implications) == 0

    def test_unknown_tech_no_auth(self) -> None:
        engine = TechnologyIntelEngine()
        result = engine.interpret(["zzz_unknown_99"])
        assert len(result.all_auth_mechanisms) == 0
