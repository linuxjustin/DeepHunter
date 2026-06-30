"""Tests for intelligence data models."""

from __future__ import annotations

from deephunter.core.types import BugClass
from deephunter.intel.models import HintCategory, HintPriority, InvestigationHint
from deephunter.tech_intel.models import (
    AttackSurfaceImplication,
    AuthMechanismClue,
    Confidence,
    InvestigationSuggestion,
    TechnologyKnowledge,
    TechnologyKnowledgeEntry,
)


class TestTechnologyKnowledgeEntry:
    def test_minimal(self) -> None:
        e = TechnologyKnowledgeEntry(technology_name="Test")
        assert e.technology_name == "Test"
        assert e.aliases == []
        assert e.tags == []
        assert e.related_technologies == []

    def test_with_implications(self) -> None:
        e = TechnologyKnowledgeEntry(
            technology_name="Laravel",
            attack_surface_implications=[
                AttackSurfaceImplication(area="Debug", description="Debug mode", confidence=Confidence.HIGH),
            ],
        )
        assert len(e.attack_surface_implications) == 1

    def test_with_auth_clues(self) -> None:
        e = TechnologyKnowledgeEntry(
            technology_name="Spring",
            potential_auth_mechanisms=[
                AuthMechanismClue(mechanism="jwt", description="JWT tokens", likelihood=Confidence.HIGH),
            ],
        )
        assert len(e.potential_auth_mechanisms) == 1

    def test_with_suggestions(self) -> None:
        e = TechnologyKnowledgeEntry(
            technology_name="Django",
            investigation_suggestions=[
                InvestigationSuggestion(title="Check admin", description="Check /admin/"),
            ],
        )
        assert len(e.investigation_suggestions) == 1

    def test_serialization(self) -> None:
        e = TechnologyKnowledgeEntry(technology_name="T", tags=["a", "b"])
        d = e.model_dump()
        assert d["technology_name"] == "T"


class TestTechnologyKnowledge:
    def test_minimal(self) -> None:
        k = TechnologyKnowledge(source_technologies=["laravel"])
        assert k.id.startswith("tk-")
        assert k.source_technologies == ["laravel"]

    def test_aggregation(self) -> None:
        k = TechnologyKnowledge(
            source_technologies=["a", "b"],
            entries=[TechnologyKnowledgeEntry(technology_name="A"), TechnologyKnowledgeEntry(technology_name="B")],
            all_related_technologies=["PHP", "MySQL"],
            all_auth_mechanisms=[AuthMechanismClue(mechanism="jwt", description="JWT")],
            all_attack_surface_implications=[AttackSurfaceImplication(area="X", description="Y")],
        )
        assert len(k.entries) == 2
        assert len(k.all_related_technologies) == 2

    def test_serialization(self) -> None:
        k = TechnologyKnowledge(source_technologies=["test"])
        d = k.model_dump(mode="json")
        assert d["id"].startswith("tk-")


class TestAttackSurfaceImplication:
    def test_minimal(self) -> None:
        imp = AttackSurfaceImplication(area="Debug", description="Debug is on")
        assert imp.area == "Debug"
        assert imp.bug_classes == []
        assert imp.confidence == Confidence.MEDIUM

    def test_with_bug_classes(self) -> None:
        imp = AttackSurfaceImplication(
            area="XSS",
            description="XSS via input",
            bug_classes=[BugClass.XSS, BugClass.SQL_INJECTION],
            confidence=Confidence.HIGH,
        )
        assert BugClass.XSS in imp.bug_classes
        assert len(imp.bug_classes) == 2

    def test_serialization(self) -> None:
        imp = AttackSurfaceImplication(area="Test", description="Desc")
        d = imp.model_dump()
        assert d["area"] == "Test"


class TestAuthMechanismClue:
    def test_minimal(self) -> None:
        clue = AuthMechanismClue(mechanism="jwt", description="JWT auth")
        assert clue.mechanism == "jwt"
        assert clue.likelihood == Confidence.MEDIUM

    def test_serialization(self) -> None:
        clue = AuthMechanismClue(mechanism="oauth", description="OAuth", likelihood=Confidence.HIGH)
        d = clue.model_dump()
        assert d["likelihood"] == "high"

    def test_equality(self) -> None:
        c1 = AuthMechanismClue(mechanism="jwt", description="desc")
        c2 = AuthMechanismClue(mechanism="jwt", description="desc")
        assert c1 == c2


class TestInvestigationSuggestion:
    def test_minimal(self) -> None:
        s = InvestigationSuggestion(title="Check", description="Check something")
        assert s.title == "Check"
        assert s.priority == 50
        assert s.references == []

    def test_custom_priority(self) -> None:
        s = InvestigationSuggestion(title="Critical", description="Do this first", priority=90)
        assert s.priority == 90

    def test_with_references(self) -> None:
        s = InvestigationSuggestion(title="T", description="D", references=["https://example.com"])
        assert len(s.references) == 1

    def test_serialization(self) -> None:
        s = InvestigationSuggestion(title="T", description="D")
        d = s.model_dump()
        assert d["title"] == "T"


class TestInvestigationHint:
    def test_minimal(self) -> None:
        h = InvestigationHint(title="Test", description="Test hint")
        assert h.id.startswith("hint-")
        assert h.category == HintCategory.GENERAL
        assert h.priority == HintPriority.MEDIUM

    def test_full_hint(self) -> None:
        h = InvestigationHint(
            title="Check Debug",
            description="Verify debug is off",
            category=HintCategory.CONFIGURATION,
            priority=HintPriority.HIGH,
            source_technology="Laravel",
            rationale="Laravel debug mode exposes sensitive data",
            investigation_steps=["Check .env", "Verify APP_DEBUG"],
            references=["https://laravel.com"],
            tags=["debug", "laravel"],
        )
        assert h.title == "Check Debug"
        assert len(h.investigation_steps) == 2

    def test_serialization(self) -> None:
        h = InvestigationHint(title="T", description="D")
        d = h.model_dump(mode="json")
        assert d["title"] == "T"

    def test_enum_values(self) -> None:
        assert HintPriority.HIGH.value == "high"
        assert HintPriority.CRITICAL.value == "critical"
        assert HintCategory.AUTHENTICATION.value == "authentication"


class TestConfidence:
    def test_values(self) -> None:
        assert Confidence.HIGH.value == "high"
        assert Confidence.MEDIUM.value == "medium"
        assert Confidence.LOW.value == "low"
        assert Confidence.UNKNOWN.value == "unknown"
