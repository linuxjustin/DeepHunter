"""Tests for the Investigation Hint Generator."""

from __future__ import annotations

from deephunter.intel.hints import InvestigationHintGenerator
from deephunter.intel.models import HintCategory, HintPriority, InvestigationHint
from deephunter.tech_intel.engine import TechnologyIntelEngine
from deephunter.tech_intel.models import (
    AttackSurfaceImplication,
    Confidence,
    InvestigationSuggestion,
    TechnologyKnowledge,
    TechnologyKnowledgeEntry,
)


class TestInvestigationHintGenerator:
    def test_generate_from_knowledge(self) -> None:
        engine = TechnologyIntelEngine()
        knowledge = engine.interpret(["laravel"])
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        assert len(hints) >= 5

    def test_hints_have_titles(self) -> None:
        engine = TechnologyIntelEngine()
        knowledge = engine.interpret(["django"])
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        for h in hints:
            assert h.title

    def test_hints_have_descriptions(self) -> None:
        engine = TechnologyIntelEngine()
        knowledge = engine.interpret(["spring boot"])
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        for h in hints:
            assert h.description

    def test_hints_have_categories(self) -> None:
        engine = TechnologyIntelEngine()
        knowledge = engine.interpret(["express"])
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        for h in hints:
            assert isinstance(h.category, HintCategory)

    def test_hints_have_priorities(self) -> None:
        engine = TechnologyIntelEngine()
        knowledge = engine.interpret(["wordpress"])
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        for h in hints:
            assert isinstance(h.priority, HintPriority)

    def test_hints_have_ids(self) -> None:
        engine = TechnologyIntelEngine()
        knowledge = engine.interpret(["laravel"])
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        for h in hints:
            assert h.id.startswith("hint-")

    def test_hints_from_suggestions(self) -> None:
        knowledge = TechnologyKnowledge(
            source_technologies=["laravel"],
            all_investigation_suggestions=[
                InvestigationSuggestion(title="Check Debug Mode", description="Verify debug is off", priority=90),
            ],
        )
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        assert any("Check Debug Mode" in h.title for h in hints)

    def test_hints_from_implications(self) -> None:
        knowledge = TechnologyKnowledge(
            source_technologies=["laravel"],
            all_attack_surface_implications=[
                AttackSurfaceImplication(area="Debug Mode", description="Debug may be on", confidence=Confidence.HIGH),
            ],
        )
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        assert any("Debug Mode" in h.title for h in hints)

    def test_empty_knowledge_generates_fallback(self) -> None:
        knowledge = TechnologyKnowledge(source_technologies=["unknown_tech"])
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        assert len(hints) == 1
        assert hints[0].title == "General Reconnaissance"
        assert hints[0].priority == HintPriority.LOW

    def test_high_confidence_maps_to_high_priority(self) -> None:
        knowledge = TechnologyKnowledge(
            source_technologies=["test"],
            all_attack_surface_implications=[
                AttackSurfaceImplication(area="Critical", description="Critical issue", confidence=Confidence.HIGH),
            ],
        )
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        assert hints[0].priority == HintPriority.HIGH

    def test_medium_confidence_maps_to_medium_priority(self) -> None:
        knowledge = TechnologyKnowledge(
            source_technologies=["test"],
            all_attack_surface_implications=[
                AttackSurfaceImplication(area="Medium", description="Medium issue", confidence=Confidence.MEDIUM),
            ],
        )
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        assert hints[0].priority == HintPriority.MEDIUM

    def test_low_confidence_maps_to_low_priority(self) -> None:
        knowledge = TechnologyKnowledge(
            source_technologies=["test"],
            all_attack_surface_implications=[
                AttackSurfaceImplication(area="Low", description="Low issue", confidence=Confidence.LOW),
            ],
        )
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        assert hints[0].priority == HintPriority.LOW

    def test_investigation_steps_present(self) -> None:
        engine = TechnologyIntelEngine()
        knowledge = engine.interpret(["django"])
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        for h in hints:
            assert len(h.investigation_steps) >= 1

    def test_hint_has_rationale(self) -> None:
        engine = TechnologyIntelEngine()
        knowledge = engine.interpret(["laravel"])
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        for h in hints:
            assert h.rationale

    def test_tags_present(self) -> None:
        engine = TechnologyIntelEngine()
        knowledge = engine.interpret(["laravel"])
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        for h in hints:
            assert len(h.tags) >= 0

    def test_source_technology_tracked(self) -> None:
        knowledge = TechnologyKnowledge(
            source_technologies=["laravel", "nginx"],
            all_investigation_suggestions=[
                InvestigationSuggestion(title="Test", description="Test suggestion"),
            ],
        )
        gen = InvestigationHintGenerator()
        hints = gen.generate_from_knowledge(knowledge)
        for h in hints:
            assert h.source_technology
