"""Integration tests for the Context Engine."""

from __future__ import annotations

from deephunter.context.engine import ContextEngine
from deephunter.context.events import (
    ContextCreatedEvent,
    ContextDeduplicatedEvent,
    ContextEventBus,
)
from deephunter.context.models import (
    Context,
    ContextBlock,
    ContextImportance,
    ContextSection,
    ContextSourceType,
)


class TestContextEngine:
    def test_build_empty(self) -> None:
        engine = ContextEngine()
        ctx = engine.build()
        assert ctx.id.startswith("ctx-")
        assert ctx.sections == []

    def test_build_with_investigation_id(self) -> None:
        engine = ContextEngine()
        ctx = engine.build(investigation_id="inv-test")
        assert ctx.investigation_id == "inv-test"

    def test_build_with_plan_id(self) -> None:
        engine = ContextEngine()
        ctx = engine.build(plan_id="plan-test")
        assert ctx.plan_id == "plan-test"

    def test_build_with_query(self) -> None:
        engine = ContextEngine()
        ctx = engine.build(query="Test query")
        assert ctx.get_section("User Query") is not None
        section = ctx.get_section("User Query")
        assert section is not None
        assert section.blocks[0].content == "Test query"

    def test_build_with_constraints(self) -> None:
        engine = ContextEngine()
        ctx = engine.build(constraints=["Constraint 1", "Constraint 2"])
        assert ctx.get_section("User Constraints") is not None
        section = ctx.get_section("User Constraints")
        assert section is not None
        assert len(section.blocks) == 2

    def test_build_with_query_and_constraints(self) -> None:
        engine = ContextEngine()
        ctx = engine.build(
            query="Find SQL injections",
            constraints=["No auth bypass", "API only"],
        )
        assert ctx.get_section("User Query") is not None
        assert ctx.get_section("User Constraints") is not None

    def test_event_emission(self) -> None:
        bus = ContextEventBus()
        events: list[ContextCreatedEvent] = []

        bus.subscribe(ContextCreatedEvent, lambda e: events.append(e))
        engine = ContextEngine(event_bus=bus)
        engine.build(investigation_id="inv-1")

        assert len(events) >= 1

    def test_save_and_load_context(self, tmp_path) -> None:
        engine = ContextEngine()
        ctx = engine.build(investigation_id="inv-save", query="Save test")
        path = tmp_path / "context.json"

        saved = engine.save_context(ctx, str(path))
        assert saved.exists()

        loaded = engine.load_context(str(path))
        assert loaded.investigation_id == "inv-save"
        assert loaded.get_section("User Query") is not None

    def test_save_creates_directory(self, tmp_path) -> None:
        engine = ContextEngine()
        ctx = engine.build()
        path = tmp_path / "subdir" / "nested" / "context.json"
        saved = engine.save_context(ctx, str(path))
        assert saved.exists()

    def test_recalculate_after_build(self) -> None:
        engine = ContextEngine()
        ctx = engine.build(query="Test")
        assert ctx.statistics.total_sections > 0
        assert ctx.statistics.total_blocks > 0


class TestContextEngineDeduplication:
    def test_deduplicate_duplicate_content(self) -> None:
        engine = ContextEngine()
        ctx = Context()
        section = ContextSection(name="Dup Test")
        section.add_block(ContextBlock(content="same content", dedup_key="a"))
        section.add_block(ContextBlock(content="same content", dedup_key="a"))
        section.add_block(ContextBlock(content="different", dedup_key="b"))
        ctx.add_section(section)

        # Run through engine's pipeline
        pipeline = engine._build_pipeline()
        pipeline.run(ctx)

        assert len(ctx.sections[0].blocks) == 2
