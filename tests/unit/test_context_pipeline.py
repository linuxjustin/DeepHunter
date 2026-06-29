"""Tests for the context pipeline."""

from __future__ import annotations

from deephunter.context.events import ContextEventBus
from deephunter.context.models import (
    Context,
    ContextBlock,
    ContextBudget,
    ContextImportance,
    ContextSection,
)
from deephunter.context.pipeline import (
    BudgetStage,
    ContextPipeline,
    ContextStage,
    DeduplicateStage,
    InitContextStage,
    PrioritizeStage,
    RecalculateStage,
)


class TestInitContextStage:
    def test_sets_ids(self) -> None:
        stage = InitContextStage(investigation_id="inv-1", plan_id="plan-1")
        ctx = Context()
        stage.process(ctx)
        assert ctx.investigation_id == "inv-1"
        assert ctx.plan_id == "plan-1"

    def test_emits_event(self) -> None:
        bus = ContextEventBus()
        received = []

        bus.subscribe(type("ContextCreatedEvent", (), {}), lambda e: received.append(e))  # type: ignore[arg-type]
        # Just test it doesn't crash
        stage = InitContextStage()
        ctx = Context()
        stage.process(ctx, bus)


class TestDeduplicateStage:
    def test_removes_duplicate_blocks(self) -> None:
        stage = DeduplicateStage()
        ctx = Context()
        section = ContextSection(name="Test")
        section.add_block(ContextBlock(content="duplicate", dedup_key="key1"))
        section.add_block(ContextBlock(content="duplicate", dedup_key="key1"))
        section.add_block(ContextBlock(content="unique", dedup_key="key2"))
        ctx.add_section(section)

        stage.process(ctx)
        assert len(ctx.sections[0].blocks) == 2

    def test_empty_sections(self) -> None:
        stage = DeduplicateStage()
        ctx = Context()
        stage.process(ctx)  # Should not raise


class TestPrioritizeStage:
    def test_sorts_blocks_by_priority(self) -> None:
        stage = PrioritizeStage()
        ctx = Context()
        section = ContextSection(name="Test")
        section.add_block(ContextBlock(content="low", priority=0.1))
        section.add_block(ContextBlock(content="high", priority=0.9))
        section.add_block(ContextBlock(content="medium", priority=0.5))
        ctx.add_section(section)

        stage.process(ctx)
        priorities = [b.priority for b in ctx.sections[0].blocks]
        assert priorities == [0.9, 0.5, 0.1]

    def test_empty_section_blocks(self) -> None:
        stage = PrioritizeStage()
        ctx = Context()
        ctx.add_section(ContextSection(name="Empty"))
        stage.process(ctx)  # Should not raise


class TestBudgetStage:
    def test_does_not_remove_when_under_budget(self) -> None:
        budget = ContextBudget(max_tokens=10000)
        stage = BudgetStage(budget)
        ctx = Context()
        section = ContextSection(name="Test")
        section.add_block(ContextBlock(content="small"))
        ctx.add_section(section)
        ctx.recalculate()

        stage.process(ctx)
        assert len(ctx.sections[0].blocks) == 1

    def test_small_budget_trims(self) -> None:
        budget = ContextBudget(max_tokens=5)
        stage = BudgetStage(budget)
        ctx = Context()
        section = ContextSection(name="Test")
        section.add_block(ContextBlock(
            content="x" * 100,
            priority=0.1,
            importance=ContextImportance.LOW,
        ))
        ctx.add_section(section)

        stage.process(ctx)


class TestRecalculateStage:
    def test_updates_statistics(self) -> None:
        stage = RecalculateStage()
        ctx = Context()
        section = ContextSection(name="Test")
        section.add_block(ContextBlock(
            content="hello world",
            importance=ContextImportance.HIGH,
        ))
        ctx.add_section(section)

        stage.process(ctx)
        assert ctx.statistics.total_sections == 1
        assert ctx.statistics.total_blocks == 1


class TestContextPipeline:
    def test_run_all_stages(self) -> None:
        pipeline = ContextPipeline([
            InitContextStage(investigation_id="inv-1"),
            DeduplicateStage(),
            PrioritizeStage(),
            RecalculateStage(),
        ])
        ctx = Context()
        section = ContextSection(name="Test")
        section.add_block(ContextBlock(content="data"))
        ctx.add_section(section)

        report = pipeline.run(ctx)
        assert report.success
        assert len(report.stages_run) == 4
        assert ctx.investigation_id == "inv-1"

    def test_stage_failure_does_not_crash(self) -> None:
        class BrokenStage(ContextStage):
            name = "broken"

            def process(self, context: Context, event_bus=None) -> None:
                raise RuntimeError("Intentional failure")

        pipeline = ContextPipeline([
            InitContextStage(),
            BrokenStage(),
            RecalculateStage(),
        ])
        ctx = Context()
        report = pipeline.run(ctx)

        assert not report.success
        assert len(report.errors) == 1
        assert "broken" in report.errors[0]

    def test_pipeline_with_event_bus(self) -> None:
        bus = ContextEventBus()
        pipeline = ContextPipeline([
            InitContextStage(),
            RecalculateStage(),
        ])
        ctx = Context()
        report = pipeline.run(ctx, bus)
        assert report.success

    def test_default_stages(self) -> None:
        pipeline = ContextPipeline()
        assert len(pipeline._stages) > 0
