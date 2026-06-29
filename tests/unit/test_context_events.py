"""Tests for context event bus."""

from __future__ import annotations

from deephunter.context.events import (
    ContextBudgetExceededEvent,
    ContextCreatedEvent,
    ContextDeduplicatedEvent,
    ContextEvent,
    ContextEventBus,
    ContextMergeEvent,
    ContextTrimmedEvent,
    ContextUpdatedEvent,
)


class TestContextEvents:
    def test_event_defaults(self) -> None:
        event = ContextEvent()
        assert event.investigation_id == ""
        assert event.plan_id == ""
        assert event.context_id == ""

    def test_context_created_event(self) -> None:
        event = ContextCreatedEvent(
            investigation_id="inv-1",
            context_id="ctx-1",
            source_count=3,
            section_count=5,
        )
        assert event.investigation_id == "inv-1"
        assert event.context_id == "ctx-1"
        assert event.source_count == 3
        assert event.section_count == 5

    def test_context_updated_event(self) -> None:
        event = ContextUpdatedEvent(context_id="ctx-1", section_count=2, block_count=10)
        assert event.context_id == "ctx-1"
        assert event.section_count == 2
        assert event.block_count == 10

    def test_context_trimmed_event(self) -> None:
        event = ContextTrimmedEvent(
            context_id="ctx-1",
            original_tokens=1000,
            trimmed_tokens=500,
            blocks_removed=3,
        )
        assert event.original_tokens == 1000
        assert event.trimmed_tokens == 500
        assert event.blocks_removed == 3

    def test_context_merge_event(self) -> None:
        event = ContextMergeEvent(
            context_id="ctx-1",
            merged_sources=2,
            total_blocks=15,
        )
        assert event.merged_sources == 2
        assert event.total_blocks == 15

    def test_context_deduplicated_event(self) -> None:
        event = ContextDeduplicatedEvent(
            context_id="ctx-1",
            original_count=10,
            deduped_count=2,
        )
        assert event.original_count == 10
        assert event.deduped_count == 2

    def test_context_budget_exceeded_event(self) -> None:
        event = ContextBudgetExceededEvent(
            context_id="ctx-1",
            total_tokens=9000,
            max_tokens=8192,
            action_taken="trimmed",
        )
        assert event.total_tokens == 9000
        assert event.max_tokens == 8192
        assert event.action_taken == "trimmed"


class TestContextEventBus:
    def test_subscribe_and_emit(self) -> None:
        bus = ContextEventBus()
        received: list[ContextCreatedEvent] = []

        bus.subscribe(ContextCreatedEvent, lambda e: received.append(e))
        event = ContextCreatedEvent(context_id="ctx-1", source_count=2)
        bus.emit(event)

        assert len(received) == 1
        assert received[0].context_id == "ctx-1"

    def test_subscribe_multiple_handlers(self) -> None:
        bus = ContextEventBus()
        results: list[int] = []

        bus.subscribe(ContextCreatedEvent, lambda e: results.append(1))
        bus.subscribe(ContextCreatedEvent, lambda e: results.append(2))
        bus.emit(ContextCreatedEvent())

        assert results == [1, 2]

    def test_unsubscribe(self) -> None:
        bus = ContextEventBus()
        results: list[int] = []

        def handler(e: ContextCreatedEvent) -> None:
            results.append(1)

        bus.subscribe(ContextCreatedEvent, handler)
        bus.emit(ContextCreatedEvent())
        assert len(results) == 1

        bus.unsubscribe(ContextCreatedEvent, handler)
        bus.emit(ContextCreatedEvent())
        assert len(results) == 1  # no change

    def test_no_handler_for_event_type(self) -> None:
        bus = ContextEventBus()
        # Should not raise
        bus.emit(ContextTrimmedEvent(context_id="ctx-1"))

    def test_clear(self) -> None:
        bus = ContextEventBus()
        results: list[int] = []

        bus.subscribe(ContextCreatedEvent, lambda e: results.append(1))
        bus.clear()
        bus.emit(ContextCreatedEvent())

        assert len(results) == 0

    def test_handler_exception_does_not_crash(self) -> None:
        bus = ContextEventBus()

        def broken(_: ContextEvent) -> None:
            raise RuntimeError("boom")

        results: list[ContextEvent] = []

        bus.subscribe(ContextCreatedEvent, broken)
        bus.subscribe(ContextCreatedEvent, lambda e: results.append(e))
        bus.emit(ContextCreatedEvent(context_id="ctx-1"))

        assert len(results) == 1
