"""Tests for the event bus and event types."""

from __future__ import annotations

from pathlib import Path

from deephunter.ingestion.events import (
    DocumentDiscoveredEvent,
    EventBus,
    IngestionEvent,
    ParseCompletedEvent,
    SKOCreatedEvent,
)


class TestEventBus:
    def test_subscribe_and_emit(self) -> None:
        bus = EventBus()
        received: list[IngestionEvent] = []

        bus.subscribe(DocumentDiscoveredEvent, lambda e: received.append(e))
        bus.emit(DocumentDiscoveredEvent(path=Path("/test.md")))

        assert len(received) == 1
        assert received[0].path == Path("/test.md")

    def test_multiple_handlers(self) -> None:
        bus = EventBus()
        results: list[int] = []

        bus.subscribe(DocumentDiscoveredEvent, lambda _: results.append(1))
        bus.subscribe(DocumentDiscoveredEvent, lambda _: results.append(2))

        bus.emit(DocumentDiscoveredEvent(path=Path("/a.md")))
        assert results == [1, 2]

    def test_unsubscribe(self) -> None:
        bus = EventBus()
        results: list[int] = []

        def handler(_: IngestionEvent) -> None:
            results.append(1)

        bus.subscribe(DocumentDiscoveredEvent, handler)
        bus.emit(DocumentDiscoveredEvent(path=Path("/a.md")))
        assert len(results) == 1

        bus.unsubscribe(DocumentDiscoveredEvent, handler)
        bus.emit(DocumentDiscoveredEvent(path=Path("/b.md")))
        assert len(results) == 1  # no change

    def test_no_handlers_no_error(self) -> None:
        bus = EventBus()
        bus.emit(ParseCompletedEvent(path=Path("/a.md"), content_length=10, sections_count=1))

    def test_handler_exception_does_not_crash(self) -> None:
        bus = EventBus()

        def failing(_: IngestionEvent) -> None:
            raise RuntimeError("boom")

        bus.subscribe(DocumentDiscoveredEvent, failing)
        bus.emit(DocumentDiscoveredEvent(path=Path("/a.md")))

    def test_clear(self) -> None:
        bus = EventBus()
        results: list[int] = []

        bus.subscribe(DocumentDiscoveredEvent, lambda _: results.append(1))
        bus.clear()
        bus.emit(DocumentDiscoveredEvent(path=Path("/a.md")))
        assert results == []

    def test_child_event_has_timestamp(self) -> None:
        event = SKOCreatedEvent()
        assert event.timestamp is not None

    def test_event_types_have_defaults(self) -> None:
        e1 = DocumentDiscoveredEvent()
        assert e1.path == Path()
        e2 = ParseCompletedEvent()
        assert e2.content_length == 0
