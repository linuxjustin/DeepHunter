"""Tests for prompt event bus."""

from __future__ import annotations

from deephunter.prompt.events import (
    PromptAdapterAppliedEvent,
    PromptEvent,
    PromptEventBus,
    PromptFormatAppliedEvent,
    PromptGeneratedEvent,
    PromptTemplateLoadedEvent,
    PromptTemplateNotFoundEvent,
)


class TestPromptEvents:
    def test_base_event_defaults(self) -> None:
        event = PromptEvent()
        assert event.investigation_id == ""
        assert event.context_id == ""
        assert event.prompt_id == ""

    def test_prompt_generated_event(self) -> None:
        event = PromptGeneratedEvent(
            investigation_id="inv-1",
            prompt_id="prompt-1",
            style="investigation",
            message_count=2,
            estimated_tokens=500,
        )
        assert event.investigation_id == "inv-1"
        assert event.prompt_id == "prompt-1"
        assert event.style == "investigation"
        assert event.message_count == 2
        assert event.estimated_tokens == 500

    def test_template_loaded_event(self) -> None:
        event = PromptTemplateLoadedEvent(
            template_name="investigation_default",
            template_style="investigation",
        )
        assert event.template_name == "investigation_default"
        assert event.template_style == "investigation"

    def test_template_not_found_event(self) -> None:
        event = PromptTemplateNotFoundEvent(template_name="nonexistent")
        assert event.template_name == "nonexistent"

    def test_format_applied_event(self) -> None:
        event = PromptFormatAppliedEvent(format_name="json")
        assert event.format_name == "json"

    def test_adapter_applied_event(self) -> None:
        event = PromptAdapterAppliedEvent(adapter_name="claude")
        assert event.adapter_name == "claude"


class TestPromptEventBus:
    def test_subscribe_and_emit(self) -> None:
        bus = PromptEventBus()
        received: list[PromptGeneratedEvent] = []

        bus.subscribe(PromptGeneratedEvent, lambda e: received.append(e))
        bus.emit(PromptGeneratedEvent(prompt_id="prompt-1"))

        assert len(received) == 1
        assert received[0].prompt_id == "prompt-1"

    def test_multiple_handlers(self) -> None:
        bus = PromptEventBus()
        results: list[int] = []

        bus.subscribe(PromptGeneratedEvent, lambda e: results.append(1))
        bus.subscribe(PromptGeneratedEvent, lambda e: results.append(2))
        bus.emit(PromptGeneratedEvent())

        assert results == [1, 2]

    def test_unsubscribe(self) -> None:
        bus = PromptEventBus()
        results: list[int] = []

        def handler(e: PromptGeneratedEvent) -> None:
            results.append(1)

        bus.subscribe(PromptGeneratedEvent, handler)
        bus.emit(PromptGeneratedEvent())
        assert len(results) == 1

        bus.unsubscribe(PromptGeneratedEvent, handler)
        bus.emit(PromptGeneratedEvent())
        assert len(results) == 1

    def test_clear(self) -> None:
        bus = PromptEventBus()
        results: list[int] = []

        bus.subscribe(PromptGeneratedEvent, lambda e: results.append(1))
        bus.clear()
        bus.emit(PromptGeneratedEvent())

        assert len(results) == 0

    def test_handler_exception_does_not_crash(self) -> None:
        bus = PromptEventBus()
        results: list[PromptEvent] = []

        def broken(_: PromptEvent) -> None:
            raise RuntimeError("boom")

        bus.subscribe(PromptGeneratedEvent, broken)
        bus.subscribe(PromptGeneratedEvent, lambda e: results.append(e))
        bus.emit(PromptGeneratedEvent(prompt_id="test"))

        assert len(results) == 1
