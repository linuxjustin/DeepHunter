"""Tests for router event bus."""

from __future__ import annotations

from deephunter.router.events import (
    FallbackStartedEvent,
    ProviderFailedEvent,
    ProviderRegisteredEvent,
    ProviderSelectedEvent,
    RouteCompletedEvent,
    RouteFailedEvent,
    RouterEvent,
    RouterEventBus,
)


class TestRouterEvents:
    def test_base_event(self) -> None:
        event = RouterEvent()
        assert event.request_id == ""

    def test_provider_selected_event(self) -> None:
        event = ProviderSelectedEvent(
            provider_name="openai",
            model_name="gpt-4o",
            reason="best match",
            attempt_number=1,
        )
        assert event.provider_name == "openai"
        assert event.model_name == "gpt-4o"
        assert event.attempt_number == 1

    def test_provider_failed_event(self) -> None:
        event = ProviderFailedEvent(
            provider_name="ollama",
            model_name="deepseek-coder",
            error="timeout",
        )
        assert event.provider_name == "ollama"
        assert "timeout" in event.error

    def test_fallback_started_event(self) -> None:
        event = FallbackStartedEvent(
            failed_provider="ollama",
            fallback_provider="openai",
            attempt_number=2,
        )
        assert event.failed_provider == "ollama"
        assert event.fallback_provider == "openai"
        assert event.attempt_number == 2

    def test_route_completed_event(self) -> None:
        event = RouteCompletedEvent(
            provider_name="openai",
            model_name="gpt-4o",
            elapsed_ms=1500.0,
        )
        assert event.elapsed_ms == 1500.0

    def test_route_failed_event(self) -> None:
        event = RouteFailedEvent(
            error="all providers failed",
            attempts_made=3,
        )
        assert event.error == "all providers failed"
        assert event.attempts_made == 3

    def test_provider_registered_event(self) -> None:
        event = ProviderRegisteredEvent(
            provider_name="new_provider",
            model_count=5,
        )
        assert event.provider_name == "new_provider"
        assert event.model_count == 5


class TestRouterEventBus:
    def test_subscribe_and_emit(self) -> None:
        bus = RouterEventBus()
        received: list[ProviderSelectedEvent] = []

        bus.subscribe(ProviderSelectedEvent, lambda e: received.append(e))
        bus.emit(ProviderSelectedEvent(provider_name="openai"))

        assert len(received) == 1
        assert received[0].provider_name == "openai"

    def test_multiple_handlers(self) -> None:
        bus = RouterEventBus()
        results: list[int] = []

        bus.subscribe(ProviderSelectedEvent, lambda e: results.append(1))
        bus.subscribe(ProviderSelectedEvent, lambda e: results.append(2))
        bus.emit(ProviderSelectedEvent())

        assert results == [1, 2]

    def test_unsubscribe(self) -> None:
        bus = RouterEventBus()
        results: list[int] = []

        def handler(e: ProviderSelectedEvent) -> None:
            results.append(1)

        bus.subscribe(ProviderSelectedEvent, handler)
        bus.emit(ProviderSelectedEvent())
        assert len(results) == 1

        bus.unsubscribe(ProviderSelectedEvent, handler)
        bus.emit(ProviderSelectedEvent())
        assert len(results) == 1

    def test_clear(self) -> None:
        bus = RouterEventBus()
        results: list[int] = []

        bus.subscribe(RouteCompletedEvent, lambda e: results.append(1))
        bus.clear()
        bus.emit(RouteCompletedEvent())

        assert len(results) == 0

    def test_handler_exception_does_not_crash(self) -> None:
        bus = RouterEventBus()
        results: list[RouterEvent] = []

        def broken(_: RouterEvent) -> None:
            raise RuntimeError("boom")

        bus.subscribe(ProviderSelectedEvent, broken)
        bus.subscribe(ProviderSelectedEvent, lambda e: results.append(e))
        bus.emit(ProviderSelectedEvent(provider_name="test"))

        assert len(results) == 1
