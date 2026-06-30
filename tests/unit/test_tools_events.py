"""Tests for tools/events.py."""

from __future__ import annotations

from deephunter.tools.events import (
    ToolEvent,
    ToolEventBus,
    ToolExecutionCompletedEvent,
    ToolExecutionFailedEvent,
    ToolExecutionStartedEvent,
    ToolImportCompletedEvent,
    ToolImportFailedEvent,
    ToolImportStartedEvent,
    ToolPluginDiscoveredEvent,
    ToolPluginRegisteredEvent,
)
from deephunter.tools.models import ExecutionReport, ToolStatus


class TestToolEvents:
    def test_base_event(self) -> None:
        e = ToolEvent()
        assert e.plugin_name == ""
        assert e.session_id == ""
        assert e.description == ""
        assert e.timestamp is not None

    def test_execution_started(self) -> None:
        e = ToolExecutionStartedEvent(plugin_name="subfinder")
        assert e.plugin_name == "subfinder"

    def test_execution_completed(self) -> None:
        r = ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.success)
        e = ToolExecutionCompletedEvent(plugin_name="subfinder", report=r, duration_ms=1500.0)
        assert e.report is not None
        assert e.duration_ms == 1500.0

    def test_execution_failed(self) -> None:
        e = ToolExecutionFailedEvent(plugin_name="nuclei", error="timeout", retry_attempt=2)
        assert e.error == "timeout"
        assert e.retry_attempt == 2

    def test_plugin_discovered(self) -> None:
        e = ToolPluginDiscoveredEvent(plugin_class="SubfinderPlugin", version="1.0.0")
        assert e.plugin_class == "SubfinderPlugin"

    def test_plugin_registered(self) -> None:
        e = ToolPluginRegisteredEvent(plugin_name="subfinder", plugin_class="SubfinderPlugin", version="1.0.0")
        assert e.plugin_name == "subfinder"

    def test_import_started(self) -> None:
        e = ToolImportStartedEvent(plugin_name="subfinder", parsed_count=10)
        assert e.parsed_count == 10

    def test_import_completed(self) -> None:
        r = ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.success)
        e = ToolImportCompletedEvent(plugin_name="subfinder", imported_count=8, report=r)
        assert e.imported_count == 8

    def test_import_failed(self) -> None:
        e = ToolImportFailedEvent(plugin_name="subfinder", error="parse error")
        assert e.error == "parse error"

    def test_event_with_session_id(self) -> None:
        e = ToolExecutionStartedEvent(session_id="sess_abc")
        assert e.session_id == "sess_abc"

    def test_event_with_description(self) -> None:
        e = ToolEvent(description="starting tool")
        assert e.description == "starting tool"


class TestToolEventBus:
    def test_subscribe_and_emit(self) -> None:
        bus = ToolEventBus()
        received: list[ToolEvent] = []
        bus.subscribe(ToolExecutionStartedEvent, lambda e: received.append(e))
        e = ToolExecutionStartedEvent(plugin_name="test")
        bus.emit(e)
        assert len(received) == 1
        assert received[0].plugin_name == "test"

    def test_multiple_subscribers(self) -> None:
        bus = ToolEventBus()
        received: list[ToolEvent] = []
        bus.subscribe(ToolExecutionStartedEvent, lambda e: received.append(e))
        bus.subscribe(ToolExecutionStartedEvent, lambda e: received.append(e))
        bus.emit(ToolExecutionStartedEvent())
        assert len(received) == 2

    def test_unsubscribe(self) -> None:
        bus = ToolEventBus()
        received: list[ToolEvent] = []
        handler = lambda e: received.append(e)
        bus.subscribe(ToolExecutionStartedEvent, handler)
        bus.emit(ToolExecutionStartedEvent())
        assert len(received) == 1
        bus.unsubscribe(ToolExecutionStartedEvent, handler)
        bus.emit(ToolExecutionStartedEvent())
        assert len(received) == 1

    def test_unsubscribe_nonexistent(self) -> None:
        bus = ToolEventBus()
        bus.unsubscribe(ToolExecutionStartedEvent, lambda e: None)  # should not raise

    def test_emit_other_type(self) -> None:
        bus = ToolEventBus()
        received: list[ToolEvent] = []
        bus.subscribe(ToolExecutionStartedEvent, lambda e: received.append(e))
        bus.emit(ToolExecutionFailedEvent(error="err"))
        assert len(received) == 0

    def test_handler_exception_doesnt_crash(self) -> None:
        bus = ToolEventBus()
        def bad_handler(e: ToolEvent) -> None:
            raise ValueError("handler error")
        bus.subscribe(ToolExecutionStartedEvent, bad_handler)
        bus.emit(ToolExecutionStartedEvent())  # should not raise

    def test_clear(self) -> None:
        bus = ToolEventBus()
        received: list[ToolEvent] = []
        bus.subscribe(ToolExecutionStartedEvent, lambda e: received.append(e))
        bus.clear()
        bus.emit(ToolExecutionStartedEvent())
        assert len(received) == 0

    def test_emit_to_correct_type(self) -> None:
        bus = ToolEventBus()
        started: list[ToolEvent] = []
        completed: list[ToolEvent] = []
        bus.subscribe(ToolExecutionStartedEvent, lambda e: started.append(e))
        bus.subscribe(ToolExecutionCompletedEvent, lambda e: completed.append(e))
        bus.emit(ToolExecutionStartedEvent())
        bus.emit(ToolExecutionCompletedEvent())
        assert len(started) == 1
        assert len(completed) == 1

    def test_multiple_emits(self) -> None:
        bus = ToolEventBus()
        received: list[ToolEvent] = []
        bus.subscribe(ToolEvent, lambda e: received.append(e))
        for _ in range(5):
            bus.emit(ToolEvent())
        assert len(received) == 5
