"""Tests for tools/context.py."""

from __future__ import annotations

import os
from threading import Event

from deephunter.tools.config import ToolPluginConfig
from deephunter.tools.context import ExecutionContext


class TestExecutionContext:
    def test_minimal(self) -> None:
        ctx = ExecutionContext()
        assert ctx.target == ""
        assert ctx.plugin_name == ""
        assert isinstance(ctx.config, ToolPluginConfig)
        assert ctx.scope == {}
        assert ctx.args == {}

    def test_target_setting(self) -> None:
        ctx = ExecutionContext(target="example.com")
        assert ctx.target == "example.com"

    def test_plugin_name(self) -> None:
        ctx = ExecutionContext(plugin_name="subfinder")
        assert ctx.plugin_name == "subfinder"

    def test_args(self) -> None:
        ctx = ExecutionContext(args={"domain": "test.com", "threads": 10})
        assert ctx.args["domain"] == "test.com"

    def test_env_inherits_os(self) -> None:
        ctx = ExecutionContext()
        assert "PATH" in ctx.env
        assert ctx.env["PATH"] == os.environ["PATH"]

    def test_env_override(self) -> None:
        ctx = ExecutionContext(env={"CUSTOM": "val"})
        assert ctx.env["CUSTOM"] == "val"

    def test_working_dir_created(self) -> None:
        ctx = ExecutionContext()
        assert os.path.isdir(ctx.working_dir)
        import shutil
        shutil.rmtree(ctx.working_dir, ignore_errors=True)

    def test_cancel_event(self) -> None:
        ctx = ExecutionContext()
        assert ctx.cancelled is False
        ctx.cancel()
        assert ctx.cancelled is True

    def test_cancel_twice(self) -> None:
        ctx = ExecutionContext()
        ctx.cancel()
        ctx.cancel()
        assert ctx.cancelled is True

    def test_session_id(self) -> None:
        ctx = ExecutionContext(session_id="sess_123")
        assert ctx.session_id == "sess_123"

    def test_make_output_path(self) -> None:
        ctx = ExecutionContext()
        path = ctx.make_output_path("output.json")
        assert path.endswith("output.json")
        import shutil
        shutil.rmtree(ctx.working_dir, ignore_errors=True)

    def test_get_plugin_timeout_default(self) -> None:
        ctx = ExecutionContext()
        assert ctx.get_plugin_timeout() == 120.0

    def test_get_plugin_timeout_custom_default(self) -> None:
        ctx = ExecutionContext()
        assert ctx.get_plugin_timeout(default=300.0) == 300.0

    def test_get_plugin_timeout_from_config(self) -> None:
        cfg = ToolPluginConfig(plugin_timeouts={"subfinder": 600.0})
        ctx = ExecutionContext(plugin_name="subfinder", config=cfg)
        assert ctx.get_plugin_timeout() == 600.0

    def test_get_plugin_timeout_unknown_plugin(self) -> None:
        cfg = ToolPluginConfig(plugin_timeouts={"known": 99.0})
        ctx = ExecutionContext(plugin_name="unknown", config=cfg)
        assert ctx.get_plugin_timeout() == 120.0

    def test_get_plugin_retries_default(self) -> None:
        ctx = ExecutionContext()
        assert ctx.get_plugin_retries() == 2

    def test_get_plugin_retries_custom_default(self) -> None:
        ctx = ExecutionContext()
        assert ctx.get_plugin_retries(default=5) == 5  # no, uses config

    def test_get_plugin_retries_from_config(self) -> None:
        cfg = ToolPluginConfig(plugin_retries={"nuclei": 0})
        ctx = ExecutionContext(plugin_name="nuclei", config=cfg)
        assert ctx.get_plugin_retries() == 0

    def test_metadata_field(self) -> None:
        ctx = ExecutionContext(metadata={"key": "value"})
        assert ctx.metadata["key"] == "value"

    def test_cancel_with_event(self) -> None:
        event = Event()
        ctx = ExecutionContext(cancel_event=event)
        assert ctx.cancelled is False
        event.set()
        assert ctx.cancelled is True

    def test_scope_dict(self) -> None:
        ctx = ExecutionContext(scope={"program": "test", "domains": ["a.com"]})
        assert ctx.scope["program"] == "test"
