"""Tests for tools/models.py."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from deephunter.tools.models import (
    ExecutionReport,
    PluginHealth,
    ToolCategory,
    ToolMetadata,
    ToolParameter,
    ToolStatus,
)


class TestToolStatus:
    def test_values(self) -> None:
        values = [s.value for s in ToolStatus]
        assert "pending" in values
        assert "running" in values
        assert "success" in values
        assert "failed" in values
        assert "skipped" in values
        assert "cancelled" in values
        assert "timeout" in values

    def test_enum_members(self) -> None:
        assert ToolStatus.pending.value == "pending"
        assert ToolStatus.success.value == "success"

    def test_equality(self) -> None:
        assert ToolStatus.success == ToolStatus.success
        assert ToolStatus.success != ToolStatus.failed


class TestToolCategory:
    def test_values(self) -> None:
        assert "subdomain_enumeration" in [c.value for c in ToolCategory]
        assert "port_scanning" in [c.value for c in ToolCategory]
        assert "osint" in [c.value for c in ToolCategory]

    def test_all_categories(self) -> None:
        assert len(ToolCategory) >= 15


class TestToolParameter:
    def test_defaults(self) -> None:
        p = ToolParameter(name="target")
        assert p.name == "target"
        assert p.description == ""
        assert p.type == "string"
        assert p.required is False
        assert p.default is None
        assert p.choices == []
        assert p.env_var == ""

    def test_full_init(self) -> None:
        p = ToolParameter(
            name="domain",
            description="Target domain",
            type="string",
            required=True,
            default="example.com",
            choices=["example.com", "test.com"],
            env_var="TARGET_DOMAIN",
        )
        assert p.name == "domain"
        assert p.required is True
        assert p.default == "example.com"

    def test_choices_valid(self) -> None:
        p = ToolParameter(name="mode", type="choice", choices=["fast", "full"])
        assert p.choices == ["fast", "full"]

    def test_serialization(self) -> None:
        p = ToolParameter(name="port", type="integer", default=8080)
        d = p.model_dump()
        assert d["name"] == "port"
        assert d["default"] == 8080


class TestToolMetadata:
    def test_minimal(self) -> None:
        m = ToolMetadata(name="test_tool")
        assert m.name == "test_tool"
        assert m.description == ""
        assert m.version == "1.0.0"
        assert m.author == ""
        assert m.category == ToolCategory.other
        assert m.supported_platforms == ["linux", "darwin", "windows"]
        assert m.parameters == []
        assert m.timeout_default == 120.0
        assert m.retry_default == 2

    def test_full_init(self) -> None:
        params = [ToolParameter(name="domain")]
        m = ToolMetadata(
            name="advanced_tool",
            description="Does advanced things",
            version="2.0.0",
            author="DeepHunter",
            homepage="https://example.com",
            license="MIT",
            tags=["security", "scan"],
            category=ToolCategory.port_scan,
            supported_platforms=["linux"],
            supported_formats=["json"],
            requires_network=True,
            requires_installation=False,
            parameters=params,
            timeout_default=300.0,
            retry_default=3,
        )
        assert m.name == "advanced_tool"
        assert m.tags == ["security", "scan"]
        assert m.category == ToolCategory.port_scan

    def test_network_default(self) -> None:
        m = ToolMetadata(name="offline_tool")
        assert m.requires_network is False

    def test_installation_default(self) -> None:
        m = ToolMetadata(name="tool")
        assert m.requires_installation is True

    def test_supported_formats(self) -> None:
        m = ToolMetadata(name="multi_format")
        assert "json" in m.supported_formats
        assert "yaml" in m.supported_formats

    def test_serialization(self) -> None:
        m = ToolMetadata(name="serializable", version="1.5.0")
        d = m.model_dump()
        assert d["name"] == "serializable"
        assert d["version"] == "1.5.0"

    def test_equality(self) -> None:
        m1 = ToolMetadata(name="a")
        m2 = ToolMetadata(name="a")
        assert m1 == m2

    def test_parameter_integration(self) -> None:
        m = ToolMetadata(
            name="integrated",
            parameters=[
                ToolParameter(name="p1", required=True),
                ToolParameter(name="p2", default="val"),
            ],
        )
        assert len(m.parameters) == 2
        assert m.parameters[0].required is True
        assert m.parameters[1].default == "val"


class TestExecutionReport:
    def test_minimal(self) -> None:
        r = ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.pending)
        assert r.tool_name == "t"
        assert r.plugin_name == "p"
        assert r.status == ToolStatus.pending
        assert r.id.startswith("er-")
        assert isinstance(r.started_at, datetime)

    def test_defaults(self) -> None:
        r = ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.success)
        assert r.stdout == ""
        assert r.stderr == ""
        assert r.exit_code is None
        assert r.error == ""
        assert r.retry_attempt == 0
        assert r.result_status == ""
        assert r.parsed_count == 0
        assert r.imported_count == 0
        assert r.warnings == []
        assert r.metadata == {}

    def test_finished_at_unset(self) -> None:
        r = ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.running)
        assert r.finished_at is None

    def test_full_report(self) -> None:
        from datetime import timedelta
        r = ExecutionReport(
            tool_name="subfinder",
            plugin_name="subfinder",
            status=ToolStatus.success,
            command="subfinder -d example.com",
            stdout="sub1.example.com\nsub2.example.com",
            stderr="",
            exit_code=0,
            duration_ms=1500.5,
            result_status="imported",
            parsed_count=10,
            imported_count=8,
            warnings=["no wildcard check"],
            metadata={"domain": "example.com"},
        )
        assert r.command == "subfinder -d example.com"
        assert r.parsed_count == 10
        assert r.imported_count == 8
        assert len(r.warnings) == 1

    def test_id_uniqueness(self) -> None:
        r1 = ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.pending)
        r2 = ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.pending)
        assert r1.id != r2.id

    def test_serialization(self) -> None:
        r = ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.success, exit_code=0)
        d = r.model_dump()
        assert d["tool_name"] == "t"
        assert d["exit_code"] == 0

    def test_status_transition(self) -> None:
        r = ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.pending)
        assert r.status == ToolStatus.pending
        r.status = ToolStatus.running
        assert r.status == ToolStatus.running
        r.status = ToolStatus.success
        assert r.status == ToolStatus.success

    def test_duration_rounding(self) -> None:
        r = ExecutionReport(tool_name="t", plugin_name="p", status=ToolStatus.success, duration_ms=3.33333)
        assert r.duration_ms == 3.33333

    def test_report_alias(self) -> None:
        from deephunter.tools.models import ToolReport
        assert ToolReport is ExecutionReport


class TestPluginHealth:
    def test_default_healthy(self) -> None:
        h = PluginHealth()
        assert h.healthy is True
        assert h.installed is True
        assert h.executable_found is True
        assert h.version_ok is True
        assert h.config_ok is True
        assert h.errors == []

    def test_unhealthy(self) -> None:
        h = PluginHealth(
            healthy=False,
            installed=False,
            executable_found=False,
            version_ok=False,
            errors=["subfinder not found"],
        )
        assert h.healthy is False
        assert h.errors == ["subfinder not found"]

    def test_partial_health(self) -> None:
        h = PluginHealth(installed=False, errors=["not installed"])
        assert h.healthy is True
        assert h.installed is False

    def test_serialization(self) -> None:
        h = PluginHealth(healthy=False, errors=["err"])
        d = h.model_dump()
        assert d["healthy"] is False
        assert d["errors"] == ["err"]
