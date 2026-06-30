"""Integration tests for the Tool Integration SDK.

Tests the full lifecycle across multiple modules.
"""

from __future__ import annotations

from typing import Any

from deephunter.core import DeepHunterConfig
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.config import ToolPluginConfig
from deephunter.tools.context import ExecutionContext
from deephunter.tools.events import ToolEventBus
from deephunter.tools.executor import ToolExecutor
from deephunter.tools.models import (
    ExecutionReport,
    PluginHealth,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)
from deephunter.tools.normalizer import ImportPipeline, build_default_pipeline, parse_json
from deephunter.tools.registry import ToolPluginRegistry
from deephunter.tools.reporter import build_report, report_summary


class _NmapPlugin(BaseToolPlugin):
    metadata = ToolMetadata(
        name="nmap",
        description="Port scanning via nmap",
        version="1.0.0",
        category=ToolCategory.port_scan,
        tags=["port", "scan", "network"],
        supported_platforms=["linux", "darwin"],
        requires_network=True,
        requires_installation=True,
        timeout_default=600.0,
        retry_default=0,
    )

    def execute(self, context: ExecutionContext) -> str:
        port_str = context.args.get("ports", "80,443")
        domain = context.args.get("domain", context.target)
        if not domain:
            domain = "scanme.nmap.org"
        return f"nmap scan of {domain}:{port_str}"

    def parse_output(self, raw: str | bytes | None, context: ExecutionContext) -> dict:
        hosts = [
            {"hostname": "target.com", "ip": "93.184.216.34", "ports": ["80", "443"]},
        ]
        return {"hosts": hosts}

    def normalize(self, parsed: dict, context: ExecutionContext) -> PluginResult:
        from deephunter.recon.models import Host, HostStatus, Protocol, ReconSourceType
        result = PluginResult()
        for h in parsed.get("hosts", []):
            host = Host(
                hostname=h.get("hostname", ""),
                ip=h.get("ip", ""),
                port=443,
                protocol=Protocol.HTTPS,
                status=HostStatus.ACTIVE,
                source=ReconSourceType.INTEGRATION,
            )
            result.hosts.append(host)
        return result

    def import_results(self, result: PluginResult, context: ExecutionContext) -> dict[str, int]:
        return {"hosts": len(result.hosts)}

    def health(self, context: ExecutionContext) -> PluginHealth:
        return PluginHealth(healthy=False, errors=["nmap not installed"])

    def build_command(self, context: ExecutionContext) -> str:
        return f"nmap -p {context.args.get('ports', '80,443')} {context.target}"


class TestIntegration:
    def test_full_lifecycle(self) -> None:
        plugin = _NmapPlugin()
        ctx = ExecutionContext(
            target="example.com",
            plugin_name="nmap",
            args={"ports": "80,443"},
        )

        assert plugin.validate_context(ctx) is True
        plugin.prepare(ctx)
        raw = plugin.execute(ctx)
        parsed = plugin.parse_output(raw, ctx)
        result = plugin.normalize(parsed, ctx)
        import_counts = plugin.import_results(result, ctx)
        plugin.cleanup(ctx)
        health = plugin.health(ctx)

        assert isinstance(raw, str)
        assert isinstance(parsed, dict)
        assert isinstance(result, PluginResult)
        assert import_counts["hosts"] == 1
        assert health.healthy is False

    def test_registry_lifecycle(self) -> None:
        registry = ToolPluginRegistry()
        plugin = _NmapPlugin()
        registry.register(plugin)

        assert "nmap" in registry
        assert registry.get("nmap") is plugin
        assert len(registry.list_names()) == 1

        registry.unregister("nmap")
        assert "nmap" not in registry

    def test_executor_with_full_plugin(self) -> None:
        bus = ToolEventBus()
        executor = ToolExecutor(event_bus=bus)
        plugin = _NmapPlugin()
        ctx = ExecutionContext(
            target="example.com",
            plugin_name="nmap",
            args={"ports": "80,443"},
        )

        report = executor.execute(plugin, ctx)
        assert report.status == ToolStatus.success
        assert report.tool_name == "nmap"
        assert report.duration_ms > 0
        assert report.result_status == "imported"

    def test_core_config_integration(self) -> None:
        cfg = DeepHunterConfig()
        assert cfg.tool_plugins.enabled is True
        assert cfg.tool_plugins.default_timeout == 120.0

    def test_custom_config_override(self) -> None:
        cfg = DeepHunterConfig()
        cfg.tool_plugins = ToolPluginConfig(enabled=False, default_timeout=300.0)
        assert cfg.tool_plugins.enabled is False
        assert cfg.tool_plugins.default_timeout == 300.0

    def test_event_bus_multiple_plugins(self) -> None:
        bus = ToolEventBus()
        registry = ToolPluginRegistry(event_bus=bus)
        executor = ToolExecutor(event_bus=bus)

        class _NmapPluginV2(_NmapPlugin):
            pass

        p1 = _NmapPlugin()
        p2 = _NmapPluginV2()
        p2.metadata = ToolMetadata(
            name="nmap_v2",
            description="Port scanning v2",
            version="2.0.0",
            category=ToolCategory.port_scan,
        )

        registry.register(p1)
        registry.register(p2)

        ctx1 = ExecutionContext(target="a.com", plugin_name="nmap")
        ctx2 = ExecutionContext(target="b.com", plugin_name="nmap_v2")

        r1 = executor.execute(p1, ctx1)
        r2 = executor.execute(p2, ctx2)

        assert r1.status == ToolStatus.success
        assert r2.status == ToolStatus.success

    def test_reporter_summary_across_plugins(self) -> None:
        reports = [
            ExecutionReport(tool_name="a", plugin_name="a", status=ToolStatus.success, duration_ms=100.0),
            ExecutionReport(tool_name="b", plugin_name="b", status=ToolStatus.failed, duration_ms=50.0),
            ExecutionReport(tool_name="c", plugin_name="c", status=ToolStatus.timeout, duration_ms=200.0),
        ]
        s = report_summary(reports)
        assert s["total"] == 3
        assert s["by_status"]["success"] == 1
        assert s["by_status"]["failed"] == 1
        assert s["by_status"]["timeout"] == 1

    def test_normalizer_with_plugin_output(self) -> None:
        pipeline = build_default_pipeline()
        raw = '{"hostname": "example.com", "ip": "1.2.3.4"}'
        parsed = pipeline.parse(raw, fmt="json")
        assert parsed["hostname"] == "example.com"
        assert parsed["ip"] == "1.2.3.4"

    def test_config_in_core_init_exports(self) -> None:
        from deephunter.core import ToolPluginConfig as CoreConfig
        from deephunter.tools.config import ToolPluginConfig
        assert CoreConfig is ToolPluginConfig

    def test_exception_integration(self) -> None:
        from deephunter.tools.exceptions import ToolPluginError as TPE
        from deephunter.core.exceptions import ToolPluginError as CoreTPE
        assert TPE is CoreTPE

    def test_models_serialization_roundtrip(self) -> None:
        r = ExecutionReport(
            tool_name="t",
            plugin_name="p",
            status=ToolStatus.success,
            exit_code=0,
            stdout="output",
            duration_ms=100.0,
        )
        d = r.model_dump(mode="json")
        r2 = ExecutionReport.model_validate(d)
        assert r2.tool_name == "t"
        assert r2.status == ToolStatus.success
        assert r2.exit_code == 0
        assert r2.duration_ms == 100.0

    def test_context_with_config_overrides(self) -> None:
        cfg = ToolPluginConfig(plugin_timeouts={"slow_plugin": 999.0})
        ctx = ExecutionContext(plugin_name="slow_plugin", config=cfg)
        assert ctx.get_plugin_timeout() == 999.0

    def test_builtin_plugin_importable(self) -> None:
        from deephunter.tools.plugins.subfinder_plugin import SubfinderPlugin
        p = SubfinderPlugin()
        assert p.name == "subfinder"
        assert p.category == ToolCategory.subdomain_enum

    def test_builtin_plugin_health(self) -> None:
        from deephunter.tools.plugins.subfinder_plugin import SubfinderPlugin
        p = SubfinderPlugin()
        ctx = ExecutionContext(target="example.com")
        h = p.health(ctx)
        assert isinstance(h, PluginHealth)

    def test_builtin_plugin_command(self) -> None:
        from deephunter.tools.plugins.subfinder_plugin import SubfinderPlugin
        p = SubfinderPlugin()
        ctx = ExecutionContext(target="example.com")
        cmd = p.build_command(ctx)
        assert "subfinder" in cmd
        assert "example.com" in cmd

    def test_builtin_plugin_normalize(self) -> None:
        from deephunter.tools.plugins.subfinder_plugin import SubfinderPlugin
        p = SubfinderPlugin()
        parsed = ["sub.a.com", "sub.b.com"]
        ctx = ExecutionContext(target="a.com")
        result = p.normalize(parsed, ctx)
        assert len(result.hosts) == 2
        assert result.hosts[0].hostname == "sub.a.com"

    def test_builtin_plugin_parse_output(self) -> None:
        from deephunter.tools.plugins.subfinder_plugin import SubfinderPlugin
        p = SubfinderPlugin()
        ctx = ExecutionContext(target="example.com")
        parsed = p.parse_output(b"sub1.example.com\nsub2.example.com\n", ctx)
        assert len(parsed) == 2
        assert parsed[0] == "sub1.example.com"

    def test_builtin_plugin_parse_output_none(self) -> None:
        from deephunter.tools.plugins.subfinder_plugin import SubfinderPlugin
        p = SubfinderPlugin()
        ctx = ExecutionContext(target="example.com")
        assert p.parse_output(None, ctx) == []

    def test_full_end_to_end(self) -> None:
        plugin = _NmapPlugin()
        ctx = ExecutionContext(target="example.com", plugin_name="nmap")
        executor = ToolExecutor()
        report = executor.execute(plugin, ctx)
        assert report.status == ToolStatus.success

    def test_executor_with_cancellation(self) -> None:
        plugin = _NmapPlugin()
        ctx = ExecutionContext(target="example.com", plugin_name="nmap")
        ctx.cancel()
        executor = ToolExecutor()
        report = executor.execute(plugin, ctx)
        assert report.status in (ToolStatus.cancelled, ToolStatus.success)
