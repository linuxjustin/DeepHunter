"""Tests for all built-in tool adapter plugins.

Covers parse_output, normalize, health, build_command, and metadata for
every adapter in src/deephunter/tools/plugins/.
"""

from __future__ import annotations

from typing import Any

import pytest

from deephunter.recon.models import (
    DNSRecordType,
    Endpoint,
    EndpointCategory,
    HTTPObservation,
    Host,
    JavaScriptFile,
    Technology,
)
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolStatus
from deephunter.tools.executor import ToolExecutor


# ═══════════════════════════════════════════════════════════════════════════════
# Test helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _import(name: str) -> type[BaseToolPlugin]:
    mod = __import__(f"deephunter.tools.plugins.{name}_adapter", fromlist=[name])
    cls_name = "".join(p.capitalize() for p in name.split("_")) + "Adapter"
    for attr in dir(mod):
        if attr.endswith("Adapter") and attr != "BaseToolPlugin":
            return getattr(mod, attr)
    raise ImportError(f"No Adapter class found in {name}_adapter")


def _make_ctx(**overrides: Any) -> ExecutionContext:
    args = overrides.pop("args", {})
    return ExecutionContext(target="example.com", args=args, **overrides)


# ═══════════════════════════════════════════════════════════════════════════════
# Parameterized: every adapter's metadata and health
# ═══════════════════════════════════════════════════════════════════════════════

ADAPTER_NAMES = [
    "gau", "waybackurls", "dnsx", "naabu", "katana",
    "ffuf", "nuclei", "burp", "playwright", "mcp",
]

ADAPTER_CATEGORIES = {
    "gau": ToolCategory.url_discovery,
    "waybackurls": ToolCategory.url_discovery,
    "dnsx": ToolCategory.dns_enum,
    "naabu": ToolCategory.port_scan,
    "katana": ToolCategory.url_discovery,
    "ffuf": ToolCategory.fuzzing,
    "nuclei": ToolCategory.vulnerability_scan,
    "burp": ToolCategory.web_probe,
    "playwright": ToolCategory.js_analysis,
    "mcp": ToolCategory.other,
}


class TestAdapterMetadata:
    @pytest.mark.parametrize("name", ADAPTER_NAMES)
    def test_adapter_importable(self, name: str) -> None:
        cls = _import(name)
        assert issubclass(cls, BaseToolPlugin)

    @pytest.mark.parametrize("name", ADAPTER_NAMES)
    def test_adapter_metadata_name(self, name: str) -> None:
        cls = _import(name)
        p = cls()
        assert p.name == name

    @pytest.mark.parametrize("name", ADAPTER_NAMES)
    def test_adapter_metadata_category(self, name: str) -> None:
        cls = _import(name)
        p = cls()
        assert p.category == ADAPTER_CATEGORIES[name], f"{name}: expected {ADAPTER_CATEGORIES[name]}, got {p.category}"

    @pytest.mark.parametrize("name", ADAPTER_NAMES)
    def test_adapter_health_returns_pluginhealth(self, name: str) -> None:
        cls = _import(name)
        p = cls()
        ctx = _make_ctx()
        h = p.health(ctx)
        assert isinstance(h, PluginHealth)

    @pytest.mark.parametrize("name", ADAPTER_NAMES)
    def test_adapter_build_command_returns_str(self, name: str) -> None:
        cls = _import(name)
        p = cls()
        ctx = _make_ctx()
        cmd = p.build_command(ctx)
        assert isinstance(cmd, str)


# ═══════════════════════════════════════════════════════════════════════════════
# GauAdapter
# ═══════════════════════════════════════════════════════════════════════════════

class TestGauAdapter:
    @pytest.fixture
    def plugin(self) -> BaseToolPlugin:
        cls = _import("gau")
        return cls()

    def test_name(self, plugin: BaseToolPlugin) -> None:
        assert plugin.name == "gau"

    def test_parse_output_none(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        assert plugin.parse_output(None, ctx) == []

    def test_parse_output_bytes(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        result = plugin.parse_output(b"https://a.com/path\nhttps://b.com/api\n", ctx)
        assert len(result) == 2
        assert result[0] == "https://a.com/path"

    def test_normalize(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        urls = [
            "https://example.com/page",
            "https://example.com/api/v1/users",
            "https://example.com/admin/login",
            "https://example.com/static/style.css",
        ]
        result = plugin.normalize(urls, ctx)
        assert isinstance(result, PluginResult)
        assert len(result.endpoints) == 4
        assert result.endpoints[0].path == urls[0]
        assert result.endpoints[1].category == EndpointCategory.API
        assert result.endpoints[2].category == EndpointCategory.ADMIN
        assert result.endpoints[3].category == EndpointCategory.STATIC

    def test_normalize_deduplicates(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        urls = ["https://example.com/page", "https://example.com/page"]
        result = plugin.normalize(urls, ctx)
        assert len(result.endpoints) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# WaybackURLsAdapter
# ═══════════════════════════════════════════════════════════════════════════════

class TestWaybackURLsAdapter:
    @pytest.fixture
    def plugin(self) -> BaseToolPlugin:
        cls = _import("waybackurls")
        return cls()

    def test_name(self, plugin: BaseToolPlugin) -> None:
        assert plugin.name == "waybackurls"

    def test_parse_and_normalize(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        raw = b"https://example.com/old\nhttps://example.com/dead\n"
        parsed = plugin.parse_output(raw, ctx)
        assert len(parsed) == 2
        result = plugin.normalize(parsed, ctx)
        assert len(result.endpoints) == 2
        assert result.endpoints[0].metadata.get("tool") == "waybackurls"


# ═══════════════════════════════════════════════════════════════════════════════
# DNSxAdapter
# ═══════════════════════════════════════════════════════════════════════════════

class TestDNSxAdapter:
    @pytest.fixture
    def plugin(self) -> BaseToolPlugin:
        cls = _import("dnsx")
        return cls()

    def test_name(self, plugin: BaseToolPlugin) -> None:
        assert plugin.name == "dnsx"

    def test_parse_ndjson(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        raw = b'{"host":"example.com","a":"1.2.3.4","cname":"www.example.com"}\n{"host":"test.com","a":"5.6.7.8"}\n'
        parsed = plugin.parse_output(raw, ctx)
        assert len(parsed) == 2
        assert parsed[0]["host"] == "example.com"

    def test_parse_txt(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        raw = b"example.com\ntest.com\n"
        parsed = plugin.parse_output(raw, ctx)
        assert len(parsed) == 2

    def test_normalize(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        parsed = [
            {"host": "example.com", "a": "1.2.3.4", "cname": "www.example.com", "mx": "mail.example.com"},
            {"host": "test.com", "aaaa": "::1"},
        ]
        result = plugin.normalize(parsed, ctx)
        assert len(result.hosts) == 2
        assert len(result.hosts[0].dns_records) > 0
        assert any(r.record_type == DNSRecordType.A for r in result.hosts[0].dns_records)
        assert any(r.record_type == DNSRecordType.CNAME for r in result.hosts[0].dns_records)
        assert any(r.record_type == DNSRecordType.MX for r in result.hosts[0].dns_records)

    def test_normalize_empty(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        result = plugin.normalize([], ctx)
        assert result.success is True
        assert len(result.hosts) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# NaabuAdapter
# ═══════════════════════════════════════════════════════════════════════════════

class TestNaabuAdapter:
    @pytest.fixture
    def plugin(self) -> BaseToolPlugin:
        cls = _import("naabu")
        return cls()

    def test_parse_ndjson(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        raw = b'{"host":"example.com","port":80}\n{"host":"example.com","port":443}\n'
        parsed = plugin.parse_output(raw, ctx)
        assert len(parsed) == 2

    def test_parse_host_port_line(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        raw = b"example.com:80\ntest.com:443\n"
        parsed = plugin.parse_output(raw, ctx)
        assert len(parsed) == 2
        assert parsed[0]["host"] == "example.com"
        assert parsed[0]["port"] == 80

    def test_normalize(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        parsed = [
            {"host": "example.com", "port": 80},
            {"host": "example.com", "port": 443},
            {"host": "example.com", "port": 8080},
        ]
        result = plugin.normalize(parsed, ctx)
        assert len(result.hosts) == 3
        assert result.hosts[0].port == 80
        assert result.hosts[1].port == 443
        assert result.hosts[2].port == 8080

    def test_normalize_deduplicates_host_port(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        parsed = [
            {"host": "example.com", "port": 80},
            {"host": "example.com", "port": 80},
        ]
        result = plugin.normalize(parsed, ctx)
        assert len(result.hosts) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# KatanaAdapter
# ═══════════════════════════════════════════════════════════════════════════════

class TestKatanaAdapter:
    @pytest.fixture
    def plugin(self) -> BaseToolPlugin:
        cls = _import("katana")
        return cls()

    def test_parse_ndjson(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        raw = b'{"url":"https://example.com/page","status_code":200,"content_type":"text/html"}\n'
        parsed = plugin.parse_output(raw, ctx)
        assert len(parsed) == 1
        assert parsed[0]["url"] == "https://example.com/page"

    def test_parse_txt(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        raw = b"https://example.com/a\nhttps://example.com/b\n"
        parsed = plugin.parse_output(raw, ctx)
        assert len(parsed) == 2

    def test_normalize(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        parsed = [
            {"url": "https://example.com/", "status_code": 200, "content_type": "text/html", "technique": "http"},
            {"url": "https://example.com/app.js", "status_code": 200, "content_type": "application/javascript"},
            {"url": "https://example.com/api/users", "status_code": 200},
            {"url": "https://example.com/admin", "status_code": 403},
        ]
        result = plugin.normalize(parsed, ctx)
        assert len(result.endpoints) == 4
        assert len(result.js_files) == 1
        assert result.js_files[0].url == "https://example.com/app.js"
        api_eps = [e for e in result.endpoints if e.category == EndpointCategory.API]
        assert len(api_eps) >= 1

    def test_normalize_empty(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        result = plugin.normalize([], ctx)
        assert result.success is True


# ═══════════════════════════════════════════════════════════════════════════════
# FfufAdapter
# ═══════════════════════════════════════════════════════════════════════════════

class TestFfufAdapter:
    @pytest.fixture
    def plugin(self) -> BaseToolPlugin:
        cls = _import("ffuf")
        return cls()

    def test_parse_ndjson(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        raw = b'{"url":"https://example.com/admin","status":200,"length":1234}\n'
        parsed = plugin.parse_output(raw, ctx)
        assert len(parsed) == 1
        assert parsed[0]["url"] == "https://example.com/admin"

    def test_normalize(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        parsed = [
            {"url": "https://example.com/admin", "status": 200, "length": 5000},
            {"url": "https://example.com/api", "status": 200, "content_type": "application/json"},
            {"url": "https://example.com/404", "status": 404},
        ]
        result = plugin.normalize(parsed, ctx)
        assert len(result.endpoints) == 3
        assert result.endpoints[0].status_code == 200

    def test_normalize_with_params(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        parsed = [
            {"url": "https://example.com/page", "status": 200, "input": {"FUZZ": "admin"}},
        ]
        result = plugin.normalize(parsed, ctx)
        assert len(result.endpoints) == 1
        assert len(result.endpoints[0].parameters) == 1
        assert result.endpoints[0].parameters[0].name == "FUZZ"


# ═══════════════════════════════════════════════════════════════════════════════
# NucleiAdapter
# ═══════════════════════════════════════════════════════════════════════════════

class TestNucleiAdapter:
    @pytest.fixture
    def plugin(self) -> BaseToolPlugin:
        cls = _import("nuclei")
        return cls()

    def test_parse_ndjson(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        raw = b'{"template-id":"ssl-detect","host":"example.com","matched-at":"https://example.com","info":{"name":"SSL Detect","severity":"info","tags":["ssl","tls"]}}\n'
        parsed = plugin.parse_output(raw, ctx)
        assert len(parsed) == 1
        assert parsed[0]["template-id"] == "ssl-detect"

    def test_normalize(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        parsed = [
            {
                "template-id": "tech-detect",
                "host": "example.com",
                "matched-at": "https://example.com/",
                "info": {"name": "Nginx Detect", "severity": "info", "tags": ["nginx", "server"], "technology": ["nginx"]},
            },
            {
                "template-id": "xss-test",
                "host": "example.com",
                "matched-at": "https://example.com/search",
                "info": {"name": "Reflected XSS", "severity": "high", "tags": ["xss", "injection"]},
            },
        ]
        result = plugin.normalize(parsed, ctx)
        assert len(result.hosts) >= 1
        assert len(result.endpoints) >= 2
        assert len(result.technologies) >= 1
        host = result.hosts[0]
        findings = host.metadata.get("nuclei_findings", [])
        assert len(findings) >= 2
        high_findings = [f for f in findings if f["severity"] == "high"]
        assert len(high_findings) >= 1

    def test_normalize_empty(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        result = plugin.normalize([], ctx)
        assert result.success is True


# ═══════════════════════════════════════════════════════════════════════════════
# BurpAdapter
# ═══════════════════════════════════════════════════════════════════════════════

class TestBurpAdapter:
    @pytest.fixture
    def plugin(self) -> BaseToolPlugin:
        cls = _import("burp")
        return cls()

    def test_execute_raises(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        with pytest.raises(NotImplementedError):
            plugin.execute(ctx)

    def test_parse_xml_items(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        xml = b"""<?xml version="1.0"?>
<items>
  <item>
    <url>https://example.com/page</url>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/page</path>
    <request>R0VUIC9wYWdlIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KDQo=</request>
    <response>SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KDQo8aHRtbD48L2h0bWw+</response>
  </item>
</items>"""
        parsed = plugin.parse_output(xml, ctx)
        assert len(parsed) >= 1
        assert parsed[0]["url"] == "https://example.com/page"
        assert parsed[0]["status_code"] == 200

    def test_parse_json(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        raw = b'{"url":"https://example.com/api","host":"example.com","status_code":200}\n'
        parsed = plugin.parse_output(raw, ctx)
        assert len(parsed) == 1

    def test_normalize(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        parsed = [
            {"url": "https://example.com/page", "host": "example.com", "method": "GET", "status_code": 200, "headers": {"content-type": "text/html"}},
            {"url": "https://example.com/api/users", "host": "example.com", "method": "POST", "status_code": 201, "headers": {"content-type": "application/json"}},
        ]
        result = plugin.normalize(parsed, ctx)
        assert len(result.endpoints) == 2
        assert len(result.http_observations) == 2
        assert result.endpoints[0].path == "https://example.com/page"

    def test_normalize_issues(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        parsed = [
            {"url": "https://example.com/login", "host": "example.com", "type": "issue", "issue_name": "Missing HSTS", "severity": "medium"},
        ]
        result = plugin.normalize(parsed, ctx)
        assert len(result.endpoints) == 1
        assert "burp_issues" in result.endpoints[0].metadata
        assert result.endpoints[0].metadata["burp_issues"][0]["severity"] == "medium"

    def test_health_ok(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        h = plugin.health(ctx)
        assert h.healthy is True

    def test_build_command(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        assert plugin.build_command(ctx) == ""


# ═══════════════════════════════════════════════════════════════════════════════
# PlaywrightAdapter
# ═══════════════════════════════════════════════════════════════════════════════

class TestPlaywrightAdapter:
    @pytest.fixture
    def plugin(self) -> BaseToolPlugin:
        cls = _import("playwright")
        return cls()

    def test_execute_raises(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        with pytest.raises(NotImplementedError):
            plugin.execute(ctx)

    def test_parse_json(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        raw = b'{"url":"https://example.com","title":"Test","jsFiles":["app.js"],"endpoints":["/api"]}'
        parsed = plugin.parse_output(raw, ctx)
        assert parsed["url"] == "https://example.com"

    def test_parse_empty(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        assert plugin.parse_output(None, ctx) == {}

    def test_normalize(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        data = {
            "url": "https://example.com/",
            "title": "Example",
            "jsFiles": ["https://example.com/app.js", "https://example.com/vendor.js"],
            "endpoints": ["/api/v1/users", "/login"],
            "technologies": ["React", "nginx"],
        }
        result = plugin.normalize(data, ctx)
        assert len(result.http_observations) == 1
        assert len(result.js_files) == 2
        assert len(result.endpoints) == 2
        assert len(result.technologies) == 2

    def test_normalize_empty(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        result = plugin.normalize({}, ctx)
        assert result.success is True

    def test_health_import_error(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        h = plugin.health(ctx)
        assert isinstance(h, PluginHealth)


# ═══════════════════════════════════════════════════════════════════════════════
# MCPAdapter
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPAdapter:
    @pytest.fixture
    def plugin(self) -> BaseToolPlugin:
        cls = _import("mcp")
        return cls()

    def test_name(self, plugin: BaseToolPlugin) -> None:
        assert plugin.name == "mcp"

    def test_list_tools(self, plugin: BaseToolPlugin) -> None:
        from deephunter.tools.plugins.mcp_adapter import MCPAdapter
        mcp = plugin
        tools = mcp.list_tools()
        assert len(tools) >= 5
        names = {t.name for t in tools}
        assert "scan_domain" in names
        assert "resolve_dns" in names
        assert "fetch_url" in names
        assert "search_wayback" in names
        assert "check_technology" in names

    def test_get_tools_json(self, plugin: BaseToolPlugin) -> None:
        from deephunter.tools.plugins.mcp_adapter import MCPAdapter
        mcp = plugin
        result = mcp.get_tools_json()
        assert isinstance(result, list)
        assert all("name" in t and "input_schema" in t for t in result)

    def test_execute_builtin_scan(self, plugin: BaseToolPlugin) -> None:
        from deephunter.tools.plugins.mcp_adapter import MCPAdapter, MCPToolCall
        mcp = plugin
        result = mcp.execute_tool_call(MCPToolCall(tool_name="resolve_dns", arguments={"domain": "example.com"}))
        assert result.is_error is False
        assert len(result.content) == 1

    def test_execute_unknown_tool(self, plugin: BaseToolPlugin) -> None:
        from deephunter.tools.plugins.mcp_adapter import MCPAdapter, MCPToolCall
        mcp = plugin
        result = mcp.execute_tool_call(MCPToolCall(tool_name="nonexistent"))
        assert result.is_error is True

    def test_execute_fetch_url_schema(self, plugin: BaseToolPlugin) -> None:
        from deephunter.tools.plugins.mcp_adapter import MCPAdapter
        mcp = plugin
        tool = mcp.get_tool("fetch_url")
        assert tool is not None
        assert "url" in tool.input_schema.get("properties", {})

    def test_execute_action_list(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx(args={"action": "list_tools"})
        output = plugin.execute(ctx)
        assert output is not None
        import json
        data = json.loads(output)
        assert isinstance(data, list)
        assert len(data) >= 5

    def test_execute_action_execute(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx(args={"action": "execute", "tool_call": {"tool_name": "resolve_dns", "arguments": {"domain": "test.com"}}})
        output = plugin.execute(ctx)
        assert output is not None
        import json
        data = json.loads(output)
        assert "content" in data

    def test_normalize_empty(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        result = plugin.normalize({}, ctx)
        assert result.success is True

    def test_normalize_with_data(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        data = {
            "hosts": [{"hostname": "sub.example.com", "ip": "1.2.3.4"}],
            "endpoints": [{"url": "https://example.com/api"}],
        }
        result = plugin.normalize(data, ctx)
        assert len(result.hosts) == 1
        assert result.hosts[0].hostname == "sub.example.com"
        assert len(result.endpoints) == 1

    def test_health(self, plugin: BaseToolPlugin) -> None:
        ctx = _make_ctx()
        h = plugin.health(ctx)
        assert h.healthy is True

    def test_register_tool(self, plugin: BaseToolPlugin) -> None:
        from deephunter.tools.plugins.mcp_adapter import MCPAdapter, MCPToolDefinition
        mcp = plugin
        mcp.register_tool(MCPToolDefinition(name="my_tool", description="Custom tool", input_schema={"type": "object", "properties": {}}))
        assert mcp.get_tool("my_tool") is not None
        assert len(mcp.list_tools()) >= 6


# ═══════════════════════════════════════════════════════════════════════════════
# Cross-cutting: executor integration
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdapterExecutorIntegration:
    @pytest.mark.parametrize("name", ["gau", "waybackurls", "dnsx", "naabu", "katana", "ffuf", "nuclei"])
    def test_executor_with_mock_adapter(self, name: str) -> None:
        class _MockAdapter(BaseToolPlugin):
            metadata = type("md", (), {"name": name, "description": "", "version": "1.0.0", "category": ADAPTER_CATEGORIES[name], "tags": [], "supported_formats": [], "requires_network": False, "requires_installation": False, "timeout_default": 30.0, "retry_default": 0})()

            def execute(self, ctx: ExecutionContext) -> str:
                return "mock output"

            def parse_output(self, raw: str | bytes | None, ctx: ExecutionContext) -> list[str]:
                return ["mock-result"]

            def normalize(self, parsed: Any, ctx: ExecutionContext) -> PluginResult:
                r = PluginResult()
                r.endpoints.append(Endpoint(path="https://example.com/", source="integration"))
                return r

            def import_results(self, r: PluginResult, ctx: ExecutionContext) -> dict[str, int]:
                return {"endpoints": len(r.endpoints)}

        executor = ToolExecutor()
        plugin = _MockAdapter()
        ctx = ExecutionContext(target="example.com", plugin_name=name)
        report = executor.execute(plugin, ctx)
        assert report.status == ToolStatus.success
        assert report.tool_name == name
        assert report.duration_ms > 0
