"""Tests for tool adapters (import-only plugins)."""

from __future__ import annotations

import json

from deephunter.recon.plugin import PluginResult
from deephunter.tools.context import ExecutionContext
from deephunter.tools.plugins.amass_adapter import AmassAdapter
from deephunter.tools.plugins.assetfinder_adapter import AssetfinderAdapter
from deephunter.tools.plugins.httpx_adapter import HTTPxAdapter
from deephunter.tools.plugins.subfinder_adapter import SubfinderAdapter


class TestSubfinderAdapter:
    def test_parse_json(self) -> None:
        adapter = SubfinderAdapter()
        raw = json.dumps({"host": "sub.example.com", "ip": "1.2.3.4", "source": "crtsh"})
        ctx = ExecutionContext(args={"domain": "example.com"})
        parsed = adapter.parse_output(raw, ctx)
        assert len(parsed) == 1
        assert parsed[0]["host"] == "sub.example.com"

    def test_parse_json_list(self) -> None:
        adapter = SubfinderAdapter()
        raw = json.dumps([{"host": "a.com"}, {"host": "b.com"}])
        ctx = ExecutionContext()
        parsed = adapter.parse_output(raw, ctx)
        assert len(parsed) == 2

    def test_parse_txt(self) -> None:
        adapter = SubfinderAdapter()
        raw = "sub1.example.com\nsub2.example.com\n"
        ctx = ExecutionContext()
        parsed = adapter.parse_output(raw, ctx)
        assert len(parsed) == 2
        assert parsed[0]["host"] == "sub1.example.com"

    def test_parse_empty(self) -> None:
        adapter = SubfinderAdapter()
        ctx = ExecutionContext()
        assert adapter.parse_output(None, ctx) == []
        assert adapter.parse_output("", ctx) == []
        assert adapter.parse_output(b"", ctx) == []

    def test_normalize_subfinder(self) -> None:
        adapter = SubfinderAdapter()
        parsed = [{"host": "a.example.com", "ip": "1.1.1.1", "source": "crtsh"},
                   {"host": "b.example.com", "ip": "2.2.2.2"}]
        ctx = ExecutionContext(args={"domain": "example.com"})
        result = adapter.normalize(parsed, ctx)
        assert isinstance(result, PluginResult)
        assert len(result.assets) == 2
        assert len(result.hosts) == 2
        assert result.hosts[0].hostname == "a.example.com"
        assert result.hosts[1].ip == "2.2.2.2"

    def test_normalize_dedup(self) -> None:
        adapter = SubfinderAdapter()
        parsed = [{"host": "a.example.com"}, {"host": "A.EXAMPLE.COM"}]
        ctx = ExecutionContext()
        result = adapter.normalize(parsed, ctx)
        assert len(result.hosts) == 1

    def test_normalize_empty_hostname(self) -> None:
        adapter = SubfinderAdapter()
        parsed = [{"host": ""}, {"host": "valid.com"}]
        ctx = ExecutionContext()
        result = adapter.normalize(parsed, ctx)
        assert len(result.hosts) == 1

    def test_build_command(self) -> None:
        adapter = SubfinderAdapter()
        ctx = ExecutionContext(args={"domain": "test.com", "format": "json"})
        cmd = adapter.build_command(ctx)
        assert "subfinder" in cmd
        assert "test.com" in cmd

    def test_metadata(self) -> None:
        adapter = SubfinderAdapter()
        assert adapter.name == "subfinder_adapter"


class TestAssetfinderAdapter:
    def test_parse_txt(self) -> None:
        adapter = AssetfinderAdapter()
        raw = "sub1.example.com\nsub2.example.com"
        ctx = ExecutionContext()
        parsed = adapter.parse_output(raw, ctx)
        assert len(parsed) == 2

    def test_parse_bytes(self) -> None:
        adapter = AssetfinderAdapter()
        parsed = adapter.parse_output(b"sub.example.com\n", ExecutionContext())
        assert len(parsed) == 1

    def test_parse_empty(self) -> None:
        adapter = AssetfinderAdapter()
        assert adapter.parse_output(None, ExecutionContext()) == []

    def test_normalize(self) -> None:
        adapter = AssetfinderAdapter()
        parsed = ["a.example.com", "b.example.com"]
        ctx = ExecutionContext(args={"domain": "example.com"})
        result = adapter.normalize(parsed, ctx)
        assert len(result.assets) == 2
        assert len(result.hosts) == 2
        assert result.hosts[0].tags == ["assetfinder"]

    def test_normalize_dedup(self) -> None:
        adapter = AssetfinderAdapter()
        parsed = ["a.example.com", "a.example.com"]
        ctx = ExecutionContext()
        result = adapter.normalize(parsed, ctx)
        assert len(result.hosts) == 1

    def test_normalize_blank_lines(self) -> None:
        adapter = AssetfinderAdapter()
        parsed = ["", "  ", "valid.com"]
        ctx = ExecutionContext()
        result = adapter.normalize(parsed, ctx)
        assert len(result.hosts) == 1

    def test_build_command(self) -> None:
        adapter = AssetfinderAdapter()
        ctx = ExecutionContext(args={"domain": "test.com"})
        cmd = adapter.build_command(ctx)
        assert "assetfinder" in cmd

    def test_metadata(self) -> None:
        adapter = AssetfinderAdapter()
        assert adapter.name == "assetfinder_adapter"


class TestAmassAdapter:
    AMASS_JSON = '{"name":"sub.example.com","addresses":[{"ip":"1.1.1.1"}],"asn":12345,"cidr":"1.1.1.0/24"}'

    def test_parse_ndjson(self) -> None:
        adapter = AmassAdapter()
        raw = self.AMASS_JSON + "\n" + self.AMASS_JSON
        ctx = ExecutionContext()
        parsed = adapter.parse_output(raw, ctx)
        assert len(parsed) == 2

    def test_parse_txt(self) -> None:
        adapter = AmassAdapter()
        raw = "sub1.example.com\nsub2.example.com"
        ctx = ExecutionContext()
        parsed = adapter.parse_output(raw, ctx)
        assert len(parsed) == 2

    def test_parse_empty(self) -> None:
        adapter = AmassAdapter()
        assert adapter.parse_output(None, ExecutionContext()) == []

    def test_normalize_full(self) -> None:
        adapter = AmassAdapter()
        parsed = [{"name": "sub.example.com", "addresses": [{"ip": "1.1.1.1"}], "asn": 12345, "cidr": "1.1.1.0/24"}]
        ctx = ExecutionContext(args={"domain": "example.com"})
        result = adapter.normalize(parsed, ctx)
        assert len(result.assets) >= 2  # ASN asset + subdomain asset
        assert len(result.hosts) == 1
        assert result.hosts[0].hostname == "sub.example.com"
        assert result.hosts[0].ip == "1.1.1.1"
        assert len(result.hosts[0].dns_records) >= 1

    def test_normalize_asn_asset(self) -> None:
        adapter = AmassAdapter()
        parsed = [{"asn": 12345, "asn_description": "ACME CORP"}]
        ctx = ExecutionContext()
        result = adapter.normalize(parsed, ctx)
        assert any(a.asset_type == "asn" for a in result.assets)

    def test_normalize_cidr_asset(self) -> None:
        adapter = AmassAdapter()
        parsed = [{"cidr": "10.0.0.0/16"}]
        ctx = ExecutionContext()
        result = adapter.normalize(parsed, ctx)
        assert any(a.asset_type == "cidr" for a in result.assets)

    def test_normalize_dedup(self) -> None:
        adapter = AmassAdapter()
        parsed = [{"name": "sub.example.com"}, {"name": "sub.example.com"}]
        ctx = ExecutionContext()
        result = adapter.normalize(parsed, ctx)
        assert len(result.hosts) == 1

    def test_build_command(self) -> None:
        adapter = AmassAdapter()
        ctx = ExecutionContext(args={"domain": "test.com"})
        cmd = adapter.build_command(ctx)
        assert "amass" in cmd

    def test_metadata(self) -> None:
        adapter = AmassAdapter()
        assert adapter.name == "amass_adapter"


class TestHTTPxAdapter:
    HTTPX_LINE = json.dumps({
        "url": "https://example.com",
        "host": "example.com",
        "ip": "93.184.216.34",
        "port": 443,
        "status_code": 200,
        "title": "Example Domain",
        "content_type": "text/html",
        "content_length": 1256,
        "response_time": 0.152,
        "scheme": "https",
        "webserver": "ECS",
        "technologies": ["Laravel", "PHP", "Nginx"],
        "headers": {"strict-transport-security": "max-age=31536000", "x-frame-options": "DENY"},
    })

    def test_parse_ndjson(self) -> None:
        adapter = HTTPxAdapter()
        raw = self.HTTPX_LINE + "\n" + self.HTTPX_LINE
        ctx = ExecutionContext()
        parsed = adapter.parse_output(raw, ctx)
        assert len(parsed) == 2

    def test_parse_txt(self) -> None:
        adapter = HTTPxAdapter()
        raw = "https://example.com\nhttps://test.com"
        ctx = ExecutionContext()
        parsed = adapter.parse_output(raw, ctx)
        assert len(parsed) == 2
        assert parsed[0]["url"] == "https://example.com"

    def test_parse_empty(self) -> None:
        adapter = HTTPxAdapter()
        assert adapter.parse_output(None, ExecutionContext()) == []

    def test_normalize_full(self) -> None:
        adapter = HTTPxAdapter()
        import json
        parsed = [json.loads(self.HTTPX_LINE)]
        ctx = ExecutionContext(args={"target": "example.com"})
        result = adapter.normalize(parsed, ctx)
        assert len(result.hosts) == 1
        assert len(result.http_observations) == 1
        assert len(result.technologies) >= 3
        assert len(result.applications) >= 1
        obs = result.http_observations[0]
        assert obs.status_code == 200
        assert obs.title == "Example Domain"
        assert len(obs.security_headers) >= 2

    def test_normalize_host_from_httpx(self) -> None:
        adapter = HTTPxAdapter()
        import json
        parsed = [json.loads(self.HTTPX_LINE)]
        ctx = ExecutionContext()
        result = adapter.normalize(parsed, ctx)
        host = result.hosts[0]
        assert host.hostname == "example.com"
        assert host.ip == "93.184.216.34"
        assert host.port == 443
        assert host.title == "Example Domain"

    def test_normalize_technologies(self) -> None:
        adapter = HTTPxAdapter()
        parsed = [{"url": "https://x.com", "technologies": ["React", "Node.js", "Express"]}]
        ctx = ExecutionContext()
        result = adapter.normalize(parsed, ctx)
        assert len(result.technologies) == 3
        assert any(t.name == "React" for t in result.technologies)

    def test_security_headers(self) -> None:
        adapter = HTTPxAdapter()
        parsed = [{"url": "https://x.com", "headers": {"strict-transport-security": "max-age=31536000", "x-frame-options": "DENY"}}]
        ctx = ExecutionContext()
        result = adapter.normalize(parsed, ctx)
        obs = result.http_observations[0]
        assert len(obs.security_headers) >= 2
        hsts = next(sh for sh in obs.security_headers if sh.name.value == "strict-transport-security")
        assert hsts.present is True
        assert hsts.secure is True

    def test_normalize_webserver_as_tech(self) -> None:
        adapter = HTTPxAdapter()
        parsed = [{"url": "https://x.com", "webserver": "Nginx"}]
        ctx = ExecutionContext()
        result = adapter.normalize(parsed, ctx)
        assert any(t.name == "Nginx" for t in result.technologies)

    def test_build_command(self) -> None:
        adapter = HTTPxAdapter()
        ctx = ExecutionContext(args={"target": "test.com"})
        assert "httpx" in adapter.build_command(ctx)

    def test_metadata(self) -> None:
        adapter = HTTPxAdapter()
        assert adapter.name == "httpx_adapter"

    def test_normalize_empty_urls(self) -> None:
        adapter = HTTPxAdapter()
        parsed = [{"url": ""}, {"url": "https://valid.com"}]
        ctx = ExecutionContext()
        result = adapter.normalize(parsed, ctx)
        assert len(result.http_observations) == 1

    def test_scheme_http(self) -> None:
        adapter = HTTPxAdapter()
        parsed = [{"url": "http://x.com", "scheme": "http", "host": "x.com"}]
        ctx = ExecutionContext()
        result = adapter.normalize(parsed, ctx)
        assert result.hosts[0].protocol.value == "http"

    def test_content_type_application_json(self) -> None:
        adapter = HTTPxAdapter()
        parsed = [{"url": "https://api.x.com", "host": "api.x.com", "content_type": "application/json", "status_code": 200}]
        ctx = ExecutionContext()
        result = adapter.normalize(parsed, ctx)
        assert any(a.app_type.value == "api" for a in result.applications)
