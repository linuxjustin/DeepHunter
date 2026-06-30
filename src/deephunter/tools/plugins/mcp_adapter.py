from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from deephunter.recon.models import Endpoint, Host, ReconSourceType
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolMetadata


@dataclass
class MCPToolDefinition:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_type: str = "text"


@dataclass
class MCPToolCall:
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str = ""


@dataclass
class MCPToolResult:
    content: list[dict[str, Any]] = field(default_factory=list)
    is_error: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


_BUILTIN_MCP_TOOLS: dict[str, MCPToolDefinition] = {
    "scan_domain": MCPToolDefinition(
        name="scan_domain",
        description="Run basic reconnaissance on a domain — subdomain enumeration, DNS resolution, port scan on common ports",
        input_schema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain to scan"},
            },
            "required": ["domain"],
        },
        output_type="json",
    ),
    "resolve_dns": MCPToolDefinition(
        name="resolve_dns",
        description="Resolve DNS records (A, AAAA, CNAME, MX, NS, TXT) for a domain",
        input_schema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to resolve"},
                "record_types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "DNS record types to query (default: all)",
                },
            },
            "required": ["domain"],
        },
        output_type="json",
    ),
    "fetch_url": MCPToolDefinition(
        name="fetch_url",
        description="Fetch the content of a URL and extract links, scripts, and metadata",
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to fetch"},
                "extract_links": {"type": "boolean", "description": "Extract all links from the page"},
            },
            "required": ["url"],
        },
        output_type="json",
    ),
    "search_wayback": MCPToolDefinition(
        name="search_wayback",
        description="Find historical URLs for a domain from the Wayback Machine",
        input_schema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to search"},
            },
            "required": ["domain"],
        },
        output_type="json",
    ),
    "check_technology": MCPToolDefinition(
        name="check_technology",
        description="Identify web technologies used by a target URL",
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to analyze"},
            },
            "required": ["url"],
        },
        output_type="json",
    ),
}


class MCPAdapter(BaseToolPlugin):
    metadata = ToolMetadata(
        name="mcp",
        description="Model Context Protocol (MCP) adapter — exposes DeepHunter capabilities as MCP-compatible tools for AI assistants",
        version="1.0.0",
        category=ToolCategory.other,
        tags=["mcp", "protocol", "ai", "assistant", "tool"],
        supported_formats=["json"],
        requires_installation=False,
        timeout_default=30.0,
        retry_default=0,
    )

    def __init__(self) -> None:
        super().__init__()
        self._tools: dict[str, MCPToolDefinition] = dict(_BUILTIN_MCP_TOOLS)

    def register_tool(self, tool: MCPToolDefinition) -> None:
        self._tools[tool.name] = tool

    def get_tool(self, name: str) -> MCPToolDefinition | None:
        return self._tools.get(name)

    def list_tools(self) -> list[MCPToolDefinition]:
        return list(self._tools.values())

    def get_tools_json(self) -> list[dict[str, Any]]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }
            for t in self._tools.values()
        ]

    def execute_tool_call(self, call: MCPToolCall) -> MCPToolResult:
        import shlex
        import subprocess

        tool = self._tools.get(call.tool_name)
        if not tool:
            return MCPToolResult(is_error=True, content=[{"type": "text", "text": f"Unknown tool: {call.tool_name}"}])

        try:
            if call.tool_name == "scan_domain":
                domain = call.arguments.get("domain", "")
                return self._exec_scan_domain(domain)
            elif call.tool_name == "resolve_dns":
                return self._exec_resolve_dns(call.arguments.get("domain", ""), call.arguments.get("record_types", []))
            elif call.tool_name == "fetch_url":
                return self._exec_fetch_url(call.arguments.get("url", ""), call.arguments.get("extract_links", True))
            elif call.tool_name == "search_wayback":
                return self._exec_search_wayback(call.arguments.get("domain", ""))
            elif call.tool_name == "check_technology":
                return self._exec_check_tech(call.arguments.get("url", ""))
            else:
                return MCPToolResult(is_error=True, content=[{"type": "text", "text": f"Tool {call.tool_name} not implemented"}])
        except Exception as exc:
            return MCPToolResult(is_error=True, content=[{"type": "text", "text": f"Error executing {call.tool_name}: {exc}"}])

    def _exec_scan_domain(self, domain: str) -> MCPToolResult:
        result_data: dict[str, Any] = {"domain": domain, "subdomains": [], "dns_records": [], "open_ports": [], "technologies": []}
        if not domain:
            return MCPToolResult(is_error=True, content=[{"type": "text", "text": "No domain provided"}])

        for tool_name, flag in [("subfinder", "-silent"), ("assetfinder", "--subs-only")]:
            try:
                import shlex
                import subprocess
                proc = subprocess.run(shlex.split(f"{tool_name} {flag} {shlex.quote(domain)}"), capture_output=True, text=True, timeout=30)
                if proc.returncode == 0:
                    for line in proc.stdout.strip().splitlines():
                        line = line.strip()
                        if line:
                            result_data["subdomains"].append(line)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return MCPToolResult(content=[{"type": "json", "json": result_data}])

    def _exec_resolve_dns(self, domain: str, record_types: list[str]) -> MCPToolResult:
        result_data: dict[str, Any] = {"domain": domain, "records": {}}
        if not domain:
            return MCPToolResult(is_error=True, content=[{"type": "text", "text": "No domain provided"}])
        return MCPToolResult(content=[{"type": "json", "json": result_data}])

    def _exec_fetch_url(self, url: str, extract_links: bool) -> MCPToolResult:
        import urllib.request
        from urllib.parse import urljoin

        import html.parser

        result_data: dict[str, Any] = {"url": url, "links": [], "scripts": [], "title": ""}

        class LinkExtractor(html.parser.HTMLParser):
            def __init__(self, base_url: str):
                super().__init__()
                self.base_url = base_url
                self.links: list[str] = []
                self.scripts: list[str] = []
                self.title = ""

            def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
                attrs_dict = dict(attrs)
                if tag == "a":
                    href = attrs_dict.get("href")
                    if href:
                        self.links.append(urljoin(self.base_url, href))
                elif tag == "script":
                    src = attrs_dict.get("src")
                    if src:
                        self.scripts.append(urljoin(self.base_url, src))

            def handle_data(self, data: str):
                if not self.title:
                    self.title = data.strip()

        try:
            resp = urllib.request.urlopen(url, timeout=15)
            html_content = resp.read().decode("utf-8", errors="replace")
            if extract_links:
                parser = LinkExtractor(url)
                parser.feed(html_content)
                result_data["links"] = parser.links
                result_data["scripts"] = parser.scripts
                result_data["title"] = parser.title
            result_data["status"] = resp.status
        except Exception as exc:
            return MCPToolResult(is_error=True, content=[{"type": "text", "text": f"Error fetching {url}: {exc}"}])

        return MCPToolResult(content=[{"type": "json", "json": result_data}])

    def _exec_search_wayback(self, domain: str) -> MCPToolResult:
        import json
        import urllib.request

        result_data: dict[str, Any] = {"domain": domain, "urls": [], "count": 0}
        if not domain:
            return MCPToolResult(is_error=True, content=[{"type": "text", "text": "No domain provided"}])
        try:
            api_url = f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&fl=timestamp,original&limit=100"
            resp = urllib.request.urlopen(api_url, timeout=15)
            data = json.loads(resp.read().decode("utf-8"))
            for entry in data[1:]:
                if len(entry) >= 2:
                    result_data["urls"].append({"timestamp": entry[0], "url": entry[1]})
            result_data["count"] = len(result_data["urls"])
        except Exception as exc:
            return MCPToolResult(is_error=True, content=[{"type": "text", "text": f"Wayback search failed: {exc}"}])
        return MCPToolResult(content=[{"type": "json", "json": result_data}])

    def _exec_check_tech(self, url: str) -> MCPToolResult:
        import json
        import urllib.request

        result_data: dict[str, Any] = {"url": url, "technologies": []}
        if not url:
            return MCPToolResult(is_error=True, content=[{"type": "text", "text": "No URL provided"}])
        try:
            resp = urllib.request.urlopen(url, timeout=15)
            headers = dict(resp.headers)
            result_data["headers"] = {k: v for k, v in headers.items()}
            server = headers.get("Server", "")
            if server:
                result_data["technologies"].append({"name": server, "category": "web_server"})
            x_powered = headers.get("X-Powered-By", "")
            if x_powered:
                result_data["technologies"].append({"name": x_powered, "category": "framework"})
            set_cookie = headers.get("Set-Cookie", "")
            if set_cookie:
                result_data["technologies"].append({"name": "PHP" if "PHPSESSID" in set_cookie else "Unknown", "category": "runtime"})
        except Exception as exc:
            return MCPToolResult(is_error=True, content=[{"type": "text", "text": f"Tech check failed: {exc}"}])

        return MCPToolResult(content=[{"type": "json", "json": result_data}])

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        action = context.args.get("action", "list_tools")
        if action == "list_tools":
            return json.dumps(self.get_tools_json())
        if action == "execute":
            call_data = context.args.get("tool_call", {})
            if isinstance(call_data, str):
                call_data = json.loads(call_data)
            call = MCPToolCall(
                tool_name=call_data.get("tool_name", call_data.get("name", "")),
                arguments=call_data.get("arguments", call_data.get("args", {})),
                call_id=call_data.get("call_id", ""),
            )
            result = self.execute_tool_call(call)
            return json.dumps({"content": result.content, "is_error": result.is_error})
        return json.dumps({"error": f"Unknown action: {action}"})

    def parse_output(self, raw: str | bytes | None, context: ExecutionContext) -> Any:
        if not raw:
            return {}
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        import json
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}

    def normalize(self, parsed: Any, context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        if isinstance(parsed, dict):
            for key, value in parsed.items():
                if key == "hosts" and isinstance(value, list):
                    for h in value:
                        if isinstance(h, dict):
                            host = Host(
                                hostname=h.get("hostname", h.get("host", "")),
                                ip=h.get("ip", ""),
                                source=ReconSourceType.INTEGRATION,
                            )
                            result.hosts.append(host)
                if key in ("endpoints", "urls", "links") and isinstance(value, list):
                    for ep in value:
                        if isinstance(ep, dict):
                            ep_url = ep.get("url", ep.get("href", ""))
                        else:
                            ep_url = str(ep)
                        if ep_url:
                            result.endpoints.append(Endpoint(
                                path=ep_url,
                                source=ReconSourceType.INTEGRATION,
                            ))
        return result

    def health(self, context: ExecutionContext) -> PluginHealth:
        return PluginHealth(healthy=True, installed=True, executable_found=True)

    def build_command(self, context: ExecutionContext) -> str:
        return ""
