from __future__ import annotations

from typing import Any

from deephunter.recon.models import Endpoint, EndpointCategory, HttpMethod, Parameter, ParamLocation, ReconSourceType
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolMetadata
from deephunter.tools.normalizer import parse_txt


class GauAdapter(BaseToolPlugin):
    metadata = ToolMetadata(
        name="gau",
        description="Get all URLs from AlienVault, Wayback Machine, CommonCrawl, and URLScan via gau",
        version="1.0.0",
        category=ToolCategory.url_discovery,
        tags=["url", "discovery", "wayback", "alienvault", "commoncrawl", "urlscan"],
        supported_formats=["txt"],
        requires_network=True,
        requires_installation=True,
        timeout_default=120.0,
        retry_default=1,
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        import shlex
        import subprocess

        domain = context.args.get("domain", context.target)
        cmd = f"gau {shlex.quote(domain)}"
        try:
            proc = subprocess.run(
                shlex.split(cmd),
                capture_output=True,
                text=True,
                timeout=context.get_plugin_timeout(),
                env=context.env,
            )
            return proc.stdout
        except subprocess.TimeoutExpired:
            return None

    def parse_output(self, raw: str | bytes | None, context: ExecutionContext) -> list[str]:
        if not raw:
            return []
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        return parse_txt(raw, {})

    def normalize(self, parsed: list[str], context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        seen: set[str] = set()
        for url in parsed:
            url = url.strip()
            if not url or url in seen:
                continue
            seen.add(url)
            endpoint = Endpoint(
                path=url,
                method=HttpMethod.GET,
                category=self._categorize_url(url),
                source=ReconSourceType.URL_COLLECTION,
                metadata={"tool": "gau"},
            )
            result.endpoints.append(endpoint)
        result.success = True
        return result

    @staticmethod
    def _categorize_url(url: str) -> EndpointCategory:
        lower = url.lower()
        if "/api/" in lower or "/v1/" in lower or "/v2/" in lower or "/graphql" in lower:
            return EndpointCategory.API
        if "/admin" in lower or "/wp-admin" in lower or "/dashboard" in lower:
            return EndpointCategory.ADMIN
        if "/login" in lower or "/signin" in lower or "/auth" in lower:
            if "/login" in lower:
                return EndpointCategory.LOGIN
            return EndpointCategory.AUTH
        if "/logout" in lower or "/signout" in lower:
            return EndpointCategory.LOGOUT
        if "/register" in lower or "/signup" in lower:
            return EndpointCategory.REGISTER
        if "/reset" in lower or "/forgot" in lower:
            return EndpointCategory.PASSWORD_RESET
        if "/upload" in lower:
            return EndpointCategory.FILE_UPLOAD
        if "/download" in lower:
            return EndpointCategory.FILE_DOWNLOAD
        if "/search" in lower or "/query" in lower:
            return EndpointCategory.SEARCH
        if "/ws" in lower or "/websocket" in lower or lower.startswith("ws://") or lower.startswith("wss://"):
            return EndpointCategory.WEBSOCKET
        if "/webhook" in lower:
            return EndpointCategory.WEBHOOK
        if "/health" in lower or "/healthz" in lower or "/ping" in lower:
            return EndpointCategory.HEALTH
        if "/metrics" in lower or "/debug" in lower or "/trace" in lower:
            return EndpointCategory.METRICS
        if url.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs")):
            return EndpointCategory.UNKNOWN
        if url.endswith((".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2")):
            return EndpointCategory.STATIC
        return EndpointCategory.UNKNOWN

    def health(self, context: ExecutionContext) -> PluginHealth:
        import shutil
        found = shutil.which("gau") is not None
        return PluginHealth(
            healthy=found,
            installed=found,
            executable_found=found,
            errors=[] if found else ["gau not found on PATH"],
        )

    def build_command(self, context: ExecutionContext) -> str:
        domain = context.args.get("domain", context.target)
        return f"gau {domain}"
