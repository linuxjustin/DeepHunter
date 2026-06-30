from __future__ import annotations

from typing import Any

from deephunter.recon.models import Endpoint, EndpointCategory, HttpMethod, JavaScriptFile, ReconSourceType
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolMetadata
from deephunter.tools.normalizer import parse_ndjson, parse_txt


class KatanaAdapter(BaseToolPlugin):
    metadata = ToolMetadata(
        name="katana",
        description="Web crawler via Katana — discovers URLs, endpoints, JavaScript files, and forms",
        version="1.0.0",
        category=ToolCategory.url_discovery,
        tags=["crawler", "url", "discovery", "spider", "katana"],
        supported_formats=["ndjson", "txt"],
        requires_network=True,
        requires_installation=True,
        timeout_default=300.0,
        retry_default=0,
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        import shlex
        import subprocess

        target = context.args.get("url", context.target)
        depth = context.args.get("depth", "2")
        cmd = f"katana -u {shlex.quote(target)} -d {depth} -jsonl"
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

    def parse_output(self, raw: str | bytes | None, context: ExecutionContext) -> list[dict[str, Any]]:
        if not raw:
            return []
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if raw.strip().startswith("{"):
            return parse_ndjson(raw, {})
        lines = parse_txt(raw, {})
        return [{"url": line} for line in lines]

    def normalize(self, parsed: list[dict[str, Any]], context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        seen_urls: set[str] = set()
        seen_js: set[str] = set()

        for entry in parsed:
            url = entry.get("url", "") or ""
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)

            source = entry.get("source", "") or ""
            technique = entry.get("technique", "") or ""
            status_code = entry.get("status_code", 0) or 0
            content_type = entry.get("content_type", "") or ""
            body_len = entry.get("body_length", 0) or 0
            extracted = entry.get("extracted", {}) or {}

            is_js = url.endswith((".js", ".jsx", ".mjs")) or "javascript" in content_type.lower()
            if is_js:
                if url not in seen_js:
                    seen_js.add(url)
                    js_file = JavaScriptFile(
                        url=url,
                        size=body_len,
                        source=ReconSourceType.WEB_CRAWL,
                        metadata={"discovered_by": "katana", "technique": technique},
                    )
                    result.js_files.append(js_file)

            endpoint = Endpoint(
                path=url,
                method=HttpMethod.GET,
                category=self._classify_endpoint(url, content_type, status_code),
                status_code=status_code if status_code > 0 else None,
                content_length=body_len,
                source=ReconSourceType.WEB_CRAWL,
                metadata={
                    "tool": "katana",
                    "technique": technique,
                    "source": source,
                    "content_type": content_type,
                },
            )
            result.endpoints.append(endpoint)

        result.success = True
        return result

    @staticmethod
    def _classify_endpoint(url: str, content_type: str, status_code: int) -> EndpointCategory:
        lower = url.lower()
        if status_code == 403 or status_code == 401:
            return EndpointCategory.ADMIN if "admin" in lower else EndpointCategory.AUTH
        if "/api/" in lower or "/v1/" in lower or "/v2/" in lower or "/graphql" in lower:
            return EndpointCategory.API
        if "/admin" in lower or "/wp-admin" in lower or "/dashboard" in lower:
            return EndpointCategory.ADMIN
        if "/login" in lower or "/signin" in lower or "/auth" in lower:
            return EndpointCategory.LOGIN if "/login" in lower else EndpointCategory.AUTH
        if "/logout" in lower:
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
        if "/ws" in lower or "/websocket" in lower:
            return EndpointCategory.WEBSOCKET
        if "/webhook" in lower:
            return EndpointCategory.WEBHOOK
        if "/health" in lower or "/ping" in lower:
            return EndpointCategory.HEALTH
        if "/metrics" in lower or "/debug" in lower:
            return EndpointCategory.METRICS
        if url.endswith((".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2")):
            return EndpointCategory.STATIC
        return EndpointCategory.UNKNOWN

    def health(self, context: ExecutionContext) -> PluginHealth:
        import shutil
        found = shutil.which("katana") is not None
        return PluginHealth(
            healthy=found,
            installed=found,
            executable_found=found,
            errors=[] if found else ["katana not found on PATH"],
        )

    def build_command(self, context: ExecutionContext) -> str:
        target = context.args.get("url", context.target)
        depth = context.args.get("depth", "2")
        return f"katana -u {target} -d {depth} -jsonl"
