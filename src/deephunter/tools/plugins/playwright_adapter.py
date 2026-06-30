from __future__ import annotations

from typing import Any

from deephunter.recon.models import (
    Endpoint,
    EndpointCategory,
    HTTPHeader,
    HTTPObservation,
    HttpMethod,
    JavaScriptFile,
    ReconSourceType,
    Technology,
    TechCategory,
)
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolMetadata
from deephunter.tools.normalizer import parse_json


class PlaywrightAdapter(BaseToolPlugin):
    metadata = ToolMetadata(
        name="playwright",
        description="Browser automation via Playwright — captures page content, JavaScript files, network requests, and console output",
        version="1.0.0",
        category=ToolCategory.js_analysis,
        tags=["browser", "javascript", "automation", "playwright"],
        supported_formats=["json", "txt"],
        requires_installation=True,
        timeout_default=60.0,
        retry_default=0,
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        raise NotImplementedError("PlaywrightAdapter is import-only; use parse_output() with pre-collected Playwright output")

    def parse_output(self, raw: str | bytes | None, context: ExecutionContext) -> dict[str, Any]:
        if not raw:
            return {}
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        try:
            return parse_json(raw, {})
        except Exception:
            return {"raw": raw.strip()}

    def normalize(self, parsed: dict[str, Any], context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        seen_urls: set[str] = set()

        url = parsed.get("url", "") or ""
        title = parsed.get("title", "") or ""
        content = parsed.get("content", "") or ""
        js_files_list = parsed.get("jsFiles", []) or parsed.get("js_files", []) or []
        endpoints_list = parsed.get("endpoints", []) or parsed.get("urls", []) or []
        console_logs = parsed.get("console", []) or parsed.get("console_logs", []) or []
        cookies = parsed.get("cookies", []) or []
        local_storage = parsed.get("localStorage", {}) or {}
        session_storage = parsed.get("sessionStorage", {}) or {}
        techs = parsed.get("technologies", []) or parsed.get("techs", []) or []

        if url:
            obs = HTTPObservation(
                url=url,
                method=HttpMethod.GET,
                status_code=200,
                title=title,
                content_type="text/html",
                source=ReconSourceType.WEB_CRAWL,
            )
            result.http_observations.append(obs)

        for js_url in js_files_list:
            if isinstance(js_url, dict):
                js_url = js_url.get("url", "") or ""
            js_s = str(js_url).strip()
            if js_s and js_s not in seen_urls:
                seen_urls.add(js_s)
                js_file = JavaScriptFile(
                    url=js_s,
                    source=ReconSourceType.JAVASCRIPT_ANALYSIS,
                    metadata={"discovered_by": "playwright"},
                )
                result.js_files.append(js_file)

        for ep_url in endpoints_list:
            if isinstance(ep_url, dict):
                ep_url = ep_url.get("url", "") or ""
            ep_s = str(ep_url).strip()
            if ep_s and ep_s not in seen_urls:
                seen_urls.add(ep_s)
                endpoint = Endpoint(
                    path=ep_s,
                    method=HttpMethod.GET,
                    category=self._categorize(ep_s),
                    source=ReconSourceType.JAVASCRIPT_ANALYSIS,
                    metadata={"discovered_by": "playwright"},
                )
                result.endpoints.append(endpoint)

        for tech_name in techs:
            if isinstance(tech_name, dict):
                tech_name = tech_name.get("name", "") or tech_name.get("slug", "") or ""
            tname = str(tech_name).strip()
            if tname:
                tech = Technology(
                    name=tname,
                    category=TechCategory.FRAMEWORK,
                    source=ReconSourceType.TECHNOLOGY_FINGERPRINT,
                    metadata={"detected_by": "playwright"},
                )
                result.technologies.append(tech)

        result.success = True
        return result

    @staticmethod
    def _categorize(url: str) -> EndpointCategory:
        lower = url.lower()
        if "/api/" in lower or "/graphql" in lower or "/v1/" in lower:
            return EndpointCategory.API
        if "/admin" in lower or "/dashboard" in lower:
            return EndpointCategory.ADMIN
        if "/login" in lower or "/auth" in lower:
            return EndpointCategory.AUTH
        if url.endswith((".js", ".jsx", ".mjs")):
            return EndpointCategory.UNKNOWN
        if url.endswith((".css", ".png", ".jpg", ".svg", ".ico")):
            return EndpointCategory.STATIC
        return EndpointCategory.UNKNOWN

    def health(self, context: ExecutionContext) -> PluginHealth:
        try:
            import playwright  # noqa: F401
            return PluginHealth(healthy=True, installed=True, executable_found=True)
        except ImportError:
            return PluginHealth(
                healthy=False,
                installed=False,
                executable_found=False,
                errors=["playwright Python package not installed; run: pip install playwright"],
            )

    def build_command(self, context: ExecutionContext) -> str:
        target = context.args.get("url", context.target)
        return f"playwright open {target}"
