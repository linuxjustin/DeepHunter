"""HTTPx output adapter — imports HTTP probing results.

Input formats supported:
  - JSONL: httpx JSONL format (one JSON object per probe result)
  - JSON: httpx JSON output
  - TXT: one URL per line

Normalizes into:
  - HTTPObservation
  - Technology (from observed tech stack)
  - Application (from web server, framework info)
  - SecurityHeader
  - Host (updates status, title)
"""

from __future__ import annotations

from typing import Any

from deephunter.recon.models import (
    Application,
    ApplicationType,
    HTTPHeader,
    HTTPObservation,
    Host,
    HostStatus,
    HttpMethod,
    Protocol,
    ReconSourceType,
    SecurityHeader,
    SecurityHeaderName,
    Technology,
    TechCategory,
)
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import ToolCategory, ToolMetadata
from deephunter.tools.normalizer import parse_ndjson, parse_txt


_SECURITY_HEADER_NAMES = {
    h.value: h for h in SecurityHeaderName
}


class HTTPxAdapter(BaseToolPlugin):
    metadata = ToolMetadata(
        name="httpx_adapter",
        description="Import httpx HTTP probing output (JSONL, TXT) into recon models",
        version="1.0.0",
        category=ToolCategory.web_probe,
        tags=["http", "probe", "httpx", "import", "adapter"],
        supported_formats=["ndjson", "json", "txt"],
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        raise NotImplementedError("HTTPxAdapter is import-only; use parse_output() with pre-collected output")

    def parse_output(self, raw: str | bytes | None, context: ExecutionContext) -> list[dict[str, Any]]:
        if not raw:
            return []
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")

        raw_str = raw.strip()
        if not raw_str:
            return []

        if raw_str.startswith("{"):
            return parse_ndjson(raw_str, {})

        lines = parse_txt(raw_str, {})
        return [{"url": line} for line in lines]

    def _parse_security_headers(self, headers: dict[str, str]) -> list[SecurityHeader]:
        security: list[SecurityHeader] = []
        for name, value in headers.items():
            low_name = name.lower().strip()
            if low_name in _SECURITY_HEADER_NAMES:
                sh_name = _SECURITY_HEADER_NAMES[low_name]
                is_secure = self._evaluate_security_header(sh_name, value)
                security.append(SecurityHeader(
                    name=sh_name,
                    value=value,
                    present=True,
                    secure=is_secure,
                ))
        return security

    @staticmethod
    def _evaluate_security_header(name: SecurityHeaderName, value: str) -> bool:
        if name == SecurityHeaderName.STRICT_TRANSPORT_SECURITY:
            return "max-age" in value and "preload" not in value.lower()
        if name == SecurityHeaderName.X_FRAME_OPTIONS:
            return value.lower() in ("deny", "sameorigin")
        if name == SecurityHeaderName.X_CONTENT_TYPE_OPTIONS:
            return value.lower() == "nosniff"
        if name == SecurityHeaderName.REFERRER_POLICY:
            return True
        return bool(value.strip())

    def _parse_tech_category(self, tech_name: str) -> TechCategory:
        name = tech_name.lower().strip()
        if name in {"nginx", "apache", "iis", "caddy", "tomcat", "jetty", "httpd", "lighttpd"}:
            return TechCategory.WEB_SERVER
        if name in {"laravel", "django", "rails", "spring", "express", "flask", "fastapi", "asp.net", "next.js", "nuxt.js"}:
            return TechCategory.FRAMEWORK
        if name in {"php", "python", "node.js", "ruby", "java", "go", "rust", "dotnet"}:
            return TechCategory.RUNTIME
        if name in {"react", "vue.js", "angular", "jquery", "bootstrap", "tailwind"}:
            return TechCategory.FRONTEND
        if name in {"wordpress", "drupal", "magento", "joomla", "shopify"}:
            return TechCategory.CMS
        if name in {"cloudflare", "akamai", "cloudfront", "fastly", "incapsula"}:
            return TechCategory.CDN
        if name in {"waf", "modsecurity", "cloudflare waf"}:
            return TechCategory.WAF
        return TechCategory.UNKNOWN

    def _infer_application_type(self, techs: list[str], title: str, content_type: str) -> ApplicationType:
        tech_lower = " ".join(t.lower() for t in techs)
        if any(t in tech_lower for t in {"api", "graphql", "rest"}):
            return ApplicationType.API
        if "admin" in title.lower() or "admin" in tech_lower:
            return ApplicationType.ADMIN_PANEL
        if any(t in tech_lower for t in {"react", "vue", "angular", "nuxt"}):
            return ApplicationType.SINGLE_PAGE_APP
        if "dashboard" in title.lower():
            return ApplicationType.DASHBOARD
        if content_type and "application/json" in content_type:
            return ApplicationType.API
        return ApplicationType.WEB_APP

    def normalize(self, parsed: list[dict[str, Any]], context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        seen_urls: set[str] = set()

        for entry in parsed:
            url = entry.get("url", "") or ""
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)

            hostname = entry.get("host", "") or entry.get("input", "") or ""
            ip = entry.get("ip", "") or (entry.get("a", [""])[0] if isinstance(entry.get("a"), list) else "")
            port = int(entry.get("port", 443))
            status_code = entry.get("status_code", 0) or 0
            title = entry.get("title", "") or ""
            content_type = entry.get("content_type", "") or entry.get("content-length", "") or ""
            content_length = int(entry.get("content_length", 0) or 0)
            response_time = float(entry.get("response_time", entry.get("duration", 0)) or 0)
            scheme = entry.get("scheme", "https") or "https"
            webserver = entry.get("webserver", "") or entry.get("server", "") or ""
            tech_list: list[str] = entry.get("technologies", []) or []
            redirect_chain: list[str] = entry.get("chain", []) or []
            body_preview = entry.get("body_preview", "") or ""

            raw_headers: dict[str, str] = entry.get("headers", {}) or {}
            header_objs: list[HTTPHeader] = []
            for hname, hvalue in raw_headers.items():
                header_objs.append(HTTPHeader(name=hname, value=str(hvalue)))

            security_headers = self._parse_security_headers(raw_headers)

            protocol = Protocol.HTTPS if scheme == "https" else Protocol.HTTP

            # ── Host ─────────────────────────────────────────────
            if hostname:
                host = Host(
                    hostname=hostname.lower().strip(),
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    status=self._map_status(status_code),
                    title=title,
                    source=ReconSourceType.HTTP_PROBE,
                    metadata={
                        "url": url,
                        "status_code": status_code,
                        "content_type": content_type,
                        "content_length": content_length,
                        "webserver": webserver,
                        "response_time_ms": response_time,
                        "tech_stack": tech_list,
                    },
                )
                result.hosts.append(host)

            # ── HTTP Observation ─────────────────────────────────
            obs = HTTPObservation(
                url=url,
                method=HttpMethod.GET,
                status_code=status_code,
                response_size=content_length,
                content_type=content_type,
                response_time_ms=response_time,
                headers=header_objs,
                security_headers=security_headers,
                title=title,
                technologies=tech_list,
                redirect_chain=redirect_chain,
                body_preview=body_preview,
                source=ReconSourceType.HTTP_PROBE,
            )
            result.http_observations.append(obs)

            # ── Technologies ─────────────────────────────────────
            seen_tech: set[str] = set()
            for tname in tech_list:
                tname_lower = tname.lower().strip()
                if tname_lower in seen_tech:
                    continue
                seen_tech.add(tname_lower)
                tech = Technology(
                    name=tname,
                    category=self._parse_tech_category(tname),
                    source=ReconSourceType.TECHNOLOGY_FINGERPRINT,
                    metadata={"detected_by": "httpx", "url": url},
                )
                result.technologies.append(tech)

            if webserver and webserver.lower() not in seen_tech:
                tech = Technology(
                    name=webserver,
                    category=TechCategory.WEB_SERVER,
                    source=ReconSourceType.TECHNOLOGY_FINGERPRINT,
                    metadata={"detected_by": "httpx", "url": url, "type": "webserver"},
                )
                result.technologies.append(tech)

            # ── Application ──────────────────────────────────────
            app_type = self._infer_application_type(tech_list, title, content_type)
            app_name = webserver or title or f"webapp on {hostname}"
            app = Application(
                name=app_name,
                app_type=app_type,
                base_path="/",
                tags=tech_list,
                metadata={"url": url, "title": title, "tech_stack": tech_list},
            )
            result.applications.append(app)

        result.success = True
        return result

    @staticmethod
    def _map_status(code: int) -> HostStatus:
        if 200 <= code < 400:
            return HostStatus.ACTIVE
        if 400 <= code < 500:
            return HostStatus.REDIRECT if code in (301, 302, 307, 308) else HostStatus.ACTIVE
        return HostStatus.UNKNOWN

    def build_command(self, context: ExecutionContext) -> str:
        target = context.args.get("target", context.target)
        return f"httpx -u {target} -json"
