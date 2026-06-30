from __future__ import annotations

import base64
import io
from typing import Any
from xml.etree import ElementTree

from deephunter.recon.models import (
    Endpoint,
    EndpointCategory,
    HTTPHeader,
    HTTPObservation,
    HttpMethod,
    Parameter,
    ParamLocation,
    ParamType,
    ReconSourceType,
)
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolMetadata
from deephunter.tools.normalizer import parse_ndjson


class BurpAdapter(BaseToolPlugin):
    metadata = ToolMetadata(
        name="burp",
        description="Import Burp Suite project output (XML or JSON) into recon models — sites, endpoints, parameters, issues",
        version="1.0.0",
        category=ToolCategory.web_probe,
        tags=["burp", "proxy", "import", "adapter"],
        supported_formats=["xml", "json"],
        requires_installation=False,
        timeout_default=60.0,
        retry_default=0,
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        raise NotImplementedError("BurpAdapter is import-only; use parse_output() with pre-collected Burp Suite XML/JSON output")

    def parse_output(self, raw: str | bytes | None, context: ExecutionContext) -> list[dict[str, Any]]:
        if not raw:
            return []
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        raw = raw.strip()
        if not raw:
            return []

        if raw.startswith("<"):
            return self._parse_xml(raw)
        return parse_ndjson(raw, {})

    def _parse_xml(self, raw: str) -> list[dict[str, Any]]:
        try:
            tree = ElementTree.parse(io.StringIO(raw))
            root = tree.getroot()
        except ElementTree.ParseError:
            return [{"raw": raw}]

        results: list[dict[str, Any]] = []

        items = root.findall(".//item")
        if items:
            for item in items:
                entry = self._xml_item_to_dict(item)
                if entry:
                    results.append(entry)
            return results

        issues = root.findall(".//issue")
        if issues:
            for issue in issues:
                entry = self._xml_issue_to_dict(issue)
                if entry:
                    results.append(entry)
            return results

        return [{"raw": raw}]

    @staticmethod
    def _xml_item_to_dict(item: Any) -> dict[str, Any] | None:
        def text(tag: str) -> str:
            el = item.find(tag)
            return el.text or "" if el is not None else ""

        def maybe_decode_b64(val: str) -> str:
            try:
                decoded = base64.b64decode(val)
                return decoded.decode("utf-8", errors="replace")
            except Exception:
                return val

        url = text("url")
        if not url:
            return None

        host = text("host")
        port = text("port")
        protocol = text("protocol")
        method = text("method") or "GET"
        path = text("path")

        request_raw = text("request")
        response_raw = text("response")
        if request_raw:
            request_raw = maybe_decode_b64(request_raw)
        if response_raw:
            response_raw = maybe_decode_b64(response_raw)

        status = 0
        content_type = ""
        response_headers: dict[str, str] = {}
        if response_raw:
            parts = response_raw.split("\r\n\r\n", 1)
            header_section = parts[0]
            for line in header_section.split("\r\n"):
                if line.startswith("HTTP/"):
                    try:
                        status = int(line.split(" ")[1])
                    except (IndexError, ValueError):
                        pass
                elif ":" in line:
                    k, v = line.split(":", 1)
                    response_headers[k.strip().lower()] = v.strip()
            content_type = response_headers.get("content-type", "")

        entry: dict[str, Any] = {
            "url": url,
            "host": host,
            "port": port,
            "protocol": protocol,
            "method": method.upper(),
            "path": path,
            "status_code": status,
            "content_type": content_type,
            "headers": response_headers,
            "response": response_raw,
        }
        return entry

    @staticmethod
    def _xml_issue_to_dict(issue: Any) -> dict[str, Any] | None:
        def text(tag: str) -> str:
            el = issue.find(tag)
            return el.text or "" if el is not None else ""

        name = text("name")
        host = text("host")
        url = text("url")
        severity = text("severity")
        confidence = text("confidence")
        background = text("issueBackground")
        detail = text("issueDetail")
        remediation = text("remediationBackground")

        if not name and not url:
            return None

        return {
            "url": url,
            "host": host,
            "issue_name": name,
            "severity": severity,
            "confidence": confidence,
            "description": background or detail,
            "remediation": remediation,
            "type": "issue",
        }

    def normalize(self, parsed: list[dict[str, Any]], context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        seen: set[str] = set()

        for entry in parsed:
            url = entry.get("url", "") or ""
            if not url or url in seen:
                continue
            seen.add(url)

            hostname = entry.get("host", "")
            method_str = entry.get("method", "GET") or "GET"
            status_code = int(entry.get("status_code", 0) or 0)
            content_type = entry.get("content_type", "") or ""
            raw_headers = entry.get("headers", {}) or {}

            try:
                method = HttpMethod(method_str.upper())
            except ValueError:
                method = HttpMethod.GET

            header_objs = [HTTPHeader(name=k, value=str(v)) for k, v in raw_headers.items()]

            endpoint = Endpoint(
                path=url,
                method=method,
                category=EndpointCategory.API if ("api" in url.lower() or "json" in content_type) else EndpointCategory.WEBSOCKET if url.lower().startswith(("ws://", "wss://")) else EndpointCategory.UNKNOWN,
                status_code=status_code or None,
                source=ReconSourceType.HTTP_PROBE,
                metadata={
                    "tool": "burp",
                    "host": hostname,
                    "content_type": content_type,
                },
            )
            result.endpoints.append(endpoint)

            obs = HTTPObservation(
                url=url,
                method=method,
                status_code=status_code,
                content_type=content_type,
                headers=header_objs,
                source=ReconSourceType.HTTP_PROBE,
            )
            result.http_observations.append(obs)

            if entry.get("type") == "issue":
                for ep in result.endpoints:
                    if ep.path == url and entry.get("issue_name"):
                        if "burp_issues" not in ep.metadata:
                            ep.metadata["burp_issues"] = []
                        ep.metadata["burp_issues"].append({
                            "name": entry.get("issue_name"),
                            "severity": entry.get("severity"),
                            "confidence": entry.get("confidence"),
                        })

        result.success = True
        return result

    def health(self, context: ExecutionContext) -> PluginHealth:
        return PluginHealth(healthy=True, installed=True, executable_found=True)

    def build_command(self, context: ExecutionContext) -> str:
        return ""
