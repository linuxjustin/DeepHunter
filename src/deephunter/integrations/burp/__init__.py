"""Burp Suite integration for DeepHunter.

Imports data from Burp Suite exports including HTTP history, site map,
proxy logs, and scanner results. Normalizes data into DeepHunter's
recon models.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from deephunter.recon.models import (
    Cookie,
    Endpoint,
    EndpointCategory,
    GraphNodeType,
    GraphEdgeType,
    HTTPHeader,
    HTTPObservation,
    Host,
    HttpMethod,
    Parameter,
    ParamLocation,
    ParamType,
)
from deephunter.recon.graph import AttackSurfaceGraph
from deephunter.workspace.models import Attachment, AttachmentType


@dataclass
class BurpHttpExchange:
    """A single HTTP request/response exchange from Burp."""

    url: str = ""
    method: str = "GET"
    request_headers: list[tuple[str, str]] = field(default_factory=list)
    request_body: str = ""
    response_status: int = 0
    response_headers: list[tuple[str, str]] = field(default_factory=list)
    response_body: str = ""
    timestamp: str = ""
    host: str = ""
    port: int = 443
    protocol: str = "https"


@dataclass
class BurpSiteMapEntry:
    """A single URL in the Burp site map."""

    url: str = ""
    method: str = "GET"
    status: int = 0
    response_length: int = 0
    mime_type: str = ""
    title: str = ""
    annotations: str = ""
    host: str = ""
    port: int = 443
    path: str = ""
    query: str = ""
    children: list[BurpSiteMapEntry] = field(default_factory=list)


class BurpStateParser:
    """Parses Burp Suite state files (.bastet format - actually XML)."""

    def parse_state_file(self, file_path: str) -> list[BurpHttpExchange]:
        exchanges = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            for item in root.findall(".//item"):
                exchange = self._parse_item(item)
                if exchange:
                    exchanges.append(exchange)
        except ET.ParseError:
            pass
        return exchanges

    def _parse_item(self, item: ET.Element) -> BurpHttpExchange | None:
        try:
            url = item.findtext("url", "")
            if not url:
                return None

            parsed = urlparse(url)
            request = item.find("request")
            response = item.find("response")

            exchange = BurpHttpExchange(url=url, host=parsed.netloc.split(":")[0] or parsed.netloc)

            if ":" in parsed.netloc:
                host, port_str = parsed.netloc.rsplit(":", 1)
                exchange.host = host
                exchange.port = int(port_str)
            else:
                exchange.host = parsed.netloc
                exchange.port = 443 if parsed.scheme == "https" else 80

            if request is not None:
                self._parse_request(request, exchange)
            if response is not None:
                self._parse_response(response, exchange)

            return exchange
        except Exception:
            return None

    def _parse_request(self, request: ET.Element, exchange: BurpHttpExchange) -> None:
        for header_elem in request.findall("header"):
            name = header_elem.findtext("name", "")
            value = header_elem.findtext("value", "")
            if name and value:
                exchange.request_headers.append((name, value))
        body = request.findtext("body", "")
        if body:
            exchange.request_body = body

    def _parse_response(self, response: ET.Element, exchange: BurpHttpExchange) -> None:
        status_elem = response.find("statuscode")
        if status_elem is not None:
            exchange.response_status = int(status_elem.text or "0")
        for header_elem in response.findall("header"):
            name = header_elem.findtext("name", "")
            value = header_elem.findtext("value", "")
            if name and value:
                exchange.response_headers.append((name, value))
        body = response.findtext("body", "")
        if body:
            exchange.response_body = body


class BurpReportParser:
    """Parses Burp Suite professional HTML/JSON reports."""

    def parse_json_report(self, file_path: str) -> dict[str, Any]:
        with open(file_path) as f:
            data = json.load(f)
        return data

    def parse_issue(self, issue: dict[str, Any]) -> dict[str, Any]:
        return {
            "name": issue.get("name", ""),
            "severity": issue.get("severity", ""),
            "confidence": issue.get("confidence", ""),
            "host": issue.get("host", ""),
            "path": issue.get("path", ""),
            "type_index": issue.get("typeIndex", ""),
            "description": issue.get("description", ""),
            "remediation": issue.get("remediation", ""),
            "reference": issue.get("reference", ""),
        }


class BurpHarImporter:
    """Imports HTTP Archive (HAR) format from Burp proxy."""

    def parse_har_file(self, file_path: str) -> list[BurpHttpExchange]:
        exchanges = []
        with open(file_path) as f:
            har = json.load(f)

        for entry in har.get("log", {}).get("entries", []):
            exchange = self._parse_har_entry(entry)
            if exchange:
                exchanges.append(exchange)
        return exchanges

    def _parse_har_entry(self, entry: dict[str, Any]) -> BurpHttpExchange | None:
        try:
            request = entry.get("request", {})
            response = entry.get("response", {})

            url = request.get("url", "")
            if not url:
                return None

            parsed = urlparse(url)
            exchange = BurpHttpExchange(url=url, method=request.get("method", "GET").upper())

            if ":" in parsed.netloc:
                exchange.host, port_str = parsed.netloc.rsplit(":", 1)
                exchange.port = int(port_str)
            else:
                exchange.host = parsed.netloc
                exchange.port = 443 if parsed.scheme == "https" else 80

            for header in request.get("headers", []):
                exchange.request_headers.append((header.get("name", ""), header.get("value", "")))

            if request.get("postData"):
                exchange.request_body = request["postData"].get("text", "")

            exchange.response_status = response.get("status", 0)
            for header in response.get("headers", []):
                exchange.response_headers.append((header.get("name", ""), header.get("value", "")))

            content = response.get("content", {})
            exchange.response_body = content.get("text", "")

            timing = entry.get("timings", {})
            start = entry.get("startedDateTime", "")
            exchange.timestamp = start

            return exchange
        except Exception:
            return None


def convert_burp_exchange_to_recon(exchange: BurpHttpExchange) -> dict[str, Any]:
    """Convert a Burp HTTP exchange to DeepHunter recon models."""
    result = {
        "host": None,
        "endpoint": None,
        "parameters": [],
        "headers": [],
        "observations": [],
    }

    host = Host(
        hostname=exchange.host,
        ip_address="",
        port=exchange.port,
        status="active",
        services=["http" if exchange.port in (80, 8080) else "https"] if ":" not in exchange.host else [],
    )
    result["host"] = host

    parsed = urlparse(exchange.url)
    endpoint = Endpoint(
        path=parsed.path or "/",
        method=HttpMethod(exchange.method),
        host=exchange.host,
        port=exchange.port,
        category=EndpointCategory.API if "/api" in parsed.path else EndpointCategory.WEB,
        parameters=[],
        authenticated=False,
    )
    result["endpoint"] = endpoint

    for name, value in exchange.request_headers:
        header = HTTPHeader(name=name, value=value)
        result["headers"].append(header)
        lname = name.lower()
        if lname == "authorization":
            endpoint.authenticated = True
        if lname in ("cookie",):
            for cookie_str in value.split(";"):
                parts = cookie_str.strip().split("=")
                if len(parts) >= 2:
                    cookie = Cookie(name=parts[0], value=parts[1], domain=exchange.host)
                    result.setdefault("cookies", []).append(cookie)

    if parsed.query:
        for param in parsed.query.split("&"):
            if "=" in param:
                name, val = param.split("=", 1)
                endpoint.parameters.append(Parameter(name=name, value=val, location=ParamLocation.QUERY, type=ParamType.STRING))

    if exchange.request_body:
        endpoint.parameters.append(Parameter(name="body", value=exchange.request_body[:500], location=ParamLocation.BODY, type=ParamType.STRING))

    for name, value in exchange.response_headers:
        lname = name.lower()
        if lname == "content-security-policy":
            result["observations"].append(HTTPObservation(type="security_header", content=value, source="burp_import"))
        if lname in ("x-frame-options", "x-content-type-options", "strict-transport-security"):
            sh = SecurityHeader(header=SecurityHeaderName(lname.replace("x-", "").replace("-", "_").upper()), value=value, present=True)
            result.setdefault("security_headers", []).append(sh)

    return result


class BurpImporter:
    """Main entry point for importing Burp Suite data."""

    def __init__(self) -> None:
        self.state_parser = BurpStateParser()
        self.har_parser = BurpHarImporter()
        self.report_parser = BurpReportParser()

    def import_file(self, file_path: str, file_type: str = "auto") -> list[dict[str, Any]]:
        """Import a Burp Suite export file and return normalized data.

        Supported types: burp_state, har, burp_json, sitemap_xml
        """
        if file_type == "auto":
            if file_path.endswith(".bastet") or file_path.endswith(".burp"):
                file_type = "burp_state"
            elif file_path.endswith(".har"):
                file_type = "har"
            elif file_path.endswith(".xml"):
                file_type = "sitemap_xml"
            else:
                file_type = "burp_json"

        if file_type == "har":
            exchanges = self.har_parser.parse_har_file(file_path)
        elif file_type == "burp_state":
            exchanges = self.state_parser.parse_state_file(file_path)
        else:
            exchanges = []

        results = []
        for exchange in exchanges:
            converted = convert_burp_exchange_to_recon(exchange)
            results.append(converted)

        return results

    def import_scan_results(self, report_path: str) -> list[dict[str, Any]]:
        """Import Burp Scanner results from JSON report."""
        data = self.report_parser.parse_json_report(report_path)
        issues = []
        for issue in data.get("issues", []):
            issues.append(self.report_parser.parse_issue(issue))
        return issues