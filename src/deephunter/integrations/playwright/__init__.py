"""Playwright integration for DeepHunter.

Imports captured data from Playwright browser automation including
requests, responses, cookies, storage, screenshots (metadata),
console logs, and network timeline.
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
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
    JavaScriptFile,
    JavaScriptEndpoint,
    Parameter,
    ParamLocation,
    ParamType,
)
from deephunter.recon.graph import AttackSurfaceGraph


@dataclass
class PlaywrightNetworkEntry:
    """A single network request from Playwright."""

    url: str = ""
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    post_data: str = ""
    response_status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    timing: dict[str, float] = field(default_factory=dict)
    resource_type: str = ""
    timestamp: str = ""


@dataclass
class PlaywrightConsoleEntry:
    """A console log entry from Playwright."""

    type: str = "log"
    text: str = ""
    timestamp: str = ""
    location: dict[str, str] = field(default_factory=dict)


@dataclass
class PlaywrightStorageEntry:
    """A storage entry (localStorage/sessionStorage) from Playwright."""

    key: str = ""
    value: str = ""
    storage_type: str = ""


@dataclass
class PlaywrightCapturedData:
    """Complete captured data from a Playwright session."""

    network: list[PlaywrightNetworkEntry] = field(default_factory=list)
    console: list[PlaywrightConsoleEntry] = field(default_factory=list)
    storage: list[PlaywrightStorageEntry] = field(default_factory=list)
    cookies: list[Cookie] = field(default_factory=list)
    screenshots: list[dict[str, Any]] = field(default_factory=list)
    url: str = ""
    title: str = ""


class PlaywrightZipImporter:
    """Imports Playwright export in ZIP format (chromium network dump)."""

    def import_zip(self, zip_path: str) -> PlaywrightCapturedData:
        data = PlaywrightCapturedData()
        with zipfile.ZipFile(zip_path) as zf:
            for name in zf.namelist():
                if name.endswith("/"):
                    continue
                content = zf.read(name).decode("utf-8", errors="replace")
                self._process_file(name, content, data)
        return data

    def _process_file(self, name: str, content: str, data: PlaywrightCapturedData) -> None:
        if "network" in name and name.endswith(".json"):
            self._load_network(content, data)
        elif "console" in name and name.endswith(".json"):
            self._load_console(content, data)
        elif "storage" in name and name.endswith(".json"):
            self._load_storage(content, data)
        elif "cookies" in name and name.endswith(".json"):
            self._load_cookies(content, data)
        elif "screenshot" in name and name.endswith(".json"):
            self._load_screenshot_metadata(content, data)


class PlaywrightCDPImporter:
    """Imports Chrome DevTools Protocol (CDP) JSON format."""

    def import_cdp_file(self, file_path: str) -> PlaywrightCapturedData:
        data = PlaywrightCapturedData()
        with open(file_path) as f:
            entries = json.load(f)
        for entry in entries:
            self._process_cdp_entry(entry, data)
        return data

    def _process_cdp_entry(self, entry: dict[str, Any], data: PlaywrightCapturedData) -> None:
        if entry.get("method", "").startswith("Network."):
            self._handle_network_event(entry, data)
        elif entry.get("method", "").startswith("Runtime."):
            self._handle_console_event(entry, data)

    def _handle_network_event(self, entry: dict[str, Any], data: PlaywrightCapturedData) -> None:
        params = entry.get("params", {})
        if entry["method"] == "Network.requestWillBeSent":
            net_entry = PlaywrightNetworkEntry(
                url=params.get("request", {}).get("url", ""),
                method=params.get("request", {}).get("method", "GET"),
                headers=params.get("request", {}).get("headers", {}),
                post_data=params.get("request", {}).get("postData", ""),
                resource_type=params.get("type", ""),
                timestamp=params.get("timestamp", ""),
            )
            data.network.append(net_entry)
        elif entry["method"] == "Network.responseReceived":
            for i, net in enumerate(data.network):
                if net.url == params.get("response", {}).get("url", ""):
                    net.response_status = params.get("response", {}).get("status", 0)
                    net.response_headers = params.get("response", {}).get("headers", {})
                    break

    def _handle_console_event(self, entry: dict[str, Any], data: PlaywrightCapturedData) -> None:
        params = entry.get("params", {})
        console_entry = PlaywrightConsoleEntry(
            type=params.get("type", "log"),
            text=params.get("args", [{}])[0].get("value", "") if params.get("args") else "",
            timestamp=entry.get("timestamp", ""),
        )
        data.console.append(console_entry)


class PlaywrightHarImporter:
    """Imports standard HAR format from Playwright or DevTools."""

    def import_har(self, har_path: str) -> PlaywrightCapturedData:
        data = PlaywrightCapturedData()
        with open(har_path) as f:
            har = json.load(f)
        for entry in har.get("log", {}).get("entries", []):
            self._process_har_entry(entry, data)
        return data

    def _process_har_entry(self, entry: dict[str, Any], data: PlaywrightCapturedData) -> None:
        request = entry.get("request", {})
        response = entry.get("response", {})

        net_entry = PlaywrightNetworkEntry(
            url=request.get("url", ""),
            method=request.get("method", "GET"),
            headers=dict(request.get("headers", [])),
            post_data=request.get("postData", {}).get("text", ""),
            response_status=response.get("status", 0),
            response_headers=dict(response.get("headers", [])),
            timing=entry.get("timings", {}),
        )

        if "text" in response.get("content", {}):
            net_entry.response_body = response["content"]["text"]

        data.network.append(net_entry)


def convert_playwright_to_recon(data: PlaywrightCapturedData) -> dict[str, Any]:
    """Convert Playwright captured data to DeepHunter recon models."""
    result = {
        "hosts": [],
        "endpoints": [],
        "observations": [],
        "javascript_files": [],
        "cookies": [],
    }

    host_map: dict[str, Host] = {}
    endpoint_map: dict[str, Endpoint] = {}

    for net in data.network:
        if not net.url:
            continue

        parsed = urlparse(net.url)
        host_key = f"{parsed.netloc}"

        if host_key not in host_map:
            host = Host(
                hostname=parsed.netloc.split(":")[0],
                ip_address="",
                port=int(parsed.netloc.split(":")[-1]) if ":" in parsed.netloc else (443 if parsed.scheme == "https" else 80),
                status="open",
            )
            host_map[host_key] = host
            result["hosts"].append(host)

        endpoint_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if endpoint_key not in endpoint_map:
            endpoint = Endpoint(
                path=parsed.path or "/",
                method=HttpMethod(net.method),
                host=parsed.netloc.split(":")[0],
                port=int(parsed.netloc.split(":")[-1]) if ":" in parsed.netloc else 443,
                category=EndpointCategory.API if "/api" in parsed.path else EndpointCategory.WEB,
                parameters=[],
                authenticated=False,
            )
            endpoint_map[endpoint_key] = endpoint
            result["endpoints"].append(endpoint)

            endpoint = endpoint_map[endpoint_key]
            for name, value in net.headers.items():
                lname = name.lower()
                if lname == "authorization":
                    endpoint.authenticated = True

            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        name, val = param.split("=", 1)
                        endpoint.parameters.append(Parameter(name=name, value=val[:200], location=ParamLocation.QUERY, type=ParamType.STRING))

            if net.post_data:
                endpoint.parameters.append(Parameter(name="body", value=net.post_data[:500], location=ParamLocation.BODY, type=ParamType.STRING))

        if net.response_status >= 400:
            result["observations"].append(HTTPObservation(type="error_response", content=f"HTTP {net.response_status} on {net.method} {net.url}", source="playwright_import"))

    for cookie in data.cookies:
        result["cookies"].append(cookie)

    for console in data.console:
        if "error" in console.type.lower():
            result["observations"].append(HTTPObservation(type="console_error", content=console.text, source="playwright_import"))
        if "warning" in console.type.lower():
            result["observations"].append(HTTPObservation(type="console_warning", content=console.text, source="playwright_import"))

    return result


class PlaywrightImporter:
    """Main entry point for importing Playwright data."""

    def __init__(self) -> None:
        self.zip_importer = PlaywrightZipImporter()
        self.cdp_importer = PlaywrightCDPImporter()
        self.har_importer = PlaywrightHarImporter()

    def import_file(self, file_path: str, file_type: str = "auto") -> PlaywrightCapturedData:
        """Import a Playwright export file.

        Supported types: zip, cdp_json, har, playwright_json
        """
        if file_type == "auto":
            if file_path.endswith(".zip"):
                file_type = "zip"
            elif file_path.endswith(".har"):
                file_type = "har"
            else:
                file_type = "cdp_json"

        if file_type == "zip":
            return self.zip_importer.import_zip(file_path)
        elif file_type == "har":
            return self.har_importer.import_har(file_path)
        else:
            return self.cdp_importer.import_cdp_file(file_path)