"""Web fetch tool plugin for DeepHunter.

Provides web content fetching functionality for reconnaissance and
information gathering phases.
"""

from __future__ import annotations

from typing import Any

import httpx

from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolMetadata


class WebFetchPlugin(BaseToolPlugin):
    """Tool plugin for fetching web content.

    Retrieves HTTP responses from specified URLs, useful for
    content analysis and vulnerability scanning.
    """

    metadata = ToolMetadata(
        name="web_fetch",
        description="Fetch web content from URLs",
        version="1.0.0",
        author="DeepHunter",
        tags=["web", "fetch", "recon", "http"],
        category=ToolCategory.web_probe,
        supported_platforms=["linux", "darwin", "windows"],
        requires_network=True,
        requires_installation=False,
        parameters=[],
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        url = context.args.get("url", "")
        if not url:
            return "No URL provided"

        method = context.args.get("method", "GET").upper()
        headers_str = context.args.get("headers", "")
        body = context.args.get("body", "")

        headers = self._parse_headers(headers_str)

        try:
            timeout = context.config.timeout or 30.0
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                if method == "POST":
                    response = client.post(url, headers=headers, content=body)
                elif method == "PUT":
                    response = client.put(url, headers=headers, content=body)
                elif method == "DELETE":
                    response = client.delete(url, headers=headers)
                else:
                    response = client.get(url, headers=headers)

                return self._format_response(response)
        except Exception as exc:
            return f"Fetch failed: {exc}"

    @staticmethod
    def _parse_headers(headers_str: str) -> dict[str, str]:
        headers = {}
        if not headers_str:
            return headers
        for line in headers_str.split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        return headers

    @staticmethod
    def _format_response(response: httpx.Response) -> str:
        lines = [
            f"Status: {response.status_code}",
            f"URL: {response.url}",
            "",
            "Headers:",
        ]
        for key, value in response.headers.items():
            lines.append(f"  {key}: {value}")

        lines.extend(["", "Body:", ""])
        lines.append(response.text[:10000])

        return "\n".join(lines)

    def normalize(self, parsed: Any, context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        if isinstance(parsed, str) and parsed.startswith("Fetch failed:"):
            result.success = False
            result.error = parsed
        else:
            result.success = True
            result.raw_output = parsed if isinstance(parsed, str) else str(parsed)
        return result

    def health(self, context: ExecutionContext) -> PluginHealth:
        health = PluginHealth()
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get("https://example.com")
                health.healthy = response.status_code == 200
        except Exception as exc:
            health.healthy = False
            health.errors.append(str(exc))
        return health
