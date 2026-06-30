"""Web search tool plugin for DeepHunter.

Provides web search functionality for reconnaissance and
information gathering phases.
"""

from __future__ import annotations

from typing import Any

import httpx

from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolMetadata


class WebSearchPlugin(BaseToolPlugin):
    """Tool plugin for web searching.

    Currently uses DuckDuckGo HTML search as a fallback when
    no API key is configured.
    """

    metadata = ToolMetadata(
        name="web_search",
        description="Perform web searches for reconnaissance",
        version="1.0.0",
        author="DeepHunter",
        tags=["web", "search", "osint", "recon"],
        category=ToolCategory.osint,
        supported_platforms=["linux", "darwin", "windows"],
        requires_network=True,
        requires_installation=False,
        parameters=[],
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        query = context.params.get("query", "")
        limit = int(context.params.get("limit", 10))

        if not query:
            return "No query provided"

        try:
            results = self._search_duckduckgo(query, limit)
            return results
        except Exception as exc:
            return f"Search failed: {exc}"

    def _search_duckduckgo(self, query: str, limit: int) -> str:
        url = "https://html.duckduckgo.com/html/"
        params = {"q": query}

        with httpx.Client(timeout=30.0) as client:
            response = client.get(url, params=params)
            response.raise_for_status()

        return response.text

    def normalize(self, parsed: Any, context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        result.success = True
        result.raw_output = parsed if isinstance(parsed, str) else str(parsed)
        return result

    def health(self, context: ExecutionContext) -> PluginHealth:
        health = PluginHealth()
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get("https://html.duckduckgo.com/html/", params={"q": "test"})
                health.healthy = response.status_code == 200
        except Exception as exc:
            health.healthy = False
            health.errors.append(str(exc))
        return health
