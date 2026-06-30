"""Tool plugin adapter for the JavaScript Intelligence Platform.

Follows the existing ``BaseToolPlugin`` pattern used by httpx, subfinder,
amass, and assetfinder adapters.

This adapter is import-only — it accepts pre-collected JavaScript content
rather than executing a tool.
"""

from __future__ import annotations

from typing import Any

from deephunter.js_intel.engine import JSAnalysisEngine
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import ToolCategory, ToolMetadata


class JavaScriptIntelAdapter(BaseToolPlugin):
    """Import-only adapter for JavaScript intelligence analysis.

    Accepts raw JavaScript content (string) via ``parse_output()`` and
    normalizes into ``PluginResult`` with ``JavaScriptFile``,
    ``JavaScriptEndpoint``, ``Technology``, and ``Application`` entities.

    Input formats:
      - ``js`` / ``txt``: raw JavaScript source text

    Does NOT execute or crawl — only static analysis.
    """

    metadata = ToolMetadata(
        name="js_intel_adapter",
        description="Import JavaScript source content for static intelligence analysis",
        version="1.0.0",
        category=ToolCategory.js_analysis,
        tags=["javascript", "analysis", "import", "adapter", "static"],
        supported_formats=["js", "txt"],
    )

    def __init__(self, engine: JSAnalysisEngine | None = None) -> None:
        self._engine = engine or JSAnalysisEngine()

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        raise NotImplementedError(
            "JavaScriptIntelAdapter is import-only; use parse_output() with pre-collected JS content"
        )

    def parse_output(self, raw: str | bytes | None, context: ExecutionContext) -> str:
        if not raw:
            return ""
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return raw

    def normalize(self, parsed: str, context: ExecutionContext) -> PluginResult:
        source_url = context.args.get("source_url", context.args.get("url", ""))
        host_id = context.args.get("host_id", "")
        application_id = context.args.get("application_id", "")

        if not parsed.strip():
            result = PluginResult()
            result.success = True
            return result

        return self._engine.analyze_and_normalize(
            content=parsed,
            source_url=source_url,
            host_id=host_id,
            application_id=application_id,
        )

    def build_command(self, context: ExecutionContext) -> str:
        return "js_intel_adapter --import-only"
