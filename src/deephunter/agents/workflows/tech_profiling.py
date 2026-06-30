from __future__ import annotations

import time
from typing import Any

from deephunter.agents.base import Agent, AgentResult


class TechnologyProfilingWorkflow(Agent):
    """Workflow 3: Technology Profiling.

    Identifies web servers, frameworks, CMS, CDNs, WAFs, runtimes,
    and other technologies via HTTP headers, HTML meta tags,
    and Nuclei technology templates.
    """

    def __init__(self, name: str | None = None) -> None:
        super().__init__(name or "tech_profiling")
        self._description = "Technology profiling — web server, framework, CMS, CDN, WAF detection"

    def execute(self, context: dict[str, Any]) -> AgentResult:
        target = context.get("target", "")
        if not target:
            return AgentResult(agent_name=self.name, success=False, error="No target provided")

        started = time.monotonic()
        findings: dict[str, Any] = {"target": target, "technologies": []}
        errors: list[str] = []

        if context.get("enable_httpx", True):
            try:
                from deephunter.recon.plugin import PluginResult
                from deephunter.recon.models import Technology, TechCategory
                from deephunter.tools.context import ExecutionContext
                from deephunter.tools.executor import ToolExecutor
                from deephunter.tools.plugins.httpx_adapter import HTTPxAdapter
                plugin = HTTPxAdapter()
                ctx = ExecutionContext(target=target, plugin_name="httpx")
                raw = plugin.execute(ctx)
                if raw:
                    parsed = plugin.parse_output(raw, ctx)
                    result = plugin.normalize(parsed, ctx)
                    for t in result.technologies:
                        findings["technologies"].append({"name": t.name, "category": t.category.value if hasattr(t.category, 'value') else str(t.category)})
            except Exception as e:
                errors.append(f"httpx failed: {e}")

        if context.get("enable_nuclei_tech", True):
            try:
                from deephunter.tools.context import ExecutionContext
                from deephunter.tools.executor import ToolExecutor
                from deephunter.tools.plugins.nuclei_adapter import NucleiAdapter
                plugin = NucleiAdapter()
                ctx = ExecutionContext(target=target, plugin_name="nuclei", args={"target": target, "templates": "technologies/"})
                if plugin.health(ctx).healthy:
                    executor = ToolExecutor()
                    executor.execute(plugin, ctx)
            except Exception as e:
                errors.append(f"nuclei tech templates failed: {e}")

        elapsed = (time.monotonic() - started) * 1000
        findings["errors"] = errors
        findings["duration_ms"] = elapsed
        return AgentResult(
            agent_name=self.name,
            success=len(errors) < 2,
            data=findings,
            execution_time_ms=elapsed,
        )
