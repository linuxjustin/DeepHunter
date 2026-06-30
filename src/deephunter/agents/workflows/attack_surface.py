from __future__ import annotations

import time
from typing import Any

from deephunter.agents.base import Agent, AgentResult


class AttackSurfaceWorkflow(Agent):
    """Workflow 2: Attack Surface Expansion.

    Discovers URLs, endpoints, JavaScript files, API routes, and
    parameters from public sources (Wayback, AlienVault) and crawling.
    """

    def __init__(self, name: str | None = None) -> None:
        super().__init__(name or "attack_surface")
        self._description = "Attack surface expansion — URL discovery, JS collection, API route discovery"

    def execute(self, context: dict[str, Any]) -> AgentResult:
        target = context.get("target", "")
        if not target:
            return AgentResult(agent_name=self.name, success=False, error="No target provided")

        started = time.monotonic()
        findings: dict[str, Any] = {
            "target": target,
            "urls": [],
            "endpoints": [],
            "js_files": [],
            "parameters": [],
        }
        errors: list[str] = []

        if context.get("enable_gau", True):
            try:
                from deephunter.tools.context import ExecutionContext
                from deephunter.tools.executor import ToolExecutor
                from deephunter.tools.plugins.gau_adapter import GauAdapter
                plugin = GauAdapter()
                if plugin.health(ExecutionContext(target=target)).healthy:
                    executor = ToolExecutor()
                    ctx = ExecutionContext(target=target, plugin_name="gau", args={"domain": target})
                    executor.execute(plugin, ctx)
            except Exception as e:
                errors.append(f"gau failed: {e}")

        if context.get("enable_waybackurls", True):
            try:
                from deephunter.tools.context import ExecutionContext
                from deephunter.tools.executor import ToolExecutor
                from deephunter.tools.plugins.waybackurls_adapter import WaybackURLsAdapter
                plugin = WaybackURLsAdapter()
                if plugin.health(ExecutionContext(target=target)).healthy:
                    executor = ToolExecutor()
                    ctx = ExecutionContext(target=target, plugin_name="waybackurls", args={"domain": target})
                    executor.execute(plugin, ctx)
            except Exception as e:
                errors.append(f"waybackurls failed: {e}")

        if context.get("enable_crawl", False):
            try:
                from deephunter.tools.context import ExecutionContext
                from deephunter.tools.executor import ToolExecutor
                from deephunter.tools.plugins.katana_adapter import KatanaAdapter
                plugin = KatanaAdapter()
                if plugin.health(ExecutionContext(target=target)).healthy:
                    executor = ToolExecutor()
                    ctx = ExecutionContext(target=target, plugin_name="katana", args={"url": target})
                    executor.execute(plugin, ctx)
            except Exception as e:
                errors.append(f"katana failed: {e}")

        if context.get("enable_fuzzing", False):
            try:
                from deephunter.tools.context import ExecutionContext
                from deephunter.tools.executor import ToolExecutor
                from deephunter.tools.plugins.ffuf_adapter import FfufAdapter
                plugin = FfufAdapter()
                if plugin.health(ExecutionContext(target=target)).healthy:
                    executor = ToolExecutor()
                    wordlist = context.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
                    ctx = ExecutionContext(target=target, plugin_name="ffuf", args={"url": target + "/FUZZ", "wordlist": wordlist})
                    executor.execute(plugin, ctx)
            except Exception as e:
                errors.append(f"ffuf failed: {e}")

        elapsed = (time.monotonic() - started) * 1000
        findings["errors"] = errors
        findings["duration_ms"] = elapsed
        return AgentResult(
            agent_name=self.name,
            success=len(errors) < 4,
            data=findings,
            execution_time_ms=elapsed,
        )
