from __future__ import annotations

import time
from typing import Any

from deephunter.agents.base import Agent, AgentResult
from deephunter.recon.models import Host, HostStatus, Protocol, ReconSourceType


class InitialReconWorkflow(Agent):
    """Workflow 1: Initial Reconnaissance.

    Enumerates subdomains, resolves DNS records, scans common ports,
    and captures HTTP metadata for the target scope.
    """

    def __init__(self, name: str | None = None) -> None:
        super().__init__(name or "initial_recon")
        self._description = "Initial reconnaissance — subdomain enumeration, DNS resolution, port scanning, HTTP probing"

    def execute(self, context: dict[str, Any]) -> AgentResult:
        target = context.get("target", "")
        if not target:
            return AgentResult(agent_name=self.name, success=False, error="No target provided")

        started = time.monotonic()
        findings: dict[str, Any] = {
            "target": target,
            "subdomains": [],
            "dns_records": [],
            "open_ports": [],
            "live_hosts": [],
        }
        errors: list[str] = []

        if context.get("enable_subdomain_enum", True):
            try:
                from deephunter.tools.executor import ToolExecutor
                from deephunter.tools.context import ExecutionContext
                from deephunter.tools.plugins.subfinder_plugin import SubfinderPlugin
                executor = ToolExecutor()
                plugin = SubfinderPlugin()
                ctx = ExecutionContext(target=target, plugin_name="subfinder", args={"domain": target})
                if plugin.health(ctx).healthy:
                    report = executor.execute(plugin, ctx)
                    if report.status == "success":
                        findings["subdomains"] = [h.hostname for h in report.parsed_count]
            except Exception as e:
                errors.append(f"Subdomain enumeration failed: {e}")

        if context.get("enable_dns_resolution", True):
            try:
                from deephunter.tools.executor import ToolExecutor
                from deephunter.tools.context import ExecutionContext
                from deephunter.tools.plugins.dnsx_adapter import DNSxAdapter
                executor = ToolExecutor()
                plugin = DNSxAdapter()
                ctx = ExecutionContext(target=target, plugin_name="dnsx", args={"domain": target})
                if plugin.health(ctx).healthy:
                    report = executor.execute(plugin, ctx)
            except Exception as e:
                errors.append(f"DNS resolution failed: {e}")

        if context.get("enable_port_scan", True):
            try:
                from deephunter.tools.executor import ToolExecutor
                from deephunter.tools.context import ExecutionContext
                from deephunter.tools.plugins.naabu_adapter import NaabuAdapter
                executor = ToolExecutor()
                plugin = NaabuAdapter()
                ports = context.get("ports", "80,443,8080,8443")
                ctx = ExecutionContext(target=target, plugin_name="naabu", args={"host": target, "ports": ports})
                if plugin.health(ctx).healthy:
                    report = executor.execute(plugin, ctx)
            except Exception as e:
                errors.append(f"Port scan failed: {e}")

        if context.get("enable_http_probe", True):
            try:
                from deephunter.tools.executor import ToolExecutor
                from deephunter.tools.context import ExecutionContext
                from deephunter.tools.plugins.httpx_adapter import HTTPxAdapter
                executor = ToolExecutor()
                plugin = HTTPxAdapter()
                ctx = ExecutionContext(target=target, plugin_name="httpx", args={"target": target})
                if plugin.health(ctx).healthy:
                    report = executor.execute(plugin, ctx)
            except Exception as e:
                errors.append(f"HTTP probe failed: {e}")

        elapsed = (time.monotonic() - started) * 1000
        findings["errors"] = errors
        findings["duration_ms"] = elapsed
        return AgentResult(
            agent_name=self.name,
            success=len(errors) < 4,
            data=findings,
            execution_time_ms=elapsed,
        )
