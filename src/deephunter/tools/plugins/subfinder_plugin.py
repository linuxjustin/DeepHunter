"""Example built-in plugin wrapping Subfinder (subdomain enumeration)."""

from __future__ import annotations

from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolMetadata


class SubfinderPlugin(BaseToolPlugin):
    metadata = ToolMetadata(
        name="subfinder",
        description="Passive subdomain enumeration via Subfinder",
        version="1.0.0",
        author="DeepHunter",
        category=ToolCategory.subdomain_enum,
        tags=["subdomain", "dns", "passive"],
        supported_platforms=["linux", "darwin"],
        requires_network=True,
        requires_installation=True,
        timeout_default=300.0,
        retry_default=1,
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        import subprocess
        import shlex

        domain = context.args.get("domain", context.target)
        cmd = f"subfinder -d {shlex.quote(domain)} -silent"
        try:
            proc = subprocess.run(
                shlex.split(cmd),
                capture_output=True,
                text=True,
                timeout=context.get_plugin_timeout(),
                env=context.env,
            )
            return proc.stdout
        except subprocess.TimeoutExpired:
            return None

    def parse_output(self, raw_output: str | bytes | None, context: ExecutionContext) -> list[str]:
        if not raw_output:
            return []
        if isinstance(raw_output, bytes):
            raw_output = raw_output.decode("utf-8", errors="replace")
        return [line.strip() for line in raw_output.strip().splitlines() if line.strip()]

    def normalize(self, parsed: list[str], context: ExecutionContext) -> PluginResult:
        from deephunter.recon.models import Host, HostStatus, Protocol, ReconSourceType

        result = PluginResult()
        result.success = True
        for hostname in parsed:
            host = Host(
                hostname=hostname,
                ip="",
                port=443,
                protocol=Protocol.HTTPS,
                status=HostStatus.UNKNOWN,
                source=ReconSourceType.SUBDOMAIN_ENUMERATION,
            )
            result.hosts.append(host)
        return result

    def health(self, context: ExecutionContext) -> PluginHealth:
        import shutil
        found = shutil.which("subfinder") is not None
        return PluginHealth(
            healthy=found,
            installed=found,
            executable_found=found,
            errors=[] if found else ["subfinder not found on PATH"],
        )

    def build_command(self, context: ExecutionContext) -> str:
        domain = context.args.get("domain", context.target)
        return f"subfinder -d {domain} -silent"
