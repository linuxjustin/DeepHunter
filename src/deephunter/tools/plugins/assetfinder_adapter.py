"""Assetfinder output adapter — executes and imports subdomain enumeration results.

Input formats supported:
  - TXT: one subdomain per line
"""

from __future__ import annotations

from typing import Any

from deephunter.recon.models import (
    Asset,
    Host,
    HostStatus,
    Protocol,
    ReconSourceType,
)
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import ToolCategory, ToolMetadata
from deephunter.tools.normalizer import parse_txt


class AssetfinderAdapter(BaseToolPlugin):
    metadata = ToolMetadata(
        name="assetfinder_adapter",
        description="Subdomain enumeration via assetfinder — finds subdomains of a domain",
        version="1.0.0",
        category=ToolCategory.subdomain_enum,
        tags=["subdomain", "asset", "recon"],
        supported_formats=["txt"],
        requires_network=True,
        requires_installation=True,
        timeout_default=120.0,
        retry_default=1,
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        import shlex
        import subprocess

        cmd = self.build_command(context)
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

    def parse_output(self, raw: str | bytes | None, context: ExecutionContext) -> list[str]:
        if not raw:
            return []
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        return parse_txt(raw, {})

    def normalize(self, parsed: list[str], context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        seen: set[str] = set()
        target = context.args.get("domain", context.target)

        for hostname in parsed:
            h = hostname.lower().strip()
            if not h or h in seen:
                continue
            seen.add(h)

            asset = Asset(
                identifier=h,
                asset_type="subdomain",
                source=ReconSourceType.SUBDOMAIN_ENUMERATION,
                tags=["assetfinder"],
                metadata={"original_target": target},
            )
            result.assets.append(asset)

            host = Host(
                hostname=h,
                ip="",
                port=443,
                protocol=Protocol.HTTPS,
                status=HostStatus.UNKNOWN,
                source=ReconSourceType.SUBDOMAIN_ENUMERATION,
                tags=["assetfinder"],
                metadata={"original_target": target},
            )
            result.hosts.append(host)

        result.success = True
        return result

    def build_command(self, context: ExecutionContext) -> str:
        domain = context.args.get("domain", context.target)
        return f"assetfinder --subs-only {domain}"

    def health(self, context: ExecutionContext) -> "PluginHealth":
        import shutil
        found = shutil.which("assetfinder") is not None
        from deephunter.tools.models import PluginHealth
        return PluginHealth(
            healthy=found,
            installed=found,
            executable_found=found,
            errors=[] if found else ["assetfinder not found on PATH"],
        )
