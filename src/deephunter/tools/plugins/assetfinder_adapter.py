"""Assetfinder output adapter — imports subdomain enumeration results.

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
        description="Import assetfinder enumeration output (TXT) into recon models",
        version="1.0.0",
        category=ToolCategory.subdomain_enum,
        tags=["subdomain", "asset", "import", "adapter"],
        supported_formats=["txt"],
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        raise NotImplementedError("AssetfinderAdapter is import-only; use parse_output() with pre-collected output")

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
