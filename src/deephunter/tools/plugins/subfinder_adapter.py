"""Subfinder output adapter — imports subdomain enumeration results.

Input formats supported:
  - TXT: one subdomain per line
  - JSON: {"host":"sub.example.com","ip":"1.2.3.4","source":"...",...}
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
from deephunter.tools.normalizer import parse_json, parse_txt


class SubfinderAdapter(BaseToolPlugin):
    metadata = ToolMetadata(
        name="subfinder_adapter",
        description="Fast subdomain enumeration via subfinder — passive DNS sources",
        version="1.0.0",
        category=ToolCategory.subdomain_enum,
        tags=["subdomain", "dns", "recon"],
        supported_formats=["json", "txt"],
        requires_network=True,
        requires_installation=True,
        timeout_default=120.0,
        retry_default=1,
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        import shlex
        import subprocess

        domain = context.args.get("domain", context.target)
        cmd = f"subfinder -d {domain} -oJ -silent"
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

    def parse_output(self, raw: str | bytes | None, context: ExecutionContext) -> list[dict[str, Any]]:
        if not raw:
            return []
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")

        raw_str = raw.strip()
        if not raw_str:
            return []

        if raw_str.startswith("{") or raw_str.startswith("["):
            data = parse_json(raw_str, {})
            if isinstance(data, list):
                return data
            return [data]

        lines = parse_txt(raw_str, {})
        return [{"host": line} for line in lines]

    def normalize(self, parsed: list[dict[str, Any]], context: ExecutionContext) -> PluginResult:
        import json

        result = PluginResult()
        seen: set[str] = set()
        target = context.args.get("domain", context.target)

        for entry in parsed:
            hostname = entry.get("host", "") or entry.get("hostname", "") or entry.get("name", "")
            if not hostname:
                continue
            hostname = hostname.lower().strip()
            if hostname in seen:
                continue
            seen.add(hostname)

            ip = entry.get("ip", "")
            source_str = entry.get("source", "")
            tags_list: list[str] = []
            if source_str:
                tags_list.append(f"source:{source_str}")

            asset = Asset(
                identifier=hostname,
                asset_type="subdomain",
                source=ReconSourceType.SUBDOMAIN_ENUMERATION,
                tags=tags_list,
                metadata={"raw_source": source_str, "original_target": target},
            )
            result.assets.append(asset)

            host = Host(
                hostname=hostname,
                ip=ip,
                port=443,
                protocol=Protocol.HTTPS,
                status=HostStatus.UNKNOWN,
                source=ReconSourceType.SUBDOMAIN_ENUMERATION,
                tags=tags_list,
                metadata={"raw_source": source_str, "original_target": target},
            )
            result.hosts.append(host)

        result.success = True
        result.error = ""
        return result

    def build_command(self, context: ExecutionContext) -> str:
        domain = context.args.get("domain", context.target)
        return f"subfinder -d {domain} -oJ -silent"

    def health(self, context: ExecutionContext) -> "PluginHealth":
        import shutil
        found = shutil.which("subfinder") is not None
        from deephunter.tools.models import PluginHealth
        return PluginHealth(
            healthy=found,
            installed=found,
            executable_found=found,
            errors=[] if found else ["subfinder not found on PATH"],
        )
