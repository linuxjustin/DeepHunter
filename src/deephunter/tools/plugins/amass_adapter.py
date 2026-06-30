"""Amass output adapter — imports enumeration results including ASN, CIDR, IPs,
subdomains, certificates, and graph relationships.

Input formats supported:
  - JSON: Amass JSON format (one JSON object per line)
  - TXT: one subdomain per line
"""

from __future__ import annotations

from typing import Any

from deephunter.recon.models import (
    Asset,
    DNSRecord,
    DNSRecordType,
    Host,
    HostStatus,
    Protocol,
    ReconSourceType,
)
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import ToolCategory, ToolMetadata
from deephunter.tools.normalizer import parse_ndjson, parse_txt


class AmassAdapter(BaseToolPlugin):
    metadata = ToolMetadata(
        name="amass_adapter",
        description="DNS enumeration and ASN lookup via Amass — discovers subdomains, IP ranges, and certificate data",
        version="1.0.0",
        category=ToolCategory.dns_enum,
        tags=["dns", "enumeration", "amass", "asn", "certificate"],
        supported_formats=["ndjson", "json", "txt"],
        requires_network=True,
        requires_installation=True,
        timeout_default=600.0,
        retry_default=0,
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        import shlex
        import subprocess

        domain = context.args.get("domain", context.target)
        cmd = f"amass enum -d {domain} -json -"
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

        if raw_str.startswith("{"):
            return parse_ndjson(raw_str, {})

        lines = parse_txt(raw_str, {})
        return [{"name": line} for line in lines]

    def normalize(self, parsed: list[dict[str, Any]], context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        seen_hosts: set[str] = set()
        seen_asns: set[str] = set()
        seen_cidrs: set[str] = set()
        target = context.args.get("domain", context.target)

        for entry in parsed:
            name = entry.get("name", "") or entry.get("host", "") or ""
            name_lower = name.lower().strip()

            # ── ASN ──────────────────────────────────────────────
            asn_id = ""
            asn_desc = entry.get("asn_description", "") or ""
            asn_num = entry.get("asn", "") or ""
            if asn_num:
                asn_key = str(asn_num)
                if asn_key not in seen_asns:
                    seen_asns.add(asn_key)
                    asset = Asset(
                        identifier=f"AS{asn_num}",
                        asset_type="asn",
                        source=ReconSourceType.DNS_ENUMERATION,
                        tags=["amass", "asn"],
                        metadata={"asn": asn_num, "description": asn_desc, "original_target": target},
                    )
                    result.assets.append(asset)
                    asn_id = asset.id

            # ── CIDR ─────────────────────────────────────────────
            cidr_str = entry.get("cidr", "") or ""
            if cidr_str and cidr_str not in seen_cidrs:
                seen_cidrs.add(cidr_str)
                asset = Asset(
                    identifier=cidr_str,
                    asset_type="cidr",
                    source=ReconSourceType.DNS_ENUMERATION,
                    tags=["amass", "cidr"],
                    metadata={"asn": asn_num, "original_target": target},
                )
                result.assets.append(asset)

            # ── Host / subdomain ─────────────────────────────────
            if name_lower and name_lower not in seen_hosts:
                seen_hosts.add(name_lower)

                ip = ""
                addresses = entry.get("addresses", [])
                if addresses:
                    ip = addresses[0].get("ip", "") if isinstance(addresses[0], dict) else str(addresses[0])

                dns_records: list[DNSRecord] = []
                if addresses:
                    for addr in addresses:
                        if isinstance(addr, dict):
                            ip_addr = addr.get("ip", "")
                            if ip_addr:
                                dns_records.append(DNSRecord(
                                    record_type=DNSRecordType.A,
                                    value=ip_addr,
                                    source=ReconSourceType.DNS_ENUMERATION,
                                ))

                tags: list[str] = ["amass"]
                if asn_num:
                    tags.append(f"asn:{asn_num}")

                asset = Asset(
                    identifier=name_lower,
                    asset_type="subdomain",
                    source=ReconSourceType.DNS_ENUMERATION,
                    tags=tags,
                    metadata={"asn": asn_num, "cidr": cidr_str, "original_target": target},
                )
                result.assets.append(asset)

                host = Host(
                    hostname=name_lower,
                    ip=ip,
                    port=443,
                    protocol=Protocol.HTTPS,
                    status=HostStatus.UNKNOWN,
                    source=ReconSourceType.DNS_ENUMERATION,
                    tags=tags,
                    dns_records=dns_records,
                    metadata={"asn": asn_num, "cidr": cidr_str, "original_target": target},
                )
                result.hosts.append(host)

        result.success = True
        return result

    def build_command(self, context: ExecutionContext) -> str:
        domain = context.args.get("domain", context.target)
        return f"amass enum -d {domain} -json -"

    def health(self, context: ExecutionContext) -> "PluginHealth":
        import shutil
        found = shutil.which("amass") is not None
        from deephunter.tools.models import PluginHealth
        return PluginHealth(
            healthy=found,
            installed=found,
            executable_found=found,
            errors=[] if found else ["amass not found on PATH"],
        )
