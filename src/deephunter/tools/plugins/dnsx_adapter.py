from __future__ import annotations

from typing import Any

from deephunter.recon.models import DNSRecord, DNSRecordType, Host, HostStatus, Protocol, ReconSourceType
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolMetadata
from deephunter.tools.normalizer import parse_ndjson, parse_txt


class DNSxAdapter(BaseToolPlugin):
    metadata = ToolMetadata(
        name="dnsx",
        description="DNS resolver and prober via dnsx — resolves A, AAAA, CNAME, MX, NS, TXT records",
        version="1.0.0",
        category=ToolCategory.dns_enum,
        tags=["dns", "resolution", "probe", "dnsx"],
        supported_formats=["ndjson", "txt"],
        requires_network=True,
        requires_installation=True,
        timeout_default=120.0,
        retry_default=1,
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        import shlex
        import subprocess

        domain = context.args.get("domain", context.target)
        resp = context.args.get("retry", "3")
        cmd = f"dnsx -d {shlex.quote(domain)} -retry {resp} -a -aaaa -cname -mx -ns -txt -json"
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
        if raw.strip().startswith("{"):
            return parse_ndjson(raw, {})
        lines = parse_txt(raw, {})
        return [{"host": line} for line in lines]

    def normalize(self, parsed: list[dict[str, Any]], context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        seen_hosts: set[str] = set()

        for entry in parsed:
            hostname = entry.get("host", "") or entry.get("input", "") or ""
            hostname = hostname.lower().strip()
            if not hostname:
                continue

            dns_records: list[DNSRecord] = []
            record_types: list[str] = []

            for rtype_field, rtype_enum in [
                ("a", DNSRecordType.A),
                ("aaaa", DNSRecordType.AAAA),
                ("cname", DNSRecordType.CNAME),
                ("mx", DNSRecordType.MX),
                ("ns", DNSRecordType.NS),
                ("txt", DNSRecordType.TXT),
            ]:
                val = entry.get(rtype_field)
                if not val:
                    continue
                if isinstance(val, list):
                    for v in val:
                        dns_records.append(DNSRecord(record_type=rtype_enum, value=str(v), source=ReconSourceType.DNS_ENUMERATION))
                        record_types.append(rtype_field.upper())
                else:
                    dns_records.append(DNSRecord(record_type=rtype_enum, value=str(val), source=ReconSourceType.DNS_ENUMERATION))
                    record_types.append(rtype_field.upper())

            ip = entry.get("a", "")
            if isinstance(ip, list):
                ip = ip[0] if ip else ""
            ip = str(ip) if ip else ""

            if hostname not in seen_hosts:
                seen_hosts.add(hostname)
                host = Host(
                    hostname=hostname,
                    ip=ip,
                    port=53,
                    protocol=Protocol.TCP,
                    status=HostStatus.ACTIVE if dns_records else HostStatus.UNKNOWN,
                    source=ReconSourceType.DNS_ENUMERATION,
                    dns_records=dns_records,
                    tags=["dnsx"] + [f"record:{rt}" for rt in record_types],
                    metadata={"record_types_found": record_types},
                )
                result.hosts.append(host)

        result.success = True
        return result

    def health(self, context: ExecutionContext) -> PluginHealth:
        import shutil
        found = shutil.which("dnsx") is not None
        return PluginHealth(
            healthy=found,
            installed=found,
            executable_found=found,
            errors=[] if found else ["dnsx not found on PATH"],
        )

    def build_command(self, context: ExecutionContext) -> str:
        domain = context.args.get("domain", context.target)
        return f"dnsx -d {domain} -a -aaaa -cname -mx -ns -txt -json"
