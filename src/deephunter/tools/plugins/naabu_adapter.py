from __future__ import annotations

from typing import Any

from deephunter.recon.models import Host, HostStatus, Protocol, ReconSourceType
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolMetadata
from deephunter.tools.normalizer import parse_ndjson, parse_txt


_WELL_KNOWN_PORTS: dict[int, tuple[str, Protocol]] = {
    80: ("http", Protocol.HTTP),
    443: ("https", Protocol.HTTPS),
    8080: ("http", Protocol.HTTP),
    8443: ("https", Protocol.HTTPS),
    22: ("ssh", Protocol.TCP),
    21: ("ftp", Protocol.TCP),
    3306: ("mysql", Protocol.TCP),
    5432: ("postgresql", Protocol.TCP),
    6379: ("redis", Protocol.TCP),
    27017: ("mongodb", Protocol.TCP),
    53: ("dns", Protocol.TCP),
    25: ("smtp", Protocol.TCP),
    143: ("imap", Protocol.TCP),
    993: ("imaps", Protocol.TCP),
    389: ("ldap", Protocol.TCP),
    636: ("ldaps", Protocol.TCP),
}


class NaabuAdapter(BaseToolPlugin):
    metadata = ToolMetadata(
        name="naabu",
        description="Fast port scanner via naabu — discovers open TCP ports on targets",
        version="1.0.0",
        category=ToolCategory.port_scan,
        tags=["port", "scan", "network", "naabu"],
        supported_formats=["ndjson", "txt"],
        requires_network=True,
        requires_installation=True,
        timeout_default=600.0,
        retry_default=0,
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        import shlex
        import subprocess

        host = context.args.get("host", context.target)
        ports = context.args.get("ports", "80,443,8080,8443")
        cmd = f"naabu -host {shlex.quote(host)} -p {shlex.quote(ports)} -json"
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
        return [self._parse_line(line) for line in lines]

    @staticmethod
    def _parse_line(line: str) -> dict[str, Any]:
        import re
        line = line.strip()
        m = re.match(r"(\S+):(\d+)", line)
        if m:
            return {"host": m.group(1), "port": int(m.group(2))}
        parts = line.split()
        if len(parts) >= 2 and parts[-1].isdigit():
            return {"host": parts[0], "port": int(parts[-1])}
        return {"host": line, "port": 0}

    def normalize(self, parsed: list[dict[str, Any]], context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        seen: set[tuple[str, int]] = set()
        for entry in parsed:
            hostname = entry.get("host", "").lower().strip()
            port = int(entry.get("port", 0) or 0)
            if not hostname or port <= 0:
                continue
            key = (hostname, port)
            if key in seen:
                continue
            seen.add(key)

            service, protocol = _WELL_KNOWN_PORTS.get(port, ("unknown", Protocol.TCP))
            host = Host(
                hostname=hostname,
                ip=entry.get("ip", ""),
                port=port,
                protocol=protocol,
                status=HostStatus.ACTIVE,
                source=ReconSourceType.INTEGRATION,
                tags=["naabu", f"port:{port}", f"service:{service}"],
                metadata={"port": port, "service": service},
            )
            result.hosts.append(host)
        result.success = True
        return result

    def health(self, context: ExecutionContext) -> PluginHealth:
        import shutil
        found = shutil.which("naabu") is not None
        return PluginHealth(
            healthy=found,
            installed=found,
            executable_found=found,
            errors=[] if found else ["naabu not found on PATH"],
        )

    def build_command(self, context: ExecutionContext) -> str:
        host = context.args.get("host", context.target)
        ports = context.args.get("ports", "80,443,8080,8443")
        return f"naabu -host {host} -p {ports} -json"
