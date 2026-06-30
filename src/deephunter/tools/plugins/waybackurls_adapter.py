from __future__ import annotations

from typing import Any

from deephunter.recon.models import Endpoint, EndpointCategory, HttpMethod, ReconSourceType
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolMetadata
from deephunter.tools.normalizer import parse_txt


class WaybackURLsAdapter(BaseToolPlugin):
    metadata = ToolMetadata(
        name="waybackurls",
        description="Fetch known URLs from the Wayback Machine for a given domain",
        version="1.0.0",
        category=ToolCategory.url_discovery,
        tags=["url", "discovery", "wayback", "archive", "history"],
        supported_formats=["txt"],
        requires_network=True,
        requires_installation=True,
        timeout_default=120.0,
        retry_default=1,
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        import shlex
        import subprocess

        domain = context.args.get("domain", context.target)
        cmd = f"waybackurls {shlex.quote(domain)}"
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
        for url in parsed:
            url = url.strip()
            if not url or url in seen:
                continue
            seen.add(url)
            endpoint = Endpoint(
                path=url,
                method=HttpMethod.GET,
                category=EndpointCategory.UNKNOWN,
                source=ReconSourceType.URL_COLLECTION,
                metadata={"tool": "waybackurls"},
            )
            result.endpoints.append(endpoint)
        result.success = True
        return result

    def health(self, context: ExecutionContext) -> PluginHealth:
        import shutil
        found = shutil.which("waybackurls") is not None
        return PluginHealth(
            healthy=found,
            installed=found,
            executable_found=found,
            errors=[] if found else ["waybackurls not found on PATH"],
        )

    def build_command(self, context: ExecutionContext) -> str:
        domain = context.args.get("domain", context.target)
        return f"waybackurls {domain}"
