from __future__ import annotations

from typing import Any

from deephunter.recon.models import Endpoint, EndpointCategory, Host, HostStatus, HttpMethod, Protocol, ReconSourceType, Technology, TechCategory
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolMetadata
from deephunter.tools.normalizer import parse_ndjson


_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class NucleiAdapter(BaseToolPlugin):
    metadata = ToolMetadata(
        name="nuclei",
        description="Vulnerability scanner via Nuclei — runs YAML-based templates to detect security issues",
        version="1.0.0",
        category=ToolCategory.vulnerability_scan,
        tags=["vulnerability", "scan", "template", "nuclei"],
        supported_formats=["ndjson"],
        requires_network=True,
        requires_installation=True,
        timeout_default=600.0,
        retry_default=0,
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        import shlex
        import subprocess

        target = context.args.get("target", context.target)
        templates = context.args.get("templates", "")
        severity = context.args.get("severity", "")
        cmd = f"nuclei -u {shlex.quote(target)} -json"
        if templates:
            cmd += f" -t {shlex.quote(templates)}"
        if severity:
            cmd += f" -severity {shlex.quote(severity)}"
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
        return parse_ndjson(raw, {})

    def normalize(self, parsed: list[dict[str, Any]], context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        seen_hosts: dict[str, Host] = {}
        seen_findings: set[str] = set()

        for finding in parsed:
            template_id = finding.get("template-id", "") or finding.get("template_id", "") or ""
            host_str = finding.get("host", "") or finding.get("ip", "") or ""
            matched = finding.get("matched-at", "") or finding.get("matched_at", "") or finding.get("url", "") or ""
            severity = (finding.get("info", {}) or {}).get("severity", "info")
            name = (finding.get("info", {}) or {}).get("name", template_id)
            description = (finding.get("info", {}) or {}).get("description", "")
            tags = (finding.get("info", {}) or {}).get("tags", [])
            if isinstance(tags, str):
                tags = [tags]
            type_name = (finding.get("type", "") or "").lower()
            extracted = finding.get("extracted-results", []) or finding.get("extracted_results", []) or []

            if not host_str and not matched:
                continue

            finding_key = f"{template_id}:{matched}"
            if finding_key in seen_findings:
                continue
            seen_findings.add(finding_key)

            severity_score = _SEVERITY_ORDER.get(severity, 0)
            finding_tags = ["nuclei", f"template:{template_id}", f"severity:{severity}"] + list(tags)
            finding_tags.append(f"severity_score:{severity_score}")

            if host_str and host_str not in seen_hosts:
                host = Host(
                    hostname=host_str.lower().strip(),
                    ip="",
                    port=443,
                    protocol=Protocol.HTTPS,
                    status=HostStatus.ACTIVE,
                    source=ReconSourceType.INTEGRATION,
                    tags=["nuclei"],
                    metadata={
                        "nuclei_findings": [],
                    },
                )
                seen_hosts[host_str] = host

            if host_str in seen_hosts:
                host_findings = seen_hosts[host_str].metadata.get("nuclei_findings", [])
                if not isinstance(host_findings, list):
                    host_findings = []
                finding_entry = {
                    "template_id": template_id,
                    "name": name,
                    "severity": severity,
                    "severity_score": severity_score,
                    "description": description,
                    "matched": matched,
                    "type": type_name,
                    "tags": tags,
                    "extracted": extracted,
                }
                host_findings.append(finding_entry)
                seen_hosts[host_str].metadata["nuclei_findings"] = host_findings

            if matched:
                endpoint = Endpoint(
                    path=matched,
                    method=HttpMethod.GET,
                    category=EndpointCategory.UNKNOWN,
                    source=ReconSourceType.INTEGRATION,
                    metadata={
                        "tool": "nuclei",
                        "template_id": template_id,
                        "finding_name": name,
                        "severity": severity,
                        "severity_score": severity_score,
                    },
                )
                result.endpoints.append(endpoint)

            found_tech = (finding.get("info", {}) or {}).get("technology", [])
            if isinstance(found_tech, str):
                found_tech = [found_tech]
            for tech_name in found_tech:
                if isinstance(tech_name, str):
                    tech = Technology(
                        name=tech_name,
                        category=TechCategory.UNKNOWN,
                        source=ReconSourceType.TECHNOLOGY_FINGERPRINT,
                        metadata={"detected_by": "nuclei", "template_id": template_id},
                    )
                    result.technologies.append(tech)

        for host in seen_hosts.values():
            result.hosts.append(host)

        result.success = True
        return result

    def health(self, context: ExecutionContext) -> PluginHealth:
        import shutil
        found = shutil.which("nuclei") is not None
        return PluginHealth(
            healthy=found,
            installed=found,
            executable_found=found,
            errors=[] if found else ["nuclei not found on PATH"],
        )

    def build_command(self, context: ExecutionContext) -> str:
        target = context.args.get("target", context.target)
        return f"nuclei -u {target} -json"
