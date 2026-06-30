from __future__ import annotations

import json
import time
from typing import Any

from deephunter.agents.base import Agent, AgentResult

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class FindingPreparationWorkflow(Agent):
    """Workflow 10: Finding Preparation.

    Aggregates findings from all prior workflows, deduplicates,
    triages by severity, assigns CVSS scores, and prepares
    structured finding entries for the report.
    """

    def __init__(self, name: str | None = None) -> None:
        super().__init__(name or "finding_prep")
        self._description = "Finding preparation — aggregation, deduplication, triage, severity scoring"

    def execute(self, context: dict[str, Any]) -> AgentResult:
        started = time.monotonic()
        raw_findings = context.get("findings", [])
        if not raw_findings:
            return AgentResult(agent_name=self.name, success=False, error="No findings to prepare")

        findings: list[dict[str, Any]] = []
        seen_signatures: set[str] = set()

        for raw in raw_findings:
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except json.JSONDecodeError:
                    continue
            if not isinstance(raw, dict):
                continue

            title = raw.get("title", raw.get("name", "Untitled Finding"))
            description = raw.get("description", raw.get("detail", ""))
            severity = raw.get("severity", "medium").lower()
            confidence = raw.get("confidence", raw.get("certainty", "medium")).lower()
            category = raw.get("category", raw.get("type", "unknown"))
            endpoint = raw.get("endpoint", raw.get("url", raw.get("path", "")))
            evidence = raw.get("evidence", raw.get("proof", raw.get("output", "")))
            remediation = raw.get("remediation", raw.get("fix", ""))
            references = raw.get("references", [])

            signature = f"{title}:{endpoint}:{severity}"
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)

            cvss_score = _SEVERITY_ORDER.get(severity, 1)
            finding = {
                "title": title,
                "description": description,
                "severity": severity,
                "cvss_score": cvss_score,
                "confidence": confidence,
                "category": category,
                "endpoint": endpoint,
                "evidence": str(evidence)[:1000],
                "remediation": remediation,
                "references": references if isinstance(references, list) else [references],
            }
            findings.append(finding)

        findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 0), reverse=True)
        summary = {
            "total": len(findings),
            "by_severity": {s: 0 for s in _SEVERITY_ORDER},
        }
        for f in findings:
            sev = f["severity"]
            if sev in summary["by_severity"]:
                summary["by_severity"][sev] += 1

        elapsed = (time.monotonic() - started) * 1000
        result_data = {"findings": findings, "summary": summary}
        return AgentResult(
            agent_name=self.name,
            success=True,
            data=result_data,
            execution_time_ms=elapsed,
        )
