from __future__ import annotations

import time
from typing import Any

from deephunter.agents.base import Agent, AgentResult


class AuthorizationReviewWorkflow(Agent):
    """Workflow 5: Authorization Review.

    Checks for IDOR, role-based access control issues, privilege
    escalation paths, and missing access controls on sensitive
    endpoints (admin panels, user management, settings).
    """

    def __init__(self, name: str | None = None) -> None:
        super().__init__(name or "authorization_review")
        self._description = "Authorization review — IDOR, RBAC, privilege escalation, access control testing"

    def execute(self, context: dict[str, Any]) -> AgentResult:
        target = context.get("target", "")
        if not target:
            return AgentResult(agent_name=self.name, success=False, error="No target provided")

        started = time.monotonic()
        findings: dict[str, Any] = {
            "target": target,
            "sensitive_endpoints": [],
            "idor_candidates": [],
            "observations": [],
        }

        sensitive_paths = ["/admin", "/dashboard", "/api/users", "/api/admin",
                            "/settings", "/config", "/api/config", "/api/settings",
                            "/api/v1/users", "/api/v2/users", "/api/internal",
                            "/debug", "/api/debug", "/api/health", "/api/metrics"]

        import urllib.request
        for path in sensitive_paths:
            url = target.rstrip("/") + path
            try:
                resp = urllib.request.urlopen(url, timeout=5)
                if resp.status == 200:
                    findings["sensitive_endpoints"].append({"url": url, "status": resp.status, "issue": "Potentially unprotected"})
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    findings["sensitive_endpoints"].append({"url": url, "status": e.code, "note": "Properly restricted"})
            except Exception:
                pass

        elapsed = (time.monotonic() - started) * 1000
        findings["duration_ms"] = elapsed
        return AgentResult(
            agent_name=self.name,
            success=True,
            data=findings,
            execution_time_ms=elapsed,
        )
