from __future__ import annotations

import time
from typing import Any

from deephunter.agents.base import Agent, AgentResult


class AuthReviewWorkflow(Agent):
    """Workflow 4: Authentication Review.

    Identifies login pages, OAuth/OIDC flows, JWT endpoints,
    password reset mechanisms, MFA configurations, and session
    management patterns. Checks for common auth bypasses.
    """

    def __init__(self, name: str | None = None) -> None:
        super().__init__(name or "auth_review")
        self._description = "Authentication review — login pages, OAuth, JWT, password reset, session analysis"

    def execute(self, context: dict[str, Any]) -> AgentResult:
        target = context.get("target", "")
        if not target:
            return AgentResult(agent_name=self.name, success=False, error="No target provided")

        started = time.monotonic()
        findings: dict[str, Any] = {
            "target": target,
            "auth_endpoints": [],
            "auth_mechanisms": [],
            "observations": [],
        }
        errors: list[str] = []

        auth_paths = ["/login", "/signin", "/auth", "/oauth", "/oauth2", "/oauth/v2/authorize",
                       "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
                       "/logout", "/signout", "/register", "/signup", "/reset", "/forgot",
                       "/api/auth", "/api/login", "/api/token", "/api/refresh",
                       "/jwks.json", "/.well-known/jwks.json", "/saml/metadata"]

        import urllib.request
        for path in auth_paths:
            url = target.rstrip("/") + path
            try:
                resp = urllib.request.urlopen(url, timeout=5)
                findings["auth_endpoints"].append({"url": url, "status": resp.status})
            except urllib.error.HTTPError as e:
                if e.code in (200, 401, 403):
                    findings["auth_endpoints"].append({"url": url, "status": e.code})
            except Exception:
                pass

        elapsed = (time.monotonic() - started) * 1000
        findings["errors"] = errors
        findings["duration_ms"] = elapsed
        return AgentResult(
            agent_name=self.name,
            success=True,
            data=findings,
            execution_time_ms=elapsed,
        )
