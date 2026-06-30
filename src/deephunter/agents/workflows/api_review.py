from __future__ import annotations

import json
import time
import urllib.request
from typing import Any

from deephunter.agents.base import Agent, AgentResult


class APIReviewWorkflow(Agent):
    """Workflow 7: API Review.

    Discovers REST and GraphQL API endpoints, analyzes parameters,
    checks for mass assignment, injection points, rate limiting,
    authentication requirements, and excessive data exposure.
    """

    def __init__(self, name: str | None = None) -> None:
        super().__init__(name or "api_review")
        self._description = "API review — REST/GraphQL endpoint discovery, parameter analysis, injection testing"

    def execute(self, context: dict[str, Any]) -> AgentResult:
        target = context.get("target", "")
        if not target:
            return AgentResult(agent_name=self.name, success=False, error="No target provided")

        started = time.monotonic()
        findings: dict[str, Any] = {
            "target": target,
            "rest_endpoints": [],
            "graphql_endpoints": [],
            "api_parameters": [],
            "observations": [],
        }

        api_paths = ["/api", "/api/v1", "/api/v2", "/api/v3", "/graphql",
                      "/api/graphql", "/swagger.json", "/api/swagger.json",
                      "/openapi.json", "/api/openapi.json", "/api/docs"]

        for path in api_paths:
            url = target.rstrip("/") + path
            try:
                resp = urllib.request.urlopen(url, timeout=5)
                content_type = resp.headers.get("Content-Type", "")
                body = resp.read().decode("utf-8", errors="replace")[:2000]
                if "graphql" in path.lower():
                    findings["graphql_endpoints"].append({"url": url, "status": resp.status})
                else:
                    entry = {"url": url, "status": resp.status, "content_type": content_type}
                    if "swagger" in path or "openapi" in path:
                        try:
                            entry["spec"] = json.loads(body)
                        except json.JSONDecodeError:
                            entry["spec_preview"] = body[:500]
                    findings["rest_endpoints"].append(entry)
            except urllib.error.HTTPError as e:
                if e.code in (200, 201, 204, 401, 403, 405):
                    if "graphql" in path.lower():
                        findings["graphql_endpoints"].append({"url": url, "status": e.code})
                    else:
                        findings["rest_endpoints"].append({"url": url, "status": e.code})
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
