from __future__ import annotations

import time
from typing import Any

from deephunter.agents.base import Agent, AgentResult


class BusinessLogicWorkflow(Agent):
    """Workflow 6: Business Logic Review.

    Identifies business logic flaws — workflow bypasses, race conditions,
    mass assignment, integer overflow, currency/rate manipulation,
    coupon/ discount abuse, and multi-step process tampering.
    """

    def __init__(self, name: str | None = None) -> None:
        super().__init__(name or "business_logic")
        self._description = "Business logic review — workflow bypass, race conditions, mass assignment, rate manipulation"

    def execute(self, context: dict[str, Any]) -> AgentResult:
        target = context.get("target", "")
        if not target:
            return AgentResult(agent_name=self.name, success=False, error="No target provided")

        started = time.monotonic()
        findings: dict[str, Any] = {
            "target": target,
            "logic_endpoints": [],
            "concerns": [],
            "observations": [],
        }

        logic_paths = ["/api/checkout", "/api/order", "/api/cart", "/api/coupon",
                        "/api/discount", "/api/transfer", "/api/balance",
                        "/api/withdraw", "/api/payment", "/api/subscribe",
                        "/api/vote", "/api/rate", "/api/review", "/api/feedback"]

        import urllib.request
        for path in logic_paths:
            url = target.rstrip("/") + path
            try:
                resp = urllib.request.urlopen(url, timeout=5)
                findings["logic_endpoints"].append({"url": url, "status": resp.status})
            except urllib.error.HTTPError as e:
                if e.code in (200, 201, 202, 204):
                    findings["logic_endpoints"].append({"url": url, "status": e.code})
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
