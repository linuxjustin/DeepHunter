from __future__ import annotations

import json
import re
import time
import urllib.request
from urllib.parse import urljoin
from typing import Any

from deephunter.agents.base import Agent, AgentResult

_SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'["\']sk_live_[0-9a-zA-Z]{24,}["\']', "Stripe Live Secret"),
    (r'["\']pk_live_[0-9a-zA-Z]{24,}["\']', "Stripe Live Publishable Key"),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Private Key"),
    (r'gh[ps]_[0-9a-zA-Z]{36}', "GitHub Token"),
    (r'xox[baprs]-[0-9a-zA-Z]{10,}', "Slack Token"),
    (r'["\'](?:api|api_key|apikey|secret|token)["\']\s*:\s*["\'][0-9a-zA-Z_\-]{16,}["\']', "Hardcoded API Key/Secret"),
    (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', "JWT Token"),
    (r'["\']password["\']\s*:\s*["\'][^"\']{4,}["\']', "Hardcoded Password"),
]


class JavaScriptReviewWorkflow(Agent):
    """Workflow 8: JavaScript Review.

    Discovers JavaScript files from crawled URLs, extracts embedded
    endpoints, API routes, and secrets (API keys, tokens, passwords).
    Analyzes source maps if available.
    """

    def __init__(self, name: str | None = None) -> None:
        super().__init__(name or "js_review")
        self._description = "JavaScript review — JS file discovery, endpoint extraction, secret scanning"

    def execute(self, context: dict[str, Any]) -> AgentResult:
        target = context.get("target", "")
        if not target:
            return AgentResult(agent_name=self.name, success=False, error="No target provided")

        started = time.monotonic()
        findings: dict[str, Any] = {
            "target": target,
            "js_files": [],
            "discovered_endpoints": [],
            "secrets": [],
            "observations": [],
        }

        try:
            resp = urllib.request.urlopen(target, timeout=10)
            html = resp.read().decode("utf-8", errors="replace")
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for src in script_srcs:
                js_url = urljoin(target, src)
                findings["js_files"].append(js_url)
                try:
                    js_resp = urllib.request.urlopen(js_url, timeout=10)
                    js_content = js_resp.read().decode("utf-8", errors="replace")
                    api_paths = re.findall(r'["\'](/[a-zA-Z0-9_\-/{}]+)["\']', js_content)
                    for p in api_paths:
                        if any(k in p.lower() for k in ["api", "v1", "v2", "graphql", "admin", "auth"]):
                            findings["discovered_endpoints"].append(p)
                    for pattern, name in _SECRET_PATTERNS:
                        matches = re.findall(pattern, js_content)
                        for m in matches:
                            masked = m[:8] + "..." + m[-4:] if len(m) > 12 else m[:4] + "..."
                            findings["secrets"].append({"type": name, "match": masked, "file": js_url})
                except Exception:
                    pass
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
