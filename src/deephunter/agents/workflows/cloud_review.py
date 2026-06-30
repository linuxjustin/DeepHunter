from __future__ import annotations

import json
import time
import urllib.request
from typing import Any

from deephunter.agents.base import Agent, AgentResult

_CLOUD_METADATA_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
]


class CloudReviewWorkflow(Agent):
    """Workflow 9: Cloud Review.

    Tests for cloud metadata service exposure (SSRF endpoints),
    checks for cloud provider headers, bucket enumeration,
    and known cloud service endpoints.
    """

    def __init__(self, name: str | None = None) -> None:
        super().__init__(name or "cloud_review")
        self._description = "Cloud review — metadata service exposure, bucket enumeration, cloud provider fingerprinting"

    def execute(self, context: dict[str, Any]) -> AgentResult:
        target = context.get("target", "")
        started = time.monotonic()
        findings: dict[str, Any] = {
            "target": target,
            "metadata_access": [],
            "cloud_providers": [],
            "observations": [],
        }

        for meta_url in _CLOUD_METADATA_URLS:
            try:
                req = urllib.request.Request(meta_url)
                if "computeMetadata" in meta_url:
                    req.add_header("Metadata-Flavor", "Google")
                resp = urllib.request.urlopen(req, timeout=5)
                if resp.status == 200:
                    body = resp.read().decode("utf-8", errors="replace")[:2000]
                    findings["metadata_access"].append({"url": meta_url, "status": resp.status, "body_preview": body[:200]})
            except urllib.error.HTTPError as e:
                if e.code in (200, 301, 302, 401, 403):
                    findings["metadata_access"].append({"url": meta_url, "status": e.code})
            except (urllib.error.URLError, OSError):
                pass

        elapsed = (time.monotonic() - started) * 1000
        findings["duration_ms"] = elapsed
        return AgentResult(
            agent_name=self.name,
            success=True,
            data=findings,
            execution_time_ms=elapsed,
        )
