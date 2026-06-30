"""Checklist generation engine.

Generates structured checklists from methodology + framework profile + attack surface.
"""

from __future__ import annotations

from deephunter.methodology.models import (
    Checklist,
    ChecklistItem,
    EvidenceRequirement,
    FrameworkProfile,
    Methodology,
    MethodologySelection,
    Priority,
    Reference,
)
from deephunter.methodology.profiles import get_framework_profiles


_CHECKLIST_PATTERNS: dict[str, tuple[str, str]] = {
    "reconnaissance": (
        "Enumerate endpoints and detect technology",
        "Map all accessible routes, endpoints, and API surfaces; identify underlying technologies and versions.",
    ),
    "authentication": (
        "Test authentication mechanisms",
        "Verify authentication bypass, session management, credential handling, and multi-factor auth.",
    ),
    "authorization": (
        "Test authorization controls",
        "Verify access controls, privilege separation, and horizontal/vertical escalation paths.",
    ),
    "input validation": (
        "Test input validation and sanitization",
        "Identify injection vulnerabilities (SQL, NoSQL, XSS, SSTI, command injection, etc.).",
    ),
    "session management": (
        "Test session handling",
        "Verify session token security, fixation protection, cookie attributes, and expiry.",
    ),
    "configuration": (
        "Test security configuration",
        "Check for security misconfiguration, debug endpoints, unnecessary features, and default credentials.",
    ),
    "api security": (
        "Test API security",
        "Verify API authentication, rate limiting, mass assignment, parameter pollution, and data exposure.",
    ),
    "file upload": (
        "Test file upload functionality",
        "Verify file type validation, path traversal protection, size limits, and stored file access controls.",
    ),
    "business logic": (
        "Test business logic flaws",
        "Identify logic errors in workflows, state manipulation, race conditions, and abuse of legitimate features.",
    ),
}


class ChecklistEngine:
    """Generates ordered checklists from methodology + framework profile + attack surface."""

    def __init__(self) -> None:
        self._cache: dict[str, Checklist] = {}

    def generate(
        self,
        selections: list[MethodologySelection],
        framework_profiles: list[FrameworkProfile] | None = None,
        attack_surface_areas: list[str] | None = None,
    ) -> list[Checklist]:
        """Generate checklists for each methodology selection."""
        if framework_profiles is None:
            framework_profiles = list(get_framework_profiles().values())

        checklists: list[Checklist] = []
        for selection in selections:
            cl = self._generate_for_selection(selection, framework_profiles, attack_surface_areas or [])
            if cl.items:
                checklists.append(cl)

        return checklists

    def _generate_for_selection(
        self,
        selection: MethodologySelection,
        framework_profiles: list[FrameworkProfile],
        attack_surface_areas: list[str],
    ) -> Checklist:
        methodology = selection.methodology
        checklist = Checklist(methodology_id=methodology.id)

        # Match framework profile
        fp = next(
            (p for p in framework_profiles if p.framework_name in methodology.frameworks),
            None,
        )

        # Collect items from 3 axes
        seen: set[str] = set()
        items: list[ChecklistItem] = []

        # Axis 1: Methodology objectives
        for obj in methodology.objectives:
            item = self._make_item(obj.name, obj.description, Priority.HIGH, "reconnaissance", obj.tags)
            if item.objective not in seen:
                seen.add(item.objective)
                items.append(item)

        # Axis 2: Framework profile investigation areas
        if fp:
            for area in fp.investigation_areas:
                if area not in seen:
                    seen.add(area)
                    priority = self._priority_for_area(area)
                    items.append(
                        ChecklistItem(
                            objective=area,
                            description=f"{area} testing for {fp.framework_name}",
                            priority=priority,
                            related_frameworks=[fp.framework_name],
                            procedure=self._suggest_procedure(area),
                        )
                    )

        # Axis 3: Attack surface areas
        for area in attack_surface_areas:
            if area not in seen:
                seen.add(area)
                pattern = _CHECKLIST_PATTERNS.get(area, (area, f"Manual testing of {area}"))
                items.append(
                    ChecklistItem(
                        objective=pattern[0],
                        description=pattern[1],
                        priority=Priority.MEDIUM,
                        procedure=self._suggest_procedure(area),
                    )
                )

        # Sort by priority
        priority_order = {
            Priority.CRITICAL: 0,
            Priority.HIGH: 1,
            Priority.MEDIUM: 2,
            Priority.LOW: 3,
        }
        items.sort(key=lambda it: priority_order.get(it.priority, 99))

        checklist.items = items
        checklist.recalculate()
        return checklist

    def _make_item(
        self,
        objective: str,
        description: str,
        priority: Priority,
        area_key: str,
        tags: list[str] | None = None,
    ) -> ChecklistItem:
        procedure = self._suggest_procedure(objective)
        ref = Reference(
            source="OWASP",
            ref_id="WSTG",
            title="OWASP Web Security Testing Guide",
            description=f"Refer to OWASP WSTG for {objective} testing procedures.",
        )
        return ChecklistItem(
            objective=objective,
            description=description,
            procedure=procedure,
            priority=priority,
            references=[ref],
            tags=tags or [],
            required_evidence=[
                EvidenceRequirement(
                    description=f"Evidence of {objective} testing",
                    evidence_type="screenshot",
                )
            ],
        )

    def _suggest_procedure(self, objective: str) -> str:
        obj_lower = objective.lower()
        if "injection" in obj_lower or "sql" in obj_lower:
            return (
                f"1. Map all input vectors (params, body, headers, cookies)\n"
                f"2. Craft injection payloads specific to the target DB/parser\n"
                f"3. Test each vector for error-based, blind, time-based, and out-of-band detection\n"
                f"4. Verify impact and document proof of concept"
            )
        if "xss" in obj_lower or "cross-site" in obj_lower or "cross site" in obj_lower:
            return (
                f"1. Identify all reflection and storage points for user-controlled data\n"
                f"2. Test context-specific payloads (HTML context, attribute, JS, URL)\n"
                f"3. Test for DOM-based XSS via source/sink analysis\n"
                f"4. Verify with alert/prompt or external callback"
            )
        if "auth" in obj_lower:
            return (
                f"1. Enumerate authentication endpoints and flows\n"
                f"2. Test for credential brute-force / rate limiting\n"
                f"3. Test session token strength and entropy\n"
                f"4. Test password reset flows for token prediction\n"
                f"5. Test multi-factor auth bypass scenarios"
            )
        if "upload" in obj_lower:
            return (
                f"1. Identify file upload endpoints and accepted MIME types\n"
                f"2. Test extension whitelist/blacklist bypass (.php5, .phtml, .pHp)\n"
                f"3. Test content-type validation bypass (image/gif with PHP payload)\n"
                f"4. Test path traversal in filename\n"
                f"5. Test double extension and null byte injection"
            )
        if "api" in obj_lower:
            return (
                f"1. Enumerate all API endpoints via docs, discovery, or crawling\n"
                f"2. Test each endpoint for proper authentication and authorization\n"
                f"3. Test for mass assignment via extra fields in request body\n"
                f"4. Test for parameter pollution (duplicate params, HTTP param pollution)\n"
                f"5. Test rate limiting and resource exhaustion"
            )
        if "business" in obj_lower or "logic" in obj_lower:
            return (
                f"1. Understand the intended workflow by using the feature legitimately\n"
                f"2. Identify state transitions and their enforcement on the server\n"
                f"3. Test for race conditions (concurrent requests)\n"
                f"4. Test for integer/currency overflow in financial operations\n"
                f"5. Test coupon/discount/voucher abuse"
            )
        if "recon" in obj_lower or "enumeration" in obj_lower:
            return (
                f"1. Scan target with accessible URL enumeration tools\n"
                f"2. Check for exposed files (.git, .env, backup files, source maps)\n"
                f"3. Enumerate API endpoints (OpenAPI, Swagger, WSDL)\n"
                f"4. Check debug endpoints (/debug, /actuator, /console, /phpinfo)\n"
                f"5. Review HTTP response headers for tech fingerprinting"
            )
        return (
            f"1. Understand the feature and its data flow\n"
            f"2. Identify user-controlled input points\n"
            f"3. Craft and send test payloads targeting the vulnerability class\n"
            f"4. Analyze responses and verify findings"
        )

    def _priority_for_area(self, area: str) -> Priority:
        area_lower = area.lower()
        if any(
            kw in area_lower
            for kw in [
                "rce", "sql injection", "deserialization", "ssti", "command injection",
                "remote code execution", "unserialize",
            ]
        ):
            return Priority.CRITICAL
        if any(kw in area_lower for kw in ["xss", "idor", "csrf", "ssrf", "privilege escalation"]):
            return Priority.HIGH
        if any(kw in area_lower for kw in ["auth", "session", "access control", "injection"]):
            return Priority.HIGH
        return Priority.MEDIUM
