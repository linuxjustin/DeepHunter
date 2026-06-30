"""Methodology selection engine.

Selects the most relevant methodology for a given set of detected
technologies, frameworks, and attack surface areas.
"""

from __future__ import annotations

from deephunter.methodology.models import (
    Confidence,
    Methodology,
    MethodologySelection,
    Priority,
    RiskCategory,
    TestingObjective,
    TestingTechnique,
)
from deephunter.methodology.profiles import get_framework_profiles


def _build_methodologies() -> list[Methodology]:
    """Build a list of known methodologies from framework profiles.

    Each framework profile becomes a methodology with appropriate
    objectives and techniques drawn from the profile's investigation areas.
    """
    methodologies: list[Methodology] = []
    for name, profile in get_framework_profiles().items():
        objectives = [
            TestingObjective(
                name=area,
                description=f"Investigation area: {area} - Framework: {profile.framework_name}",
                tags=profile.tags,
            )
            for area in profile.investigation_areas
        ]
        techniques = [
            TestingTechnique(
                name=wf,
                description=f"Workflow: {wf} - Framework: {profile.framework_name}",
                tags=profile.tags,
            )
            for wf in profile.testing_workflows
        ]
        methodology = Methodology(
            name=f"{profile.framework_name} Security Testing",
            description=f"Security testing methodology for {profile.framework_name}",
            objectives=objectives,
            techniques=techniques,
            tags=profile.tags,
            technologies=[profile.framework_name],
            frameworks=[profile.framework_name],
            attack_surface_areas=list(profile.investigation_areas),
        )
        # Assign risk per technique based on typical bug class severity
        for tech in techniques:
            if any(
                kw in tech.name.lower()
                for kw in ["rce", "sql injection", "deserialization", "ssti", "xxe"]
            ):
                tech.risk = RiskCategory.CRITICAL
            elif any(
                kw in tech.name.lower()
                for kw in ["xss", "idor", "csrf", "ssrf", "privilege escalation"]
            ):
                tech.risk = RiskCategory.HIGH
        methodologies.append(methodology)

    return methodologies


_DEFAULT_METHODOLOGY = Methodology(
    name="General Web Security Testing",
    description="Standard OWASP-aligned security testing methodology",
    tags=["web", "general"],
    technologies=["*"],
    frameworks=["*"],
    attack_surface_areas=["authentication", "authorization", "input validation", "session management"],
    objectives=[
        TestingObjective(
            name="Authentication",
            description="Test authentication mechanisms for bypass, brute force, and session weaknesses",
        ),
        TestingObjective(
            name="Authorization",
            description="Test access controls for privilege escalation and IDOR",
        ),
        TestingObjective(
            name="Input Validation",
            description="Test for injection vulnerabilities (SQL, XSS, SSTI, etc.)",
        ),
        TestingObjective(
            name="Session Management",
            description="Test session handling for fixation, hijacking, and insecure cookies",
        ),
        TestingObjective(
            name="Configuration",
            description="Test for security misconfiguration and sensitive data exposure",
        ),
    ],
    techniques=[
        TestingTechnique(name="Reconnaissance", description="Enumerate endpoints, tech stack, exposed files"),
        TestingTechnique(name="Dynamic Testing", description="Manual exploratory testing of all attack vectors"),
        TestingTechnique(name="Authentication Testing", description="Test auth mechanisms and session handling"),
    ],
)


def _score_match(
    methodology: Methodology,
    technologies: list[str],
    frameworks: list[str],
    attack_surface_areas: list[str],
) -> float:
    """Compute a match score between 0.0 and 1.0.

    Scoring rule:
    - Framework exact match: +0.4 per match
    - Technology tag overlap: +0.2 per match
    - Attack surface area overlap: +0.1 per match
    - Methodology name substring match: +0.1
    - Denominator normalizes by max possible score.
    """
    score = 0.0
    max_score = 0.0

    tech_lower = [t.lower() for t in technologies]
    fw_lower = [f.lower() for f in frameworks]
    area_lower = [a.lower() for a in attack_surface_areas]
    meth_techs = [t.lower() for t in methodology.technologies]
    meth_fws = [f.lower() for f in methodology.frameworks]
    meth_areas = [a.lower() for a in methodology.attack_surface_areas]

    for mt in meth_techs:
        max_score += 0.4
        for t in tech_lower:
            if t == mt or mt == "*" or t in mt or mt in t:
                score += 0.4
                break

    for mf in meth_fws:
        max_score += 0.2
        if mf == "*":
            continue
        for f in fw_lower:
            if f == mf or f in mf or mf in f:
                score += 0.2
                break

    for ma in meth_areas:
        max_score += 0.1
        for a in area_lower:
            if a == ma or ma in a or a in ma:
                score += 0.1
                break

    for name_part in methodology.name.lower().split():
        max_score += 0.1
        for t in tech_lower:
            if name_part in t or t in name_part:
                score += 0.1
                break

    if max_score == 0.0:
        return 0.0

    normalized = score / max_score
    return min(normalized, 1.0)


class MethodologySelector:
    """Selects relevant methodologies given detected tech, frameworks, and attack surface."""

    def __init__(self, methodologies: list[Methodology] | None = None) -> None:
        self.methodologies = methodologies or _build_methodologies()

    def select(
        self,
        technologies: list[str] | None = None,
        frameworks: list[str] | None = None,
        attack_surface_areas: list[str] | None = None,
        threshold: float = 0.3,
    ) -> list[MethodologySelection]:
        """Select and rank methodologies matching the given context.

        Args:
            technologies: Detected technology names (e.g., ['Python', 'PostgreSQL']).
            frameworks: Detected framework names (e.g., ['Django', 'DRF']).
            attack_surface_areas: Attack surface areas (e.g., ['authentication', 'api']).
            threshold: Minimum relevance score (0.0 to 1.0) to include a result.

        Returns:
            Sorted list of MethodologySelection with relevance scores.
        """
        technologies = technologies or []
        frameworks = frameworks or []
        attack_surface_areas = attack_surface_areas or []
        all_tech = list(set(technologies + frameworks))

        selections: list[MethodologySelection] = []
        for methodology in self.methodologies:
            score = _score_match(methodology, all_tech, frameworks, attack_surface_areas)
            if score < threshold:
                continue

            matched_techs = [
                t
                for t in all_tech
                if any(
                    t.lower() in mt.lower() or mt.lower() in t.lower()
                    for mt in methodology.technologies
                )
            ]
            matched_areas = [
                a
                for a in attack_surface_areas
                if any(a.lower() == ma.lower() for ma in methodology.attack_surface_areas)
                or any(ma.lower() in a.lower() for ma in methodology.attack_surface_areas)
            ]

            confidence = (
                Confidence.HIGH
                if score >= 0.8
                else Confidence.MEDIUM if score >= 0.5 else Confidence.LOW
            )

            selections.append(
                MethodologySelection(
                    methodology=methodology,
                    confidence=confidence,
                    relevance_score=score,
                    matched_technologies=matched_techs,
                    matched_frameworks=list(set(matched_techs) & set(frameworks)),
                    matched_areas=matched_areas,
                )
            )

        # Always include a fallback general methodology
        general_score = _score_match(_DEFAULT_METHODOLOGY, all_tech, frameworks, attack_surface_areas)
        if general_score < 0.5 and not selections:
            selections.append(
                MethodologySelection(
                    methodology=_DEFAULT_METHODOLOGY,
                    confidence=Confidence.MEDIUM,
                    relevance_score=0.5,
                )
            )

        selections.sort(key=lambda s: s.relevance_score, reverse=True)
        return selections
