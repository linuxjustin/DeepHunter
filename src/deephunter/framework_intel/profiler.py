"""Attack Surface Profiler — generates structured attack surface profiles
from framework stacks and technology intelligence.
"""

from __future__ import annotations

from deephunter.framework_intel.correlator import FrameworkCorrelator
from deephunter.framework_intel.models import (
    ApplicationProfile,
    AttackSurfaceProfile,
    FrameworkStack,
)
from deephunter.recon.models import ApplicationType
from deephunter.tech_intel.engine import TechnologyIntelEngine
from deephunter.tech_intel.models import TechnologyKnowledgeEntry


class AttackSurfaceProfiler:
    """Generates attack surface profiles by combining framework correlation
    with technology intelligence."""

    def __init__(
        self,
        tech_intel: TechnologyIntelEngine | None = None,
        correlator: FrameworkCorrelator | None = None,
    ) -> None:
        self._tech_intel = tech_intel or TechnologyIntelEngine()
        self._correlator = correlator or FrameworkCorrelator()

    def profile(self, detected_technologies: list[str]) -> AttackSurfaceProfile:
        """Generate an attack surface profile from detected technologies."""
        stack_corr = self._correlator.correlate(detected_technologies)
        tech_knowledge = self._tech_intel.interpret(detected_technologies)

        apps: list[ApplicationProfile] = []

        if stack_corr.stacks:
            for stack in stack_corr.stacks:
                app = self._build_app_profile(stack, tech_knowledge.entries)
                apps.append(app)

        if not apps:
            app = ApplicationProfile(
                name="Unidentified Application",
                app_type=ApplicationType.UNKNOWN,
                technologies=tech_knowledge.entries,
                combined_attack_surface=tech_knowledge.all_attack_surface_implications,
                combined_auth_mechanisms=tech_knowledge.all_auth_mechanisms,
                combined_trust_boundaries=tech_knowledge.all_trust_boundaries,
                combined_investigation_suggestions=tech_knowledge.all_investigation_suggestions,
            )
            apps.append(app)

        all_implications = []
        for a in apps:
            all_implications.extend(a.combined_attack_surface)

        priority_areas = sorted(
            {imp.area for imp in all_implications},
            key=lambda x: sum(1 for imp in all_implications if imp.area == x),
            reverse=True,
        )[:10]

        return AttackSurfaceProfile(
            application_profiles=apps,
            total_attack_surface_areas=len({imp.area for imp in all_implications}),
            total_auth_mechanisms=sum(len(a.combined_auth_mechanisms) for a in apps),
            total_trust_boundaries=sum(len(a.combined_trust_boundaries) for a in apps),
            total_suggestions=sum(len(a.combined_investigation_suggestions) for a in apps),
            priority_areas=priority_areas,
        )

    def _build_app_profile(
        self,
        stack: FrameworkStack,
        all_tech_entries: list[TechnologyKnowledgeEntry],
    ) -> ApplicationProfile:
        relevant = [e for e in all_tech_entries if e.technology_name.lower() in {t.lower() for t in stack.technologies}]

        implications: list = []
        auth: list = []
        boundaries: list = []
        suggestions: list = []

        for e in relevant:
            implications.extend(e.attack_surface_implications)
            auth.extend(e.potential_auth_mechanisms)
            boundaries.extend(e.trust_boundaries)
            suggestions.extend(e.investigation_suggestions)

        return ApplicationProfile(
            name=stack.name,
            app_type=ApplicationType.WEB_APP,
            technologies=relevant,
            stacks=[stack],
            combined_attack_surface=implications,
            combined_auth_mechanisms=auth,
            combined_trust_boundaries=boundaries,
            combined_investigation_suggestions=suggestions,
        )
