"""Context source collectors for the Context Engine.

Each collector extracts structured context blocks from a specific
source type (InvestigationSession, InvestigationPlan, etc.).
"""

from __future__ import annotations

from typing import Any

from deephunter.context.models import (
    Context,
    ContextBlock,
    ContextImportance,
    ContextReference,
    ContextSection,
    ContextSource,
    ContextSourceType,
)

try:
    from deephunter.planning.models import InvestigationPlan
    from deephunter.reasoning.session import InvestigationSession
except ImportError:
    InvestigationPlan = None  # type: ignore[assignment, misc]
    InvestigationSession = None  # type: ignore[assignment, misc]


def collect_from_session(
    session: Any, context: Context, source_type: ContextSourceType = ContextSourceType.REASONING_SESSION
) -> Context:
    """Collect context from an InvestigationSession."""
    source = ContextSource(
        type=source_type,
        name="Investigation Session",
        description=f"Session for target: {getattr(session.investigation, 'target', 'unknown')}",
    )

    # Target information
    target_section = ContextSection(name="Target Information", description="Target and investigation metadata")
    target_block = ContextBlock(
        source_type=source_type,
        importance=ContextImportance.CRITICAL,
        priority=1.0,
        content=f"Target: {getattr(session.investigation, 'target', 'unknown')}\n"
        f"Investigation ID: {getattr(session.investigation, 'id', '')}\n"
        f"Name: {getattr(session.investigation, 'name', '')}",
        summary="Investigation target and metadata",
    )
    target_section.add_block(target_block)
    context.add_section(target_section)

    # Technology fingerprint
    state = getattr(session, 'state', None)
    if state:
        tech = getattr(state, 'technology_fingerprint', None)
        if tech and any([tech.technologies, tech.frameworks, tech.programming_languages]):
            tech_section = ContextSection(name="Technology Fingerprint", description="Detected technologies and frameworks")
            tech_lines = []
            if tech.technologies:
                tech_lines.append(f"Technologies: {', '.join(t.value if hasattr(t, 'value') else str(t) for t in tech.technologies)}")
            if tech.frameworks:
                tech_lines.append(f"Frameworks: {', '.join(f.value if hasattr(f, 'value') else str(f) for f in tech.frameworks)}")
            if tech.programming_languages:
                tech_lines.append(f"Languages: {', '.join(tech.programming_languages)}")
            if tech.cloud_providers:
                tech_lines.append(f"Cloud: {', '.join(c.value if hasattr(c, 'value') else str(c) for c in tech.cloud_providers)}")
            if tech.auth_mechanisms:
                tech_lines.append(f"Auth: {', '.join(a.value if hasattr(a, 'value') else str(a) for a in tech.auth_mechanisms)}")
            tech_block = ContextBlock(
                source_type=source_type,
                importance=ContextImportance.HIGH,
                priority=0.9,
                content="\n".join(tech_lines),
                summary=f"{len(tech.technologies)} technologies, {len(tech.frameworks)} frameworks",
            )
            tech_section.add_block(tech_block)
            context.add_section(tech_section)
            source.record_count += 1

        # Observations
        observations = getattr(state, 'observations', [])
        if observations:
            obs_section = ContextSection(name="Observations", description="All recorded observations")
            for obs in observations:
                obs_block = ContextBlock(
                    source_type=ContextSourceType.REASONING_SESSION,
                    importance=ContextImportance.MEDIUM,
                    priority=0.6,
                    content=f"Type: {getattr(obs, 'type', '')}\n"
                    f"Description: {getattr(obs, 'description', '')}\n"
                    f"Detail: {getattr(obs, 'detail', '')}",
                    summary=getattr(obs, 'description', ''),
                )
                obs_section.add_block(obs_block)
            context.add_section(obs_section)
            source.record_count += len(observations)

        # Evidence
        evidence = getattr(state, 'evidence', [])
        if evidence:
            ev_section = ContextSection(name="Evidence", description="All collected evidence")
            for ev in evidence:
                ev_block = ContextBlock(
                    source_type=ContextSourceType.PREVIOUS_EVIDENCE,
                    importance=ContextImportance.HIGH,
                    priority=0.8,
                    content=f"Source: {getattr(ev, 'source', '')}\nContent: {getattr(ev, 'content', '')}",
                    summary=getattr(ev, 'source', ''),
                )
                ev_section.add_block(ev_block)
            context.add_section(ev_section)
            source.record_count += len(evidence)

        # Findings
        findings = getattr(state, 'findings', [])
        if findings:
            fnd_section = ContextSection(name="Findings", description="Confirmed findings")
            for fnd in findings:
                fnd_block = ContextBlock(
                    source_type=ContextSourceType.PREVIOUS_FINDINGS,
                    importance=ContextImportance.CRITICAL,
                    priority=0.95,
                    content=f"Title: {getattr(fnd, 'title', '')}\n"
                    f"Severity: {getattr(fnd, 'severity', '')}\n"
                    f"Description: {getattr(fnd, 'description', '')}",
                    summary=getattr(fnd, 'title', ''),
                )
                fnd_section.add_block(fnd_block)
            context.add_section(fnd_section)
            source.record_count += len(findings)

    context.sources.append(source)
    return context


def collect_from_plan(
    plan: Any, context: Context, source_type: ContextSourceType = ContextSourceType.INVESTIGATION_PLAN
) -> Context:
    """Collect context from an InvestigationPlan."""
    source = ContextSource(
        type=source_type,
        name="Investigation Plan",
        description=f"Plan: {getattr(plan, 'title', '')}",
    )

    plan_section = ContextSection(name="Investigation Plan", description="Planned investigation steps")
    summary_block = ContextBlock(
        source_type=source_type,
        importance=ContextImportance.HIGH,
        priority=0.85,
        content=f"Title: {getattr(plan, 'title', '')}\n"
        f"Target: {getattr(plan, 'target', '')}\n"
        f"Total Steps: {len(getattr(plan, 'steps', []))}\n"
        f"Estimated Hours: {getattr(plan, 'total_estimated_hours', 0)}\n"
        f"Overall Risk: {getattr(getattr(plan, 'risk', None), 'overall', 'N/A')}\n"
        f"Overall Priority: {getattr(plan, 'overall_priority', 0)}",
        summary=f"{len(getattr(plan, 'steps', []))} steps planned",
    )
    plan_section.add_block(summary_block)
    context.add_section(plan_section)

    steps = getattr(plan, 'steps', [])
    if steps:
        steps_section = ContextSection(name="Plan Steps", description="Individual investigation steps")
        for step in steps:
            step_block = ContextBlock(
                source_type=source_type,
                importance=ContextImportance.MEDIUM,
                priority=getattr(step, 'priority_score', 0.5),
                content=f"Phase: {getattr(step, 'phase', '')}\n"
                f"Title: {getattr(step, 'title', '')}\n"
                f"Description: {getattr(step, 'description', '')}\n"
                f"Priority: {getattr(step, 'priority_score', 0):.2f}\n"
                f"Cost: {getattr(step, 'estimated_cost_hours', 0)}h",
                summary=getattr(step, 'title', ''),
            )
            steps_section.add_block(step_block)
        context.add_section(steps_section)

    source.record_count += 1 + len(steps)
    context.sources.append(source)
    return context


def collect_from_query(query: str, context: Context) -> Context:
    """Collect context from a user query string."""
    source = ContextSource(
        type=ContextSourceType.USER_QUERY,
        name="User Query",
        description="User-provided query for this context",
    )

    query_section = ContextSection(name="User Query", description="The user's investigation query")
    query_block = ContextBlock(
        source_type=ContextSourceType.USER_QUERY,
        importance=ContextImportance.CRITICAL,
        priority=1.0,
        content=query,
        summary=query[:100] if len(query) > 100 else query,
    )
    query_section.add_block(query_block)
    context.add_section(query_section)

    source.record_count = 1
    context.sources.append(source)
    return context


def collect_from_constraints(constraints: list[str], context: Context) -> Context:
    """Collect context from user constraints."""
    if not constraints:
        return context

    source = ContextSource(
        type=ContextSourceType.USER_CONSTRAINTS,
        name="User Constraints",
        description=f"{len(constraints)} user-provided constraints",
    )

    constraint_section = ContextSection(name="User Constraints", description="Constraints for the investigation")
    for i, constraint in enumerate(constraints):
        c_block = ContextBlock(
            source_type=ContextSourceType.USER_CONSTRAINTS,
            importance=ContextImportance.HIGH,
            priority=0.9,
            content=constraint,
            summary=f"Constraint {i + 1}: {constraint[:80]}",
        )
        constraint_section.add_block(c_block)

    context.add_section(constraint_section)
    source.record_count = len(constraints)
    context.sources.append(source)
    return context


def merge_contexts(contexts: list[Context]) -> Context:
    """Merge multiple Context objects into one.

    Combines sections, sources, references, and warnings from all
    input contexts.  Deduplicates sections by name.
    """
    if not contexts:
        return Context()
    if len(contexts) == 1:
        return contexts[0]

    base = contexts[0].model_copy(deep=True)
    seen_section_names = {s.name for s in base.sections}

    for ctx in contexts[1:]:
        for section in ctx.sections:
            if section.name not in seen_section_names:
                base.add_section(section)
                seen_section_names.add(section.name)

        for source in ctx.sources:
            base.sources.append(source)

        for ref in ctx.references:
            base.references.append(ref)

        base.warnings.extend(ctx.warnings)

    base.recalculate()
    return base
