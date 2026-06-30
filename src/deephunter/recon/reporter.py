"""Recon Reporter — converts recon intelligence into Security Knowledge Objects (SKOs).

Integrates with the existing ``knowledge/models.py`` to produce SKOs
from reconnaissance data, enabling downstream consumption by the
Reasoning Engine and Investigation Planner.
"""

from __future__ import annotations

from typing import Any

from deephunter.core.types import (
    AttackSurfaceEntry,
    AuthMechanism as CoreAuthMechanism,
    BugClass,
    Confidence,
    SourceType,
    Technology as CoreTechnology,
)
from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.recon.models import (
    Endpoint,
    Host,
    ReconSourceType,
    Technology,
)


def host_to_sko(host: Host, source: ReconSourceType = ReconSourceType.MANUAL) -> SecurityKnowledgeObject:
    """Create an SKO describing a discovered host."""
    source_map = {
        ReconSourceType.HTTP_PROBE: SourceType.OTHER,
        ReconSourceType.SUBDOMAIN_ENUMERATION: SourceType.OTHER,
        ReconSourceType.DNS_ENUMERATION: SourceType.OTHER,
    }
    sko_source_type = source_map.get(source, SourceType.OTHER)

    entries: list[AttackSurfaceEntry] = []
    if host.hostname:
        entries.append(
            AttackSurfaceEntry(
                name=host.hostname,
                description=f"Host on port {host.port} ({host.protocol.value})",
                protocol=host.protocol.value,
                path="/",
                parameters=[],
            )
        )

    return SecurityKnowledgeObject(
        title=f"Host: {host.hostname}:{host.port}",
        summary=f"Discovered host {host.hostname} on {host.ip}:{host.port} ({host.protocol.value})",
        source=f"https://recon.internal/host/{host.id}",
        source_type=sko_source_type,
        tags=host.tags + ["recon", "host"],
        attack_surface=entries,
        confidence=Confidence.MEDIUM,
    )


def endpoint_to_sko(endpoint: Endpoint, source: ReconSourceType = ReconSourceType.UNKNOWN) -> SecurityKnowledgeObject:
    """Create an SKO describing a discovered endpoint."""
    return SecurityKnowledgeObject(
        title=f"Endpoint: {endpoint.method.value} {endpoint.path}",
        summary=f"Discovered {endpoint.method.value} endpoint at {endpoint.path}",
        source=f"https://recon.internal/endpoint/{endpoint.id}",
        source_type=SourceType.OTHER,
        tags=["recon", "endpoint", endpoint.category.value],
        interesting_endpoints=[endpoint.path],
        confidence=Confidence.MEDIUM,
    )


def technology_to_sko(tech: Technology, source: ReconSourceType = ReconSourceType.TECHNOLOGY_FINGERPRINT) -> SecurityKnowledgeObject:
    """Create an SKO describing a detected technology."""
    core_techs: list[CoreTechnology] = []
    known = {t.value: t for t in CoreTechnology}
    if tech.name.lower() in known:
        core_techs.append(known[tech.name.lower()])

    return SecurityKnowledgeObject(
        title=f"Technology: {tech.name} ({tech.category.value})",
        summary=f"Detected {tech.name} (version: {tech.version or 'unknown'})",
        source=f"https://recon.internal/technology/{tech.id}",
        source_type=SourceType.OTHER,
        tags=["recon", "technology", tech.category.value],
        technology=core_techs,
        confidence=Confidence.MEDIUM if tech.confidence >= 0.5 else Confidence.LOW,
    )


def observations_to_sko_report(
    hosts: list[Host],
    endpoints: list[Endpoint],
    technologies: list[Technology],
) -> SecurityKnowledgeObject:
    """Create a consolidated SKO report from multiple recon observations."""
    entries: list[AttackSurfaceEntry] = []
    all_techs: list[CoreTechnology] = []
    all_endpoints: list[str] = []

    known_techs = {t.value: t for t in CoreTechnology}

    for host in hosts:
        entries.append(
            AttackSurfaceEntry(
                name=host.hostname or host.ip,
                description=f"Host on port {host.port} ({host.protocol.value})",
                protocol=host.protocol.value,
                path="/",
            )
        )

    for tech in technologies:
        if tech.name.lower() in known_techs:
            all_techs.append(known_techs[tech.name.lower()])

    for ep in endpoints:
        all_endpoints.append(f"{ep.method.value} {ep.path}")

    return SecurityKnowledgeObject(
        title="Reconnaissance Intelligence Report",
        summary=f"Consolidated recon report with {len(hosts)} hosts, {len(endpoints)} endpoints, {len(technologies)} technologies",
        source="https://recon.internal/session/report",
        source_type=SourceType.OTHER,
        tags=["recon", "report"],
        technology=all_techs,
        attack_surface=entries,
        interesting_endpoints=all_endpoints,
        confidence=Confidence.MEDIUM,
    )
