"""Knowledge Pack Registry — loading, validation, and access."""

from __future__ import annotations

from deephunter.knowledge.packs.base import (
    KnowledgePack,
    KnowledgePackCategory,
    KnowledgePackIndex,
    KnowledgeRelationship,
    KnowledgeRelationshipGraph,
    KnowledgeRelationshipType,
)


class KnowledgePackRegistry:
    """Central registry for all loaded knowledge packs."""

    def __init__(self) -> None:
        self._packs: dict[str, KnowledgePack] = {}
        self._graph = KnowledgeRelationshipGraph()

    def register(self, pack: KnowledgePack) -> None:
        self.validate(pack)
        self._packs[pack.name] = pack
        # Build relationship graph
        for rel in pack.relationships:
            self._graph.add_relationship(pack.name, rel)
            # Also add reverse relationship
            reverse = KnowledgeRelationship(
                target_pack_name=pack.name,
                relationship_type=rel.relationship_type,
                description=f"Reverse: {rel.description}",
                direction="inbound",
            )
            self._graph.add_relationship(rel.target_pack_name, reverse)

    def get(self, name: str) -> KnowledgePack | None:
        return self._packs.get(name)

    def get_by_technology(self, tech_name: str) -> list[KnowledgePack]:
        tech_lower = tech_name.lower()
        return [
            p for p in self._packs.values()
            if tech_lower == p.technology.name.lower()
            or tech_lower in [a.lower() for a in p.technology.common_aliases]
        ]

    def get_by_vendor(self, vendor: str) -> list[KnowledgePack]:
        vendor_lower = vendor.lower()
        return [
            p for p in self._packs.values()
            if vendor_lower in p.technology.vendor.lower()
        ]

    def get_by_category(self, category: KnowledgePackCategory) -> list[KnowledgePack]:
        return [p for p in self._packs.values() if p.category == category]

    def list_all(self) -> list[KnowledgePack]:
        return list(self._packs.values())

    def count(self) -> int:
        return len(self._packs)

    def clear(self) -> None:
        self._packs.clear()
        self._graph = KnowledgeRelationshipGraph()

    def get_graph(self) -> KnowledgeRelationshipGraph:
        return self._graph

    def get_technology_stack(self, pack_name: str, depth: int = 3) -> list[str]:
        return self._graph.get_technology_stack(pack_name, depth)

    def get_by_version(self, version: str) -> list[KnowledgePack]:
        return [
            p for p in self._packs.values()
            if version in p.technology.supported_versions
            or version.startswith(p.technology.supported_versions[0].rsplit(".", 1)[0])
            if p.technology.supported_versions
        ]

    def get_by_relationship_type(
        self, rel_type: KnowledgeRelationshipType
    ) -> list[KnowledgePack]:
        return [
            p for p in self._packs.values()
            if any(r.relationship_type == rel_type for r in p.relationships)
        ]

    def get_packs_for_technologies(
        self, tech_names: list[str],
    ) -> list[KnowledgePack]:
        packs: list[KnowledgePack] = []
        seen: set[str] = set()
        for name in tech_names:
            for pack in self.get_by_technology(name):
                if pack.name not in seen:
                    seen.add(pack.name)
                    packs.append(pack)
            for pack in self._packs.values():
                if (
                    name.lower() in pack.technology.dependencies
                    and pack.name not in seen
                ):
                    seen.add(pack.name)
                    packs.append(pack)
        return packs

    def get_investigation_plan_for_technologies(
        self, tech_names: list[str],
    ) -> str:
        packs = self.get_packs_for_technologies(tech_names)
        if not packs:
            return "No knowledge packs found for the specified technologies."

        sections: list[str] = []
        for pack in packs:
            section_parts: list[str] = [f"### {pack.name} ({pack.category.value})"]
            if pack.description:
                section_parts.append(pack.description)

            if pack.technology.version:
                section_parts.append(f"**Version**: {pack.technology.version}")
            if pack.technology.architecture_description:
                section_parts.append(
                    f"**Architecture**: {pack.technology.architecture_description}"
                )

            if pack.attack_surface.attack_surface_areas:
                section_parts.append("**Attack Surface Areas**:")
                for area in pack.attack_surface.attack_surface_areas:
                    section_parts.append(f"  - {area}")

            if pack.attack_surface.investigation_areas:
                section_parts.append("**Investigation Priorities**:")
                for area in pack.attack_surface.investigation_areas:
                    section_parts.append(f"  - {area}")

            if pack.workflow:
                section_parts.append("**Workflow**:")
                for step in pack.workflow:
                    section_parts.append(f"  - {step}")

            if pack.cwe_ids:
                section_parts.append(
                    f"**CWEs**: {', '.join(pack.cwe_ids)}"
                )
            if pack.cve_ids:
                section_parts.append(
                    f"**CVEs**: {', '.join(pack.cve_ids[:5])}"
                )

            if pack.references:
                section_parts.append("**References**:")
                for ref in pack.references[:3]:
                    if isinstance(ref, dict):
                        section_parts.append(
                            f"  - {ref.get('title', 'N/A')}: {ref.get('url', 'N/A')}"
                        )
                    else:
                        section_parts.append(f"  - {ref}")

            sections.append("\n".join(section_parts))

        return (
            "## Investigation Plan\n\n"
            + f"Found {len(packs)} relevant knowledge pack(s) for: {', '.join(tech_names)}\n\n"
            + "\n\n".join(sections)
        )

    def to_index(self) -> KnowledgePackIndex:
        idx = KnowledgePackIndex(packs=self._packs)
        idx.recalculate()
        return idx

    @staticmethod
    def validate(pack: KnowledgePack) -> None:
        errors: list[str] = []
        if not pack.name:
            errors.append("Pack must have a name")
        if not pack.version:
            errors.append("Pack must have a version")
        if not pack.technology.name:
            errors.append("Pack must have a technology name")
        if not pack.description:
            errors.append(f"Pack '{pack.name}' should have a description")
        for rel in pack.relationships:
            if not rel.target_pack_name:
                errors.append(f"Relationship in '{pack.name}' missing target")
        if errors:
            from deephunter.methodology.packs.registry import PackValidationError
            raise PackValidationError(
                f"Validation errors for Knowledge Pack '{pack.name}': {'; '.join(errors)}"
            )


# Module-level singleton
_REGISTRY: KnowledgePackRegistry = KnowledgePackRegistry()


def register_knowledge_pack(pack: KnowledgePack) -> None:
    _REGISTRY.register(pack)


def get_kp(name: str) -> KnowledgePack | None:
    return _REGISTRY.get(name)


def get_kp_by_technology(tech_name: str) -> list[KnowledgePack]:
    return _REGISTRY.get_by_technology(tech_name)


def get_kp_by_vendor(vendor: str) -> list[KnowledgePack]:
    return _REGISTRY.get_by_vendor(vendor)


def get_knowledge_packs_by_category(category: KnowledgePackCategory) -> list[KnowledgePack]:
    return _REGISTRY.get_by_category(category)


def get_investigation_plan_for_technologies(tech_names: list[str]) -> str:
    return _REGISTRY.get_investigation_plan_for_technologies(tech_names)


def list_all_knowledge_packs() -> list[KnowledgePack]:
    return _REGISTRY.list_all()


def load_all_knowledge_packs() -> KnowledgePackRegistry:
    """Import all built-in knowledge packs, registering each."""
    _import_framework_packs()
    _import_infrastructure_packs()
    _import_cloud_packs()
    _import_database_packs()
    _import_cross_cutting_packs()
    return _REGISTRY


def _import_framework_packs() -> None:
    from deephunter.knowledge.packs.framework import (
        laravel, nextjs, spring_boot, django, rails, express,
        fastapi, aspnet, flask, symfony, phoenix, nestjs, nuxt,
        wordpress, drupal, magento,
    )
    for p in [
        laravel.PACK, nextjs.PACK, spring_boot.PACK, django.PACK,
        rails.PACK, express.PACK, fastapi.PACK, aspnet.PACK,
        flask.PACK, symfony.PACK, phoenix.PACK, nestjs.PACK, nuxt.PACK,
        wordpress.PACK, drupal.PACK, magento.PACK,
    ]:
        _REGISTRY.register(p)


def _import_infrastructure_packs() -> None:
    from deephunter.knowledge.packs.infrastructure import (
        nginx, apache, redis, rabbitmq, kubernetes, docker,
    )
    for p in [
        nginx.PACK, apache.PACK, redis.PACK, rabbitmq.PACK,
        kubernetes.PACK, docker.PACK,
    ]:
        _REGISTRY.register(p)


def _import_cloud_packs() -> None:
    from deephunter.knowledge.packs.cloud import (
        aws, azure, gcp, cloudflare,
    )
    for p in [aws.PACK, azure.PACK, gcp.PACK, cloudflare.PACK]:
        _REGISTRY.register(p)


def _import_database_packs() -> None:
    from deephunter.knowledge.packs.database import (
        postgresql, mysql, mongodb,
    )
    for p in [postgresql.PACK, mysql.PACK, mongodb.PACK]:
        _REGISTRY.register(p)


def _import_cross_cutting_packs() -> None:
    from deephunter.knowledge.packs.cross_cutting import (
        graphql, rest, jwt, oauth, oidc, saml,
    )
    for p in [
        graphql.PACK, rest.PACK, jwt.PACK,
        oauth.PACK, oidc.PACK, saml.PACK,
    ]:
        _REGISTRY.register(p)
