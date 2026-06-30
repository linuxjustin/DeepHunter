"""Pack registry — manages loading, validation, and access to methodology packs."""

from __future__ import annotations

from typing import Any

from deephunter.methodology.packs.base import MethodologyPack, PackCategory


class PackValidationError(Exception):
    """Raised when a pack fails validation."""


class PackLoadError(Exception):
    """Raised when a pack cannot be loaded."""


class PackRegistry:
    """Central registry for all loaded methodology packs."""

    def __init__(self) -> None:
        self._packs: dict[str, MethodologyPack] = {}

    def register(self, pack: MethodologyPack) -> None:
        self.validate(pack)
        self._packs[pack.name] = pack

    def get(self, name: str) -> MethodologyPack | None:
        return self._packs.get(name)

    def get_by_technology(self, technology: str) -> list[MethodologyPack]:
        tech_lower = technology.lower()
        return [
            p
            for p in self._packs.values()
            if any(tech_lower in t.lower() for t in p.supported_technologies)
        ]

    def get_by_framework(self, framework: str) -> list[MethodologyPack]:
        fw_lower = framework.lower()
        return [
            p
            for p in self._packs.values()
            if any(fw_lower in f.lower() for f in p.supported_frameworks)
        ]

    def get_by_attack_surface(self, area: str) -> list[MethodologyPack]:
        area_lower = area.lower()
        return [
            p
            for p in self._packs.values()
            if any(area_lower in a.lower() for a in p.attack_surface_areas)
        ]

    def get_by_category(self, category: PackCategory) -> list[MethodologyPack]:
        return [p for p in self._packs.values() if p.category == category]

    def list_all(self) -> list[MethodologyPack]:
        return list(self._packs.values())

    def count(self) -> int:
        return len(self._packs)

    def clear(self) -> None:
        self._packs.clear()

    @staticmethod
    def validate(pack: MethodologyPack) -> None:
        errors: list[str] = []
        if not pack.name:
            errors.append("Pack must have a name")
        if not pack.version:
            errors.append("Pack must have a version")
        if not pack.supported_technologies and not pack.supported_frameworks and not pack.attack_surface_areas:
            errors.append("Pack must support at least one technology, framework, or attack surface area")

        for ci in pack.checklists:
            if not ci.objective:
                errors.append(f"Checklist item in pack '{pack.name}' has empty objective")
            if ci.priority not in ("critical", "high", "medium", "low"):
                errors.append(f"Checklist item '{ci.objective}' has invalid priority '{ci.priority}'")

        if errors:
            raise PackValidationError(f"Validation errors for pack '{pack.name}': {'; '.join(errors)}")

    def to_pack_set(self) -> object:
        from deephunter.methodology.packs.base import MethodologyPackSet

        pset = MethodologyPackSet(packs=self.list_all())
        pset.recalculate()
        return pset


# Module-level singleton
_REGISTRY: PackRegistry = PackRegistry()


def register_pack(pack: MethodologyPack) -> None:
    _REGISTRY.register(pack)


def get_pack(name: str) -> MethodologyPack | None:
    return _REGISTRY.get(name)


def get_packs_by_category(category: PackCategory) -> list[MethodologyPack]:
    return _REGISTRY.get_by_category(category)


def get_packs_by_technology(technology: str) -> list[MethodologyPack]:
    return _REGISTRY.get_by_technology(technology)


def list_all_packs() -> list[MethodologyPack]:
    return _REGISTRY.list_all()


def load_all_packs() -> PackRegistry:
    """Import all built-in methodology packs, registering each."""
    _import_framework_packs()
    _import_cross_cutting_packs()
    return _REGISTRY


def _import_framework_packs() -> None:
    from deephunter.methodology.packs.framework import (
        laravel,
        spring_boot,
        django,
        express,
        fastapi,
        nextjs,
        nuxt,
        rails,
        aspnet,
        wordpress,
        drupal,
        magento,
    )
    _registry: list[MethodologyPack] = [
        laravel.PACK,
        spring_boot.PACK,
        django.PACK,
        express.PACK,
        fastapi.PACK,
        nextjs.PACK,
        nuxt.PACK,
        rails.PACK,
        aspnet.PACK,
        wordpress.PACK,
        drupal.PACK,
        magento.PACK,
    ]
    for p in _registry:
        _REGISTRY.register(p)


def _import_cross_cutting_packs() -> None:
    from deephunter.methodology.packs.cross_cutting import (
        graphql,
        rest_api,
        oauth,
        oidc,
        jwt,
        session,
        file_upload,
        business_logic,
        cloud,
        microservices,
        command_injection,
        race_conditions,
        ssrf,
    )
    _registry: list[MethodologyPack] = [
        graphql.PACK,
        rest_api.PACK,
        oauth.PACK,
        oidc.PACK,
        jwt.PACK,
        session.PACK,
        file_upload.PACK,
        business_logic.PACK,
        cloud.PACK,
        microservices.PACK,
        command_injection.PACK,
        race_conditions.PACK,
        ssrf.PACK,
    ]
    for p in _registry:
        _REGISTRY.register(p)
