"""Execution Profile Registry — manages available profiles."""

from __future__ import annotations

from pathlib import Path

import yaml

from deephunter.investigation.profiles import (
    BUILTIN_PROFILES,
    ExecutionProfile,
    ExecutionProfileType,
)
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class ProfileRegistry:
    """Central registry for execution profiles."""

    def __init__(self) -> None:
        self._profiles: dict[str, ExecutionProfile] = {}
        for name, profile in BUILTIN_PROFILES.items():
            self.register(profile)

    def register(self, profile: ExecutionProfile) -> None:
        self._profiles[profile.name] = profile

    def get(self, name: str) -> ExecutionProfile | None:
        return self._profiles.get(name)

    def get_by_type(self, profile_type: ExecutionProfileType) -> list[ExecutionProfile]:
        return [
            p for p in self._profiles.values()
            if p.profile_type == profile_type
        ]

    def list_all(self) -> list[ExecutionProfile]:
        return list(self._profiles.values())

    def list_names(self) -> list[str]:
        return list(self._profiles.keys())

    def load_from_file(self, path: str | Path) -> ExecutionProfile:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Profile file not found: {p}")
        data = yaml.safe_load(p.read_text("utf-8")) or {}
        profile = ExecutionProfile(**data)
        self.register(profile)
        return profile

    def save_to_file(self, profile: ExecutionProfile, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(yaml.dump(profile.model_dump(), default_flow_style=False), "utf-8")

    def create_custom_profile(
        self,
        name: str,
        base_profile: str = "passive",
        **overrides,
    ) -> ExecutionProfile:
        base = self.get(base_profile)
        if not base:
            base = BUILTIN_PROFILES["passive"]

        profile = ExecutionProfile(
            name=name,
            profile_type=ExecutionProfileType.CUSTOM,
            description=f"Custom profile: {name}",
            **{k: v for k, v in overrides.items() if v is not None},
        )
        self.register(profile)
        return profile

    def remove(self, name: str) -> bool:
        if name in BUILTIN_PROFILES:
            logger.warning("Cannot remove built-in profile: %s", name)
            return False
        if name in self._profiles:
            del self._profiles[name]
            return True
        return False

    def count(self) -> int:
        return len(self._profiles)


_PROFILE_REGISTRY: ProfileRegistry | None = None


def get_profile_registry() -> ProfileRegistry:
    global _PROFILE_REGISTRY
    if _PROFILE_REGISTRY is None:
        _PROFILE_REGISTRY = ProfileRegistry()
    return _PROFILE_REGISTRY


def get_profile(name: str) -> ExecutionProfile | None:
    return get_profile_registry().get(name)


def list_profiles() -> list[ExecutionProfile]:
    return get_profile_registry().list_all()


def list_profile_names() -> list[str]:
    return get_profile_registry().list_names()