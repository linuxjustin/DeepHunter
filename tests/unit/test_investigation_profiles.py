"""Unit tests for investigation profiles and profile registry."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from deephunter.investigation.profiles import (
    ExecutionProfile,
    ExecutionProfileType,
    PASSIVE_PROFILE,
    BUGBOUNTY_PROFILE,
    BUILTIN_PROFILES,
    ToolGroup,
)
from deephunter.investigation.profile_registry import (
    ProfileRegistry,
    get_profile_registry,
    get_profile,
    list_profiles,
)


class TestExecutionProfile:
    def test_passive_profile_defaults(self) -> None:
        assert PASSIVE_PROFILE.name == "passive"
        assert PASSIVE_PROFILE.profile_type == ExecutionProfileType.PASSIVE
        assert PASSIVE_PROFILE.require_manual_approval is False
        assert PASSIVE_PROFILE.auto_approve_passive is True
        assert PASSIVE_PROFILE.estimated_cost_usd == 0.0

    def test_bugbounty_profile_defaults(self) -> None:
        assert BUGBOUNTY_PROFILE.name == "bugbounty"
        assert BUGBOUNTY_PROFILE.profile_type == ExecutionProfileType.BUGBOUNTY
        assert BUGBOUNTY_PROFILE.require_manual_approval is True
        assert BUGBOUNTY_PROFILE.workflow_name == "web_app_review"

    def test_profile_tool_group_enabled(self) -> None:
        assert PASSIVE_PROFILE.is_tool_group_enabled(ToolGroup.SUBDOMAIN_ENUM) is True
        assert PASSIVE_PROFILE.is_tool_group_enabled(ToolGroup.VULN_SCAN) is False

    def test_profile_tool_group_disabled(self) -> None:
        profile = ExecutionProfile(
            name="test",
            profile_type=ExecutionProfileType.CUSTOM,
            disabled_tool_groups=[ToolGroup.WEB_CRAWLING],
        )
        assert profile.is_tool_group_enabled(ToolGroup.WEB_CRAWLING) is False

    def test_builtin_profiles_count(self) -> None:
        assert len(BUILTIN_PROFILES) == 7
        assert "passive" in BUILTIN_PROFILES
        assert "bugbounty" in BUILTIN_PROFILES
        assert "api" in BUILTIN_PROFILES
        assert "graphql" in BUILTIN_PROFILES
        assert "cloud" in BUILTIN_PROFILES
        assert "mobile" in BUILTIN_PROFILES
        assert "custom" in BUILTIN_PROFILES


class TestProfileRegistry:
    def test_registry_singleton(self) -> None:
        reg1 = get_profile_registry()
        reg2 = get_profile_registry()
        assert reg1 is reg2

    def test_registry_get_profile(self) -> None:
        profile = get_profile("passive")
        assert profile is not None
        assert profile.name == "passive"

    def test_registry_get_unknown_profile(self) -> None:
        profile = get_profile("nonexistent")
        assert profile is None

    def test_registry_list_profiles(self) -> None:
        profiles = list_profiles()
        assert len(profiles) == 7

    def test_registry_register_custom_profile(self) -> None:
        reg = ProfileRegistry()
        custom = ExecutionProfile(
            name="my_custom",
            profile_type=ExecutionProfileType.CUSTOM,
            description="My custom profile",
        )
        reg.register(custom)
        assert reg.get("my_custom") is not None

    def test_registry_cannot_remove_builtin(self) -> None:
        reg = ProfileRegistry()
        result = reg.remove("passive")
        assert result is False
        assert reg.get("passive") is not None

    def test_registry_load_from_file(self, tmp_path: Path) -> None:
        import yaml

        reg = ProfileRegistry()
        profile_data = {
            "name": "file_profile",
            "profile_type": "custom",
            "description": "Loaded from file",
        }
        f = tmp_path / "profile.yaml"
        f.write_text(yaml.dump(profile_data))

        loaded = reg.load_from_file(f)
        assert loaded.name == "file_profile"
        assert reg.get("file_profile") is not None

    def test_registry_save_to_file(self, tmp_path: Path) -> None:
        reg = ProfileRegistry()
        profile = ExecutionProfile(
            name="save_test",
            profile_type=ExecutionProfileType.CUSTOM,
        )
        reg.save_to_file(profile, tmp_path / "saved.yaml")

        assert (tmp_path / "saved.yaml").exists()

    def test_registry_create_custom_profile(self) -> None:
        reg = ProfileRegistry()
        custom = reg.create_custom_profile(
            name="derived",
            base_profile="passive",
            description="Derived from passive",
        )
        assert custom.name == "derived"
        assert custom.profile_type == ExecutionProfileType.CUSTOM
        assert reg.get("derived") is not None