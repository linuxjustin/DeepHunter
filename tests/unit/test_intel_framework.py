"""Tests for the Framework Intelligence module."""

from __future__ import annotations

from deephunter.framework_intel.correlator import FrameworkCorrelator
from deephunter.framework_intel.models import FrameworkStack, StackCorrelation
from deephunter.framework_intel.profiler import AttackSurfaceProfiler
from deephunter.recon.models import ApplicationType
from deephunter.tech_intel.engine import TechnologyIntelEngine


class TestFrameworkCorrelator:
    def test_laravel_stack(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["nginx", "php", "laravel"])
        assert len(result.stacks) >= 1
        names = [s.name for s in result.stacks]
        assert "LEMP + Laravel" in names

    def test_wordpress_stack(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["nginx", "php", "wordpress"])
        assert len(result.stacks) >= 1
        names = [s.name for s in result.stacks]
        assert "WordPress Stack" in names

    def test_django_stack(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["nginx", "python", "django"])
        assert len(result.stacks) >= 1

    def test_spring_boot_stack(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["nginx", "java", "spring"])
        assert len(result.stacks) >= 1
        assert any("Spring" in s.name for s in result.stacks)

    def test_express_stack(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["nginx", "node.js", "express"])
        assert len(result.stacks) >= 1

    def test_nextjs_stack(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["nginx", "node.js", "next.js"])
        assert len(result.stacks) >= 1

    def test_rails_stack(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["nginx", "ruby", "rails"])
        assert len(result.stacks) >= 1

    def test_flask_stack(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["nginx", "python", "flask"])
        assert len(result.stacks) >= 1

    def test_fastapi_stack(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["nginx", "python", "fastapi"])
        assert len(result.stacks) >= 1

    def test_aspnet_stack(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["iis", "asp.net", "dotnet"])
        assert len(result.stacks) >= 1

    def test_drupal_stack(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["nginx", "php", "drupal"])
        assert len(result.stacks) >= 1

    def test_magento_stack(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["nginx", "php", "magento"])
        assert len(result.stacks) >= 1

    def test_unmatched_technologies(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["unknown_tech", "laravel"])
        assert "unknown_tech" in result.unmatched_technologies

    def test_empty_input(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate([])
        assert len(result.stacks) == 0

    def test_case_insensitive(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["NGINX", "PHP", "LARAVEL"])
        assert len(result.stacks) >= 1

    def test_multiple_stacks(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["nginx", "php", "laravel", "cloudflare"])
        assert len(result.stacks) >= 2

    def test_partial_match(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["laravel", "php"])
        assert len(result.stacks) >= 1  # Laravel Application

    def test_add_custom_signature(self) -> None:
        corr = FrameworkCorrelator()
        corr.add_custom_signature({"custom", "tech"}, "Custom Stack", "A custom stack")
        result = corr.correlate(["custom", "tech", "laravel"])
        assert any(s.name == "Custom Stack" for s in result.stacks)

    def test_list_known_stacks(self) -> None:
        corr = FrameworkCorrelator()
        stacks = corr.list_known_stacks()
        assert "LEMP + Laravel" in stacks
        assert len(stacks) >= 20

    def test_stack_has_metadata(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["nginx", "php", "laravel"])
        stack = result.stacks[0]
        assert isinstance(stack, FrameworkStack)
        assert stack.id.startswith("fs-")
        assert len(stack.technologies) >= 1
        assert stack.confidence in ("high", "medium", "low")

    def test_correlation_result_has_id(self) -> None:
        corr = FrameworkCorrelator()
        result = corr.correlate(["nginx", "php", "laravel"])
        assert isinstance(result, StackCorrelation)
        assert result.id.startswith("sc-")


class TestAttackSurfaceProfiler:
    def test_profile_laravel(self) -> None:
        profiler = AttackSurfaceProfiler()
        profile = profiler.profile(["nginx", "php", "laravel"])
        assert len(profile.application_profiles) >= 1
        assert profile.total_attack_surface_areas >= 5
        assert profile.total_auth_mechanisms >= 1
        assert profile.total_suggestions >= 1
        assert len(profile.priority_areas) >= 1

    def test_profile_unknown(self) -> None:
        profiler = AttackSurfaceProfiler()
        profile = profiler.profile(["unknown_tech"])
        assert len(profile.application_profiles) >= 1
        assert profile.application_profiles[0].name == "Unidentified Application"

    def test_profile_with_explicit_deps(self) -> None:
        tech_intel = TechnologyIntelEngine()
        corr = FrameworkCorrelator()
        profiler = AttackSurfaceProfiler(tech_intel=tech_intel, correlator=corr)
        profile = profiler.profile(["django", "python", "nginx"])
        assert len(profile.application_profiles) >= 1

    def test_profile_application_type(self) -> None:
        profiler = AttackSurfaceProfiler()
        profile = profiler.profile(["nginx", "php", "laravel"])
        app = profile.application_profiles[0]
        assert app.name in ("LEMP + Laravel", "PHP Web Stack")

    def test_profile_aggregates_technologies(self) -> None:
        profiler = AttackSurfaceProfiler()
        profile = profiler.profile(["laravel", "django"])
        assert len(profile.application_profiles) >= 1

    def test_profile_attack_surface_profile_id(self) -> None:
        profiler = AttackSurfaceProfiler()
        profile = profiler.profile(["laravel"])
        assert profile.id.startswith("asp-")

    def test_profile_single_tech(self) -> None:
        profiler = AttackSurfaceProfiler()
        profile = profiler.profile(["express"])
        assert profile.total_attack_surface_areas >= 2
