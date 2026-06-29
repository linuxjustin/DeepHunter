"""Tests for planning rules and rule registry."""

from __future__ import annotations

import pytest

from deephunter.planning.models import PlannerContext, PlanningPhase
from deephunter.planning.rules import (
    AuthenticationRule,
    AuthorizationRule,
    BugClassRule,
    BusinessLogicRule,
    CloudProviderRule,
    EndpointAnalysisRule,
    FileUploadRule,
    FrameworkDetectionRule,
    PlanningRule,
    PrivilegeEscalationRule,
    ReconRule,
    ReportPreparationRule,
    RuleRegistry,
    TechnologyRule,
)


class DummyRule(PlanningRule):
    name = "dummy"
    description = "Test rule"
    phase = PlanningPhase.RECON
    priority = 50

    def evaluate(self, context: PlannerContext) -> list:
        return []


class TestPlanningRule:
    def test_abc_cannot_instantiate(self) -> None:
        with pytest.raises(TypeError):
            PlanningRule()  # type: ignore[abstract]

    def test_dummy_rule(self) -> None:
        rule = DummyRule()
        assert rule.name == "dummy"
        assert rule.phase == PlanningPhase.RECON


class TestRuleRegistry:
    def test_empty_registry(self) -> None:
        reg = RuleRegistry()
        assert reg.list_rules() == []

    def test_register_and_get(self) -> None:
        reg = RuleRegistry()
        rule = DummyRule()
        reg.register(rule)
        assert reg.get("dummy") is rule
        assert len(reg.list_rules()) == 1

    def test_deregister(self) -> None:
        reg = RuleRegistry()
        reg.register(DummyRule())
        reg.deregister("dummy")
        assert reg.get("dummy") is None

    def test_get_by_phase(self) -> None:
        reg = RuleRegistry()
        reg.register(DummyRule())
        reg.register(ReconRule())
        recon_rules = reg.get_by_phase(PlanningPhase.RECON)
        assert len(recon_rules) == 2

    def test_evaluate_all_empty(self) -> None:
        reg = RuleRegistry()
        ctx = PlannerContext()
        steps = reg.evaluate_all(ctx)
        assert steps == []

    def test_evaluate_phase_empty(self) -> None:
        reg = RuleRegistry()
        ctx = PlannerContext()
        steps = reg.evaluate_phase(ctx, PlanningPhase.RECON)
        assert steps == []

    def test_failing_rule_does_not_crash(self) -> None:
        class CrashRule(PlanningRule):
            name = "crash"
            description = "Crashes"
            phase = PlanningPhase.RECON
            priority = 1

            def evaluate(self, context: PlannerContext) -> list:
                raise RuntimeError("boom")

        reg = RuleRegistry()
        reg.register(CrashRule())
        reg.register(DummyRule())
        ctx = PlannerContext()
        steps = reg.evaluate_all(ctx)  # should not crash
        assert len(steps) == 0

    def test_evaluate_respects_priority_order(self) -> None:
        class HighPriRule(PlanningRule):
            name = "high"
            description = "High priority"
            phase = PlanningPhase.RECON
            priority = 10

            def evaluate(self, context: PlannerContext) -> list:
                return [1]

        class LowPriRule(PlanningRule):
            name = "low"
            description = "Low priority"
            phase = PlanningPhase.RECON
            priority = 20

            def evaluate(self, context: PlannerContext) -> list:
                return [2]

        reg = RuleRegistry()
        reg.register(LowPriRule())
        reg.register(HighPriRule())
        ctx = PlannerContext()
        steps = reg.evaluate_all(ctx)
        assert steps == [1, 2]

    def test_with_default_rules(self) -> None:
        reg = RuleRegistry.with_default_rules()
        assert len(reg.list_rules()) == 12


class TestReconRule:
    def test_always_produces_step(self) -> None:
        rule = ReconRule()
        ctx = PlannerContext(target="https://example.com")
        steps = rule.evaluate(ctx)
        assert len(steps) == 1
        assert steps[0].phase == PlanningPhase.RECON

    def test_step_has_high_priority(self) -> None:
        rule = ReconRule()
        steps = rule.evaluate(PlannerContext())
        assert steps[0].priority_score == 0.90


class TestTechnologyRule:
    def test_empty_technologies(self) -> None:
        rule = TechnologyRule()
        steps = rule.evaluate(PlannerContext())
        assert steps == []

    def test_known_technology(self) -> None:
        rule = TechnologyRule()
        ctx = PlannerContext(technologies=["laravel"])
        steps = rule.evaluate(ctx)
        assert len(steps) == 1
        assert "Laravel" in steps[0].title

    def test_unknown_technology(self) -> None:
        rule = TechnologyRule()
        ctx = PlannerContext(technologies=["unknown_framework"])
        steps = rule.evaluate(ctx)
        assert steps == []

    def test_multiple_technologies(self) -> None:
        rule = TechnologyRule()
        ctx = PlannerContext(technologies=["laravel", "django", "react"])
        steps = rule.evaluate(ctx)
        assert len(steps) == 3


class TestAuthenticationRule:
    def test_empty_auth(self) -> None:
        rule = AuthenticationRule()
        steps = rule.evaluate(PlannerContext())
        assert steps == []

    def test_jwt_auth(self) -> None:
        rule = AuthenticationRule()
        ctx = PlannerContext(auth_mechanisms=["jwt"])
        steps = rule.evaluate(ctx)
        assert len(steps) == 1
        assert "JWT" in steps[0].title

    def test_multiple_auth(self) -> None:
        rule = AuthenticationRule()
        ctx = PlannerContext(auth_mechanisms=["jwt", "oauth2", "api_key"])
        steps = rule.evaluate(ctx)
        assert len(steps) == 3


class TestBugClassRule:
    def test_empty(self) -> None:
        rule = BugClassRule()
        steps = rule.evaluate(PlannerContext())
        assert steps == []

    def test_known_bug_class(self) -> None:
        rule = BugClassRule()
        ctx = PlannerContext(bug_classes=["sql_injection"])
        steps = rule.evaluate(ctx)
        assert len(steps) == 1
        assert "SQL Injection" in steps[0].title

    def test_multiple_bug_classes(self) -> None:
        rule = BugClassRule()
        ctx = PlannerContext(bug_classes=["sql_injection", "xss", "ssrf"])
        steps = rule.evaluate(ctx)
        assert len(steps) == 3


class TestEndpointAnalysisRule:
    def test_no_endpoints(self) -> None:
        rule = EndpointAnalysisRule()
        steps = rule.evaluate(PlannerContext())
        assert steps == []

    def test_with_endpoints(self) -> None:
        rule = EndpointAnalysisRule()
        ctx = PlannerContext(interesting_endpoints=["/api/login", "/api/users"])
        steps = rule.evaluate(ctx)
        assert len(steps) == 1
        assert "API Endpoint" in steps[0].title


class TestCloudProviderRule:
    def test_empty(self) -> None:
        rule = CloudProviderRule()
        steps = rule.evaluate(PlannerContext())
        assert steps == []

    def test_aws(self) -> None:
        rule = CloudProviderRule()
        ctx = PlannerContext(cloud_providers=["aws"])
        steps = rule.evaluate(ctx)
        assert len(steps) == 1
        assert "AWS" in steps[0].title

    def test_multiple_providers(self) -> None:
        rule = CloudProviderRule()
        ctx = PlannerContext(cloud_providers=["aws", "azure", "gcp"])
        steps = rule.evaluate(ctx)
        assert len(steps) == 3


class TestBusinessLogicRule:
    def test_no_observation(self) -> None:
        rule = BusinessLogicRule()
        steps = rule.evaluate(PlannerContext())
        assert steps == []

    def test_with_business_logic_observation(self) -> None:
        rule = BusinessLogicRule()
        ctx = PlannerContext(observation_types=["business_logic"])
        steps = rule.evaluate(ctx)
        assert len(steps) == 1
        assert "Business Logic" in steps[0].title


class TestFileUploadRule:
    def test_no_upload_endpoints(self) -> None:
        rule = FileUploadRule()
        steps = rule.evaluate(PlannerContext())
        assert steps == []

    def test_with_upload_endpoint(self) -> None:
        rule = FileUploadRule()
        ctx = PlannerContext(interesting_endpoints=["/upload", "/api/files"])
        steps = rule.evaluate(ctx)
        assert len(steps) == 1
        assert "File Upload" in steps[0].title


class TestFrameworkDetectionRule:
    def test_no_frameworks(self) -> None:
        rule = FrameworkDetectionRule()
        steps = rule.evaluate(PlannerContext())
        assert steps == []

    def test_with_frameworks(self) -> None:
        rule = FrameworkDetectionRule()
        ctx = PlannerContext(frameworks=["django", "flask"])
        steps = rule.evaluate(ctx)
        assert len(steps) == 1
        assert "Framework Version" in steps[0].title


class TestAuthorizationRule:
    def test_always_produces(self) -> None:
        rule = AuthorizationRule()
        steps = rule.evaluate(PlannerContext())
        assert len(steps) == 1
        assert "Authorization" in steps[0].title


class TestPrivilegeEscalationRule:
    def test_always_produces(self) -> None:
        rule = PrivilegeEscalationRule()
        steps = rule.evaluate(PlannerContext())
        assert len(steps) == 1
        assert "Privilege Escalation" in steps[0].title


class TestReportPreparationRule:
    def test_always_produces(self) -> None:
        rule = ReportPreparationRule()
        steps = rule.evaluate(PlannerContext())
        assert len(steps) == 1
        assert "Report Preparation" in steps[0].title
