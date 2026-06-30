"""Tests for all 11 Bug Bounty Workflows."""
from __future__ import annotations

import pytest

from deephunter.agents.base import AgentResult
from deephunter.agents.workflows.initial_recon import InitialReconWorkflow
from deephunter.agents.workflows.attack_surface import AttackSurfaceWorkflow
from deephunter.agents.workflows.tech_profiling import TechnologyProfilingWorkflow
from deephunter.agents.workflows.auth_review import AuthReviewWorkflow
from deephunter.agents.workflows.authorization_review import AuthorizationReviewWorkflow
from deephunter.agents.workflows.business_logic import BusinessLogicWorkflow
from deephunter.agents.workflows.api_review import APIReviewWorkflow
from deephunter.agents.workflows.js_review import JavaScriptReviewWorkflow
from deephunter.agents.workflows.cloud_review import CloudReviewWorkflow
from deephunter.agents.workflows.finding_prep import FindingPreparationWorkflow
from deephunter.agents.workflows.report_gen import ReportGenerationWorkflow

ALL_WORKFLOWS = [
    ("initial_recon", InitialReconWorkflow),
    ("attack_surface", AttackSurfaceWorkflow),
    ("tech_profiling", TechnologyProfilingWorkflow),
    ("auth_review", AuthReviewWorkflow),
    ("authorization_review", AuthorizationReviewWorkflow),
    ("business_logic", BusinessLogicWorkflow),
    ("api_review", APIReviewWorkflow),
    ("js_review", JavaScriptReviewWorkflow),
    ("cloud_review", CloudReviewWorkflow),
    ("finding_prep", FindingPreparationWorkflow),
    ("report_gen", ReportGenerationWorkflow),
]


class TestWorkflowMetadata:
    @pytest.mark.parametrize("name,cls", ALL_WORKFLOWS)
    def test_workflow_importable(self, name: str, cls: type) -> None:
        assert cls is not None

    @pytest.mark.parametrize("name,cls", ALL_WORKFLOWS)
    def test_workflow_has_name(self, name: str, cls: type) -> None:
        wf = cls()
        assert wf.name is not None

    @pytest.mark.parametrize("name,cls", ALL_WORKFLOWS)
    def test_workflow_has_description(self, name: str, cls: type) -> None:
        wf = cls()
        assert len(wf.description) > 0


class TestInitialReconWorkflow:
    def test_no_target(self) -> None:
        wf = InitialReconWorkflow()
        result = wf.execute({"target": ""})
        assert result.success is False
        assert "No target" in (result.error or "")

    def test_execute_with_target(self) -> None:
        wf = InitialReconWorkflow()
        result = wf.execute({"target": "https://example.com", "enable_subdomain_enum": False, "enable_dns_resolution": False, "enable_port_scan": False, "enable_http_probe": False})
        assert isinstance(result, AgentResult)
        assert result.data["target"] == "https://example.com"
        assert result.execution_time_ms >= 0


class TestAttackSurfaceWorkflow:
    def test_no_target(self) -> None:
        wf = AttackSurfaceWorkflow()
        result = wf.execute({"target": ""})
        assert result.success is False

    def test_execute_disabled_steps(self) -> None:
        wf = AttackSurfaceWorkflow()
        result = wf.execute({"target": "https://example.com", "enable_gau": False, "enable_waybackurls": False, "enable_crawl": False, "enable_fuzzing": False})
        assert result.success is True
        assert result.data["duration_ms"] >= 0


class TestTechnologyProfilingWorkflow:
    def test_no_target(self) -> None:
        wf = TechnologyProfilingWorkflow()
        result = wf.execute({"target": ""})
        assert result.success is False

    def test_execute(self) -> None:
        wf = TechnologyProfilingWorkflow()
        result = wf.execute({"target": "https://example.com", "enable_httpx": False, "enable_nuclei_tech": False})
        assert isinstance(result, AgentResult)
        assert "technologies" in result.data


class TestAuthReviewWorkflow:
    def test_no_target(self) -> None:
        wf = AuthReviewWorkflow()
        result = wf.execute({"target": ""})
        assert result.success is False

    def test_execute(self) -> None:
        wf = AuthReviewWorkflow()
        result = wf.execute({"target": "https://example.com"})
        assert result.success is True
        assert "auth_endpoints" in result.data


class TestAuthorizationReviewWorkflow:
    def test_execute(self) -> None:
        wf = AuthorizationReviewWorkflow()
        result = wf.execute({"target": "https://example.com"})
        assert result.success is True
        assert "sensitive_endpoints" in result.data


class TestBusinessLogicWorkflow:
    def test_execute(self) -> None:
        wf = BusinessLogicWorkflow()
        result = wf.execute({"target": "https://example.com"})
        assert result.success is True
        assert "logic_endpoints" in result.data


class TestAPIReviewWorkflow:
    def test_execute(self) -> None:
        wf = APIReviewWorkflow()
        result = wf.execute({"target": "https://example.com"})
        assert result.success is True
        assert "rest_endpoints" in result.data
        assert "graphql_endpoints" in result.data


class TestJavaScriptReviewWorkflow:
    def test_execute(self) -> None:
        wf = JavaScriptReviewWorkflow()
        result = wf.execute({"target": "https://example.com"})
        assert result.success is True
        assert "js_files" in result.data
        assert "secrets" in result.data


class TestCloudReviewWorkflow:
    def test_execute(self) -> None:
        wf = CloudReviewWorkflow()
        result = wf.execute({"target": "https://example.com"})
        assert result.success is True
        assert "metadata_access" in result.data


class TestFindingPreparationWorkflow:
    def test_no_findings(self) -> None:
        wf = FindingPreparationWorkflow()
        result = wf.execute({"findings": []})
        assert result.success is False

    def test_deduplication(self) -> None:
        wf = FindingPreparationWorkflow()
        raw = [
            {"title": "XSS", "severity": "high", "endpoint": "/search"},
            {"title": "XSS", "severity": "high", "endpoint": "/search"},
            {"title": "SQLI", "severity": "critical", "endpoint": "/api/users"},
        ]
        result = wf.execute({"findings": raw})
        assert result.success is True
        assert result.data["summary"]["total"] == 2

    def test_severity_sorting(self) -> None:
        wf = FindingPreparationWorkflow()
        raw = [
            {"title": "Low Issue", "severity": "low"},
            {"title": "Critical Issue", "severity": "critical"},
            {"title": "Medium Issue", "severity": "medium"},
        ]
        result = wf.execute({"findings": raw})
        assert result.success is True
        findings = result.data["findings"]
        assert findings[0]["severity"] == "critical"
        assert findings[-1]["severity"] == "low"


class TestReportGenerationWorkflow:
    def test_no_findings(self) -> None:
        wf = ReportGenerationWorkflow()
        result = wf.execute({"findings": []})
        assert result.success is False

    def test_markdown_report(self) -> None:
        wf = ReportGenerationWorkflow()
        findings = [
            {"title": "XSS Vulnerability", "severity": "high", "endpoint": "/search", "description": "Reflected XSS in search", "evidence": "<script>alert(1)</script>"},
            {"title": "SQL Injection", "severity": "critical", "endpoint": "/api/users", "description": "Blind SQLi in user ID"},
        ]
        result = wf.execute({"target": "example.com", "findings": findings, "summary": {"total": 2, "by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0}}, "format": "markdown"})
        assert result.success is True
        report = result.data["report"]
        assert "# Bug Bounty Report" in report
        assert "XSS Vulnerability" in report
        assert "SQL Injection" in report

    def test_json_report(self) -> None:
        wf = ReportGenerationWorkflow()
        findings = [{"title": "XSS", "severity": "high", "endpoint": "/search"}]
        result = wf.execute({"target": "example.com", "findings": findings, "summary": {"total": 1, "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}}, "format": "json"})
        assert result.success is True
        import json
        parsed = json.loads(result.data["report"])
        assert parsed["report"]["target"] == "example.com"

    def test_html_report(self) -> None:
        wf = ReportGenerationWorkflow()
        findings = [{"title": "XSS", "severity": "high", "endpoint": "/search"}]
        result = wf.execute({"target": "example.com", "findings": findings, "summary": {"total": 1, "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}}, "format": "html"})
        assert result.success is True
        assert "<html>" in result.data["report"]
        assert "XSS" in result.data["report"]
