"""Tests for Research Dashboard."""

from __future__ import annotations

from datetime import UTC, datetime

from deephunter.dashboard import (
    DashboardService,
    ResearchDashboard,
    DashboardOverview,
    CoverageAssessment,
    CoverageLevel,
    HealthStatus,
    HypothesisSummary,
    EvidenceSummary,
    TaskBoardSummary,
    TechnologySummary,
    AttackSurfaceSummary,
    FindingSummary,
    NotebookSummary,
    TimelineActivitySummary,
)


class TestDashboardService:
    def test_generate_dashboard_basic(self) -> None:
        service = DashboardService()
        dashboard = service.generate_dashboard(
            target_id="tgt-1",
            target_name="Test Target",
            target_url="https://test.com",
            investigation_status="in_progress",
        )
        assert dashboard.target_id == "tgt-1"
        assert dashboard.health_status in (HealthStatus.HEALTHY, HealthStatus.AT_RISK, HealthStatus.STALLED)

    def test_generate_dashboard_with_hypotheses(self) -> None:
        service = DashboardService()

        class MockHypothesis:
            id = "hyp-1"
            title = "SQL Injection"
            status = "proposed"
            confidence = 0.7
            priority = "high"
            bug_classes = []
            finding_id = None

        dashboard = service.generate_dashboard(
            target_id="tgt-1",
            hypothesis_states=[MockHypothesis()],
        )
        assert dashboard.hypothesis is not None
        assert dashboard.hypothesis.total == 1

    def test_coverage_assessment(self) -> None:
        service = DashboardService()
        dashboard = service.generate_dashboard(
            target_id="tgt-1",
            endpoints=["e1", "e2", "e3", "e4", "e5"] * 5,
            technologies=["react", "node", "postgres"],
        )
        assert dashboard.coverage is not None
        assert dashboard.coverage.coverage_by_endpoint > 50.0

    def test_health_assessment_stalled(self) -> None:
        service = DashboardService()
        dashboard = service.generate_dashboard(
            target_id="tgt-1",
            investigation_status="in_progress",
            last_activity=datetime(2020, 1, 1, tzinfo=UTC),
        )
        assert dashboard.health_status in (HealthStatus.STALLED, HealthStatus.AT_RISK)

    def test_finding_summary_cvss(self) -> None:
        service = DashboardService()

        class MockFinding:
            severity = "critical"
            cvss_score = 9.8
            category = "sql_injection"

        dashboard = service.generate_dashboard(
            target_id="tgt-1",
            findings=[MockFinding()],
        )
        assert dashboard.findings is not None
        assert dashboard.findings.critical_count == 1


class TestDashboardModels:
    def test_research_dashboard(self) -> None:
        dashboard = ResearchDashboard(target_id="tgt-1")
        assert dashboard.target_id == "tgt-1"
        assert dashboard.id.startswith("dash-")

    def test_dashboard_overview(self) -> None:
        ov = DashboardOverview(
            target_id="tgt-1",
            target_name="Test",
            progress_pct=50.0,
        )
        assert ov.progress_pct == 50.0
        assert ov.health_status == HealthStatus.HEALTHY

    def test_coverage_levels(self) -> None:
        assert CoverageLevel.NONE.value == "none"
        assert CoverageLevel.COMPREHENSIVE.value == "comprehensive"

    def test_health_status(self) -> None:
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.BLOCKED.value == "blocked"
        assert HealthStatus.COMPLETED.value == "completed"

    def test_hypothesis_summary(self) -> None:
        hs = HypothesisSummary(
            total=5,
            by_status={"proposed": 3, "confirmed": 2},
            by_priority={"high": 2, "medium": 3},
            by_bug_class={"sql_injection": 2, "xss": 1},
            avg_confidence=0.65,
            confirmed_findings=2,
            refuted=0,
        )
        assert hs.total == 5
        assert hs.confirmed_findings == 2

    def test_finding_summary(self) -> None:
        fs = FindingSummary(
            total=3,
            by_severity={"critical": 1, "high": 1, "medium": 1},
            by_category={"sql_injection": 1, "xss": 1},
            cvss_scores=[9.8, 7.5, 5.0],
            avg_cvss=7.43,
            critical_count=1,
            high_count=1,
            medium_count=1,
            low_count=0,
            info_count=0,
        )
        assert fs.critical_count == 1
        assert fs.avg_cvss == 7.43

    def test_task_board_summary(self) -> None:
        ts = TaskBoardSummary(
            total_cards=10,
            backlog=3,
            planned=2,
            in_progress=2,
            needs_verification=1,
            completed=2,
            archived=0,
            completion_rate=20.0,
        )
        assert ts.total_cards == 10
        assert ts.completion_rate == 20.0

    def test_attack_surface_summary(self) -> None:
        ass = AttackSurfaceSummary(
            total_endpoints=25,
            total_parameters=100,
            total_hosts=5,
            total_technologies=8,
        )
        assert ass.total_endpoints == 25
        assert ass.total_parameters == 100