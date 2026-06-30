"""Research Dashboard Service.

Generates comprehensive dashboards with overview, progress, coverage,
and health metrics for investigations.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from deephunter.dashboard.models import (
    AttackSurfaceSummary,
    CoverageAssessment,
    CoverageLevel,
    DashboardOverview,
    EvidenceSummary,
    FindingSummary,
    HealthStatus,
    HypothesisSummary,
    NotebookSummary,
    ResearchDashboard,
    TaskBoardSummary,
    TechnologySummary,
    TimelineActivitySummary,
)
from deephunter.investigation.notebook.models import NoteStatus
from deephunter.investigation.taskboard.models import BoardColumn
from deephunter.reasoning.models import HypothesisStatus
from deephunter.utils import get_logger

logger = get_logger(__name__)


class DashboardService:
    """Generates research dashboards from investigation state."""

    def generate_dashboard(
        self,
        target_id: str,
        investigation_id: str = "",
        target_name: str = "",
        target_url: str = "",
        project_name: str = "",
        investigation_status: str = "",
        start_time: datetime | None = None,
        last_activity: datetime | None = None,
        hypothesis_states: list[Any] | None = None,
        evidence_records: list[Any] | None = None,
        task_cards: list[Any] | None = None,
        technologies: list[Any] | None = None,
        endpoints: list[Any] | None = None,
        parameters: list[Any] | None = None,
        findings: list[Any] | None = None,
        notebook_entries: list[Any] | None = None,
        timeline_events: list[Any] | None = None,
    ) -> ResearchDashboard:
        now = datetime.now(UTC)

        overview = self._build_overview(
            target_id=target_id,
            target_name=target_name,
            target_url=target_url,
            project_name=project_name,
            investigation_id=investigation_id,
            investigation_status=investigation_status,
            start_time=start_time,
            last_activity=last_activity,
        )

        hyp_sum = self._build_hypothesis_summary(hypothesis_states or [])
        ev_sum = self._build_evidence_summary(evidence_records or [])
        task_sum = self._build_task_summary(task_cards or [])
        tech_sum = self._build_technology_summary(technologies or [])
        surf_sum = self._build_attack_surface_summary(endpoints or [], parameters or [], technologies or [])
        nb_sum = self._build_notebook_summary(notebook_entries or [])
        find_sum = self._build_finding_summary(findings or [])
        tl_sum = self._build_timeline_summary(timeline_events or [])
        cov = self._build_coverage(
            endpoints=endpoints or [],
            parameters=parameters or [],
            technologies=technologies or [],
            hypothesis_states=hypothesis_states or [],
        )

        health, messages = self._assess_health(
            overview=overview,
            hyp_sum=hyp_sum,
            ev_sum=ev_sum,
            task_sum=task_sum,
            find_sum=find_sum,
            cov=cov,
        )
        overview.health_status = health

        return ResearchDashboard(
            target_id=target_id,
            investigation_session_id=investigation_id,
            overview=overview,
            hypothesis=hyp_sum,
            evidence=ev_sum,
            tasks=task_sum,
            technologies=tech_sum,
            attack_surface=surf_sum,
            notebook=nb_sum,
            findings=find_sum,
            timeline_activity=tl_sum,
            coverage=cov,
            health_status=health,
            health_messages=messages,
        )

    def _build_overview(
        self,
        target_id: str,
        target_name: str,
        target_url: str,
        project_name: str,
        investigation_id: str,
        investigation_status: str,
        start_time: datetime | None,
        last_activity: datetime | None,
    ) -> DashboardOverview:
        duration_minutes = 0.0
        if start_time:
            duration_minutes = (datetime.now(UTC) - start_time).total_seconds() / 60

        progress = 0.0
        if investigation_status == "completed":
            progress = 100.0
        elif investigation_status == "in_progress":
            progress = 50.0

        return DashboardOverview(
            target_id=target_id,
            target_name=target_name,
            target_url=target_url,
            project_name=project_name,
            investigation_id=investigation_id,
            investigation_status=investigation_status,
            start_time=start_time,
            last_activity_time=last_activity or datetime.now(UTC),
            total_duration_minutes=duration_minutes,
            progress_pct=progress,
            health_status=HealthStatus.HEALTHY,
            active_researchers=1,
            ai_conversations_count=0,
        )

    def _build_hypothesis_summary(self, hypotheses: list[Any]) -> HypothesisSummary:
        by_status: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        by_bug_class: dict[str, int] = {}
        total_confidence = 0.0
        confirmed = 0
        refuted = 0

        for h in hypotheses:
            status = getattr(h, "status", "proposed")
            priority = getattr(h, "priority", "medium")
            by_status[status] = by_status.get(status, 0) + 1
            by_priority[priority] = by_priority.get(priority, 0) + 1

            for bc in getattr(h, "bug_classes", []):
                bc_name = bc.value if hasattr(bc, "value") else str(bc)
                by_bug_class[bc_name] = by_bug_class.get(bc_name, 0) + 1

            total_confidence += getattr(h, "confidence", 0.0)

            finding_id = getattr(h, "finding_id", None)
            if finding_id:
                confirmed += 1
            elif status == "refuted":
                refuted += 1

        n = len(hypotheses) or 1
        return HypothesisSummary(
            total=len(hypotheses),
            by_status=by_status,
            by_priority=by_priority,
            by_bug_class=by_bug_class,
            avg_confidence=total_confidence / n,
            confirmed_findings=confirmed,
            refuted=refuted,
        )

    def _build_evidence_summary(self, evidence: list[Any]) -> EvidenceSummary:
        by_type: dict[str, int] = {}
        http_exchanges = 0
        screenshots = 0
        code_snippets = 0
        recon_artifacts = 0
        manual_notes = 0

        for ev in evidence:
            ev_type = getattr(ev, "type", "unknown")
            by_type[ev_type] = by_type.get(ev_type, 0) + 1
            if ev_type == "http_response" or ev_type == "http_exchange":
                http_exchanges += 1
            elif ev_type == "screenshot":
                screenshots += 1
            elif ev_type == "code_snippet":
                code_snippets += 1
            elif ev_type == "recon_artifact":
                recon_artifacts += 1
            elif ev_type == "manual_note":
                manual_notes += 1

        return EvidenceSummary(
            total=len(evidence),
            by_type=by_type,
            http_exchanges=http_exchanges,
            screenshots=screenshots,
            code_snippets=code_snippets,
            recon_artifacts=recon_artifacts,
            manual_notes=manual_notes,
        )

    def _build_task_summary(self, tasks: list[Any]) -> TaskBoardSummary:
        backlog = planned = in_progress = needs_verif = completed = archived = 0
        by_priority: dict[str, int] = {}
        by_category: dict[str, int] = {}

        for task in tasks:
            col = getattr(task, "column", BoardColumn.BACKLOG)
            col_val = col.value if hasattr(col, "value") else str(col)
            if col_val == "backlog":
                backlog += 1
            elif col_val == "planned":
                planned += 1
            elif col_val == "in_progress":
                in_progress += 1
            elif col_val == "needs_verification":
                needs_verif += 1
            elif col_val == "completed":
                completed += 1
            elif col_val == "archived":
                archived += 1

            pri = getattr(task, "priority", "medium")
            pri_val = pri.value if hasattr(pri, "value") else str(pri)
            by_priority[pri_val] = by_priority.get(pri_val, 0) + 1

            cat = getattr(task, "category", "other")
            cat_val = cat.value if hasattr(cat, "value") else str(cat)
            by_category[cat_val] = by_category.get(cat_val, 0) + 1

        total = len(tasks) or 1
        completion_rate = (completed / total) * 100

        return TaskBoardSummary(
            total=len(tasks),
            backlog=backlog,
            planned=planned,
            in_progress=in_progress,
            needs_verification=needs_verif,
            completed=completed,
            archived=archived,
            by_priority=by_priority,
            by_category=by_category,
            completion_rate=completion_rate,
            overdue=0,
        )

    def _build_technology_summary(self, technologies: list[Any]) -> TechnologySummary:
        by_category: dict[str, int] = {}
        tech_list = []

        for tech in technologies:
            cat = getattr(tech, "category", "unknown")
            by_category[cat] = by_category.get(cat, 0) + 1
            tech_list.append({
                "name": getattr(tech, "name", "Unknown"),
                "category": cat,
                "version": getattr(tech, "version", ""),
            })

        return TechnologySummary(
            total=len(technologies),
            by_category=by_category,
            technologies=tech_list,
        )

    def _build_attack_surface_summary(
        self,
        endpoints: list[Any],
        parameters: list[Any],
        technologies: list[Any],
    ) -> AttackSurfaceSummary:
        by_category: dict[str, int] = {}
        by_method: dict[str, int] = {}
        by_auth: dict[str, int] = {}

        for ep in endpoints:
            cat = getattr(ep, "category", "unknown")
            by_category[cat] = by_category.get(cat, 0) + 1
            method = getattr(ep, "method", "GET")
            by_method[method] = by_method.get(method, 0) + 1
            auth = getattr(ep, "auth_required", False)
            by_auth["auth_required" if auth else "no_auth"] = by_auth.get("no_auth", 0) + 1

        return AttackSurfaceSummary(
            total_endpoints=len(endpoints),
            total_parameters=len(parameters),
            total_hosts=0,
            total_technologies=len(technologies),
            total_auth_flows=0,
            total_apis=0,
            by_category=by_category,
            by_http_method=by_method,
            by_auth_required=by_auth,
        )

    def _build_notebook_summary(self, entries: list[Any]) -> NotebookSummary:
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        flagged = 0
        archived = 0

        for entry in entries:
            t = getattr(entry, "entry_type", "unknown")
            t_val = t.value if hasattr(t, "value") else str(t)
            by_type[t_val] = by_type.get(t_val, 0) + 1
            s = getattr(entry, "status", "active")
            s_val = s.value if hasattr(s, "value") else str(s)
            by_status[s_val] = by_status.get(s_val, 0) + 1
            if s_val == "flagged":
                flagged += 1
            elif s_val == "archived":
                archived += 1

        return NotebookSummary(
            total_entries=len(entries),
            by_type=by_type,
            by_status=by_status,
            flagged=flagged,
            archived=archived,
        )

    def _build_finding_summary(self, findings: list[Any]) -> FindingSummary:
        by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_category: dict[str, int] = {}
        cvss_scores: list[float] = []

        for f in findings:
            sev = getattr(f, "severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            cat = getattr(f, "category", "unknown")
            by_category[cat] = by_category.get(cat, 0) + 1
            score = getattr(f, "cvss_score", 0.0)
            if score > 0:
                cvss_scores.append(score)

        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0

        return FindingSummary(
            total=len(findings),
            by_severity=by_severity,
            by_category=by_category,
            cvss_scores=cvss_scores,
            avg_cvss=avg_cvss,
            critical_count=by_severity.get("critical", 0),
            high_count=by_severity.get("high", 0),
            medium_count=by_severity.get("medium", 0),
            low_count=by_severity.get("low", 0),
            info_count=by_severity.get("info", 0),
        )

    def _build_timeline_summary(self, events: list[Any]) -> TimelineActivitySummary:
        now = datetime.now(UTC)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=today_start.weekday())
        month_start = today_start.replace(day=1)

        by_type: dict[str, int] = {}
        today_count = 0
        week_count = 0
        month_count = 0

        for evt in events:
            evt_type = getattr(evt, "event_type", "unknown")
            by_type[evt_type] = by_type.get(evt_type, 0) + 1
            created = getattr(evt, "created_at", None)
            if created:
                if created >= today_start:
                    today_count += 1
                if created >= week_start:
                    week_count += 1
                if created >= month_start:
                    month_count += 1

        total = len(events)
        days_span = max(1, (now - (events[0].created_at if events else now)).days)
        avg_per_day = total / max(1, days_span)

        return TimelineActivitySummary(
            total_events=total,
            events_today=today_count,
            events_this_week=week_count,
            events_this_month=month_count,
            by_event_type=by_type,
            avg_events_per_day=avg_per_day,
        )

    def _build_coverage(
        self,
        endpoints: list[Any],
        parameters: list[Any],
        technologies: list[Any],
        hypothesis_states: list[Any],
    ) -> CoverageAssessment:
        ep_count = len(endpoints)
        param_count = len(parameters)
        tech_count = len(technologies)

        cov_by_ep = min(100.0, ep_count * 5.0)
        cov_by_param = min(100.0, param_count * 2.0)
        cov_by_tech = min(100.0, tech_count * 10.0)

        def level(val: float) -> CoverageLevel:
            if val < 20:
                return CoverageLevel.NONE
            elif val < 40:
                return CoverageLevel.MINIMAL
            elif val < 60:
                return CoverageLevel.PARTIAL
            elif val < 80:
                return CoverageLevel.GOOD
            return CoverageLevel.COMPREHENSIVE

        overall_score = (cov_by_ep + cov_by_param + cov_by_tech) / 3

        return CoverageAssessment(
            overall=level(overall_score),
            coverage_by_endpoint=cov_by_ep,
            coverage_by_parameter=cov_by_param,
            coverage_by_technology=cov_by_tech,
        )

    def _assess_health(
        self,
        overview: DashboardOverview,
        hyp_sum: HypothesisSummary,
        ev_sum: EvidenceSummary,
        task_sum: TaskBoardSummary,
        find_sum: FindingSummary,
        cov: CoverageAssessment,
    ) -> tuple[HealthStatus, list[str]]:
        messages: list[str] = []
        health = HealthStatus.HEALTHY

        if overview.investigation_status == "completed":
            return HealthStatus.COMPLETED, ["Investigation completed"]

        if ev_sum.total == 0:
            messages.append("No evidence collected yet")
            health = HealthStatus.STALLED

        if hyp_sum.total == 0:
            messages.append("No hypotheses generated yet")
            health = HealthStatus.AT_RISK

        if task_sum.overdue_cards > 0:
            messages.append(f"{task_sum.overdue_cards} tasks are overdue")
            health = HealthStatus.AT_RISK

        if cov.overall in (CoverageLevel.NONE, CoverageLevel.MINIMAL):
            messages.append("Coverage is minimal - expand investigation scope")
            health = HealthStatus.AT_RISK

        if find_sum.critical_count > 0:
            messages.append(f"Found {find_sum.critical_count} critical findings")

        if task_sum.in_progress == 0 and hyp_sum.total > 0:
            messages.append("No active tasks - investigation may be stalled")

        if overview.last_activity_time:
            hours_since = (datetime.now(UTC) - overview.last_activity_time).total_seconds() / 3600
            if hours_since > 48:
                messages.append(f"No activity for {int(hours_since)} hours")
                health = HealthStatus.STALLED

        return health, messages