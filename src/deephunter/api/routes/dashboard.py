"""Research Dashboard API routes."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from deephunter.dashboard.models import ResearchDashboard
from deephunter.dashboard.service import DashboardService
from deephunter.workspace.manager import WorkspaceManager

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_dashboard_service = DashboardService()

_dashboards: dict[str, ResearchDashboard] = {}


class GenerateDashboardRequest(BaseModel):
    target_id: str
    investigation_session_id: str = ""
    target_name: str = ""
    target_url: str = ""
    project_name: str = ""
    investigation_status: str = ""


@router.post("/generate")
async def generate_dashboard(req: GenerateDashboardRequest) -> dict:
    dashboard = _dashboard_service.generate_dashboard(
        target_id=req.target_id,
        investigation_id=req.investigation_session_id,
        target_name=req.target_name,
        target_url=req.target_url,
        project_name=req.project_name,
        investigation_status=req.investigation_status,
        start_time=datetime.now(UTC),
        last_activity=datetime.now(UTC),
    )

    _dashboards[req.target_id] = dashboard

    return {
        "id": dashboard.id,
        "target_id": dashboard.target_id,
        "health_status": dashboard.health_status.value,
        "health_messages": dashboard.health_messages,
        "overview": _dashboard_to_dict(dashboard),
    }


@router.get("/{target_id}")
async def get_dashboard(target_id: str) -> dict:
    if target_id in _dashboards:
        d = _dashboards[target_id]
        return {
            "id": d.id,
            "target_id": d.target_id,
            "health_status": d.health_status.value,
            "health_messages": d.health_messages,
            "overview": _dashboard_to_dict(d),
        }

    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=404, detail="No workspace found")

    target = None
    for t in manager.current_workspace.state.targets:
        if t.id == target_id:
            target = t
            break

    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    dashboard = _dashboard_service.generate_dashboard(
        target_id=target_id,
        target_name=target.name,
        target_url=target.url,
    )
    _dashboards[target_id] = dashboard

    return {
        "id": dashboard.id,
        "target_id": dashboard.target_id,
        "health_status": dashboard.health_status.value,
        "health_messages": dashboard.health_messages,
        "overview": _dashboard_to_dict(dashboard),
    }


@router.get("/{target_id}/overview")
async def get_dashboard_overview(target_id: str) -> dict:
    if target_id in _dashboards:
        d = _dashboards[target_id]
    else:
        d = _dashboard_service.generate_dashboard(target_id=target_id)

    return _dashboard_to_dict(d)


@router.get("/{target_id}/coverage")
async def get_dashboard_coverage(target_id: str) -> dict:
    if target_id in _dashboards:
        d = _dashboards[target_id]
    else:
        d = _dashboard_service.generate_dashboard(target_id=target_id)

    if d.coverage is None:
        return {}
    cov = d.coverage
    return {
        "overall": cov.overall.value,
        "coverage_by_endpoint": cov.coverage_by_endpoint,
        "coverage_by_parameter": cov.coverage_by_parameter,
        "coverage_by_technology": cov.coverage_by_technology,
    }


@router.get("/{target_id}/health")
async def get_dashboard_health(target_id: str) -> dict:
    if target_id in _dashboards:
        d = _dashboards[target_id]
    else:
        d = _dashboard_service.generate_dashboard(target_id=target_id)

    return {
        "status": d.health_status.value,
        "messages": d.health_messages,
    }


def _dashboard_to_dict(d: ResearchDashboard) -> dict:
    result: dict = {}

    if d.overview:
        o = d.overview
        result["overview"] = {
            "target_id": o.target_id,
            "target_name": o.target_name,
            "target_url": o.target_url,
            "project_name": o.project_name,
            "investigation_status": o.investigation_status,
            "progress_pct": o.progress_pct,
            "health_status": o.health_status.value if o.health_status else "healthy",
            "total_duration_minutes": o.total_duration_minutes,
        }

    if d.hypothesis:
        h = d.hypothesis
        result["hypotheses"] = {
            "total": h.total,
            "by_status": h.by_status,
            "by_priority": h.by_priority,
            "by_bug_class": h.by_bug_class,
            "avg_confidence": h.avg_confidence,
            "confirmed_findings": h.confirmed_findings,
        }

    if d.evidence:
        e = d.evidence
        result["evidence"] = {
            "total": e.total,
            "by_type": e.by_type,
            "http_exchanges": e.http_exchanges,
        }

    if d.tasks:
        t = d.tasks
        result["tasks"] = {
            "total": t.total,
            "completed": t.completed,
            "in_progress": t.in_progress,
            "backlog": t.backlog,
            "completion_rate": t.completion_rate,
        }

    if d.findings:
        f = d.findings
        result["findings"] = {
            "total": f.total,
            "critical": f.critical_count,
            "high": f.high_count,
            "medium": f.medium_count,
            "low": f.low_count,
        }

    if d.attack_surface:
        a = d.attack_surface
        result["attack_surface"] = {
            "total_endpoints": a.total_endpoints,
            "total_parameters": a.total_parameters,
            "total_technologies": a.total_technologies,
        }

    return result