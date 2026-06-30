"""Extended Timeline API routes for research events."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from deephunter.workspace.manager import WorkspaceManager

router = APIRouter(prefix="/timeline", tags=["timeline"])


class TimelineEventRequest(BaseModel):
    project_id: str
    target_id: str | None = None
    event_type: str
    title: str
    description: str = ""
    severity: str = "info"
    entity_type: str = ""
    entity_id: str = ""
    created_by: str = ""


class ReplayRequest(BaseModel):
    project_id: str
    target_id: str | None = None
    event_types: list[str] | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
    limit: int = 100


@router.post("/events")
async def create_timeline_event(req: TimelineEventRequest) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")

    from deephunter.workspace.models import TimelineEvent as WTimelineEvent

    event = WTimelineEvent(
        project_id=req.project_id,
        target_id=req.target_id,
        event_type=req.event_type,
        title=req.title,
        description=req.description,
        severity=req.severity,
        entity_type=req.entity_type,
        entity_id=req.entity_id,
        created_by=req.created_by,
    )
    manager.current_workspace.state.timeline.append(event)
    manager.save_workspace()
    return {"id": event.id, "event_type": event.event_type, "title": event.title}


@router.get("/events")
async def list_timeline_events(
    project_id: str,
    target_id: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    entity_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        return {"total": 0, "events": []}

    events = manager.current_workspace.state.timeline
    if project_id:
        events = [e for e in events if e.project_id == project_id]
    if target_id:
        events = [e for e in events if e.target_id == target_id]
    if event_type:
        events = [e for e in events if e.event_type == event_type]
    if severity:
        events = [e for e in events if e.severity == severity]
    if entity_type:
        events = [e for e in events if e.entity_type == entity_type]

    events = sorted(events, key=lambda x: x.created_at, reverse=True)
    total = len(events)
    paginated = events[offset : offset + limit]

    return {
        "total": total,
        "events": [e.model_dump_for_storage() for e in paginated],
    }


@router.get("/events/types")
async def get_event_types() -> dict:
    return {
        "event_types": [
            {"value": "created", "description": "Resource created"},
            {"value": "updated", "description": "Resource updated"},
            {"value": "recon_imported", "description": "Recon data imported"},
            {"value": "technology_identified", "description": "Technology identified"},
            {"value": "knowledge_pack_loaded", "description": "Knowledge pack loaded"},
            {"value": "methodology_selected", "description": "Methodology selected"},
            {"value": "hypothesis_created", "description": "Hypothesis created"},
            {"value": "hypothesis_updated", "description": "Hypothesis updated"},
            {"value": "evidence_added", "description": "Evidence added"},
            {"value": "experiment_completed", "description": "Experiment completed"},
            {"value": "finding_created", "description": "Finding created"},
            {"value": "task_created", "description": "Task created"},
            {"value": "task_completed", "description": "Task completed"},
            {"value": "planner_updated", "description": "Plan updated"},
            {"value": "ai_conversation", "description": "AI conversation message"},
            {"value": "report_generated", "description": "Report generated"},
            {"value": "notebook_entry", "description": "Notebook entry added"},
            {"value": "scope_defined", "description": "Scope defined"},
            {"value": "target_created", "description": "Target created"},
            {"value": "project_created", "description": "Project created"},
        ]
    }


@router.post("/replay")
async def replay_timeline(req: ReplayRequest) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        return {"total": 0, "events": [], "replay": []}

    events = manager.current_workspace.state.timeline
    if req.project_id:
        events = [e for e in events if e.project_id == req.project_id]
    if req.target_id:
        events = [e for e in events if e.target_id == req.target_id]
    if req.event_types:
        events = [e for e in events if e.event_type in req.event_types]
    if req.date_from:
        events = [e for e in events if e.created_at >= req.date_from]
    if req.date_to:
        events = [e for e in events if e.created_at <= req.date_to]

    events = sorted(events, key=lambda x: x.created_at)

    replay = []
    for e in events:
        replay.append({
            "timestamp": e.created_at.isoformat(),
            "event_type": e.event_type,
            "title": e.title,
            "description": e.description,
        })

    return {
        "total": len(events),
        "events": [e.model_dump_for_storage() for e in events],
        "replay": replay,
    }


@router.get("/summary/{project_id}")
async def get_timeline_summary(project_id: str) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        return {"total_events": 0, "by_type": {}, "by_severity": {}}

    events = [e for e in manager.current_workspace.state.timeline if e.project_id == project_id]

    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for e in events:
        by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
        by_severity[e.severity] = by_severity.get(e.severity, 0) + 1

    return {
        "total_events": len(events),
        "by_type": by_type,
        "by_severity": by_severity,
    }


@router.get("/export/{project_id}")
async def export_timeline_markdown(project_id: str, target_id: str | None = None) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=404, detail="No workspace found")

    events = [e for e in manager.current_workspace.state.timeline if e.project_id == project_id]
    if target_id:
        events = [e for e in events if e.target_id == target_id]

    events = sorted(events, key=lambda x: x.created_at)

    lines = ["# Investigation Timeline\n"]
    for e in events:
        lines.append(f"## [{e.created_at.isoformat()}] {e.event_type}: {e.title}\n")
        if e.description:
            lines.append(f"{e.description}\n")
        if e.severity and e.severity != "info":
            lines.append(f"Severity: {e.severity}\n")
        lines.append("\n")

    return {"format": "markdown", "content": "\n".join(lines)}