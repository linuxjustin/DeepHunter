"""Workspace-level API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from pathlib import Path

from deephunter.workspace.manager import WorkspaceManager

router = APIRouter()


@router.get("/workspace", response_model=dict)
async def get_workspace() -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")
    ws = manager.current_workspace
    return {"id": ws.id, "name": ws.name, "description": ws.description, "created_at": ws.created_at.isoformat(), "projects_count": len(ws.state.projects), "targets_count": len(ws.state.targets), "reports_count": len(ws.state.reports), "conversations_count": len(ws.state.conversations)}


@router.post("/workspace/save")
async def save_workspace() -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=400, detail="No workspace to save")
    path = manager.save_workspace()
    return {"status": "saved", "path": str(path)}


@router.post("/workspace/load/{workspace_id}")
async def load_workspace(workspace_id: str) -> dict:
    manager = WorkspaceManager()
    try:
        ws = manager.load_workspace(workspace_id)
        return {"status": "loaded", "id": ws.id, "name": ws.name}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Workspace not found")


@router.get("/workspace/list")
async def list_workspaces() -> list[dict]:
    manager = WorkspaceManager()
    return manager.list_workspaces()


@router.post("/workspace/timeline", response_model=list[dict])
async def get_timeline(limit: int = 50) -> list[dict]:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")
    events = manager.current_workspace.state.timeline[-limit:]
    return [{"id": e.id, "event_type": e.event_type, "title": e.title, "severity": e.severity, "created_at": e.created_at.isoformat()} for e in events]


@router.get("/workspace/export")
async def export_workspace() -> FileResponse:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")
    path = manager.save_workspace()
    return FileResponse(path, filename=f"deephunter-workspace-{manager.current_workspace.id}.json", media_type="application/json")