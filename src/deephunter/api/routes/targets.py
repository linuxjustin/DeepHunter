"""Target management API endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from deephunter.workspace.manager import WorkspaceManager
from deephunter.workspace.models import TargetType

router = APIRouter()


class CreateTargetRequest(BaseModel):
    project_id: str
    name: str
    url: str = ""
    target_type: str = "web_application"
    description: str = ""


class UpdateTargetRequest(BaseModel):
    name: str | None = None
    url: str | None = None
    status: str | None = None
    description: str | None = None
    metadata: dict[str, Any] | None = None


@router.get("/targets", response_model=list[dict])
async def list_targets(project_id: str | None = None) -> list[dict]:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")
    targets = manager.current_workspace.state.targets
    if project_id:
        targets = [t for t in targets if t.project_id == project_id]
    return [{"id": t.id, "name": t.name, "project_id": t.project_id, "url": t.url, "target_type": t.target_type.value, "status": t.status.value, "created_at": t.created_at.isoformat()} for t in targets]


@router.post("/targets", response_model=dict)
async def create_target(req: CreateTargetRequest) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")
    target = manager.create_target(req.project_id, req.name, req.url, req.target_type)
    if target is None:
        raise HTTPException(status_code=400, detail="Failed to create target")
    manager.save_workspace()
    return {"id": target.id, "name": target.name, "project_id": target.project_id, "url": target.url}


@router.get("/targets/{target_id}", response_model=dict)
async def get_target(target_id: str) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=400, detail="No workspace loaded")
    target = manager.get_target(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return {"id": target.id, "name": target.name, "project_id": target.project_id, "url": target.url, "target_type": target.target_type.value, "status": target.status.value, "description": target.description, "scope": target.scope.model_dump(), "created_at": target.created_at.isoformat()}


@router.patch("/targets/{target_id}", response_model=dict)
async def update_target(target_id: str, req: UpdateTargetRequest) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=400, detail="No workspace loaded")
    updates: dict[str, Any] = {}
    if req.name is not None:
        updates["name"] = req.name
    if req.url is not None:
        updates["url"] = req.url
    if req.status is not None:
        updates["status"] = req.status
    if req.description is not None:
        updates["description"] = req.description
    target = manager.update_target(target_id, **updates)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    manager.save_workspace()
    return {"id": target.id, "status": target.status.value}


@router.get("/targets/{target_id}/assets", response_model=list[dict])
async def list_target_assets(target_id: str) -> list[dict]:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=400, detail="No workspace loaded")
    assets = [a for a in manager.current_workspace.state.assets if a.target_id == target_id]
    return [{"id": a.id, "type": a.asset_type, "value": a.value, "source": a.source, "discovered_at": a.discovered_at.isoformat()} for a in assets]