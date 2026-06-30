"""Project management API endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from deephunter.workspace.manager import WorkspaceManager
from deephunter.workspace.models import Project, ProjectStatus

router = APIRouter()


class CreateProjectRequest(BaseModel):
    name: str
    description: str = ""
    metadata: dict[str, Any] = {}


class UpdateProjectRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    status: str | None = None
    metadata: dict[str, Any] | None = None


@router.get("/projects", response_model=list[dict])
async def list_projects() -> list[dict]:
    """List all projects in the current workspace."""
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")
    projects = manager.current_workspace.state.projects
    return [{"id": p.id, "name": p.name, "status": p.status.value, "description": p.description, "created_at": p.created_at.isoformat(), "updated_at": p.updated_at.isoformat()} for p in projects]


@router.post("/projects", response_model=dict)
async def create_project(req: CreateProjectRequest) -> dict:
    """Create a new project."""
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")
    project = manager.create_project(name=req.name, description=req.description)
    manager.save_workspace()
    return {"id": project.id, "name": project.name, "status": project.status.value, "description": project.description, "created_at": project.created_at.isoformat()}


@router.get("/projects/{project_id}", response_model=dict)
async def get_project(project_id: str) -> dict:
    """Get a project by ID."""
    manager = WorkspaceManager()
    manager.load_workspace("default") if False else None
    if manager.current_workspace is None:
        manager.create_workspace("Default")
    project = manager.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"id": project.id, "name": project.name, "status": project.status.value, "description": project.description, "created_at": project.created_at.isoformat(), "updated_at": project.updated_at.isoformat(), "tags": project.tags, "metadata": project.metadata}


@router.patch("/projects/{project_id}", response_model=dict)
async def update_project(project_id: str, req: UpdateProjectRequest) -> dict:
    """Update a project."""
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=400, detail="No workspace loaded")

    updates: dict[str, Any] = {}
    if req.name is not None:
        updates["name"] = req.name
    if req.description is not None:
        updates["description"] = req.description
    if req.status is not None:
        updates["status"] = req.status
    if req.metadata is not None:
        updates["metadata"] = req.metadata

    project = manager.update_project(project_id, **updates)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    manager.save_workspace()
    return {"id": project.id, "name": project.name, "status": project.status.value}


@router.delete("/projects/{project_id}")
async def archive_project(project_id: str) -> dict:
    """Archive a project."""
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=400, detail="No workspace loaded")
    project = manager.archive_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    manager.save_workspace()
    return {"status": "archived", "id": project_id}