"""Investigation Notebook API routes."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from deephunter.investigation.notebook.manager import NotebookManager
from deephunter.investigation.notebook.models import (
    BoardColumn,
    BoardState,
    NoteStatus,
    NoteType,
    NotebookChecklist,
    NotebookChecklistItem,
    NotebookEntry,
    NotebookState,
    TaskBoardManager,
    TaskPriority,
)
from deephunter.workspace.manager import WorkspaceManager

router = APIRouter(prefix="/notebook", tags=["notebook"])


class CreateEntryRequest(BaseModel):
    target_id: str
    investigation_session_id: str = ""
    entry_type: str
    title: str
    content: str = ""
    author_id: str = ""
    tags: list[str] = []
    severity: str = ""
    confidence: float = 0.0


class UpdateEntryRequest(BaseModel):
    title: str | None = None
    content: str | None = None
    status: str | None = None
    tags: list[str] | None = None
    severity: str | None = None
    confidence: float | None = None


class LinkEntryRequest(BaseModel):
    entry_id: str
    evidence_ids: list[str] = []
    hypothesis_ids: list[str] = []
    task_ids: list[str] = []
    finding_ids: list[str] = []
    endpoint_ids: list[str] = []
    parameter_ids: list[str] = []
    technology_ids: list[str] = []


@router.post("/entries")
async def create_entry(req: CreateEntryRequest) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")

    nb_manager = NotebookManager.new(req.target_id, req.investigation_session_id)
    entry = nb_manager.add_entry(
        entry_type=NoteType(req.entry_type),
        title=req.title,
        content=req.content,
        author_id=req.author_id,
        tags=req.tags,
        severity=req.severity,
        confidence=req.confidence,
    )
    manager.save_workspace()
    return {"id": entry.id, "entry_type": entry.entry_type.value, "title": entry.title}


@router.get("/entries")
async def list_entries(
    target_id: str,
    entry_type: str | None = None,
    status: str | None = None,
    tag: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        return {"total": 0, "entries": []}

    entries = [
        e for e in manager.current_workspace.state.notes
        if getattr(e, "target_id", "") == target_id
        or getattr(e, "entity_type", "") == "notebook"
    ]
    return {"total": len(entries), "entries": entries}


@router.get("/entries/{entry_id}")
async def get_entry(entry_id: str) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    for e in manager.current_workspace.state.notes:
        if e.id == entry_id:
            return e.model_dump_for_storage()
    raise HTTPException(status_code=404, detail="Entry not found")


@router.patch("/entries/{entry_id}")
async def update_entry(entry_id: str, req: UpdateEntryRequest) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    for e in manager.current_workspace.state.notes:
        if e.id == entry_id:
            if req.title is not None:
                e.title = req.title
            if req.content is not None:
                e.content = req.content
            if req.status is not None:
                e.status = NoteStatus(req.status)
            if req.tags is not None:
                e.tags = req.tags
            e.updated_at = datetime.now()
            manager.save_workspace()
            return e.model_dump_for_storage()
    raise HTTPException(status_code=404, detail="Entry not found")


@router.delete("/entries/{entry_id}")
async def delete_entry(entry_id: str) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    initial = len(manager.current_workspace.state.notes)
    manager.current_workspace.state.notes = [
        e for e in manager.current_workspace.state.notes if e.id != entry_id
    ]
    if len(manager.current_workspace.state.notes) == initial:
        raise HTTPException(status_code=404, detail="Entry not found")
    manager.save_workspace()
    return {"status": "deleted", "id": entry_id}


@router.get("/entries/{entry_id}/export")
async def export_entry_markdown(entry_id: str) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    for e in manager.current_workspace.state.notes:
        if e.id == entry_id:
            md = f"## {e.title}\n\n{e.content}\n\n"
            if e.tags:
                md += f"Tags: {', '.join(e.tags)}\n"
            md += f"_Created: {e.created_at.isoformat()}_\n"
            return {"format": "markdown", "content": md}
    raise HTTPException(status_code=404, detail="Entry not found")


@router.get("/summary/{target_id}")
async def get_notebook_summary(target_id: str) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        return {"total_entries": 0, "entries_by_type": {}, "entries_by_status": {}}
    entries = [e for e in manager.current_workspace.state.notes if getattr(e, "target_id", "") == target_id]
    by_type = {}
    by_status = {}
    for e in entries:
        t = e.entry_type.value if hasattr(e.entry_type, "value") else str(e.entry_type)
        by_type[t] = by_type.get(t, 0) + 1
        s = e.status.value if hasattr(e.status, "value") else str(e.status)
        by_status[s] = by_status.get(s, 0) + 1
    return {
        "total_entries": len(entries),
        "entries_by_type": by_type,
        "entries_by_status": by_status,
        "total_evidence_refs": 0,
        "total_endpoint_refs": 0,
        "total_parameter_refs": 0,
        "total_technology_refs": 0,
    }