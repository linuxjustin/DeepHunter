"""Evidence and note management API endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from deephunter.workspace.manager import WorkspaceManager

router = APIRouter()


class CreateNoteRequest(BaseModel):
    entity_type: str
    entity_id: str
    content: str
    author_id: str = ""


class CreateAssetRequest(BaseModel):
    target_id: str
    asset_type: str
    value: str
    source: str = ""


class NoteResponse(BaseModel):
    id: str
    entity_type: str
    entity_id: str
    content: str
    author_id: str = ""
    created_at: str


class AssetResponse(BaseModel):
    id: str
    target_id: str
    asset_type: str
    value: str
    source: str = ""
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DeleteResponse(BaseModel):
    status: str
    id: str


@router.get("/notes", response_model=list[NoteResponse])
async def list_notes(entity_type: str | None = None, entity_id: str | None = None) -> list[NoteResponse]:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")
    notes = manager.current_workspace.state.notes
    if entity_type:
        notes = [n for n in notes if n.entity_type == entity_type]
    if entity_id:
        notes = [n for n in notes if n.entity_id == entity_id]
    return [NoteResponse(id=n.id, entity_type=n.entity_type, entity_id=n.entity_id, content=n.content, author_id=n.author_id, created_at=n.created_at.isoformat()) for n in notes]


@router.post("/notes", response_model=NoteResponse)
async def create_note(req: CreateNoteRequest) -> NoteResponse:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")
    note = manager.create_note(req.entity_type, req.entity_id, req.content, req.author_id)
    manager.save_workspace()
    return NoteResponse(id=note.id, entity_type=note.entity_type, entity_id=note.entity_id, content=note.content, author_id=note.author_id, created_at=note.created_at.isoformat())


@router.get("/assets", response_model=list[AssetResponse])
async def list_assets(target_id: str | None = None, asset_type: str | None = None) -> list[AssetResponse]:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")
    assets = manager.current_workspace.state.assets
    if target_id:
        assets = [a for a in assets if a.target_id == target_id]
    if asset_type:
        assets = [a for a in assets if a.asset_type == asset_type]
    return [AssetResponse(id=a.id, target_id=a.target_id, asset_type=a.asset_type, value=a.value, source=a.source, tags=a.tags, metadata=a.metadata) for a in assets]


@router.post("/assets", response_model=AssetResponse)
async def create_asset(req: CreateAssetRequest) -> AssetResponse:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=400, detail="No workspace loaded")
    asset = manager.create_asset(req.target_id, req.asset_type, req.value, req.source)
    manager.save_workspace()
    return AssetResponse(id=asset.id, target_id=asset.target_id, asset_type=asset.asset_type, value=asset.value, source=asset.source, tags=asset.tags, metadata=asset.metadata)


@router.delete("/assets/{asset_id}", response_model=DeleteResponse)
async def delete_asset(asset_id: str) -> DeleteResponse:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=400, detail="No workspace loaded")
    initial_len = len(manager.current_workspace.state.assets)
    manager.current_workspace.state.assets = [a for a in manager.current_workspace.state.assets if a.id != asset_id]
    if len(manager.current_workspace.state.assets) == initial_len:
        raise HTTPException(status_code=404, detail="Asset not found")
    manager.save_workspace()
    return DeleteResponse(status="deleted", id=asset_id)