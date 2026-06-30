"""AI conversation API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from deephunter.workspace.manager import WorkspaceManager
from deephunter.workspace.models import ConversationMessage, ConversationRole

router = APIRouter()


class CreateConversationRequest(BaseModel):
    target_id: str
    title: str = "New Conversation"


class SendMessageRequest(BaseModel):
    content: str
    role: str = "user"
    model: str = ""
    tokens_used: int = 0


@router.get("/conversations", response_model=list[dict])
async def list_conversations(target_id: str | None = None) -> list[dict]:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")
    convs = manager.current_workspace.state.conversations
    if target_id:
        convs = [c for c in convs if c.target_id == target_id]
    return [{"id": c.id, "title": c.title, "target_id": c.target_id, "message_count": len(c.messages), "last_message_at": c.last_message_at.isoformat(), "created_at": c.created_at.isoformat()} for c in convs]


@router.post("/conversations", response_model=dict)
async def create_conversation(req: CreateConversationRequest) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")
    conv = manager.create_conversation(req.target_id, req.title)
    manager.save_workspace()
    return {"id": conv.id, "title": conv.title, "target_id": conv.target_id}


@router.get("/conversations/{conversation_id}", response_model=dict)
async def get_conversation(conversation_id: str) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=400, detail="No workspace loaded")
    for conv in manager.current_workspace.state.conversations:
        if conv.id == conversation_id:
            return {"id": conv.id, "title": conv.title, "target_id": conv.target_id, "messages": [{"id": m.id, "role": m.role.value, "content": m.content, "model": m.model, "tokens_used": m.tokens_used, "created_at": m.created_at.isoformat()} for m in conv.messages], "context_summary": conv.context_summary, "investigation_session_id": conv.investigation_session_id, "evidence_references": conv.evidence_references, "created_at": conv.created_at.isoformat(), "updated_at": conv.updated_at.isoformat()}
    raise HTTPException(status_code=404, detail="Conversation not found")


@router.post("/conversations/{conversation_id}/messages", response_model=dict)
async def send_message(conversation_id: str, req: SendMessageRequest) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=400, detail="No workspace loaded")

    msg = manager.add_conversation_message(
        conversation_id=conversation_id,
        role=ConversationRole(req.role),
        content=req.content,
        model=req.model,
        tokens_used=req.tokens_used,
    )
    if msg is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    manager.save_workspace()
    return {"id": msg.id, "role": msg.role.value, "content": msg.content, "model": msg.model, "tokens_used": msg.tokens_used, "created_at": msg.created_at.isoformat()}


@router.patch("/conversations/{conversation_id}", response_model=dict)
async def update_conversation(conversation_id: str, title: str | None = None, context_summary: str | None = None) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=400, detail="No workspace loaded")
    for conv in manager.current_workspace.state.conversations:
        if conv.id == conversation_id:
            if title is not None:
                conv.title = title
            if context_summary is not None:
                conv.context_summary = context_summary
            manager.save_workspace()
            return {"id": conv.id, "title": conv.title, "updated_at": conv.updated_at.isoformat()}
    raise HTTPException(status_code=404, detail="Conversation not found")


@router.delete("/conversations/{conversation_id}")
async def delete_conversation(conversation_id: str) -> dict:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=400, detail="No workspace loaded")
    initial_len = len(manager.current_workspace.state.conversations)
    manager.current_workspace.state.conversations = [c for c in manager.current_workspace.state.conversations if c.id != conversation_id]
    if len(manager.current_workspace.state.conversations) == initial_len:
        raise HTTPException(status_code=404, detail="Conversation not found")
    manager.save_workspace()
    return {"status": "deleted", "id": conversation_id}