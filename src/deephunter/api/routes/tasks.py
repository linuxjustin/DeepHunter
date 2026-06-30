"""Task Board API routes - Kanban-style task management."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from deephunter.investigation.taskboard.models import (
    BoardCard,
    BoardColumn,
    BoardState,
    TaskCategory,
    TaskPriority,
    TaskStatus,
)
from deephunter.workspace.manager import WorkspaceManager

router = APIRouter(prefix="/tasks", tags=["tasks"])


class CreateCardRequest(BaseModel):
    target_id: str
    investigation_session_id: str = ""
    title: str
    description: str = ""
    column: str = "backlog"
    priority: str = "medium"
    category: str = "other"
    assigned_to: str = ""
    estimated_minutes: int = 0
    tags: list[str] = []
    depends_on: list[str] = []


class MoveCardRequest(BaseModel):
    card_id: str
    target_column: str
    order: int = 0


class UpdateCardRequest(BaseModel):
    title: str | None = None
    description: str | None = None
    priority: str | None = None
    assigned_to: str | None = None
    estimated_minutes: int | None = None
    tags: list[str] | None = None
    notes: str | None = None
    findings: str | None = None
    status: str | None = None


class ColumnConfigRequest(BaseModel):
    column: str
    wip_limit: int = 0
    collapsed: bool = False
    color: str = "#6366f1"


_board_states: dict[str, BoardState] = {}


def _get_board(target_id: str) -> BoardState:
    if target_id not in _board_states:
        _board_states[target_id] = BoardState(target_id=target_id)
    return _board_states[target_id]


@router.post("/cards")
async def create_card(req: CreateCardRequest) -> dict:
    board = _get_board(req.target_id)
    card = BoardCard(
        target_id=req.target_id,
        investigation_session_id=req.investigation_session_id,
        title=req.title,
        description=req.description,
        column=BoardColumn(req.column),
        priority=TaskPriority(req.priority),
        category=TaskCategory(req.category),
        assigned_to=req.assigned_to,
        estimated_minutes=req.estimated_minutes,
        tags=req.tags,
        depends_on=req.depends_on,
    )
    board.cards.append(card)
    return {"id": card.id, "title": card.title, "column": card.column.value}


@router.get("/cards")
async def list_cards(
    target_id: str,
    column: str | None = None,
    status: str | None = None,
    priority: str | None = None,
    category: str | None = None,
    assigned_to: str | None = None,
) -> dict:
    board = _get_board(target_id)
    cards = board.cards
    if column:
        cards = [c for c in cards if c.column.value == column]
    if status:
        cards = [c for c in cards if c.status.value == status]
    if priority:
        cards = [c for c in cards if c.priority.value == priority]
    if category:
        cards = [c for c in cards if c.category.value == category]
    if assigned_to:
        cards = [c for c in cards if c.assigned_to == assigned_to]

    by_column: dict[str, int] = {}
    for c in cards:
        col = c.column.value
        by_column[col] = by_column.get(col, 0) + 1

    return {
        "total": len(cards),
        "by_column": by_column,
        "cards": [c.model_dump_for_storage() for c in cards],
    }


@router.get("/cards/{card_id}")
async def get_card(card_id: str) -> dict:
    for board in _board_states.values():
        for card in board.cards:
            if card.id == card_id:
                return card.model_dump_for_storage()
    raise HTTPException(status_code=404, detail="Card not found")


@router.patch("/cards/{card_id}")
async def update_card(card_id: str, req: UpdateCardRequest) -> dict:
    for board in _board_states.values():
        for card in board.cards:
            if card.id == card_id:
                if req.title is not None:
                    card.title = req.title
                if req.description is not None:
                    card.description = req.description
                if req.priority is not None:
                    card.priority = TaskPriority(req.priority)
                if req.assigned_to is not None:
                    card.assigned_to = req.assigned_to
                if req.estimated_minutes is not None:
                    card.estimated_minutes = req.estimated_minutes
                if req.tags is not None:
                    card.tags = req.tags
                if req.notes is not None:
                    card.notes = req.notes
                if req.findings is not None:
                    card.findings = req.findings
                if req.status is not None:
                    card.status = TaskStatus(req.status)
                    if req.status == "completed":
                        card.completed_at = datetime.now()
                card.updated_at = datetime.now()
                return card.model_dump_for_storage()
    raise HTTPException(status_code=404, detail="Card not found")


@router.post("/cards/move")
async def move_card(req: MoveCardRequest) -> dict:
    for board in _board_states.values():
        for card in board.cards:
            if card.id == req.card_id:
                card.column = BoardColumn(req.target_column)
                card.order_in_column = req.order
                card.updated_at = datetime.now()
                return {"id": card.id, "column": card.column.value}
    raise HTTPException(status_code=404, detail="Card not found")


@router.delete("/cards/{card_id}")
async def delete_card(card_id: str) -> dict:
    for board in _board_states.values():
        for i, card in enumerate(board.cards):
            if card.id == card_id:
                board.cards.pop(i)
                return {"status": "deleted", "id": card_id}
    raise HTTPException(status_code=404, detail="Card not found")


@router.post("/cards/{card_id}/complete")
async def complete_card(card_id: str, findings: str = "") -> dict:
    for board in _board_states.values():
        for card in board.cards:
            if card.id == card_id:
                card.status = TaskStatus.COMPLETED
                card.column = BoardColumn.COMPLETED
                card.findings = findings
                card.completed_at = datetime.now()
                card.updated_at = datetime.now()
                return {"id": card.id, "status": "completed"}
    raise HTTPException(status_code=404, detail="Card not found")


@router.get("/board/{target_id}/summary")
async def get_board_summary(target_id: str) -> dict:
    board = _get_board(target_id)
    by_col: dict[str, int] = {}
    by_stat: dict[str, int] = {}
    by_pri: dict[str, int] = {}
    by_cat: dict[str, int] = {}
    for c in board.cards:
        by_col[c.column.value] = by_col.get(c.column.value, 0) + 1
        by_stat[c.status.value] = by_stat.get(c.status.value, 0) + 1
        by_pri[c.priority.value] = by_pri.get(c.priority.value, 0) + 1
        by_cat[c.category.value] = by_cat.get(c.category.value, 0) + 1

    completed = len([c for c in board.cards if c.column == BoardColumn.COMPLETED])
    total = len(board.cards) or 1

    return {
        "total_cards": len(board.cards),
        "cards_by_column": by_col,
        "cards_by_status": by_stat,
        "cards_by_priority": by_pri,
        "cards_by_category": by_cat,
        "completion_rate": (completed / total) * 100,
        "overdue_cards": 0,
    }


@router.post("/board/{target_id}/column-config")
async def update_column_config(target_id: str, req: ColumnConfigRequest) -> dict:
    board = _get_board(target_id)
    for cfg in board.column_configs:
        if cfg.column.value == req.column:
            cfg.wip_limit = req.wip_limit
            cfg.collapsed = req.collapsed
            cfg.color = req.color
            return cfg.model_dump()
    from deephunter.investigation.taskboard.models import ColumnConfig
    new_cfg = ColumnConfig(
        column=BoardColumn(req.column),
        wip_limit=req.wip_limit,
        collapsed=req.collapsed,
        color=req.color,
    )
    board.column_configs.append(new_cfg)
    return new_cfg.model_dump()


@router.get("/board/{target_id}/export")
async def export_board(target_id: str) -> dict:
    board = _get_board(target_id)
    md_lines = ["# Task Board\n"]
    for col in BoardColumn:
        cards = [c for c in board.cards if c.column == col]
        if cards:
            md_lines.append(f"## {col.value.replace('_', ' ').title()}\n")
            for c in cards:
                md_lines.append(f"- [{c.priority.value.upper()}] {c.title}")
                if c.assigned_to:
                    md_lines.append(f"  - Assigned: {c.assigned_to}")
    return {"format": "markdown", "content": "\n".join(md_lines)}