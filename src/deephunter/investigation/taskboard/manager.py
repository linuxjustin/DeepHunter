"""Task Board Manager - Kanban board lifecycle management."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from deephunter.investigation.taskboard.models import (
    BoardCard,
    BoardColumn,
    BoardState,
    BoardSummary,
    ColumnConfig,
    TaskPriority,
)
from deephunter.utils import get_logger

logger = get_logger(__name__)


class TaskBoardManager:
    """Manages the Kanban task board."""

    def __init__(self, state: BoardState) -> None:
        self._state = state
        self._init_default_columns()

    def _init_default_columns(self) -> None:
        existing_cols = {c.column for c in self._state.column_configs}
        defaults = [
            ColumnConfig(column=BoardColumn.BACKLOG, color="#64748b"),
            ColumnConfig(column=BoardColumn.PLANNED, color="#3b82f6"),
            ColumnConfig(column=BoardColumn.IN_PROGRESS, color="#f59e0b"),
            ColumnConfig(column=BoardColumn.NEEDS_VERIFICATION, color="#8b5cf6"),
            ColumnConfig(column=BoardColumn.COMPLETED, color="#10b981"),
            ColumnConfig(column=BoardColumn.ARCHIVED, color="#6b7280"),
        ]
        for dc in defaults:
            if dc.column not in existing_cols:
                self._state.column_configs.append(dc)

    @classmethod
    def new(cls, target_id: str, investigation_session_id: str = "") -> TaskBoardManager:
        state = BoardState(
            target_id=target_id,
            investigation_session_id=investigation_session_id,
        )
        return cls(state)

    @property
    def state(self) -> BoardState:
        return self._state

    def create_card(
        self,
        title: str,
        description: str = "",
        column: BoardColumn = BoardColumn.BACKLOG,
        priority: TaskPriority = TaskPriority.MEDIUM,
        category: str = "",
        assigned_to: str = "",
        estimated_minutes: int = 0,
        tags: list[str] | None = None,
        depends_on: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> BoardCard:
        card = BoardCard(
            target_id=self._state.target_id,
            investigation_session_id=self._state.investigation_session_id,
            title=title,
            description=description,
            column=column,
            priority=priority,
            category=category or "other",
            assigned_to=assigned_to,
            estimated_minutes=estimated_minutes,
            tags=tags or [],
            depends_on=depends_on or [],
            metadata=metadata or {},
        )
        self._state.cards.append(card)
        self._state.updated_at = datetime.now(UTC)
        return card

    def get_card(self, card_id: str) -> BoardCard | None:
        for card in self._state.cards:
            if card.id == card_id:
                return card
        return None

    def update_card(self, card_id: str, **updates: Any) -> BoardCard | None:
        for card in self._state.cards:
            if card.id == card_id:
                for key, value in updates.items():
                    if hasattr(card, key):
                        setattr(card, key, value)
                card.updated_at = datetime.now(UTC)
                self._state.updated_at = datetime.now(UTC)
                return card
        return None

    def move_card(self, card_id: str, target_column: BoardColumn, order: int = 0) -> bool:
        card = self.update_card(card_id, column=target_column, order_in_column=order)
        return card is not None

    def assign_card(self, card_id: str, user_id: str) -> bool:
        card = self.update_card(card_id, assigned_to=user_id)
        return card is not None

    def set_priority(self, card_id: str, priority: TaskPriority) -> bool:
        card = self.update_card(card_id, priority=priority)
        return card is not None

    def complete_card(self, card_id: str, findings: str = "") -> bool:
        card = self.update_card(card_id, status="completed", column=BoardColumn.COMPLETED, completed_at=datetime.now(UTC), findings=findings)
        return card is not None

    def archive_card(self, card_id: str) -> bool:
        card = self.update_card(card_id, column=BoardColumn.ARCHIVED, archived_at=datetime.now(UTC))
        return card is not None

    def delete_card(self, card_id: str) -> bool:
        for i, card in enumerate(self._state.cards):
            if card.id == card_id:
                self._state.cards.pop(i)
                self._state.updated_at = datetime.now(UTC)
                return True
        return False

    def get_cards_by_column(self, column: BoardColumn) -> list[BoardCard]:
        col_str = column.value
        return sorted(
            [c for c in self._state.cards if self._str(c.column) == col_str],
            key=lambda x: x.order_in_column,
        )

    def get_cards_by_status(self, status: str) -> list[BoardCard]:
        return [c for c in self._state.cards if self._str(c.status) == status]

    def get_cards_by_priority(self, priority: TaskPriority) -> list[BoardCard]:
        pri_str = priority.value
        return [c for c in self._state.cards if self._str(c.priority) == pri_str]

    def get_cards_by_category(self, category: str) -> list[BoardCard]:
        return [c for c in self._state.cards if self._str(c.category) == category]

    def get_active_cards(self) -> list[BoardCard]:
        return [c for c in self._state.cards if self._str(c.column) != "archived"]

    def get_overdue_cards(self) -> list[BoardCard]:
        return [
            c for c in self._state.cards
            if c.estimated_minutes > 0 and self._str(c.status) not in ("completed", "skipped")
            and self._str(c.column) == "in_progress"
        ]

    def get_blocked_cards(self) -> list[BoardCard]:
        return [c for c in self._state.cards if self._str(c.status) == "blocked"]

    def get_assigned_cards(self, user_id: str) -> list[BoardCard]:
        return [c for c in self._state.cards if c.assigned_to == user_id]

    def search_cards(self, query: str) -> list[BoardCard]:
        q = query.lower()
        return [
            c for c in self._state.cards
            if q in c.title.lower() or q in c.description.lower()
        ]

    def update_column_wip(self, column: BoardColumn, limit: int) -> bool:
        for cfg in self._state.column_configs:
            if cfg.column == column:
                cfg.wip_limit = limit
                return True
        return False

    def get_column_wip(self, column: BoardColumn) -> int:
        for cfg in self._state.column_configs:
            if cfg.column == column:
                return cfg.wip_limit
        return 0

    def _str(self, v: Any) -> str:
        return str(v.value) if hasattr(v, "value") else str(v)

    def get_summary(self) -> BoardSummary:
        by_col: dict[str, int] = {}
        by_stat: dict[str, int] = {}
        by_pri: dict[str, int] = {}
        by_cat: dict[str, int] = {}

        for card in self._state.cards:
            col_val = self._str(card.column)
            stat_val = self._str(card.status)
            pri_val = self._str(card.priority)
            cat_val = self._str(card.category)
            by_col[col_val] = by_col.get(col_val, 0) + 1
            by_stat[stat_val] = by_stat.get(stat_val, 0) + 1
            by_pri[pri_val] = by_pri.get(pri_val, 0) + 1
            by_cat[cat_val] = by_cat.get(cat_val, 0) + 1

        completed = len([c for c in self._state.cards if self._str(c.column) == "completed"])
        total = len(self._state.cards)
        completion_rate = (completed / total * 100) if total > 0 else 0.0
        overdue = len(self.get_overdue_cards())

        return BoardSummary(
            total_cards=total,
            cards_by_column=by_col,
            cards_by_status=by_stat,
            cards_by_priority=by_pri,
            cards_by_category=by_cat,
            completion_rate=completion_rate,
            overdue_cards=overdue,
        )

    def export_to_dict(self) -> dict[str, Any]:
        return self._state.model_dump_for_storage()