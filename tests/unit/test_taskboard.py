"""Tests for Task Board models and manager."""

from __future__ import annotations

from deephunter.investigation.taskboard import (
    TaskBoardManager,
    BoardCard,
    BoardColumn,
    BoardState,
    BoardSummary,
    ColumnConfig,
    TaskPriority,
    TaskCategory,
    TaskStatus,
)


class TestTaskBoardManager:
    def test_new_board(self) -> None:
        manager = TaskBoardManager.new("tgt-123", "inv-456")
        assert manager.state.target_id == "tgt-123"
        assert len(manager.state.column_configs) == 6

    def test_create_card(self) -> None:
        manager = TaskBoardManager.new("tgt-1")
        card = manager.create_card(
            title="Test SQL Injection",
            description="Test the login endpoint for SQLi",
            priority=TaskPriority.HIGH,
            category=TaskCategory.INPUT_VALIDATION,
            estimated_minutes=30,
        )
        assert card.title == "Test SQL Injection"
        assert card.column == BoardColumn.BACKLOG
        assert card.priority == TaskPriority.HIGH
        assert card.id.startswith("card-")

    def test_create_card_with_depends(self) -> None:
        manager = TaskBoardManager.new("tgt-1")
        card1 = manager.create_card(title="Step 1")
        card2 = manager.create_card(title="Step 2", depends_on=[card1.id])
        assert card1.id in card2.depends_on

    def test_move_card(self) -> None:
        manager = TaskBoardManager.new("tgt-1")
        card = manager.create_card(title="Test Card")
        result = manager.move_card(card.id, BoardColumn.IN_PROGRESS)
        assert result is True
        updated = manager.get_card(card.id)
        assert updated is not None
        assert updated.column == BoardColumn.IN_PROGRESS

    def test_assign_card(self) -> None:
        manager = TaskBoardManager.new("tgt-1")
        card = manager.create_card(title="Test Card")
        result = manager.assign_card(card.id, "user-1")
        assert result is True
        assert manager.get_card(card.id) is not None
        assert manager.get_card(card.id).assigned_to == "user-1"

    def test_complete_card(self) -> None:
        manager = TaskBoardManager.new("tgt-1")
        card = manager.create_card(title="Test Card")
        result = manager.complete_card(card.id, findings="Found SQLi vulnerability")
        assert result is True
        c = manager.get_card(card.id)
        assert c is not None
        status_val = c.status.value if hasattr(c.status, 'value') else str(c.status)
        assert status_val == "completed"
        assert "SQLi" in c.findings

    def test_archive_card(self) -> None:
        manager = TaskBoardManager.new("tgt-1")
        card = manager.create_card(title="Old Card")
        manager.archive_card(card.id)
        c = manager.get_card(card.id)
        assert c is not None
        assert c.column == BoardColumn.ARCHIVED

    def test_delete_card(self) -> None:
        manager = TaskBoardManager.new("tgt-1")
        card = manager.create_card(title="To Delete")
        result = manager.delete_card(card.id)
        assert result is True
        assert manager.get_card(card.id) is None

    def test_get_cards_by_column(self) -> None:
        manager = TaskBoardManager.new("tgt-1")
        c1 = manager.create_card(title="Backlog 1", column=BoardColumn.BACKLOG)
        c2 = manager.create_card(title="Backlog 2", column=BoardColumn.BACKLOG)
        manager.create_card(title="In Progress", column=BoardColumn.IN_PROGRESS)
        backlog = manager.get_cards_by_column(BoardColumn.BACKLOG)
        assert len(backlog) == 2
        in_prog = manager.get_cards_by_column(BoardColumn.IN_PROGRESS)
        assert len(in_prog) == 1

    def test_get_cards_by_priority(self) -> None:
        manager = TaskBoardManager.new("tgt-1")
        manager.create_card(title="High Priority", priority=TaskPriority.HIGH)
        manager.create_card(title="Low Priority", priority=TaskPriority.LOW)
        manager.create_card(title="High Again", priority=TaskPriority.HIGH)
        high = manager.get_cards_by_priority(TaskPriority.HIGH)
        assert len(high) == 2

    def test_search_cards(self) -> None:
        manager = TaskBoardManager.new("tgt-1")
        manager.create_card(title="SQL Injection Test", description="Test login endpoint")
        manager.create_card(title="XSS Test", description="Test search param")
        results = manager.search_cards("SQL")
        assert len(results) == 1
        assert "SQL" in results[0].title

    def test_update_column_wip(self) -> None:
        manager = TaskBoardManager.new("tgt-1")
        manager.update_column_wip(BoardColumn.IN_PROGRESS, 3)
        assert manager.get_column_wip(BoardColumn.IN_PROGRESS) == 3

    def test_get_summary(self) -> None:
        manager = TaskBoardManager.new("tgt-1")
        manager.create_card(title="c1", column=BoardColumn.BACKLOG)
        manager.create_card(title="c2", column=BoardColumn.BACKLOG)
        manager.create_card(title="c3", column=BoardColumn.IN_PROGRESS)
        manager.complete_card(manager.create_card(title="c4", column=BoardColumn.IN_PROGRESS).id)
        summary = manager.get_summary()
        assert summary.total_cards == 4
        assert summary.cards_by_column.get("backlog", 0) == 2
        assert summary.cards_by_column.get("in_progress", 0) == 1
        assert summary.completion_rate == 25.0


class TestTaskBoardModels:
    def test_board_card_defaults(self) -> None:
        card = BoardCard(target_id="tgt-1", title="Test")
        assert card.column == BoardColumn.BACKLOG
        assert card.status == TaskStatus.PENDING
        assert card.priority == TaskPriority.MEDIUM
        assert card.id.startswith("card-")

    def test_board_card_with_tags(self) -> None:
        card = BoardCard(
            target_id="tgt-1",
            title="Test",
            tags=["sql_injection", "auth"],
            linked_hypothesis_ids=["hyp-1"],
            linked_evidence_ids=["ev-1"],
        )
        assert "sql_injection" in card.tags
        assert "hyp-1" in card.linked_hypothesis_ids

    def test_column_config(self) -> None:
        cfg = ColumnConfig(column=BoardColumn.IN_PROGRESS, wip_limit=3, color="#f59e0b")
        assert cfg.wip_limit == 3
        assert cfg.color == "#f59e0b"

    def test_board_state(self) -> None:
        state = BoardState(target_id="tgt-1")
        assert state.target_id == "tgt-1"
        assert len(state.cards) == 0