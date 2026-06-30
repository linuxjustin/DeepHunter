"""Storage interface and SQLite implementation for the Recon Intelligence Platform.

Follows the same pattern as ``KnowledgeStore`` in the knowledge module.
"""

from __future__ import annotations

import json
import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from deephunter.recon.models import (
    APIEndpoint,
    Asset,
    AuthMechanism,
    AuthObservation,
    CloudResource,
    DNSRecord,
    Endpoint,
    HTTPObservation,
    Host,
    JavaScriptEndpoint,
    JavaScriptFile,
    Parameter,
    Program,
    ReconState,
    Scope,
    Technology,
)


class ReconStore(ABC):
    """Abstract interface for recon data persistence."""

    @abstractmethod
    def save_state(self, state: ReconState) -> None: ...

    @abstractmethod
    def load_state(self, state_id: str) -> ReconState | None: ...

    @abstractmethod
    def list_states(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def delete_state(self, state_id: str) -> bool: ...

    @abstractmethod
    def clear(self) -> None: ...


class SQLiteReconStore(ReconStore):
    """SQLite-backed recon store."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._path = Path(db_path) if db_path else Path.home() / ".deephunter" / "recon.db"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._path))
            self._conn.row_factory = sqlite3.Row
            self._init_db()
        return self._conn

    def _init_db(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS recon_states (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL DEFAULT '',
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        self._conn.commit()

    def save_state(self, state: ReconState) -> None:
        conn = self._connect()
        data = state.model_dump_json()
        conn.execute(
            "INSERT OR REPLACE INTO recon_states (id, target, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (state.id, state.target, data, state.created_at.isoformat(), state.updated_at.isoformat()),
        )
        conn.commit()

    def load_state(self, state_id: str) -> ReconState | None:
        conn = self._connect()
        row = conn.execute("SELECT data FROM recon_states WHERE id = ?", (state_id,)).fetchone()
        if row is None:
            return None
        return ReconState.model_validate_json(row["data"])

    def list_states(self) -> list[dict[str, Any]]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT id, target, created_at, updated_at FROM recon_states ORDER BY updated_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_state(self, state_id: str) -> bool:
        conn = self._connect()
        cursor = conn.execute("DELETE FROM recon_states WHERE id = ?", (state_id,))
        conn.commit()
        return cursor.rowcount > 0

    def clear(self) -> None:
        conn = self._connect()
        conn.execute("DELETE FROM recon_states")
        conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
