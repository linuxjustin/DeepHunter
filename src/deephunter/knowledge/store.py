"""Knowledge store — SQLite-backed with full-text search.

Replaces the previous in-memory dict + JSON file approach with
a proper SQLite database. Supports efficient tag-based lookup,
full-text search, and incremental saves.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from pathlib import Path

from deephunter.core.exceptions import StorageError
from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS skos (
    id TEXT PRIMARY KEY,
    schema_version INTEGER DEFAULT 1,
    title TEXT NOT NULL,
    summary TEXT DEFAULT '',
    description TEXT DEFAULT '',
    source TEXT NOT NULL,
    source_type TEXT DEFAULT 'other',
    document_type TEXT DEFAULT 'unknown',
    author TEXT,
    created TEXT NOT NULL,
    updated TEXT NOT NULL,
    tags TEXT DEFAULT '[]',
    technology TEXT DEFAULT '[]',
    framework TEXT DEFAULT '[]',
    language TEXT DEFAULT '[]',
    operating_system TEXT DEFAULT '[]',
    cloud_provider TEXT DEFAULT '[]',
    bug_classes TEXT DEFAULT '[]',
    authentication TEXT DEFAULT '[]',
    authorization TEXT DEFAULT '[]',
    trust_boundaries TEXT DEFAULT '[]',
    business_logic TEXT DEFAULT '[]',
    attack_surface TEXT DEFAULT '[]',
    interesting_headers TEXT DEFAULT '[]',
    interesting_parameters TEXT DEFAULT '[]',
    interesting_endpoints TEXT DEFAULT '[]',
    high_level_testing_ideas TEXT DEFAULT '[]',
    manual_test_checklist TEXT DEFAULT '[]',
    payload_references TEXT DEFAULT '[]',
    related_frameworks TEXT DEFAULT '[]',
    related_writeups TEXT DEFAULT '[]',
    related_cves TEXT DEFAULT '[]',
    related_cwes TEXT DEFAULT '[]',
    refs TEXT DEFAULT '[]',
    confidence TEXT DEFAULT 'unknown',
    raw_content TEXT,
    normalized_content TEXT,
    metadata TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS tag_index (
    tag TEXT NOT NULL,
    sko_id TEXT NOT NULL REFERENCES skos(id) ON DELETE CASCADE,
    PRIMARY KEY (tag, sko_id)
);

CREATE INDEX IF NOT EXISTS idx_tag_index_tag ON tag_index(tag);
CREATE INDEX IF NOT EXISTS idx_skos_source_type ON skos(source_type);
CREATE INDEX IF NOT EXISTS idx_skos_bug_classes ON skos(bug_classes);
CREATE VIRTUAL TABLE IF NOT EXISTS skos_fts USING fts5(
    title, summary, raw_content, content='skos', content_rowid='rowid'
);
"""

_NEW_COLUMNS: list[str] = [
    "schema_version",
    "description",
    "operating_system",
    "authorization",
    "business_logic",
    "attack_surface",
    "interesting_endpoints",
    "manual_test_checklist",
    "payload_references",
    "related_cwes",
    "normalized_content",
]

# Mapping from Pydantic field name to SQL column name.
_FIELD_TO_COLUMN: dict[str, str] = {
    "references": "refs",
    "programming_language": "language",
    "created_at": "created",
    "updated_at": "updated",
}

# Columns whose value is a JSON string in SQLite; populated from FIELD_TO_COLUMN
# values + field names that are already native SQL columns.
_JSON_COLUMNS: set[str] = {
    "tags",
    "technology",
    "framework",
    "language",
    "operating_system",
    "cloud_provider",
    "bug_classes",
    "authentication",
    "authorization",
    "trust_boundaries",
    "business_logic",
    "attack_surface",
    "interesting_headers",
    "interesting_parameters",
    "interesting_endpoints",
    "high_level_testing_ideas",
    "manual_test_checklist",
    "payload_references",
    "related_frameworks",
    "related_writeups",
    "related_cves",
    "related_cwes",
    "refs",
    "metadata",
}

_INSERT_COLUMNS: list[str] = [
    "id", "schema_version", "title", "summary", "description", "source",
    "source_type", "document_type", "author", "created", "updated",
    "tags", "technology", "framework", "language", "operating_system",
    "cloud_provider", "bug_classes", "authentication", "authorization",
    "trust_boundaries", "business_logic", "attack_surface",
    "interesting_headers", "interesting_parameters", "interesting_endpoints",
    "high_level_testing_ideas", "manual_test_checklist", "payload_references",
    "related_frameworks", "related_writeups",
    "related_cves", "related_cwes", "refs", "confidence",
    "raw_content", "normalized_content", "metadata",
]

_UPDATE_COLUMNS: list[str] = [
    "schema_version", "title", "summary", "description", "source",
    "source_type", "document_type", "author", "created", "updated",
    "tags", "technology", "framework", "language", "operating_system",
    "cloud_provider", "bug_classes", "authentication", "authorization",
    "trust_boundaries", "business_logic", "attack_surface",
    "interesting_headers", "interesting_parameters", "interesting_endpoints",
    "high_level_testing_ideas", "manual_test_checklist", "payload_references",
    "related_frameworks", "related_writeups",
    "related_cves", "related_cwes", "refs", "confidence",
    "raw_content", "normalized_content", "metadata",
]


class KnowledgeStore:
    """SQLite-backed store for SecurityKnowledgeObjects.

    Provides CRUD operations, tag-based lookup, full-text search,
    and efficient persistence without loading everything into memory.

    Thread-safe for reads; writes should be serialized.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = Path(db_path) if db_path else Path("~/.deephunter/store.db")
        self._db_path = self._db_path.expanduser().resolve()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()
        self._migrate()

    def _init_schema(self) -> None:
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.commit()

    def _migrate(self) -> None:
        """Add columns that may not exist in older databases."""
        for col in _NEW_COLUMNS:
            try:
                self._conn.execute(f"ALTER TABLE skos ADD COLUMN {col} TEXT")
            except sqlite3.OperationalError:
                pass
        self._conn.commit()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add(self, sko: SecurityKnowledgeObject) -> str:
        existing = self._conn.execute(
            "SELECT id FROM skos WHERE id = ?", (sko.id,)
        ).fetchone()
        if existing:
            raise StorageError(f"SKO with id '{sko.id}' already exists")

        self._insert_sko(sko)
        self._conn.commit()
        logger.debug("Added SKO %s: %s", sko.id, sko.title)
        return sko.id

    def add_batch(self, skos: Sequence[SecurityKnowledgeObject]) -> list[str]:
        ids: list[str] = []
        for sko in skos:
            existing = self._conn.execute(
                "SELECT id FROM skos WHERE id = ?", (sko.id,)
            ).fetchone()
            if existing:
                raise StorageError(f"SKO with id '{sko.id}' already exists (batch)")
            ids.append(sko.id)

        for sko in skos:
            self._insert_sko(sko)
        self._conn.commit()
        logger.debug("Added %d SKOs in batch", len(skos))
        return ids

    def get(self, sko_id: str) -> SecurityKnowledgeObject | None:
        row = self._conn.execute(
            "SELECT * FROM skos WHERE id = ?", (sko_id,)
        ).fetchone()
        return self._row_to_sko(row) if row else None

    def update(self, sko: SecurityKnowledgeObject) -> None:
        existing = self._conn.execute(
            "SELECT id FROM skos WHERE id = ?", (sko.id,)
        ).fetchone()
        if not existing:
            raise StorageError(f"Cannot update: SKO '{sko.id}' not found")

        self._conn.execute("DELETE FROM tag_index WHERE sko_id = ?", (sko.id,))
        self._update_sko(sko)
        self._conn.commit()
        logger.debug("Updated SKO %s", sko.id)

    def delete(self, sko_id: str) -> bool:
        cursor = self._conn.execute("DELETE FROM skos WHERE id = ?", (sko_id,))
        self._conn.commit()
        removed = cursor.rowcount > 0
        if removed:
            logger.debug("Deleted SKO %s", sko_id)
        return removed

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) as cnt FROM skos").fetchone()
        return row["cnt"] if row else 0

    def list_all(self) -> list[SecurityKnowledgeObject]:
        rows = self._conn.execute("SELECT * FROM skos ORDER BY created").fetchall()
        return [self._row_to_sko(r) for r in rows]

    def clear(self) -> None:
        self._conn.execute("DELETE FROM tag_index")
        self._conn.execute("DELETE FROM skos")
        self._conn.commit()
        logger.debug("Cleared store")

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def search_by_title(self, query: str, case_sensitive: bool = False) -> list[SecurityKnowledgeObject]:
        if case_sensitive:
            rows = self._conn.execute(
                "SELECT * FROM skos WHERE title GLOB ?",
                (f"*{query}*",),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM skos WHERE LOWER(title) LIKE LOWER(?)",
                (f"%{query}%",),
            ).fetchall()
        return [self._row_to_sko(r) for r in rows]

    def search_by_tag(self, tag: str) -> list[SecurityKnowledgeObject]:
        tag_lower = tag.lower()
        rows = self._conn.execute(
            """SELECT skos.* FROM skos
               JOIN tag_index ON skos.id = tag_index.sko_id
               WHERE tag_index.tag = ?""",
            (tag_lower,),
        ).fetchall()
        return [self._row_to_sko(r) for r in rows]

    def search_by_bug_class(self, bug_class: str) -> list[SecurityKnowledgeObject]:
        q = bug_class.lower()
        rows = self._conn.execute(
            "SELECT * FROM skos WHERE LOWER(bug_classes) LIKE ?",
            (f"%{q}%",),
        ).fetchall()
        return [self._row_to_sko(r) for r in rows]

    def search_raw_content(self, query: str) -> list[SecurityKnowledgeObject]:
        rows = self._conn.execute(
            "SELECT * FROM skos WHERE LOWER(raw_content) LIKE LOWER(?)",
            (f"%{query}%",),
        ).fetchall()
        return [self._row_to_sko(r) for r in rows]

    def search_source_type(self, source_type: str) -> list[SecurityKnowledgeObject]:
        q = source_type.lower().replace("-", "_")
        rows = self._conn.execute(
            "SELECT * FROM skos WHERE source_type = ?", (q,)
        ).fetchall()
        return [self._row_to_sko(r) for r in rows]

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def save(self, path: str | Path | None = None) -> None:
        logger.debug("SQLite store auto-persists; save() is a no-op")

    def load(self, path: str | Path | None = None) -> int:
        return self.count()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _map_data(data: dict) -> dict:
        """Map Pydantic field names to SQL column names."""
        return {_FIELD_TO_COLUMN.get(k, k): v for k, v in data.items()}

    def _insert_sko(self, sko: SecurityKnowledgeObject) -> None:
        data = self._map_data(self._flatten_for_sql(sko.model_dump(mode="json")))
        placeholders = ", ".join(f":{c}" for c in _INSERT_COLUMNS)
        columns = ", ".join(_INSERT_COLUMNS)
        self._conn.execute(
            f"INSERT INTO skos ({columns}) VALUES ({placeholders})",
            data,
        )
        for tag in sko.tags:
            self._conn.execute(
                "INSERT OR IGNORE INTO tag_index (tag, sko_id) VALUES (?, ?)",
                (tag.lower(), sko.id),
            )

    def _update_sko(self, sko: SecurityKnowledgeObject) -> None:
        data = self._map_data(self._flatten_for_sql(sko.model_dump(mode="json")))
        set_clause = ", ".join(f"{c}=:{c}" for c in _UPDATE_COLUMNS)
        self._conn.execute(
            f"UPDATE skos SET {set_clause} WHERE id=:id",
            data,
        )
        for tag in sko.tags:
            self._conn.execute(
                "INSERT OR IGNORE INTO tag_index (tag, sko_id) VALUES (?, ?)",
                (tag.lower(), sko.id),
            )

    @staticmethod
    def _flatten_for_sql(data: dict) -> dict:
        """Convert list/dict fields to JSON strings for SQLite storage."""
        flat = {}
        for key, value in data.items():
            if isinstance(value, (list, dict)):
                flat[key] = json.dumps(value, default=str)
            else:
                flat[key] = value
        return flat

    def _row_to_sko(self, row: sqlite3.Row) -> SecurityKnowledgeObject:
        """Convert a SQLite row back to a SecurityKnowledgeObject."""
        data = dict(row)
        # Deserialize JSON columns BEFORE mapping column → field names,
        # because the column values are stored under their SQL column names
        # (which may differ from the Pydantic field names).
        for col in _JSON_COLUMNS:
            if col in data and isinstance(data[col], str):
                try:
                    data[col] = json.loads(data[col])
                except (json.JSONDecodeError, TypeError):
                    pass
        # Map SQL column names back to Pydantic field names.
        col_to_field = {v: k for k, v in _FIELD_TO_COLUMN.items()}
        mapped: dict = {}
        for k, v in data.items():
            mapped[col_to_field.get(k, k)] = v
        return SecurityKnowledgeObject(**mapped)
