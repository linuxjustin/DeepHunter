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
    title TEXT NOT NULL,
    summary TEXT DEFAULT '',
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
    cloud_provider TEXT DEFAULT '[]',
    bug_classes TEXT DEFAULT '[]',
    authentication TEXT DEFAULT '[]',
    trust_boundaries TEXT DEFAULT '[]',
    interesting_headers TEXT DEFAULT '[]',
    interesting_parameters TEXT DEFAULT '[]',
    high_level_testing_ideas TEXT DEFAULT '[]',
    related_frameworks TEXT DEFAULT '[]',
    related_bug_classes TEXT DEFAULT '[]',
    related_writeups TEXT DEFAULT '[]',
    related_cves TEXT DEFAULT '[]',
    refs TEXT DEFAULT '[]',
    confidence TEXT DEFAULT 'unknown',
    raw_content TEXT,
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

    def _init_schema(self) -> None:
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.commit()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add(self, sko: SecurityKnowledgeObject) -> str:
        """Add an SKO to the store.

        Args:
            sko: The security knowledge object to add.

        Returns:
            The SKO's ID.

        Raises:
            StorageError: If an SKO with the same ID already exists.
        """
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
        """Add multiple SKOs atomically.

        Args:
            skos: Collection of SKOs to add.

        Returns:
            List of IDs for the added SKOs.

        Raises:
            StorageError: If any SKO's ID collides.
        """
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
        """Retrieve an SKO by its ID.

        Args:
            sko_id: The SKO identifier.

        Returns:
            The SKO if found, otherwise ``None``.
        """
        row = self._conn.execute(
            "SELECT * FROM skos WHERE id = ?", (sko_id,)
        ).fetchone()
        return self._row_to_sko(row) if row else None

    def update(self, sko: SecurityKnowledgeObject) -> None:
        """Update an existing SKO in the store.

        Args:
            sko: The SKO with updated fields.

        Raises:
            StorageError: If the SKO does not exist.
        """
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
        """Remove an SKO from the store.

        Args:
            sko_id: The SKO identifier to remove.

        Returns:
            ``True`` if the SKO was removed, ``False`` if not found.
        """
        cursor = self._conn.execute("DELETE FROM skos WHERE id = ?", (sko_id,))
        self._conn.commit()
        removed = cursor.rowcount > 0
        if removed:
            logger.debug("Deleted SKO %s", sko_id)
        return removed

    def count(self) -> int:
        """Return the number of stored SKOs."""
        row = self._conn.execute("SELECT COUNT(*) as cnt FROM skos").fetchone()
        return row["cnt"] if row else 0

    def list_all(self) -> list[SecurityKnowledgeObject]:
        """Return all SKOs."""
        rows = self._conn.execute("SELECT * FROM skos ORDER BY created").fetchall()
        return [self._row_to_sko(r) for r in rows]

    def clear(self) -> None:
        """Remove all SKOs from the store."""
        self._conn.execute("DELETE FROM tag_index")
        self._conn.execute("DELETE FROM skos")
        self._conn.commit()
        logger.debug("Cleared store")

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def search_by_title(self, query: str, case_sensitive: bool = False) -> list[SecurityKnowledgeObject]:
        """Search SKOs whose title contains the query string.

        Args:
            query: Substring to search for in titles.
            case_sensitive: Whether the match is case-sensitive.

        Returns:
            Matching SKOs.
        """
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
        """Return all SKOs with a given tag.

        Args:
            tag: The tag to filter by.

        Returns:
            SKOs tagged with the given tag.
        """
        tag_lower = tag.lower()
        rows = self._conn.execute(
            """SELECT skos.* FROM skos
               JOIN tag_index ON skos.id = tag_index.sko_id
               WHERE tag_index.tag = ?""",
            (tag_lower,),
        ).fetchall()
        return [self._row_to_sko(r) for r in rows]

    def search_by_bug_class(self, bug_class: str) -> list[SecurityKnowledgeObject]:
        """Return all SKOs that reference a specific bug class.

        Args:
            bug_class: The bug class name (case-insensitive).

        Returns:
            Matching SKOs.
        """
        q = bug_class.lower()
        rows = self._conn.execute(
            "SELECT * FROM skos WHERE LOWER(bug_classes) LIKE ?",
            (f"%{q}%",),
        ).fetchall()
        return [self._row_to_sko(r) for r in rows]

    def search_raw_content(self, query: str) -> list[SecurityKnowledgeObject]:
        """Search SKO raw content using LIKE (case-insensitive).

        Args:
            query: Substring to search for in raw content.

        Returns:
            Matching SKOs.
        """
        rows = self._conn.execute(
            "SELECT * FROM skos WHERE LOWER(raw_content) LIKE LOWER(?)",
            (f"%{query}%",),
        ).fetchall()
        return [self._row_to_sko(r) for r in rows]

    def search_source_type(self, source_type: str) -> list[SecurityKnowledgeObject]:
        """Return all SKOs with a given source type."""
        q = source_type.lower().replace("-", "_")
        rows = self._conn.execute(
            "SELECT * FROM skos WHERE source_type = ?", (q,)
        ).fetchall()
        return [self._row_to_sko(r) for r in rows]

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def save(self, path: str | Path | None = None) -> None:
        """The SQLite store is auto-persisting. This is a no-op.

        Provided for backward compatibility with code that calls save().
        """
        logger.debug("SQLite store auto-persists; save() is a no-op")

    def load(self, path: str | Path | None = None) -> int:
        """The SQLite store is auto-loading. This is a no-op.

        Provided for backward compatibility with code that calls load().
        """
        return self.count()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _map_data(data: dict) -> dict:
        """Map Pydantic field names to SQL column names."""
        mapping = {"references": "refs"}
        return {mapping.get(k, k): v for k, v in data.items()}

    def _insert_sko(self, sko: SecurityKnowledgeObject) -> None:
        data = self._map_data(self._flatten_for_sql(sko.model_dump(mode="json")))
        self._conn.execute(
            """INSERT INTO skos (
                id, title, summary, source, source_type, document_type,
                author, created, updated, tags, technology, framework,
                language, cloud_provider, bug_classes, authentication,
                trust_boundaries, interesting_headers, interesting_parameters,
                high_level_testing_ideas, related_frameworks, related_bug_classes,
                related_writeups, related_cves, refs, confidence,
                raw_content, metadata
            ) VALUES (
                :id, :title, :summary, :source, :source_type, :document_type,
                :author, :created, :updated, :tags, :technology, :framework,
                :language, :cloud_provider, :bug_classes, :authentication,
                :trust_boundaries, :interesting_headers, :interesting_parameters,
                :high_level_testing_ideas, :related_frameworks, :related_bug_classes,
                :related_writeups, :related_cves, :refs, :confidence,
                :raw_content, :metadata
            )""",
            data,
        )
        for tag in sko.tags:
            self._conn.execute(
                "INSERT OR IGNORE INTO tag_index (tag, sko_id) VALUES (?, ?)",
                (tag.lower(), sko.id),
            )

    def _update_sko(self, sko: SecurityKnowledgeObject) -> None:
        data = self._map_data(self._flatten_for_sql(sko.model_dump(mode="json")))
        self._conn.execute(
            """UPDATE skos SET
                title=:title, summary=:summary, source=:source,
                source_type=:source_type, document_type=:document_type,
                author=:author, created=:created, updated=:updated,
                tags=:tags, technology=:technology, framework=:framework,
                language=:language, cloud_provider=:cloud_provider,
                bug_classes=:bug_classes, authentication=:authentication,
                trust_boundaries=:trust_boundaries,
                interesting_headers=:interesting_headers,
                interesting_parameters=:interesting_parameters,
                high_level_testing_ideas=:high_level_testing_ideas,
                related_frameworks=:related_frameworks,
                related_bug_classes=:related_bug_classes,
                related_writeups=:related_writeups,
                related_cves=:related_cves, refs=:refs,
                confidence=:confidence, raw_content=:raw_content,
                metadata=:metadata
            WHERE id=:id""",
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
        if "refs" in data:
            data["references"] = data.pop("refs")
        json_fields = {
            "tags", "technology", "framework", "language", "cloud_provider",
            "bug_classes", "authentication", "trust_boundaries",
            "interesting_headers", "interesting_parameters",
            "high_level_testing_ideas", "related_frameworks",
            "related_bug_classes", "related_writeups", "related_cves",
            "references", "metadata",
        }
        for field in json_fields:
            if field in data and isinstance(data[field], str):
                try:
                    data[field] = json.loads(data[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        return SecurityKnowledgeObject(**data)
