"""JSON-file-backed knowledge store.

Each SKO is persisted as an individual JSON file named
``<sko_id>.json`` inside a configurable directory.
Supports all standard CRUD operations.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from deephunter.core.exceptions import StorageError
from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class JSONKnowledgeStore:
    """Store SKOs as individual JSON files on disk.

    Each SKO is written to ``<base_path>/<sko_id>.json``.

    Thread-safe for reads; writes should be externally synchronized.
    """

    def __init__(self, base_path: str | Path) -> None:
        self._base = Path(base_path).expanduser().resolve()
        self._base.mkdir(parents=True, exist_ok=True)

    def _path_for(self, sko_id: str) -> Path:
        return self._base / f"{sko_id}.json"

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add(self, sko: SecurityKnowledgeObject) -> str:
        """Add an SKO to the store.

        Args:
            sko: The SKO to persist.

        Returns:
            The SKO's ID.

        Raises:
            StorageError: If an SKO with the same ID already exists.
        """
        path = self._path_for(sko.id)
        if path.exists():
            raise StorageError(f"SKO with id '{sko.id}' already exists at {path}")
        self._write_sko(sko)
        logger.debug("Added SKO %s: %s", sko.id, sko.title)
        return sko.id

    def add_batch(self, skos: Sequence[SecurityKnowledgeObject]) -> list[str]:
        """Add multiple SKOs atomically (best-effort)."""
        ids: list[str] = []
        for sko in skos:
            path = self._path_for(sko.id)
            if path.exists():
                raise StorageError(
                    f"SKO with id '{sko.id}' already exists (batch)"
                )
            ids.append(sko.id)
        for sko in skos:
            self._write_sko(sko)
        logger.debug("Added %d SKOs in batch", len(skos))
        return ids

    def get(self, sko_id: str) -> SecurityKnowledgeObject | None:
        """Retrieve an SKO by ID."""
        path = self._path_for(sko_id)
        if not path.exists():
            return None
        data = json.loads(path.read_text("utf-8"))
        return SecurityKnowledgeObject.from_dict(data)

    def update(self, sko: SecurityKnowledgeObject) -> None:
        """Update an existing SKO.

        Raises:
            StorageError: If the SKO does not exist.
        """
        path = self._path_for(sko.id)
        if not path.exists():
            raise StorageError(f"Cannot update: SKO '{sko.id}' not found")
        self._write_sko(sko)
        logger.debug("Updated SKO %s", sko.id)

    def delete(self, sko_id: str) -> bool:
        """Remove an SKO.

        Returns:
            ``True`` if removed, ``False`` if not found.
        """
        path = self._path_for(sko_id)
        if not path.exists():
            return False
        path.unlink()
        logger.debug("Deleted SKO %s", sko_id)
        return True

    def count(self) -> int:
        """Return the number of stored SKOs."""
        return sum(1 for _ in self._base.glob("sko-*.json"))

    def list_all(self) -> list[SecurityKnowledgeObject]:
        """Return all SKOs sorted by filename."""
        paths = sorted(self._base.glob("sko-*.json"))
        result: list[SecurityKnowledgeObject] = []
        for path in paths:
            try:
                data = json.loads(path.read_text("utf-8"))
                result.append(SecurityKnowledgeObject.from_dict(data))
            except (json.JSONDecodeError, Exception) as exc:
                logger.warning("Failed to load %s: %s", path.name, exc)
        return result

    def clear(self) -> None:
        """Remove all SKO files."""
        for path in self._base.glob("sko-*.json"):
            path.unlink()
        logger.debug("Cleared JSON store at %s", self._base)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def search_by_title(
        self, query: str, case_sensitive: bool = False
    ) -> list[SecurityKnowledgeObject]:
        result: list[SecurityKnowledgeObject] = []
        for sko in self.list_all():
            title = sko.title if case_sensitive else sko.title.lower()
            q = query if case_sensitive else query.lower()
            if q in title:
                result.append(sko)
        return result

    def search_by_tag(self, tag: str) -> list[SecurityKnowledgeObject]:
        tag_lower = tag.lower()
        return [
            sko for sko in self.list_all()
            if tag_lower in {t.lower() for t in sko.tags}
        ]

    def save(self, path: str | Path | None = None) -> None:
        """No-op: JSON store is auto-persisting."""

    def load(self, path: str | Path | None = None) -> int:
        """Re-read all SKOs from disk and return the count."""
        return self.count()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write_sko(self, sko: SecurityKnowledgeObject) -> None:
        data = sko.model_dump_for_storage()
        path = self._path_for(sko.id)
        path.write_text(json.dumps(data, indent=2, default=str), "utf-8")
