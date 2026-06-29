"""Knowledge store — in-memory with optional JSON persistence.

The store is the central registry for all ingested SKOs and supports
tag-based lookup, full-text search, and bulk import/export.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from deephunter.core.exceptions import StorageError
from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class KnowledgeStore:
    """In-memory store for SecurityKnowledgeObjects with JSON persistence.

    The store indexes SKOs by their ID and maintains a tag index
    for efficient tag-based filtering.

    This is not thread-safe; callers must provide their own locking
    if used from multiple threads.
    """

    def __init__(self, persist_path: Optional[str | Path] = None) -> None:
        self._skos: Dict[str, SecurityKnowledgeObject] = {}
        self._persist_path: Optional[Path] = (
            Path(persist_path) if persist_path else None
        )
        self._tag_index: Dict[str, List[str]] = {}

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
        if sko.id in self._skos:
            raise StorageError(f"SKO with id '{sko.id}' already exists")
        self._skos[sko.id] = sko
        self._index_tags(sko)
        logger.debug("Added SKO %s: %s", sko.id, sko.title)
        return sko.id

    def add_batch(self, skos: Sequence[SecurityKnowledgeObject]) -> List[str]:
        """Add multiple SKOs atomically.

        Args:
            skos: Collection of SKOs to add.

        Returns:
            List of IDs for the added SKOs.

        Raises:
            StorageError: If any SKO's ID collides.
        """
        ids: List[str] = []
        for sko in skos:
            if sko.id in self._skos:
                raise StorageError(f"SKO with id '{sko.id}' already exists (batch)")
            ids.append(sko.id)
        for sko in skos:
            self._skos[sko.id] = sko
            self._index_tags(sko)
        logger.debug("Added %d SKOs in batch", len(skos))
        return ids

    def get(self, sko_id: str) -> Optional[SecurityKnowledgeObject]:
        """Retrieve an SKO by its ID.

        Args:
            sko_id: The SKO identifier.

        Returns:
            The SKO if found, otherwise ``None``.
        """
        return self._skos.get(sko_id)

    def update(self, sko: SecurityKnowledgeObject) -> None:
        """Update an existing SKO in the store.

        Args:
            sko: The SKO with updated fields.

        Raises:
            StorageError: If the SKO does not exist.
        """
        if sko.id not in self._skos:
            raise StorageError(f"Cannot update: SKO '{sko.id}' not found")
        self._skos[sko.id] = sko
        self._rebuild_tag_index()
        logger.debug("Updated SKO %s", sko.id)

    def delete(self, sko_id: str) -> bool:
        """Remove an SKO from the store.

        Args:
            sko_id: The SKO identifier to remove.

        Returns:
            ``True`` if the SKO was removed, ``False`` if not found.
        """
        removed = self._skos.pop(sko_id, None)
        if removed is not None:
            self._rebuild_tag_index()
            logger.debug("Deleted SKO %s", sko_id)
            return True
        return False

    def count(self) -> int:
        """Return the number of stored SKOs."""
        return len(self._skos)

    def list_all(self) -> List[SecurityKnowledgeObject]:
        """Return all SKOs in insertion order."""
        return list(self._skos.values())

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def search_by_title(self, query: str, case_sensitive: bool = False) -> List[SecurityKnowledgeObject]:
        """Search SKOs whose title contains the query string.

        Args:
            query: Substring to search for in titles.
            case_sensitive: Whether the match is case-sensitive.

        Returns:
            Matching SKOs.
        """
        if case_sensitive:
            return [s for s in self._skos.values() if query in s.title]
        q = query.lower()
        return [s for s in self._skos.values() if q in s.title.lower()]

    def search_by_tag(self, tag: str) -> List[SecurityKnowledgeObject]:
        """Return all SKOs with a given tag.

        Args:
            tag: The tag to filter by.

        Returns:
            SKOs tagged with the given tag.
        """
        ids = self._tag_index.get(tag.lower(), [])
        return [self._skos[i] for i in ids if i in self._skos]

    def search_by_bug_class(self, bug_class: str) -> List[SecurityKnowledgeObject]:
        """Return all SKOs that reference a specific bug class.

        Args:
            bug_class: The bug class name (case-insensitive enum value).

        Returns:
            Matching SKOs.
        """
        q = bug_class.lower()
        results: List[SecurityKnowledgeObject] = []
        for sko in self._skos.values():
            for bc in sko.bug_classes:
                if bc.value.lower() == q:
                    results.append(sko)
                    break
        return results

    def search_raw_content(self, query: str) -> List[SecurityKnowledgeObject]:
        """Full-text search over SKO raw content.

        Args:
            query: Substring to search for in raw content.

        Returns:
            SKOs whose raw content contains the query.
        """
        q = query.lower()
        results: List[SecurityKnowledgeObject] = []
        for sko in self._skos.values():
            if sko.raw_content and q in sko.raw_content.lower():
                results.append(sko)
        return results

    def search_source_type(self, source_type: str) -> List[SecurityKnowledgeObject]:
        q = source_type.lower().replace("-", "_")
        results: List[SecurityKnowledgeObject] = []
        for sko in self._skos.values():
            if sko.source_type.value.lower() == q:
                results.append(sko)
        return results

    def clear(self) -> None:
        """Remove all SKOs from the store."""
        self._skos.clear()
        self._tag_index.clear()
        logger.debug("Cleared store")

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: Optional[str | Path] = None) -> None:
        """Persist all SKOs to a JSON file.

        Args:
            path: Destination path. Falls back to the path provided at init.

        Raises:
            StorageError: If no path is configured and none is provided.
        """
        target = Path(path) if path else self._persist_path
        if not target:
            raise StorageError("No persist path configured")
        target.parent.mkdir(parents=True, exist_ok=True)
        data = [sko.model_dump_for_storage() for sko in self._skos.values()]
        with open(target, "w") as f:
            json.dump(data, f, indent=2, default=str)
        logger.info("Saved %d SKOs to %s", len(data), target)

    def load(self, path: Optional[str | Path] = None) -> int:
        """Load SKOs from a JSON file, replacing all current data.

        Args:
            path: Source path. Falls back to the path provided at init.

        Returns:
            Number of SKOs loaded.

        Raises:
            StorageError: If the file cannot be read or parsed.
        """
        target = Path(path) if path else self._persist_path
        if not target:
            raise StorageError("No persist path configured")
        if not target.exists():
            raise StorageError(f"Persist file not found: {target}")
        try:
            with open(target, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            raise StorageError(f"Failed to load from {target}: {e}") from e

        self._skos.clear()
        self._tag_index.clear()
        for item in data:
            sko = SecurityKnowledgeObject.from_dict(item)
            self._skos[sko.id] = sko
            self._index_tags(sko)
        logger.info("Loaded %d SKOs from %s", len(self._skos), target)
        return len(self._skos)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _index_tags(self, sko: SecurityKnowledgeObject) -> None:
        for tag in sko.tags:
            key = tag.lower()
            if key not in self._tag_index:
                self._tag_index[key] = []
            if sko.id not in self._tag_index[key]:
                self._tag_index[key].append(sko.id)

    def _rebuild_tag_index(self) -> None:
        self._tag_index.clear()
        for sko in self._skos.values():
            self._index_tags(sko)