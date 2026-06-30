from __future__ import annotations

import re
from typing import Any


class MetadataFilter:
    """Filter search results by metadata fields with comparison operators."""

    SUPPORTED_OPS = {"eq", "neq", "gt", "gte", "lt", "lte", "in", "nin", "exists", "regex"}

    def filter(
        self,
        results: list[tuple[Any, float]],
        filters: dict[str, Any] | list[dict[str, Any]],
    ) -> list[tuple[Any, float]]:
        if not filters:
            return results
        if isinstance(filters, dict):
            filters = [{"field": k, "op": "eq", "value": v} for k, v in filters.items()]

        filtered: list[tuple[Any, float]] = []
        for item, score in results:
            metadata = self._extract_metadata(item)
            if self._matches_all(metadata, filters):
                filtered.append((item, score))
        return filtered

    @staticmethod
    def _extract_metadata(item: Any) -> dict[str, Any]:
        if isinstance(item, dict):
            return item
        if hasattr(item, "metadata"):
            m = item.metadata
            if isinstance(m, dict):
                return m
            if isinstance(m, list):
                return {kv.key: kv.value for kv in m if hasattr(kv, "key")}
        return {}

    def _matches_all(self, metadata: dict[str, Any], filters: list[dict[str, Any]]) -> bool:
        for f in filters:
            field = f.get("field", "")
            op = f.get("op", "eq")
            value = f.get("value")
            actual = self._get_nested(metadata, field)

            if op == "exists":
                if value and actual is None:
                    return False
                if not value and actual is not None:
                    return False
                continue

            if op == "eq":
                if actual != value:
                    return False
            elif op == "neq":
                if actual == value:
                    return False
            elif op == "gt":
                if not (actual is not None and actual > value):
                    return False
            elif op == "gte":
                if not (actual is not None and actual >= value):
                    return False
            elif op == "lt":
                if not (actual is not None and actual < value):
                    return False
            elif op == "lte":
                if not (actual is not None and actual <= value):
                    return False
            elif op == "in":
                if actual not in (value or []):
                    return False
            elif op == "nin":
                if actual in (value or []):
                    return False
            elif op == "regex":
                if not (actual and re.search(str(value), str(actual))):
                    return False
            else:
                raise ValueError(f"Unsupported filter operator: {op}")
        return True

    @staticmethod
    def _get_nested(metadata: dict[str, Any], field: str) -> Any:
        parts = field.split(".")
        current: Any = metadata
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current
