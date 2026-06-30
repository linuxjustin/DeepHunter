"""Output normalizer for the Tool Integration SDK.

Parses raw tool output in various formats (JSON, YAML, CSV, TXT, NDJSON)
and normalizes into PluginResult (domain recon models).
"""

from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
from typing import Any, Callable

import yaml

from deephunter.recon.plugin import PluginResult
from deephunter.tools.context import ExecutionContext
from deephunter.tools.exceptions import PluginParseError


ParseHandler = Callable[[str, dict[str, Any]], Any]
NormalizeHandler = Callable[[Any, dict[str, Any]], PluginResult]


class ImportPipeline:
    """Chain of format-specific parsers.  Converts raw output → intermediate
    structured data → PluginResult.
    """

    def __init__(
        self,
        parsers: dict[str, ParseHandler] | None = None,
        normalizer: NormalizeHandler | None = None,
    ) -> None:
        self._parsers: dict[str, ParseHandler] = parsers or {}
        self._normalizer: NormalizeHandler | None = normalizer

    def register_parser(self, fmt: str, handler: ParseHandler) -> None:
        self._parsers[fmt] = handler

    def register_normalizer(self, handler: NormalizeHandler) -> None:
        self._normalizer = handler

    def parse(self, raw: str | bytes | None, fmt: str = "auto", **kwargs: Any) -> Any:
        if raw is None:
            return {}
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")

        if fmt == "auto":
            fmt = self._detect_format(raw)
        handler = self._parsers.get(fmt)
        if handler is None:
            raise PluginParseError(f"No parser registered for format '{fmt}'")
        return handler(raw, kwargs)

    def normalize(self, parsed: Any, context: ExecutionContext | None = None) -> PluginResult:
        ctx: dict[str, Any] = {"context": context} if context else {}
        if self._normalizer:
            return self._normalizer(parsed, ctx)
        result = PluginResult()
        return result

    def run(self, raw: str | bytes | None, fmt: str = "auto", context: ExecutionContext | None = None) -> PluginResult:
        parsed = self.parse(raw, fmt=fmt)
        return self.normalize(parsed, context)

    @staticmethod
    def _detect_format(raw: str) -> str:
        s = raw.strip()
        if not s:
            return "txt"
        if s.startswith(("{", "[")):
            return "json"
        if s.startswith("---") or ":" in s[:200]:
            return "yaml"
        if "," in s[:200] and "\n" in s[:5000]:
            return "csv"
        if "\n" in s[:100]:
            return "ndjson"
        return "txt"


def parse_json(raw: str, kwargs: dict[str, Any]) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PluginParseError(f"Invalid JSON: {exc}") from exc


def parse_yaml(raw: str, kwargs: dict[str, Any]) -> Any:
    try:
        docs = list(yaml.safe_load_all(raw))
        if not docs:
            return None
        if len(docs) == 1:
            return docs[0]
        return docs
    except yaml.YAMLError as exc:
        raise PluginParseError(f"Invalid YAML: {exc}") from exc


def parse_csv(raw: str, kwargs: dict[str, Any]) -> list[dict[str, str]]:
    if not raw.strip():
        return []
    try:
        reader = csv.DictReader(io.StringIO(raw))
        return list(reader)
    except Exception as exc:
        raise PluginParseError(f"Invalid CSV: {exc}") from exc


def parse_txt(raw: str, kwargs: dict[str, Any]) -> list[str]:
    return [line.strip() for line in raw.strip().splitlines() if line.strip()]


def parse_ndjson(raw: str, kwargs: dict[str, Any]) -> list[Any]:
    results: list[Any] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            results.append({"raw": line})
    return results


def parse_path(path: str | Path, fmt: str = "auto", **kwargs: Any) -> Any:
    p = Path(path)
    raw = p.read_text(encoding="utf-8", errors="replace")
    pipeline = ImportPipeline(
        parsers={
            "json": parse_json,
            "yaml": parse_yaml,
            "csv": parse_csv,
            "txt": parse_txt,
            "ndjson": parse_ndjson,
        },
    )
    if fmt == "auto":
        ext = p.suffix.lower()
        ext_map = {".json": "json", ".yaml": "yaml", ".yml": "yaml", ".csv": "csv", ".txt": "txt", ".ndjson": "ndjson"}
        if ext in ext_map:
            fmt = ext_map[ext]
    return pipeline.parse(raw, fmt=fmt)


def build_default_pipeline() -> ImportPipeline:
    pipeline = ImportPipeline(
        parsers={
            "json": parse_json,
            "yaml": parse_yaml,
            "csv": parse_csv,
            "txt": parse_txt,
            "ndjson": parse_ndjson,
        },
    )
    return pipeline
