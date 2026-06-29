"""Ingestion pipeline — stage-based document ingestion engine.

Every stage is independently testable.  The pipeline orchestrates:

    Discovery → Parser Selection → Parsing → Metadata Extraction
    → Normalization → SKO Construction → Validation → Dedup → Storage
    → Event hooks at every stage

Failures in validation, parsing, or dedup never crash the pipeline;
they are collected into a final ``IngestionReport``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from deephunter.core.config import DeepHunterConfig
from deephunter.core.exceptions import ParsingError
from deephunter.core.types import DocumentType, SourceType
from deephunter.ingestion.dedup import (
    ContentHashDedup,
    DeduplicationEngine,
    NoOpDedup,
)
from deephunter.ingestion.discovery import FileDiscoverer
from deephunter.ingestion.events import (
    DocumentDiscoveredEvent,
    DocumentSkippedEvent,
    DocumentStoredEvent,
    DuplicateSkippedEvent,
    EventBus,
    IngestionCompleteEvent,
    MetadataExtractedEvent,
    ParseCompletedEvent,
    ParseFailedEvent,
    ParseStartedEvent,
    SKOCreatedEvent,
    ValidationFailedEvent,
)
from deephunter.ingestion.extractor import MetadataExtractor
from deephunter.ingestion.normalizer import ContentNormalizer
from deephunter.ingestion.validator import SKOValidator, ValidationReport
from deephunter.knowledge.json_store import JSONKnowledgeStore
from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.knowledge.store import KnowledgeStore
from deephunter.parsers import default_registry as _default_parser_registry
from deephunter.parsers.base import ParseResult, ParserRegistry
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)

# ── Extension map (suffix → DocumentType) ────────────────────────────────────

_EXTENSION_MAP: dict[str, DocumentType] = {
    ".md": DocumentType.MARKDOWN,
    ".markdown": DocumentType.MARKDOWN,
    ".mdown": DocumentType.MARKDOWN,
    ".html": DocumentType.HTML,
    ".htm": DocumentType.HTML,
    ".xhtml": DocumentType.HTML,
    ".json": DocumentType.JSON,
    ".yaml": DocumentType.YAML,
    ".yml": DocumentType.YAML,
    ".pdf": DocumentType.PDF,
    ".txt": DocumentType.TEXT,
}

_SOURCE_TYPE_MAP: dict[str, SourceType] = {
    "hacktricks": SourceType.HACKTRICKS,
    "payloadsallthethings": SourceType.PAYLOADS_ALL_THE_THINGS,
    "owasp": SourceType.OWASP,
    "portswigger": SourceType.PORSTWIGGER,
    "nuclei": SourceType.NUCLEI,
    "cves": SourceType.CVE,
    "writeups": SourceType.WRITEUP,
    "writeup": SourceType.WRITEUP,
    "frameworks": SourceType.FRAMEWORK_DOCS,
    "cloud": SourceType.CLOUD_DOCS,
    "notes": SourceType.INTERNAL_NOTES,
}


# ── Report types ─────────────────────────────────────────────────────────────


@dataclass
class FileResult:
    """Result of processing a single file through the pipeline."""

    path: Path
    status: str  # "parsed", "skipped", "failed", "duplicate"
    sko_id: str | None = None
    error: str | None = None
    duration_ms: float = 0.0


@dataclass
class IngestionReport:
    """Aggregate report for a pipeline run."""

    total: int = 0
    parsed: int = 0
    stored: int = 0
    skipped: int = 0
    duplicates: int = 0
    failed: int = 0
    elapsed_seconds: float = 0.0
    validation: ValidationReport = field(default_factory=ValidationReport)
    errors: list[FileResult] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total == 0:
            return 1.0
        return (self.parsed + self.duplicates) / self.total


# ── Pipeline ─────────────────────────────────────────────────────────────────


class IngestionPipeline:
    """Stage-based ingestion pipeline.

    Usage::

        pipeline = IngestionPipeline(config, store)
        report = pipeline.run(["docs/"])
    """

    def __init__(
        self,
        config: DeepHunterConfig,
        store: KnowledgeStore,
        parser_registry: ParserRegistry | None = None,
        event_bus: EventBus | None = None,
        dedup_engine: DeduplicationEngine | None = None,
    ) -> None:
        self._config = config
        self._store = store
        self._parser_registry = parser_registry or _default_parser_registry
        self._event_bus = event_bus or EventBus()
        self._extractor = MetadataExtractor()
        self._normalizer = ContentNormalizer()

        dedup_enabled = config.ingestion.dedup.enabled
        if dedup_engine is not None:
            self._dedup = dedup_engine
        elif dedup_enabled:
            self._dedup = DeduplicationEngine(
                strategies=[ContentHashDedup()],
                require_all=config.ingestion.dedup.require_all,
            )
        else:
            self._dedup = DeduplicationEngine(strategies=[NoOpDedup()])

        ext_map = self._supported_extensions()
        self._discoverer = FileDiscoverer(
            supported_extensions=ext_map,
            max_file_size_bytes=config.parser.max_file_size_bytes,
        )

        self._json_store: JSONKnowledgeStore | None = None
        if config.ingestion.storage.backend == "json":
            self._json_store = JSONKnowledgeStore(config.ingestion.storage.json_path)

    # ── Public API ─────────────────────────────────────────────────

    def run(
        self,
        paths: list[str | Path] | None = None,
        recursive: bool | None = None,
    ) -> IngestionReport:
        """Run the full ingestion pipeline.

        Args:
            paths: File or directory paths to ingest.  If ``None``, uses
                the configured ``data_dir`` or ``watch_directories``.
            recursive: Whether to scan directories recursively.  If
                ``None``, uses the configured ``discovery.recursive``.

        Returns:
            An ``IngestionReport`` with per-file results and aggregate stats.
        """
        start = time.perf_counter()
        report = IngestionReport()

        files = self._stage_discovery(paths, recursive)
        report.total = len(files)

        for file_path in files:
            self._event_bus.emit(DocumentDiscoveredEvent(path=file_path))
            result = self._process_single(file_path, report)
            if result.status == "parsed":
                report.parsed += 1
                report.stored += 1
            elif result.status == "duplicate":
                report.duplicates += 1
            elif result.status == "failed":
                report.failed += 1
                report.errors.append(result)
            else:
                report.skipped += 1

        report.elapsed_seconds = time.perf_counter() - start
        self._event_bus.emit(
            IngestionCompleteEvent(
                total=report.total,
                parsed=report.parsed,
                stored=report.stored,
                skipped=report.skipped,
                duplicates=report.duplicates,
                failed=report.failed,
                elapsed_seconds=report.elapsed_seconds,
            )
        )
        logger.info(
            "Pipeline complete: %d total, %d parsed, %d stored, "
            "%d skipped, %d duplicates, %d failed in %.2fs",
            report.total, report.parsed, report.stored,
            report.skipped, report.duplicates, report.failed,
            report.elapsed_seconds,
        )
        return report

    def parse_single(self, file_path: str | Path) -> SecurityKnowledgeObject:
        """Parse a single file and return an SKO.

        Useful for testing or one-off ingestion.  Skips dedup and storage.

        Raises:
            FileNotFoundError: If the file does not exist.
            ParsingError: If no parser is available or parsing fails.
        """
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        parse_result = self._stage_parse(path)
        sko = self._build_sko(path, parse_result)
        return sko

    @property
    def event_bus(self) -> EventBus:
        """Expose the event bus for external subscribers."""
        return self._event_bus

    # ── Stage: Discovery ──────────────────────────────────────────

    def _stage_discovery(
        self,
        paths: list[str | Path] | None,
        recursive: bool | None,
    ) -> list[Path]:
        if paths:
            all_files: list[Path] = []
            for p in paths:
                all_files.extend(
                    self._discoverer.discover(p, recursive=recursive if recursive is not None else True)
                )
            return all_files

        dirs = self._config.ingestion.watch_directories
        if not dirs:
            dirs = [self._config.data_dir]

        all_files = []
        rec = recursive if recursive is not None else self._config.ingestion.discovery.recursive
        for d in dirs:
            try:
                all_files.extend(self._discoverer.discover(d, recursive=rec))
            except FileNotFoundError:
                logger.warning("Discovery path not found: %s", d)
        return all_files

    # ── Stage: Parse ──────────────────────────────────────────────

    def _stage_parse(self, path: Path) -> ParseResult:
        parser = self._parser_registry.get_for_path(path)
        if parser is None:
            raise ParsingError(f"No parser found for {path.suffix} ({path.name})")
        raw = path.read_bytes()
        return parser.parse(raw, source_path=str(path))

    # ── Stage: Build SKO ──────────────────────────────────────────

    def _build_sko(self, path: Path, result: ParseResult) -> SecurityKnowledgeObject:
        content_text = result.content
        meta = result.metadata

        # Metadata extraction
        technologies = self._extractor.extract_technologies(content_text)
        bug_classes = self._extractor.extract_bug_classes(content_text)
        cloud_providers = self._extractor.extract_cloud_providers(content_text)
        frameworks = self._extractor.extract_frameworks(content_text)
        languages = self._extractor.extract_programming_languages(content_text)
        operating_systems = self._extractor.extract_operating_systems(content_text)
        tags = self._extractor.extract_tags(content_text)
        title = (
            self._extractor.extract_title(content_text)
            or meta.get("title")
            or path.stem
        )
        author = self._extractor.extract_author(content_text) or meta.get("author")

        # Normalization
        normalized = self._normalizer.normalize_sko(content_text)

        sko = SecurityKnowledgeObject(
            title=title[:500],
            summary=(content_text[:500] if content_text else ""),
            description="",
            source=str(path),
            source_type=self._detect_source_type(path),
            document_type=self._detect_document_type(path),
            author=author,
            raw_content=content_text[:100_000] if content_text else None,
            normalized_content=normalized[:100_000] if normalized else None,
            tags=tags,
            technology=technologies,
            framework=frameworks,
            programming_language=languages,
            operating_system=operating_systems,
            cloud_provider=cloud_providers,
            bug_classes=bug_classes,
        )
        return sko

    # ── Single file processing ────────────────────────────────────

    def _process_single(self, path: Path, report: IngestionReport) -> FileResult:
        start = time.perf_counter()

        # Parse
        self._event_bus.emit(ParseStartedEvent(path=path))
        try:
            parse_result = self._stage_parse(path)
        except (ParsingError, FileNotFoundError, Exception) as exc:
            self._event_bus.emit(ParseFailedEvent(path=path, error=str(exc)))
            return FileResult(
                path=path, status="failed", error=str(exc),
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        self._event_bus.emit(
            ParseCompletedEvent(
                path=path,
                content_length=len(parse_result.content),
                sections_count=len(parse_result.sections),
            )
        )

        # Build SKO
        try:
            sko = self._build_sko(path, parse_result)
        except Exception as exc:
            return FileResult(
                path=path, status="failed", error=f"SKO construction: {exc}",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        self._event_bus.emit(SKOCreatedEvent(sko=sko))

        # Validate
        valid, errors = SKOValidator.validate_and_report(sko)
        if not valid:
            report.validation.total += 1
            report.validation.failed += 1
            self._event_bus.emit(ValidationFailedEvent(sko_id=sko.id, errors=errors))
            return FileResult(
                path=path, status="failed", error=f"Validation: {'; '.join(errors)}",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        report.validation.total += 1
        report.validation.passed += 1

        # Dedup
        if self._config.ingestion.dedup.enabled:
            dedup_result = self._dedup.is_duplicate(sko, self._store)
            if dedup_result.is_duplicate:
                self._event_bus.emit(
                    DuplicateSkippedEvent(sko=sko, strategy=dedup_result.strategy)
                )
                return FileResult(
                    path=path, status="duplicate",
                    sko_id=sko.id,
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

        # Store
        try:
            self._store.add(sko)
            if self._json_store is not None:
                self._json_store.add(sko)
        except Exception as exc:
            return FileResult(
                path=path, status="failed", error=f"Storage: {exc}",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        self._event_bus.emit(
            DocumentStoredEvent(
                sko=sko, backend=self._config.ingestion.storage.backend
            )
        )

        return FileResult(
            path=path, status="parsed", sko_id=sko.id,
            duration_ms=(time.perf_counter() - start) * 1000,
        )

    # ── Detection helpers ─────────────────────────────────────────

    @staticmethod
    def _detect_source_type(path: Path) -> SourceType:
        parts = [p.lower() for p in path.parts]
        for part in parts:
            if part in _SOURCE_TYPE_MAP:
                return _SOURCE_TYPE_MAP[part]
        return SourceType.OTHER

    @staticmethod
    def _detect_document_type(path: Path) -> DocumentType:
        return _EXTENSION_MAP.get(path.suffix.lower(), DocumentType.UNKNOWN)

    @staticmethod
    def _supported_extensions() -> set[str]:
        return set(_EXTENSION_MAP.keys())
