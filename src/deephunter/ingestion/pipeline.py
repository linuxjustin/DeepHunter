"""Ingestion pipeline — orchestrates document parsing and SKO creation.

The pipeline reads files from configured directories, routes each
file to the appropriate parser, extracts metadata, builds a
SecurityKnowledgeObject, and stores it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Set

from deephunter.core.config import DeepHunterConfig
from deephunter.core.exceptions import IngestionError, ParsingError
from deephunter.core.types import DocumentType, SourceType
from deephunter.ingestion.extractor import MetadataExtractor
from deephunter.knowledge.models import SKOBuilder, SecurityKnowledgeObject
from deephunter.knowledge.store import KnowledgeStore
from deephunter.parsers.base import ParserRegistry, ParseResult
from deephunter.utils.files import list_files
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class IngestionPipeline:
    """Orchestrates document discovery, parsing, and SKO creation.

    Typical usage::

        config = DeepHunterConfig.load("config.yaml")
        store = KnowledgeStore()
        pipeline = IngestionPipeline(config, store)
        results = pipeline.run()
    """

    def __init__(
        self,
        config: DeepHunterConfig,
        store: KnowledgeStore,
    ) -> None:
        self._config = config
        self._store = store
        self._extractor = MetadataExtractor()

    def run(
        self,
        directories: Optional[List[str]] = None,
    ) -> Dict[str, int]:
        """Run the full ingestion pipeline on the configured directories.

        Args:
            directories: Optional override list of directories to scan.

        Returns:
            Summary dict with keys: ``total``, ``parsed``, ``stored``, ``skipped``.

        Raises:
            IngestionError: If a critical failure occurs.
        """
        dirs = directories or self._config.ingestion.watch_directories
        if not dirs:
            dirs = [self._config.data_dir]

        total = 0
        parsed = 0
        stored = 0
        skipped = 0

        for directory in dirs:
            files = list_files(
                directory,
                extensions=self._supported_extensions(),
                recursive=True,
            )
            logger.info("Found %d files in %s", len(files), directory)

            for file_path in files:
                total += 1
                try:
                    parse_result = self._parse_file(file_path)
                except (ParsingError, FileNotFoundError) as exc:
                    logger.warning("Skipping %s: %s", file_path, exc)
                    skipped += 1
                    continue

                if parse_result is None:
                    skipped += 1
                    continue

                parsed += 1

                try:
                    sko = self._build_sko(file_path, parse_result)
                    self._store.add(sko)
                    stored += 1
                except Exception as exc:
                    logger.error("Failed to store SKO for %s: %s", file_path, exc)
                    skipped += 1

        logger.info(
            "Ingestion complete: %d total, %d parsed, %d stored, %d skipped",
            total, parsed, stored, skipped,
        )
        return {
            "total": total,
            "parsed": parsed,
            "stored": stored,
            "skipped": skipped,
        }

    def parse_single(self, file_path: str | Path) -> SecurityKnowledgeObject:
        """Parse a single file and return its SKO without storing.

        Args:
            file_path: Path to the file.

        Returns:
            The constructed SecurityKnowledgeObject.

        Raises:
            FileNotFoundError: If the file does not exist.
            ParsingError: If the file cannot be parsed.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        parse_result = self._parse_file(path)
        return self._build_sko(path, parse_result)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_file(self, path: Path) -> ParseResult:
        """Route a file to the correct parser and return the result."""
        parser = ParserRegistry.get_for_path(path)
        if parser is None:
            raise ParsingError(f"No parser found for {path.suffix}")

        raw = path.read_bytes()
        return parser.parse(raw, source_path=str(path))

    def _build_sko(self, path: Path, result: ParseResult) -> SecurityKnowledgeObject:
        """Build an SKO from a parse result."""
        content_text = result.content
        meta = result.metadata

        builder = (
            SKOBuilder()
            .title(meta.get("title", path.stem))
            .summary(content_text[:500] if content_text else "")
            .source(str(path))
            .source_type(self._detect_source_type(path))
            .document_type(self._detect_document_type(path))
            .raw_content(content_text)
        )

        for t in self._extractor.extract_technologies(content_text):
            builder.add_technology(t)
        for bc in self._extractor.extract_bug_classes(content_text):
            builder.add_bug_class(bc)

        return builder.build()

    def _detect_source_type(self, path: Path) -> SourceType:
        """Heuristic source type detection from the file path."""
        parts = [p.lower() for p in path.parts]
        source_map: Dict[str, SourceType] = {
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
        for part in parts:
            if part in source_map:
                return source_map[part]
        return SourceType.OTHER

    def _detect_document_type(self, path: Path) -> DocumentType:
        """Map file extension to DocumentType."""
        ext = path.suffix.lower()
        ext_map = {
            ".md": DocumentType.MARKDOWN,
            ".markdown": DocumentType.MARKDOWN,
            ".html": DocumentType.HTML,
            ".htm": DocumentType.HTML,
            ".xhtml": DocumentType.HTML,
            ".json": DocumentType.JSON,
            ".yaml": DocumentType.YAML,
            ".yml": DocumentType.YAML,
            ".pdf": DocumentType.PDF,
            ".txt": DocumentType.TEXT,
        }
        return ext_map.get(ext, DocumentType.UNKNOWN)

    def _supported_extensions(self) -> Set[str]:
        """Return the set of all supported file extensions."""
        return {
            ".md", ".markdown",
            ".html", ".htm", ".xhtml",
            ".json",
            ".yaml", ".yml",
            ".pdf",
            ".txt",
        }