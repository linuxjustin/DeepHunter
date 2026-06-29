"""Ingestion engine — stage-based document ingestion pipeline.

Converts documents into validated Security Knowledge Objects (SKOs)
through independent, testable stages:

    Discovery → Parser Selection → Parsing → Metadata Extraction
    → Normalization → SKO Construction → Validation → Dedup → Storage

Every stage emits typed events via ``EventBus`` so future modules
can subscribe without coupling.
"""

from deephunter.ingestion.dedup import (
    ContentHashDedup,
    DeduplicationEngine,
    DeduplicationStrategy,
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
    IngestionEvent,
    MetadataExtractedEvent,
    ParseCompletedEvent,
    ParseFailedEvent,
    ParseStartedEvent,
    SKOCreatedEvent,
    ValidationFailedEvent,
)
from deephunter.ingestion.extractor import MetadataExtractor
from deephunter.ingestion.normalizer import ContentNormalizer
from deephunter.ingestion.pipeline import IngestionPipeline, IngestionReport
from deephunter.ingestion.validator import SKOValidator, ValidationReport

__all__ = [
    "IngestionPipeline",
    "IngestionReport",
    "MetadataExtractor",
    "ContentNormalizer",
    "FileDiscoverer",
    "SKOValidator",
    "ValidationReport",
    "EventBus",
    "IngestionEvent",
    "DocumentDiscoveredEvent",
    "DocumentSkippedEvent",
    "ParseStartedEvent",
    "ParseCompletedEvent",
    "ParseFailedEvent",
    "MetadataExtractedEvent",
    "SKOCreatedEvent",
    "ValidationFailedEvent",
    "DuplicateSkippedEvent",
    "DocumentStoredEvent",
    "IngestionCompleteEvent",
    "DeduplicationStrategy",
    "ContentHashDedup",
    "NoOpDedup",
    "DeduplicationEngine",
]
