"""Ingestion pipeline — orchestrates document parsing and SKO creation."""

from deephunter.ingestion.pipeline import IngestionPipeline
from deephunter.ingestion.extractor import MetadataExtractor

__all__ = [
    "IngestionPipeline",
    "MetadataExtractor",
]