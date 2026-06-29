"""Ingestion pipeline — orchestrates document parsing and SKO creation."""

from deephunter.ingestion.extractor import MetadataExtractor
from deephunter.ingestion.pipeline import IngestionPipeline

__all__ = [
    "IngestionPipeline",
    "MetadataExtractor",
]
