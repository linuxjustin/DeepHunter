"""Integration tests for the v2 stage-based ingestion pipeline.

Tests full pipeline flows including discovery, parsing, metadata
extraction, normalization, validation, dedup, and storage.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from deephunter.core.config import DeepHunterConfig
from deephunter.ingestion.dedup import ContentHashDedup, DeduplicationEngine
from deephunter.ingestion.events import EventBus
from deephunter.ingestion.pipeline import IngestionPipeline
from deephunter.knowledge.json_store import JSONKnowledgeStore
from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.knowledge.store import KnowledgeStore
from deephunter.parsers import default_registry


class TestIngestionV2FullPipeline:
    """End-to-end pipeline tests with multiple document types."""

    @pytest.fixture
    def config(self, tmp_path: Path) -> DeepHunterConfig:
        cfg = DeepHunterConfig.default()
        cfg.data_dir = str(tmp_path / "knowledge")
        cfg.ingestion.storage.backend = "sqlite"
        return cfg

    def test_ingest_multiple_formats(
        self, config: DeepHunterConfig, tmp_path: Path,
    ) -> None:
        (tmp_path / "knowledge").mkdir()

        # Write sample files
        (tmp_path / "knowledge" / "sqli.md").write_text(
            "# SQL Injection\n\nSQL injection is a critical vulnerability in web apps."
        )
        (tmp_path / "knowledge" / "xss.html").write_text(
            "<html><title>XSS Guide</title><body>Cross-site scripting attacks.</body></html>"
        )
        (tmp_path / "knowledge" / "config.json").write_text(
            '{"title": "API Security", "severity": "high", "technique": "JWT"}'
        )
        (tmp_path / "knowledge" / "notes.yaml").write_text(
            "title: Race Conditions\ndescription: Testing for race conditions in concurrent apps."
        )
        (tmp_path / "knowledge" / "readme.txt").write_text(
            "Plain text document with some security notes."
        )

        store = KnowledgeStore(str(tmp_path / "store.db"))
        pipeline = IngestionPipeline(config, store)

        report = pipeline.run(paths=[tmp_path / "knowledge"], recursive=False)

        assert report.total == 5
        assert report.stored >= 4
        assert report.failed <= 1  # .txt has no parser yet
        assert report.stored + report.failed == report.total

    def test_ingest_recursive(
        self, config: DeepHunterConfig, tmp_path: Path,
    ) -> None:
        root = tmp_path / "docs"
        root.mkdir()
        (root / "a.md").write_text("# A\nContent A")
        sub = root / "sub"
        sub.mkdir()
        (sub / "b.md").write_text("# B\nContent B")
        (sub / "c.txt").write_text("Plain text C")

        store = KnowledgeStore(str(tmp_path / "store.db"))
        pipeline = IngestionPipeline(config, store)

        report = pipeline.run(paths=[root], recursive=True)
        assert report.total == 3
        assert report.stored == 2  # .txt has no parser
        assert report.failed == 1

    def test_ingest_non_recursive(
        self, config: DeepHunterConfig, tmp_path: Path,
    ) -> None:
        root = tmp_path / "docs"
        root.mkdir()
        (root / "a.md").write_text("# A\nContent A")
        sub = root / "sub"
        sub.mkdir()
        (sub / "b.md").write_text("# B\nContent B")

        store = KnowledgeStore(str(tmp_path / "store.db"))
        pipeline = IngestionPipeline(config, store)

        report = pipeline.run(paths=[root], recursive=False)
        assert report.total == 1
        assert report.stored == 1

    def test_ingest_empty_directory(
        self, config: DeepHunterConfig, tmp_path: Path,
    ) -> None:
        store = KnowledgeStore(str(tmp_path / "store.db"))
        pipeline = IngestionPipeline(config, store)
        report = pipeline.run(paths=[tmp_path])
        assert report.total == 0

    def test_deduplication(
        self, config: DeepHunterConfig, tmp_path: Path,
    ) -> None:
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()

        # Two files with the exact same content
        content = "# Duplicate\nThis is duplicate content."
        (doc_dir / "a.md").write_text(content)
        (doc_dir / "b.md").write_text(content)

        bus = EventBus()
        store = KnowledgeStore(str(tmp_path / "store.db"))

        config.ingestion.dedup.enabled = True

        pipeline = IngestionPipeline(
            config, store, event_bus=bus,
            dedup_engine=DeduplicationEngine(strategies=[ContentHashDedup()]),
        )
        report = pipeline.run(paths=[doc_dir])

        assert report.total == 2
        assert report.stored == 1  # first is stored
        assert report.duplicates == 1  # second is detected as duplicate

    def test_validation_does_not_crash(
        self, config: DeepHunterConfig, tmp_path: Path,
    ) -> None:
        # Even problematic documents should not crash the pipeline
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "good.md").write_text("# Good\nValid content.")
        (doc_dir / "empty.md").write_text("")  # empty file

        store = KnowledgeStore(str(tmp_path / "store.db"))
        pipeline = IngestionPipeline(config, store)

        report = pipeline.run(paths=[doc_dir])
        # At least the valid file should be processed
        assert report.total >= 1

    def test_json_storage_backend(
        self, config: DeepHunterConfig, tmp_path: Path,
    ) -> None:
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "test.md").write_text("# JSON Store Test\nContent.")

        json_path = tmp_path / "json_skos"
        config.ingestion.storage.backend = "json"
        config.ingestion.storage.json_path = str(json_path)

        store = KnowledgeStore(str(tmp_path / "store.db"))
        pipeline = IngestionPipeline(config, store)

        report = pipeline.run(paths=[doc_dir])
        assert report.stored == 1

        # Verify JSON files were written
        json_store = JSONKnowledgeStore(json_path)
        assert json_store.count() == 1

    def test_pipeline_report_accuracy(
        self, config: DeepHunterConfig, tmp_path: Path,
    ) -> None:
        doc_dir = tmp_path / "docs"
        doc_dir.mkdir()
        (doc_dir / "a.md").write_text("# A\nContent A")
        (doc_dir / "b.html").write_text("<html><title>B</title><body>B</body></html>")

        store = KnowledgeStore(str(tmp_path / "store.db"))
        pipeline = IngestionPipeline(config, store)
        report = pipeline.run(paths=[doc_dir])

        assert report.total == 2
        assert report.stored == 2
        assert report.failed == 0
        assert report.skipped == 0
        assert report.elapsed_seconds > 0
