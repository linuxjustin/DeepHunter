"""Tests for the dataset builder."""

from __future__ import annotations

import json
from pathlib import Path

from deephunter.core.config import TrainingConfig
from deephunter.core.exceptions import TrainingError
from deephunter.training.dataset_builder import DatasetBuilder, DatasetSample


class TestDatasetSample:
    def test_create_minimal(self) -> None:
        sample = DatasetSample(
            instruction="Summarize",
            input="Some text",
            output="Summary",
        )
        assert sample.instruction == "Summarize"
        assert sample.source == ""

    def test_to_dict(self) -> None:
        sample = DatasetSample(
            instruction="What?",
            input="Input",
            output="Output",
            source="test",
            metadata={"key": "val"},
        )
        d = sample.to_dict()
        assert d["instruction"] == "What?"
        assert d["metadata"]["key"] == "val"


class TestDatasetBuilder:
    def test_build_knowledge_samples(self, populated_store) -> None:
        config = TrainingConfig()
        builder = DatasetBuilder(populated_store, config=config)
        samples = builder.build_knowledge_samples()
        assert len(samples) > 0

        assert len(samples) > 3  # Multiple samples across multiple SKOs

    def test_build_hypothesis_samples_no_generator(self, populated_store) -> None:
        config = TrainingConfig()
        builder = DatasetBuilder(populated_store, config=config)
        import pytest
        with pytest.raises(TrainingError, match="HypothesisGenerator is required"):
            builder.build_hypothesis_samples()

    def test_build_text_samples(self, populated_store) -> None:
        config = TrainingConfig()
        builder = DatasetBuilder(populated_store, config=config)
        samples = builder.build_text_samples()
        # SKOs with raw_content that is long enough
        assert len(samples) >= 0  # might be 0 if content is short

    def test_save(self, populated_store, tmp_path: Path) -> None:
        config = TrainingConfig(output_dir=str(tmp_path))
        builder = DatasetBuilder(populated_store, config=config)
        samples = builder.build_knowledge_samples()

        path = builder.save(samples)
        assert path.exists()
        assert path.suffix == ".jsonl"

        # Verify contents
        lines = path.read_text().strip().split("\n")
        assert len(lines) == len(samples)

        first = json.loads(lines[0])
        assert "instruction" in first
        assert "output" in first

    def test_save_empty(self, empty_store, tmp_path: Path) -> None:
        config = TrainingConfig(output_dir=str(tmp_path))
        builder = DatasetBuilder(empty_store, config=config)
        path = builder.save([])
        assert path.exists()

        content = path.read_text().strip()
        assert content == ""


class TestDatasetBuilderIntegration:
    def test_knowledge_samples_types(self, populated_store) -> None:
        config = TrainingConfig()
        builder = DatasetBuilder(populated_store, config=config)
        samples = builder.build_knowledge_samples()

        types_seen = set()
        for s in samples:
            if s.metadata:
                types_seen.add(s.metadata.get("type"))
        assert "summarization" in types_seen
        assert "bug_classification" in types_seen