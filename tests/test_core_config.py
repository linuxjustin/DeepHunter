"""Tests for the configuration module."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from deephunter.core.config import (
    DeepHunterConfig,
    IngestionConfig,
    ParserConfig,
    RAGConfig,
    ReasoningConfig,
    TrainingConfig,
    EvaluationConfig,
)
from deephunter.core.exceptions import ConfigurationError


class TestDeepHunterConfig:
    def test_default_config(self) -> None:
        cfg = DeepHunterConfig.default()
        assert cfg.log_level == "INFO"
        assert cfg.data_dir == "./knowledge"
        assert isinstance(cfg.parser, ParserConfig)
        assert isinstance(cfg.ingestion, IngestionConfig)
        assert isinstance(cfg.rag, RAGConfig)
        assert isinstance(cfg.reasoning, ReasoningConfig)
        assert isinstance(cfg.training, TrainingConfig)
        assert isinstance(cfg.evaluation, EvaluationConfig)

    def test_load_yaml(self, tmp_path: Path) -> None:
        path = tmp_path / "test.yaml"
        data = {"log_level": "DEBUG", "data_dir": "/tmp/data"}
        with open(path, "w") as f:
            yaml.dump(data, f)

        cfg = DeepHunterConfig.load(str(path))
        assert cfg.log_level == "DEBUG"
        assert cfg.data_dir == "/tmp/data"

    def test_load_yaml_custom_path(self, sample_config_path: Path) -> None:
        cfg = DeepHunterConfig.load(str(sample_config_path))
        assert cfg.log_level == "INFO"

    def test_load_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            DeepHunterConfig.load("/nonexistent/config.yaml")

    def test_load_unsupported_format(self, tmp_path: Path) -> None:
        path = tmp_path / "config.txt"
        path.write_text("")
        with pytest.raises(ValueError, match="Unsupported config format"):
            DeepHunterConfig.load(str(path))

    def test_save_and_reload(self, tmp_path: Path) -> None:
        original = DeepHunterConfig.default()
        original.log_level = "DEBUG"
        original.rag.top_k = 20

        path = tmp_path / "saved.yaml"
        original.save(str(path))

        reloaded = DeepHunterConfig.load(str(path))
        assert reloaded.log_level == "DEBUG"
        assert reloaded.rag.top_k == 20

    def test_invalid_log_level(self) -> None:
        with pytest.raises(ValueError, match="Invalid log level"):
            DeepHunterConfig(log_level="TRACE")

    def test_parser_config_defaults(self) -> None:
        cfg = ParserConfig()
        assert "markdown" in cfg.enabled_parsers
        assert cfg.max_file_size_bytes == 50 * 1024 * 1024

    def test_parser_config_validation(self) -> None:
        with pytest.raises(ValueError):
            ParserConfig(max_file_size_bytes=100)

    def test_ingestion_config_defaults(self) -> None:
        cfg = IngestionConfig()
        assert cfg.batch_size == 10
        assert cfg.deduplicate is True

    def test_rag_config_defaults(self) -> None:
        cfg = RAGConfig()
        assert cfg.top_k == 5
        assert cfg.similarity_threshold == 0.7

    def test_reasoning_config_defaults(self) -> None:
        cfg = ReasoningConfig()
        assert cfg.hypothesis_limit == 10
        assert cfg.enable_framework_aware is True

    def test_training_config_defaults(self) -> None:
        cfg = TrainingConfig()
        assert cfg.max_samples == 10000
        assert cfg.format == "jsonl"

    def test_evaluation_config_defaults(self) -> None:
        cfg = EvaluationConfig()
        assert "precision" in cfg.metrics