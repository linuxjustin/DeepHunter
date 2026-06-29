"""Configuration management for DeepHunter.

Uses Pydantic for validation and supports loading from YAML/JSON files
with environment variable overrides.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, ValidationError
import yaml


class ParserConfig(BaseModel):
    enabled_parsers: List[str] = Field(
        default_factory=lambda: ["markdown", "html", "json", "yaml", "pdf"],
        description="List of active parser identifiers",
    )
    max_file_size_bytes: int = Field(
        default=50 * 1024 * 1024, ge=1024, description="Maximum file size in bytes"
    )


class IngestionConfig(BaseModel):
    watch_directories: List[str] = Field(
        default_factory=list,
        description="Directories to monitor for new documents",
    )
    batch_size: int = Field(default=10, ge=1, le=1000)
    deduplicate: bool = Field(default=True)


class RAGConfig(BaseModel):
    embedding_model: str = Field(
        default="text-embedding-ada-002",
        description="Embedding model identifier",
    )
    top_k: int = Field(default=5, ge=1, le=100)
    similarity_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    vector_store_path: Optional[str] = Field(default=None)


class ReasoningConfig(BaseModel):
    hypothesis_limit: int = Field(default=10, ge=1, le=100)
    min_confidence: float = Field(default=0.3, ge=0.0, le=1.0)
    enable_framework_aware: bool = Field(default=True)
    enable_cloud_aware: bool = Field(default=True)
    enable_api_aware: bool = Field(default=True)


class EvaluationConfig(BaseModel):
    metrics: List[str] = Field(
        default_factory=lambda: ["precision", "recall", "f1", "hit_rate"],
    )


class TrainingConfig(BaseModel):
    output_dir: str = Field(default="./datasets/processed")
    format: str = Field(default="jsonl")
    max_samples: int = Field(default=10000, ge=1)


class DeepHunterConfig(BaseModel):
    """Root configuration for the DeepHunter platform."""

    data_dir: str = Field(default="./knowledge")
    output_dir: str = Field(default="./output")
    log_level: str = Field(default="INFO")
    log_file: Optional[str] = Field(default=None)

    parser: ParserConfig = Field(default_factory=ParserConfig)
    ingestion: IngestionConfig = Field(default_factory=IngestionConfig)
    rag: RAGConfig = Field(default_factory=RAGConfig)
    reasoning: ReasoningConfig = Field(default_factory=ReasoningConfig)
    evaluation: EvaluationConfig = Field(default_factory=EvaluationConfig)
    training: TrainingConfig = Field(default_factory=TrainingConfig)

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            msg = f"Invalid log level: {v}. Must be one of {allowed}"
            raise ValueError(msg)
        return v.upper()

    @classmethod
    def load(cls, path: str | Path) -> DeepHunterConfig:
        """Load configuration from a YAML or JSON file.

        Args:
            path: Path to the configuration file.

        Returns:
            Loaded configuration instance.

        Raises:
            FileNotFoundError: If the config path does not exist.
            ValueError: If the file format is unsupported.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        raw: Dict[str, Any]
        if path.suffix in {".yaml", ".yml"}:
            with open(path, "r") as f:
                raw = yaml.safe_load(f) or {}
        elif path.suffix == ".json":
            import json

            with open(path, "r") as f:
                raw = json.load(f)
        else:
            raise ValueError(f"Unsupported config format: {path.suffix}")

        return cls(**raw)

    def save(self, path: str | Path) -> None:
        """Save configuration to a YAML file.

        Args:
            path: Destination file path.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = self.model_dump(mode="json")
        with open(path, "w") as f:
            yaml.dump(raw, f, default_flow_style=False, sort_keys=False)

    @classmethod
    def default(cls) -> DeepHunterConfig:
        """Return a configuration with all defaults."""
        return cls()