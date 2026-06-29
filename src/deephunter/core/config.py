"""Configuration management for DeepHunter.

Uses Pydantic for validation, pydantic-settings for environment variable
overrides, and supports loading from YAML/JSON files.

Environment variables use the prefix ``DEEPHUNTER_`` with double-underscore
as nested delimiter::

    DEEPHUNTER_RAG__TOP_K=25
    DEEPHUNTER_LOG_LEVEL=DEBUG
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ParserConfig(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    enabled_parsers: list[str] = Field(
        default_factory=lambda: ["markdown", "html", "json", "yaml", "pdf"],
        description="List of active parser identifiers",
    )
    max_file_size_bytes: int = Field(
        default=50 * 1024 * 1024, ge=1024, description="Maximum file size in bytes"
    )


class IngestionConfig(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    watch_directories: list[str] = Field(
        default_factory=list,
        description="Directories to monitor for new documents",
    )
    batch_size: int = Field(default=10, ge=1, le=1000)
    deduplicate: bool = Field(default=True)


class RAGConfig(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    embedding_model: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2",
        description="Embedding model identifier",
    )
    top_k: int = Field(default=5, ge=1, le=100)
    similarity_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    vector_store_path: str | None = Field(default=None)


class ReasoningConfig(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    hypothesis_limit: int = Field(default=10, ge=1, le=100)
    min_confidence: float = Field(default=0.3, ge=0.0, le=1.0)
    enable_framework_aware: bool = Field(default=True)
    enable_cloud_aware: bool = Field(default=True)
    enable_api_aware: bool = Field(default=True)


class EvaluationConfig(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    metrics: list[str] = Field(
        default_factory=lambda: ["precision", "recall", "f1", "hit_rate"],
    )


class TrainingConfig(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    output_dir: str = Field(default="./datasets/processed")
    format: str = Field(default="jsonl")
    max_samples: int = Field(default=10000, ge=1)


class LLMConfig(BaseSettings):
    """Configuration for LLM providers."""

    model_config = SettingsConfigDict(extra="ignore")

    provider: str = Field(
        default="ollama",
        description="LLM provider: ollama, openai, anthropic",
    )
    model: str = Field(
        default="deepseek-coder:6.7b",
        description="Model name for the selected provider",
    )
    base_url: str | None = Field(
        default=None,
        description="Base URL for the provider API (e.g. http://localhost:11434)",
    )
    api_key: str | None = Field(
        default=None,
        description="API key for the provider",
    )
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    max_tokens: int = Field(default=2048, ge=1)


class DeepHunterConfig(BaseSettings):
    """Root configuration for the DeepHunter platform.

    Supports environment variable overrides with prefix ``DEEPHUNTER_``::

        DEEPHUNTER_LOG_LEVEL=DEBUG
        DEEPHUNTER_RAG__TOP_K=25
        DEEPHUNTER_LLM__PROVIDER=openai
        DEEPHUNTER_LLM__MODEL=gpt-4o
    """

    model_config = SettingsConfigDict(
        env_prefix="DEEPHUNTER_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    data_dir: str = Field(default="./knowledge")
    output_dir: str = Field(default="./output")
    log_level: str = Field(default="INFO")
    log_file: str | None = Field(default=None)

    parser: ParserConfig = Field(default_factory=ParserConfig)
    ingestion: IngestionConfig = Field(default_factory=IngestionConfig)
    rag: RAGConfig = Field(default_factory=RAGConfig)
    reasoning: ReasoningConfig = Field(default_factory=ReasoningConfig)
    evaluation: EvaluationConfig = Field(default_factory=EvaluationConfig)
    training: TrainingConfig = Field(default_factory=TrainingConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)

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

        Environment variables override file values.

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

        raw: dict[str, Any]
        if path.suffix in {".yaml", ".yml"}:
            with open(path) as f:
                raw = yaml.safe_load(f) or {}
        elif path.suffix == ".json":
            with open(path) as f:
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
