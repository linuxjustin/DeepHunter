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


class DiscoveryConfig(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    recursive: bool = Field(
        default=True, description="Scan directories recursively"
    )
    follow_symlinks: bool = Field(
        default=False, description="Follow symbolic links"
    )
    exclude_patterns: list[str] = Field(
        default_factory=list,
        description="Glob patterns to exclude from discovery",
    )


class DedupConfig(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    enabled: bool = Field(default=True, description="Enable deduplication")
    strategy: str = Field(
        default="content_hash",
        description="Deduplication strategy: 'content_hash' or 'none'",
    )
    require_all: bool = Field(
        default=False,
        description="Require all strategies to agree before flagging duplicate",
    )


class StorageConfig(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    backend: str = Field(
        default="sqlite",
        description="Storage backend: 'sqlite' or 'json'",
    )
    json_path: str = Field(
        default="./knowledge/skos",
        description="Base directory for JSON store (used when backend='json')",
    )
    sqlite_path: str | None = Field(
        default=None,
        description="SQLite database path (None = default ~/.deephunter/store.db)",
    )


class IngestionConfig(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    watch_directories: list[str] = Field(
        default_factory=list,
        description="Directories to monitor for new documents",
    )
    batch_size: int = Field(default=10, ge=1, le=1000)
    deduplicate: bool = Field(default=True)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    dedup: DedupConfig = Field(default_factory=DedupConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)


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


class PlanningConfig(BaseSettings):
    """Configuration for the Investigation Planning Engine."""

    model_config = SettingsConfigDict(extra="ignore")

    enabled: bool = Field(default=True)
    max_steps_per_plan: int = Field(default=50, ge=1, le=200)
    default_estimated_hours: float = Field(default=2.0, ge=0.0)
    enable_technology_rules: bool = Field(default=True)
    enable_authentication_rules: bool = Field(default=True)
    enable_bug_class_rules: bool = Field(default=True)
    enable_framework_rules: bool = Field(default=True)
    enable_cloud_rules: bool = Field(default=True)
    enable_business_logic_rules: bool = Field(default=True)
    enable_recon_rules: bool = Field(default=True)
    enable_endpoint_rules: bool = Field(default=True)
    enable_file_upload_rules: bool = Field(default=True)
    enable_authorization_rules: bool = Field(default=True)
    enable_privilege_escalation_rules: bool = Field(default=True)
    minimum_priority_threshold: float = Field(default=0.0, ge=0.0, le=1.0)
    priority_weights_file: str = Field(default="")


class ContextConfig(BaseSettings):
    """Configuration for the Context Engine."""

    model_config = SettingsConfigDict(extra="ignore")

    enabled: bool = Field(default=True)
    max_sections: int = Field(default=20, ge=1, le=100)
    max_blocks_per_section: int = Field(default=50, ge=1, le=500)
    default_max_tokens: int = Field(default=8192, ge=256, le=1_000_000)
    enable_knowledge_collection: bool = Field(default=True)
    enable_evidence_collection: bool = Field(default=True)
    enable_plan_integration: bool = Field(default=True)
    enable_deduplication: bool = Field(default=True)
    enable_prioritization: bool = Field(default=True)
    enable_token_budgeting: bool = Field(default=True)
    enable_compression: bool = Field(default=True)
    enable_summaries: bool = Field(default=True)


class PromptConfig(BaseSettings):
    """Configuration for the Prompt Builder."""

    model_config = SettingsConfigDict(extra="ignore")

    enabled: bool = Field(default=True)
    default_style: str = Field(default="investigation")
    default_format: str = Field(default="markdown")
    token_estimation_method: str = Field(
        default="word_count",
        description="Token estimation method: word_count, character_count, tiktoken",
    )
    max_prompt_tokens: int = Field(default=128_000, ge=256)
    enable_templates: bool = Field(default=True)
    enable_adapters: bool = Field(default=True)
    enable_metadata: bool = Field(default=True)
    enable_statistics: bool = Field(default=True)
    template_directory: str = Field(default="")


class AgentConfig(BaseSettings):
    """Configuration for the Agent Orchestration Framework."""

    model_config = SettingsConfigDict(extra="ignore")

    enabled: bool = Field(default=True, description="Enable agent orchestration")
    default_execution_strategy: str = Field(
        default="sequential",
        description="Default execution strategy: sequential, parallel, pipeline, conditional, fan_out, fan_in",
    )
    max_concurrency: int = Field(default=4, ge=1, le=128, description="Max parallel agent executions")
    default_timeout: float = Field(default=300.0, ge=1.0, description="Default agent execution timeout")
    max_retries: int = Field(default=3, ge=0, le=10, description="Max retries per agent")
    retry_delay_seconds: float = Field(default=1.0, ge=0.0, description="Delay between retries")
    enabled_agents: list[str] = Field(default_factory=list, description="Explicitly enabled agents (empty = all)")
    disabled_agents: list[str] = Field(default_factory=list, description="Disabled agent names")
    agent_priorities: dict[str, int] = Field(default_factory=dict, description="Per-agent priority overrides")
    enable_event_bus: bool = Field(default=True, description="Enable agent event bus")
    enable_metrics: bool = Field(default=True, description="Enable execution metrics")
    use_model_router: bool = Field(default=False, description="Use ModelRouter for agent model selection")
    use_context_engine: bool = Field(default=False, description="Use ContextEngine for shared context")


class RouterConfig(BaseSettings):
    """Configuration for the Model Router & Provider Abstraction Layer."""

    model_config = SettingsConfigDict(extra="ignore")

    enabled: bool = Field(default=True)
    default_provider: str = Field(default="ollama")
    fallback_providers: list[str] = Field(default_factory=lambda: ["openai"])
    enabled_providers: list[str] = Field(default_factory=lambda: ["ollama", "openai"])
    disabled_providers: list[str] = Field(default_factory=list)
    provider_priorities: dict[str, int] = Field(default_factory=dict)
    task_provider_mapping: dict[str, str] = Field(default_factory=dict)
    offline_mode: bool = Field(default=False)
    simulation_mode: bool = Field(default=False)
    dry_run: bool = Field(default=False)
    max_fallback_attempts: int = Field(default=3, ge=0, le=10)
    default_max_tokens: int = Field(default=4096, ge=1)
    default_timeout: float = Field(default=120.0, ge=1.0)


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
    planning: PlanningConfig = Field(default_factory=PlanningConfig)
    context: ContextConfig = Field(default_factory=ContextConfig)
    prompt: PromptConfig = Field(default_factory=PromptConfig)
    router: RouterConfig = Field(default_factory=RouterConfig)
    evaluation: EvaluationConfig = Field(default_factory=EvaluationConfig)
    training: TrainingConfig = Field(default_factory=TrainingConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)

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
