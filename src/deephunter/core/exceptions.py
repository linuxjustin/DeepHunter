"""Custom exceptions for the DeepHunter platform."""


class DeepHunterError(Exception):
    """Base exception for all DeepHunter errors."""


class ConfigurationError(DeepHunterError):
    """Raised when the configuration is invalid or cannot be loaded."""


class ParsingError(DeepHunterError):
    """Raised when a document cannot be parsed."""


class IngestionError(DeepHunterError):
    """Raised when document ingestion fails."""


class StorageError(DeepHunterError):
    """Raised when reading from or writing to storage fails."""


class RetrievalError(DeepHunterError):
    """Raised when knowledge retrieval fails."""


class ReasoningError(DeepHunterError):
    """Raised when hypothesis generation fails."""


class InvestigationError(DeepHunterError):
    """Raised when an investigation operation fails."""


class EvaluationError(DeepHunterError):
    """Raised when evaluation of results fails."""


class ContextError(DeepHunterError):
    """Raised when context engine operations fail."""


class PromptError(DeepHunterError):
    """Raised when prompt builder operations fail."""


class RouterError(DeepHunterError):
    """Raised when model routing operations fail."""


class TrainingError(DeepHunterError):
    """Raised when dataset creation or model training fails."""


class AgentError(DeepHunterError):
    """Raised when agent operations fail."""


class ReconError(DeepHunterError):
    """Raised when reconnaissance operations fail."""
