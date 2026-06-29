"""Prompt Builder — transforms structured context into model-ready prompts.

Consumes ``Context`` objects from the Context Engine and produces
``Prompt`` objects with system, user, and developer messages.

Independent of any LLM.  No AI, no embeddings, no RAG.
"""

from deephunter.prompt.adapters import IdentityAdapter, ModelAdapter
from deephunter.prompt.builder import PromptBuilder
from deephunter.prompt.config import PromptConfig
from deephunter.prompt.events import (
    PromptAdapterAppliedEvent,
    PromptEvent,
    PromptEventBus,
    PromptFormatAppliedEvent,
    PromptGeneratedEvent,
    PromptTemplateLoadedEvent,
    PromptTemplateNotFoundEvent,
)
from deephunter.prompt.formats import (
    JSONFormatter,
    MarkdownFormatter,
    PlainTextFormatter,
    PromptFormatter,
    StructuredFormatter,
    get_formatter,
)
from deephunter.prompt.models import (
    Prompt,
    PromptFormat,
    PromptMessage,
    PromptMessageRole,
    PromptMetadata,
    PromptReference,
    PromptStatistics,
    PromptStyle,
    PromptTemplate,
)
from deephunter.prompt.templates import TemplateRegistry

__all__ = [
    # Config
    "PromptConfig",
    # Models
    "Prompt",
    "PromptFormat",
    "PromptMessage",
    "PromptMessageRole",
    "PromptMetadata",
    "PromptReference",
    "PromptStatistics",
    "PromptStyle",
    "PromptTemplate",
    # Builder
    "PromptBuilder",
    # Adapters
    "IdentityAdapter",
    "ModelAdapter",
    # Formats
    "JSONFormatter",
    "MarkdownFormatter",
    "PlainTextFormatter",
    "PromptFormatter",
    "StructuredFormatter",
    "get_formatter",
    # Templates
    "TemplateRegistry",
    # Events
    "PromptAdapterAppliedEvent",
    "PromptEvent",
    "PromptEventBus",
    "PromptFormatAppliedEvent",
    "PromptGeneratedEvent",
    "PromptTemplateLoadedEvent",
    "PromptTemplateNotFoundEvent",
]
