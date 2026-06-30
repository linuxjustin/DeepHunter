"""RAG engine — embedding, retrieval, search, ranking, and citation tracking.

Components:
  - Embeddings: EmbeddingProvider, RandomEmbeddingProvider, etc.
  - Retrieval: Retriever (vector), BM25Retriever (keyword), HybridRetriever
  - Search: MetadataFilter for filtered queries
  - Ranking: SemanticRanker for re-ranking results
  - Processing: TextChunker, ContextCompressor
  - Tracking: CitationTracker
  - Maintenance: IncrementalIndexer
"""

from deephunter.rag.bm25_retriever import BM25Retriever
from deephunter.rag.chunker import Chunk, TextChunker
from deephunter.rag.citation_tracker import Citation, CitationGroup, CitationTracker
from deephunter.rag.context_compressor import ContextCompressor
from deephunter.rag.embeddings import (
    EmbeddingProvider,
    EmbeddingProviderFactory,
    RandomEmbeddingProvider,
    SentenceTransformerEmbeddingProvider,
)
from deephunter.rag.hybrid_retriever import HybridRetriever
from deephunter.rag.incremental_index import IncrementalIndexer
from deephunter.rag.metadata_filter import MetadataFilter
from deephunter.rag.retriever import Retriever
from deephunter.rag.semantic_ranker import SemanticRanker

__all__ = [
    "EmbeddingProvider",
    "EmbeddingProviderFactory",
    "RandomEmbeddingProvider",
    "SentenceTransformerEmbeddingProvider",
    "Retriever",
    "BM25Retriever",
    "HybridRetriever",
    "TextChunker",
    "Chunk",
    "MetadataFilter",
    "SemanticRanker",
    "ContextCompressor",
    "CitationTracker",
    "Citation",
    "CitationGroup",
    "IncrementalIndexer",
]
