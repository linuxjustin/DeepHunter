"""OpenAI embedding provider."""

from __future__ import annotations

from deephunter.core.exceptions import RetrievalError
from deephunter.rag.embeddings import EmbeddingProvider


class OpenAIEmbeddingProvider(EmbeddingProvider):
    """Embedding provider using the OpenAI API.

    Requires the ``openai`` package and an API key set via
    environment variable or passed directly.
    """

    def __init__(
        self,
        model: str = "text-embedding-3-small",
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> None:
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RetrievalError(
                "openai package is required. Install with: pip install deephunter[openai]"
            ) from exc
        self._model = model
        self._client = OpenAI(api_key=api_key, base_url=base_url)

    def embed(self, text: str) -> list[float]:
        resp = self._client.embeddings.create(input=text, model=self._model)
        return resp.data[0].embedding

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        resp = self._client.embeddings.create(input=texts, model=self._model)
        sorted_data = sorted(resp.data, key=lambda x: x.index)
        return [d.embedding for d in sorted_data]

    @property
    def dimension(self) -> int:
        model_dims = {
            "text-embedding-3-small": 1536,
            "text-embedding-3-large": 3072,
            "text-embedding-ada-002": 1536,
        }
        return model_dims.get(self._model, 1536)
