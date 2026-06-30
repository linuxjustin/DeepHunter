from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Chunk:
    text: str
    index: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    source_id: str = ""
    token_count: int = 0


class TextChunker:
    def __init__(
        self,
        chunk_size: int = 512,
        chunk_overlap: int = 64,
        by_tokens: bool = True,
    ) -> None:
        self._chunk_size = chunk_size
        self._chunk_overlap = chunk_overlap
        self._by_tokens = by_tokens

    def chunk(self, text: str, source_id: str = "", metadata: dict[str, Any] | None = None) -> list[Chunk]:
        if not text:
            return []
        if self._by_tokens:
            chunks = self._chunk_by_tokens(text)
        else:
            chunks = self._chunk_by_chars(text)
        meta = metadata or {}
        return [
            Chunk(
                text=c,
                index=i,
                metadata=meta,
                source_id=source_id,
                token_count=self._estimate_tokens(c),
            )
            for i, c in enumerate(chunks)
        ]

    def _chunk_by_tokens(self, text: str) -> list[str]:
        words = text.split()
        chunks: list[str] = []
        if not words:
            return chunks

        chunk_size = self._chunk_size
        overlap = self._chunk_overlap
        step = max(1, chunk_size - overlap)
        i = 0
        while i < len(words):
            chunk_words = words[i : i + chunk_size]
            chunks.append(" ".join(chunk_words))
            i += step
            if i >= len(words):
                break
        return chunks

    def _chunk_by_chars(self, text: str) -> list[str]:
        chunks: list[str] = []
        step = max(1, self._chunk_size - self._chunk_overlap)
        i = 0
        while i < len(text):
            chunks.append(text[i : i + self._chunk_size])
            i += step
            if i >= len(text):
                break
        return chunks

    def chunk_document(
        self,
        text: str,
        source_id: str = "",
        metadata: dict[str, Any] | None = None,
        section_pattern: str | None = None,
    ) -> list[Chunk]:
        if section_pattern:
            sections = self._split_by_sections(text, section_pattern)
            all_chunks: list[Chunk] = []
            for sec_title, sec_text in sections:
                sec_meta = dict(metadata or {})
                sec_meta["section"] = sec_title
                chunks = self.chunk(sec_text, source_id=source_id, metadata=sec_meta)
                all_chunks.extend(chunks)
            return all_chunks
        return self.chunk(text, source_id=source_id, metadata=metadata)

    @staticmethod
    def _split_by_sections(text: str, pattern: str) -> list[tuple[str, str]]:
        sections: list[tuple[str, str]] = []
        parts = re.split(pattern, text, flags=re.MULTILINE)
        current_title = ""
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if re.match(pattern, part, re.MULTILINE):
                current_title = part
            else:
                sections.append((current_title, part))
                current_title = ""
        return sections

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        return len(text.split())

    @property
    def chunk_size(self) -> int:
        return self._chunk_size

    @property
    def chunk_overlap(self) -> int:
        return self._chunk_overlap
