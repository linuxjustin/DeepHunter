"""Google Gemini LLM provider.

Uses the google-generativeai SDK to support Gemini models
(Gemini 2.0 Flash, Gemini 1.5 Pro, etc.) with streaming and JSON mode.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

from deephunter.core.exceptions import LLMError
from deephunter.llm.base import (
    LLMChunk,
    LLMMessage,
    LLMProvider,
    LLMResponse,
    ToolDefinition,
    message_as_dict,
)
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class GeminiProvider(LLMProvider):
    """Production Gemini provider with streaming and JSON mode."""

    name = "gemini"

    def __init__(
        self,
        model: str = "gemini-2.0-flash",
        base_url: str | None = None,
        api_key: str | None = None,
        max_retries: int = 3,
        rate_limit_tpm: int = 2000,
        timeout: float = 120.0,
    ) -> None:
        super().__init__(model, max_retries=max_retries, rate_limit_tpm=rate_limit_tpm, timeout=timeout)
        try:
            import google.generativeai as genai
        except ImportError as exc:
            raise LLMError("google-generativeai package required") from exc
        if api_key:
            genai.configure(api_key=api_key)
        self._genai = genai

    def _convert_messages(self, messages: list[LLMMessage]) -> tuple[str | None, list[dict]]:
        system = None
        history: list[dict] = []
        for m in messages:
            if m.role == "system":
                system = m.content
            elif m.role == "tool":
                history.append({
                    "role": "user",
                    "parts": [{"functionResponse": {"name": m.name or "", "response": {"content": m.content}}}],
                })
            else:
                role = "model" if m.role == "assistant" else "user"
                parts: list[dict] = []
                if m.content:
                    parts.append({"text": m.content})
                if m.tool_calls:
                    for tc in m.tool_calls:
                        fn = tc.get("function", {})
                        parts.append({"functionCall": {"name": fn.get("name", ""), "args": fn.get("arguments", {})}})
                history.append({"role": role, "parts": parts})
        return system, history

    def _generate(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
        tools: list[ToolDefinition] | None = None,
    ) -> LLMResponse:
        system, history = self._convert_messages(messages)
        model_kwargs: dict[str, Any] = {}
        if temperature is not None:
            model_kwargs["temperature"] = temperature
        if max_tokens is not None:
            model_kwargs["max_output_tokens"] = max_tokens
        if json_mode:
            model_kwargs["response_mime_type"] = "application/json"

        try:
            model = self._genai.GenerativeModel(
                self._model,
                system_instruction=system,
                generation_config=model_kwargs,
            )
            prompt = history[-1]["parts"][0]["text"] if history else ""
            chat = model.start_chat(history=history[:-1] if len(history) > 1 else [])
            resp = chat.send_message(prompt)
        except Exception as exc:
            raise LLMError(f"Gemini API error: {exc}") from exc

        content = resp.text or ""
        return LLMResponse(
            content=content,
            model=self._model,
            usage={"prompt_tokens": 0, "completion_tokens": 0},
            raw=resp,
        )

    def _generate_stream(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
        tools: list[ToolDefinition] | None = None,
    ) -> Generator[LLMChunk, None, LLMResponse]:
        system, history = self._convert_messages(messages)
        model_kwargs: dict[str, Any] = {}
        if temperature is not None:
            model_kwargs["temperature"] = temperature
        if max_tokens is not None:
            model_kwargs["max_output_tokens"] = max_tokens
        if json_mode:
            model_kwargs["response_mime_type"] = "application/json"

        try:
            model = self._genai.GenerativeModel(
                self._model,
                system_instruction=system,
                generation_config=model_kwargs,
            )
            prompt = history[-1]["parts"][0]["text"] if history else ""
            chat = model.start_chat(history=history[:-1] if len(history) > 1 else [])
            stream = chat.send_message(prompt, stream=True)
        except Exception as exc:
            raise LLMError(f"Gemini API error: {exc}") from exc

        full_content: list[str] = []
        for chunk in stream:
            if chunk.text:
                full_content.append(chunk.text)
                yield LLMChunk(content=chunk.text)

        return LLMResponse(content="".join(full_content), model=self._model)

    def check_health(self) -> bool:
        try:
            model = self._genai.GenerativeModel(self._model)
            model.generate_content("ping")
            return True
        except Exception:
            return False
