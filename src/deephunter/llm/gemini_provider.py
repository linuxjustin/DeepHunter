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
        self._model_cache: dict[str | None, "genai.GenerativeModel"] = {}

    def _get_model(self, system: str | None = None) -> "genai.GenerativeModel":
        """Get or create a cached GenerativeModel instance."""
        if system not in self._model_cache:
            self._model_cache[system] = self._genai.GenerativeModel(
                self._model,
                system_instruction=system,
            )
        return self._model_cache[system]

    def _make_generation_config(self, *, temperature: float | None, max_tokens: int | None, json_mode: bool) -> dict[str, Any]:
        """Build generation config dict for send_message()."""
        cfg: dict[str, Any] = {}
        if temperature is not None:
            cfg["temperature"] = temperature
        if max_tokens is not None:
            cfg["max_output_tokens"] = max_tokens
        if json_mode:
            cfg["response_mime_type"] = "application/json"
        return cfg if cfg else {}

    def _make_tools_config(self, tools: list[ToolDefinition] | None) -> list[dict] | None:
        """Build tools config for generation."""
        if not tools:
            return None
        return [
            {"function_declarations": [
                {"name": t.name, "description": t.description, "parameters": t.parameters}
                for t in tools
            ]}
        ]

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
        gen_config = self._make_generation_config(temperature=temperature, max_tokens=max_tokens, json_mode=json_mode)
        tools_config = self._make_tools_config(tools)

        model = self._get_model(system)
        prompt = history[-1]["parts"][0]["text"] if history else ""
        chat_history = history[:-1] if len(history) > 1 else []

        try:
            chat = model.start_chat(history=chat_history)
            resp = chat.send_message(prompt, generation_config=gen_config or None, tools=tools_config)
        except Exception as exc:
            raise LLMError(f"Gemini API error: {exc}") from exc

        content = resp.text or ""

        tool_calls: list[dict] = []
        for candidate in getattr(resp, "candidates", []) or []:
            for part in getattr(candidate.content, "parts", []) or []:
                fc = getattr(part, "function_call", None)
                if fc:
                    tool_calls.append({
                        "id": f"call_{hash(getattr(fc, 'name', '') or '')}",
                        "type": "function",
                        "function": {
                            "name": getattr(fc, "name", "") or "",
                            "arguments": dict(getattr(fc, "args", {}) or {}),
                        },
                    })

        return LLMResponse(
            content=content,
            model=self._model,
            usage={"prompt_tokens": 0, "completion_tokens": 0},
            tool_calls=tool_calls,
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
        gen_config = self._make_generation_config(temperature=temperature, max_tokens=max_tokens, json_mode=json_mode)
        tools_config = self._make_tools_config(tools)

        model = self._get_model(system)
        prompt = history[-1]["parts"][0]["text"] if history else ""
        chat_history = history[:-1] if len(history) > 1 else []

        try:
            chat = model.start_chat(history=chat_history)
            stream = chat.send_message(prompt, stream=True, generation_config=gen_config or None, tools=tools_config)
        except Exception as exc:
            raise LLMError(f"Gemini stream error: {exc}") from exc

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
