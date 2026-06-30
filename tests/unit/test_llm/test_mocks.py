"""Tests for LLM provider mocks."""

from __future__ import annotations

from deephunter.llm.base import LLMMessage, ToolDefinition
from tests.unit.test_llm.mocks import (
    FallbackSequenceProvider,
    MockProvider,
    MockResponse,
    StreamingMockProvider,
    ToolCallingMockProvider,
    create_mock_provider,
)


class TestMockProvider:
    def test_mock_provider_basic(self) -> None:
        mock = MockProvider()
        messages = [LLMMessage(role="user", content="Hello")]
        response = mock.generate(messages)
        assert response.content == "Mock response"
        assert response.model == "mock-model"

    def test_mock_provider_configurable_response(self) -> None:
        custom = MockResponse(content="Custom response", model="custom-model", usage={"prompt_tokens": 5, "completion_tokens": 10, "total_tokens": 15})
        mock = MockProvider(mock_response=custom)
        messages = [LLMMessage(role="user", content="Hello")]
        response = mock.generate(messages)
        assert response.content == "Custom response"
        assert response.model == "custom-model"
        assert response.usage["total_tokens"] == 15

    def test_mock_provider_call_count(self) -> None:
        mock = MockProvider()
        messages = [LLMMessage(role="user", content="Hello")]
        mock.generate(messages)
        mock.generate(messages)
        assert mock.call_count == 2

    def test_mock_provider_last_messages(self) -> None:
        mock = MockProvider()
        messages = [LLMMessage(role="user", content="Test message")]
        mock.generate(messages)
        assert mock.last_messages[0].content == "Test message"

    def test_mock_provider_fail_with(self) -> None:
        mock = MockProvider(fail_with=RuntimeError("Provider error"))
        messages = [LLMMessage(role="user", content="Hello")]
        try:
            mock.generate(messages)
            assert False, "Should have raised"
        except RuntimeError as e:
            assert "Provider error" in str(e)

    def test_mock_provider_check_health(self) -> None:
        mock = MockProvider()
        assert mock.check_health() is True

    def test_mock_provider_json_mode(self) -> None:
        mock = MockProvider(mock_response=MockResponse(content='{"result": "valid"}'))
        messages = [LLMMessage(role="user", content="Return JSON")]
        response = mock.generate(messages, json_mode=True)
        assert response.content == '{"result": "valid"}'


class TestStreamingMockProvider:
    def test_streaming_provider(self) -> None:
        mock = StreamingMockProvider(chunks=["Hello", " ", "World"])
        messages = [LLMMessage(role="user", content="Say Hello World")]
        chunks = []
        response = None
        for chunk in mock.generate_stream(messages):
            chunks.append(chunk.content)
            if response is None:
                response = chunk
        assert "".join(chunks) == "Hello World"

    def test_streaming_provider_with_delay(self) -> None:
        mock = StreamingMockProvider(chunks=["A", "B"], chunk_delay_ms=1.0)
        messages = [LLMMessage(role="user", content="Test")]
        full_response = None
        for chunk in mock.generate_stream(messages):
            full_response = chunk
        assert full_response is not None


class TestToolCallingMockProvider:
    def test_tool_calling_with_tools(self) -> None:
        mock = ToolCallingMockProvider()
        messages = [LLMMessage(role="user", content="Use a tool")]
        tools = [ToolDefinition(name="search", description="Search the web", parameters={"type": "object", "properties": {"query": {"type": "string"}}})]
        response = mock.generate(messages, tools=tools)
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0]["function"]["name"] == "search"

    def test_tool_calling_without_tools(self) -> None:
        mock = ToolCallingMockProvider()
        messages = [LLMMessage(role="user", content="Hello")]
        response = mock.generate(messages)
        assert len(response.tool_calls) == 0


class TestFallbackSequenceProvider:
    def test_fallback_sequence(self) -> None:
        mock1 = MockProvider(mock_response=MockResponse(content="First"), fail_with=RuntimeError("Fail"))
        mock2 = MockProvider(mock_response=MockResponse(content="Second"))
        sequence = FallbackSequenceProvider([mock1, mock2])
        p1 = sequence.get_next_provider()
        assert p1 is mock1
        p2 = sequence.get_next_provider()
        assert p2 is mock2
        assert sequence.get_next_provider() is None

    def test_fallback_sequence_reset(self) -> None:
        mock1 = MockProvider()
        mock2 = MockProvider()
        sequence = FallbackSequenceProvider([mock1, mock2])
        sequence.get_next_provider()
        sequence.get_next_provider()
        sequence.reset()
        assert sequence.get_next_provider() is mock1


class TestCreateMockProvider:
    def test_create_mock_by_type(self) -> None:
        mock = create_mock_provider("mock")
        assert isinstance(mock, MockProvider)
        assert mock.name == "mock"

    def test_create_streaming_mock(self) -> None:
        mock = create_mock_provider("streaming")
        assert isinstance(mock, StreamingMockProvider)
        assert mock.name == "mock-streaming"

    def test_create_tool_calling_mock(self) -> None:
        mock = create_mock_provider("tool_calling")
        assert isinstance(mock, ToolCallingMockProvider)
        assert mock.name == "mock-tool-calling"