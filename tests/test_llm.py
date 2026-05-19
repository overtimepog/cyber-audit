"""Test LLM client — chat_completion with multi-provider support (TDD)."""

from __future__ import annotations

import os
from unittest import mock

import httpx
import pytest
from pytest_httpx import HTTPXMock

from cyber_audit.llm import (
    ChatMessage,
    LLMResponse,
    ProviderConfig,
    ToolCall,
    chat_completion,
)


# ---------------------------------------------------------------------------
# Built-in provider configs
# ---------------------------------------------------------------------------

class TestProviderConfig:
    """ProviderConfig dataclass and built-in constants."""

    def test_provider_config_fields(self):
        cfg = ProviderConfig(
            base_url="https://api.example.com/v1",
            api_key_env="EXAMPLE_API_KEY",
            default_model="example-model-v1",
        )
        assert cfg.base_url == "https://api.example.com/v1"
        assert cfg.api_key_env == "EXAMPLE_API_KEY"
        assert cfg.default_model == "example-model-v1"

    def test_provider_config_is_dataclass(self):
        import dataclasses
        assert dataclasses.is_dataclass(ProviderConfig)

    def test_deepseek_builtin(self):
        assert ProviderConfig.DEEPSEEK.base_url == "https://api.deepseek.com/v1"
        assert ProviderConfig.DEEPSEEK.api_key_env == "DEEPSEEK_API_KEY"

    def test_openai_builtin(self):
        assert ProviderConfig.OPENAI.base_url == "https://api.openai.com/v1"
        assert ProviderConfig.OPENAI.api_key_env == "OPENAI_API_KEY"


# ---------------------------------------------------------------------------
# ChatMessage dataclass
# ---------------------------------------------------------------------------

class TestChatMessage:
    """ChatMessage dataclass."""

    def test_chat_message_fields(self):
        msg = ChatMessage(role="user", content="Hello")
        assert msg.role == "user"
        assert msg.content == "Hello"
        assert msg.tool_call_id is None
        assert msg.name is None

    def test_chat_message_with_tool_call_id(self):
        msg = ChatMessage(
            role="tool",
            content="result",
            tool_call_id="call_123",
            name="my_tool",
        )
        assert msg.role == "tool"
        assert msg.content == "result"
        assert msg.tool_call_id == "call_123"
        assert msg.name == "my_tool"

    def test_chat_message_is_dataclass(self):
        import dataclasses
        assert dataclasses.is_dataclass(ChatMessage)


# ---------------------------------------------------------------------------
# ToolCall dataclass
# ---------------------------------------------------------------------------

class TestToolCall:
    """ToolCall dataclass."""

    def test_tool_call_fields(self):
        tc = ToolCall(id="call_abc", name="read_file", arguments={"path": "/tmp/x"})
        assert tc.id == "call_abc"
        assert tc.name == "read_file"
        assert tc.arguments == {"path": "/tmp/x"}

    def test_tool_call_is_dataclass(self):
        import dataclasses
        assert dataclasses.is_dataclass(ToolCall)


# ---------------------------------------------------------------------------
# LLMResponse dataclass
# ---------------------------------------------------------------------------

class TestLLMResponse:
    """LLMResponse dataclass."""

    def test_llm_response_text_content(self):
        resp = LLMResponse(
            content="Hello from AI",
            tool_calls=[],
            finish_reason="stop",
            usage={"input_tokens": 10, "output_tokens": 5},
            cost_usd=0.0001,
        )
        assert resp.content == "Hello from AI"
        assert resp.tool_calls == []
        assert resp.finish_reason == "stop"
        assert resp.usage == {"input_tokens": 10, "output_tokens": 5}
        assert resp.cost_usd == 0.0001

    def test_llm_response_tool_calls(self):
        tc = ToolCall(id="call_1", name="bash", arguments={"cmd": "ls"})
        resp = LLMResponse(
            content=None,
            tool_calls=[tc],
            finish_reason="tool_calls",
            usage={"input_tokens": 20, "output_tokens": 15},
            cost_usd=0.0002,
        )
        assert resp.content is None
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "bash"
        assert resp.finish_reason == "tool_calls"

    def test_llm_response_is_dataclass(self):
        import dataclasses
        assert dataclasses.is_dataclass(LLMResponse)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def deepseek_provider():
    return ProviderConfig.DEEPSEEK


@pytest.fixture
def openai_provider():
    return ProviderConfig.OPENAI


# ---------------------------------------------------------------------------
# Chat completion — text content
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_chat_completion_returns_text_content(
    httpx_mock: HTTPXMock, deepseek_provider
):
    """chat_completion should return text content from the API response."""
    httpx_mock.add_response(
        url="https://api.deepseek.com/v1/chat/completions",
        method="POST",
        json={
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "created": 1677652288,
            "model": "deepseek-chat",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Hello! How can I help you?",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 6,
                "total_tokens": 16,
            },
        },
    )

    with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "sk-test-key"}):
        response = await chat_completion(
            provider=deepseek_provider,
            model="deepseek-chat",
            messages=[ChatMessage(role="user", content="Hi")],
        )

    assert response.content == "Hello! How can I help you?"
    assert response.tool_calls == []
    assert response.finish_reason == "stop"
    assert response.usage["input_tokens"] == 10
    assert response.usage["output_tokens"] == 6


# ---------------------------------------------------------------------------
# Chat completion — tool calls
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_chat_completion_returns_tool_calls(
    httpx_mock: HTTPXMock, deepseek_provider
):
    """chat_completion should parse tool_calls from the API response."""
    httpx_mock.add_response(
        url="https://api.deepseek.com/v1/chat/completions",
        method="POST",
        json={
            "id": "chatcmpl-456",
            "object": "chat.completion",
            "created": 1677652290,
            "model": "deepseek-chat",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_read_1",
                                "type": "function",
                                "function": {
                                    "name": "read_file",
                                    "arguments": '{"path": "/tmp/test.txt"}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": {
                "prompt_tokens": 20,
                "completion_tokens": 15,
                "total_tokens": 35,
            },
        },
    )

    with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "sk-test-key"}):
        response = await chat_completion(
            provider=deepseek_provider,
            model="deepseek-chat",
            messages=[ChatMessage(role="user", content="Read /tmp/test.txt")],
            tools=[{"type": "function", "function": {"name": "read_file"}}],
        )

    assert response.content is None
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].id == "call_read_1"
    assert response.tool_calls[0].name == "read_file"
    assert response.tool_calls[0].arguments == {"path": "/tmp/test.txt"}
    assert response.finish_reason == "tool_calls"


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_system_prompt_included(
    httpx_mock: HTTPXMock, deepseek_provider
):
    """System prompt should be added as first message in the request."""
    httpx_mock.add_response(
        url="https://api.deepseek.com/v1/chat/completions",
        method="POST",
        json={
            "id": "chatcmpl-789",
            "object": "chat.completion",
            "created": 1677652300,
            "model": "deepseek-chat",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "OK"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 5,
                "completion_tokens": 1,
                "total_tokens": 6,
            },
        },
    )

    with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "sk-test-key"}):
        await chat_completion(
            provider=deepseek_provider,
            model="deepseek-chat",
            messages=[ChatMessage(role="user", content="Hello")],
            system_prompt="You are a helpful assistant.",
        )

    # Verify the system prompt was sent as the first message
    request = httpx_mock.get_request()
    body = httpx.Response(200, content=request.content).json()
    assert body["messages"][0]["role"] == "system"
    assert body["messages"][0]["content"] == "You are a helpful assistant."
    assert body["messages"][1]["role"] == "user"
    assert body["messages"][1]["content"] == "Hello"


# ---------------------------------------------------------------------------
# API key from environment
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_key_from_environment(
    httpx_mock: HTTPXMock, deepseek_provider
):
    """API key should be read from environment variable and sent as Bearer token."""
    httpx_mock.add_response(
        url="https://api.deepseek.com/v1/chat/completions",
        method="POST",
        json={
            "id": "chatcmpl-999",
            "object": "chat.completion",
            "created": 1677652310,
            "model": "deepseek-chat",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Pong"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 2,
                "completion_tokens": 1,
                "total_tokens": 3,
            },
        },
    )

    with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "sk-my-secret-key"}):
        await chat_completion(
            provider=deepseek_provider,
            model="deepseek-chat",
            messages=[ChatMessage(role="user", content="Ping")],
        )

    request = httpx_mock.get_request()
    auth_header = request.headers.get("Authorization")
    assert auth_header == "Bearer sk-my-secret-key"


# ---------------------------------------------------------------------------
# Missing API key
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_missing_api_key_raises(deepseek_provider):
    """Missing API key should raise a clear error."""
    with mock.patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ValueError, match="API key not found"):
            await chat_completion(
                provider=deepseek_provider,
                model="deepseek-chat",
                messages=[ChatMessage(role="user", content="Hi")],
            )


# ---------------------------------------------------------------------------
# API error
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_error_raises(httpx_mock: HTTPXMock, deepseek_provider):
    """HTTP error from the API should raise an exception."""
    httpx_mock.add_response(
        url="https://api.deepseek.com/v1/chat/completions",
        method="POST",
        status_code=500,
        json={"error": {"message": "Internal server error"}},
    )

    with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "sk-test-key"}):
        with pytest.raises(httpx.HTTPStatusError):
            await chat_completion(
                provider=deepseek_provider,
                model="deepseek-chat",
                messages=[ChatMessage(role="user", content="Hi")],
            )


# ---------------------------------------------------------------------------
# Cost calculation — DeepSeek
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cost_calculation_deepseek(
    httpx_mock: HTTPXMock, deepseek_provider
):
    """DeepSeek v4-pro: $0.28/M input, $0.28/M output."""
    httpx_mock.add_response(
        url="https://api.deepseek.com/v1/chat/completions",
        method="POST",
        json={
            "id": "chatcmpl-cost-1",
            "object": "chat.completion",
            "created": 1677652320,
            "model": "deepseek-chat",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Result"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 1_000_000,
                "completion_tokens": 500_000,
                "total_tokens": 1_500_000,
            },
        },
    )

    with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "sk-test-key"}):
        response = await chat_completion(
            provider=deepseek_provider,
            model="deepseek-chat",
            messages=[ChatMessage(role="user", content="Test")],
        )

    # 1M input * $0.28/M = $0.28, 500k output * $0.28/M = $0.14, total = $0.42
    assert response.cost_usd == pytest.approx(0.42, rel=1e-6)


# ---------------------------------------------------------------------------
# Cost calculation — OpenAI gpt-4o
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cost_calculation_openai_gpt4o(
    httpx_mock: HTTPXMock, openai_provider
):
    """OpenAI gpt-4o: $2.50/M input, $10.00/M output."""
    httpx_mock.add_response(
        url="https://api.openai.com/v1/chat/completions",
        method="POST",
        json={
            "id": "chatcmpl-cost-2",
            "object": "chat.completion",
            "created": 1677652330,
            "model": "gpt-4o-2024-08-06",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Result"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 1_000_000,
                "completion_tokens": 500_000,
                "total_tokens": 1_500_000,
            },
        },
    )

    with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test-key"}):
        response = await chat_completion(
            provider=openai_provider,
            model="gpt-4o",
            messages=[ChatMessage(role="user", content="Test")],
        )

    # 1M input * $2.50/M = $2.50, 500k output * $10.00/M = $5.00, total = $7.50
    assert response.cost_usd == pytest.approx(7.50, rel=1e-6)


# ---------------------------------------------------------------------------
# Cost calculation — OpenAI gpt-4o-mini
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cost_calculation_openai_gpt4o_mini(
    httpx_mock: HTTPXMock, openai_provider
):
    """OpenAI gpt-4o-mini: $0.15/M input, $0.60/M output."""
    httpx_mock.add_response(
        url="https://api.openai.com/v1/chat/completions",
        method="POST",
        json={
            "id": "chatcmpl-cost-3",
            "object": "chat.completion",
            "created": 1677652340,
            "model": "gpt-4o-mini-2024-07-18",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Result"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 1_000_000,
                "completion_tokens": 500_000,
                "total_tokens": 1_500_000,
            },
        },
    )

    with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test-key"}):
        response = await chat_completion(
            provider=openai_provider,
            model="gpt-4o-mini",
            messages=[ChatMessage(role="user", content="Test")],
        )

    # 1M input * $0.15/M = $0.15, 500k output * $0.60/M = $0.30, total = $0.45
    assert response.cost_usd == pytest.approx(0.45, rel=1e-6)


# ---------------------------------------------------------------------------
# Multiple messages
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_multiple_messages_in_conversation(
    httpx_mock: HTTPXMock, deepseek_provider
):
    """All messages should be sent in order."""
    httpx_mock.add_response(
        url="https://api.deepseek.com/v1/chat/completions",
        method="POST",
        json={
            "id": "chatcmpl-multi",
            "object": "chat.completion",
            "created": 1677652350,
            "model": "deepseek-chat",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Understood."},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 30,
                "completion_tokens": 5,
                "total_tokens": 35,
            },
        },
    )

    messages = [
        ChatMessage(role="user", content="First question"),
        ChatMessage(role="assistant", content="First answer"),
        ChatMessage(role="user", content="Second question"),
    ]

    with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "sk-test-key"}):
        await chat_completion(
            provider=deepseek_provider,
            model="deepseek-chat",
            messages=messages,
        )

    request = httpx_mock.get_request()
    body = httpx.Response(200, content=request.content).json()
    assert len(body["messages"]) == 3
    assert body["messages"][0]["role"] == "user"
    assert body["messages"][0]["content"] == "First question"
    assert body["messages"][1]["role"] == "assistant"
    assert body["messages"][1]["content"] == "First answer"
    assert body["messages"][2]["role"] == "user"
    assert body["messages"][2]["content"] == "Second question"


# ---------------------------------------------------------------------------
# Temperature and max_tokens passed through
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_temperature_and_max_tokens_passed_through(
    httpx_mock: HTTPXMock, deepseek_provider
):
    """temperature and max_tokens should be forwarded in the request body."""
    httpx_mock.add_response(
        url="https://api.deepseek.com/v1/chat/completions",
        method="POST",
        json={
            "id": "chatcmpl-params",
            "object": "chat.completion",
            "created": 1677652360,
            "model": "deepseek-chat",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "OK"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 3,
                "completion_tokens": 1,
                "total_tokens": 4,
            },
        },
    )

    with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "sk-test-key"}):
        await chat_completion(
            provider=deepseek_provider,
            model="deepseek-chat",
            messages=[ChatMessage(role="user", content="Hi")],
            max_tokens=2048,
            temperature=0.7,
        )

    request = httpx_mock.get_request()
    body = httpx.Response(200, content=request.content).json()
    assert body["max_tokens"] == 2048
    assert body["temperature"] == 0.7


# ---------------------------------------------------------------------------
# Default parameters
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_default_max_tokens_and_temperature(
    httpx_mock: HTTPXMock, deepseek_provider
):
    """Default max_tokens=4096 and temperature=0.1 should be sent."""
    httpx_mock.add_response(
        url="https://api.deepseek.com/v1/chat/completions",
        method="POST",
        json={
            "id": "chatcmpl-defaults",
            "object": "chat.completion",
            "created": 1677652370,
            "model": "deepseek-chat",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "OK"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 2,
                "completion_tokens": 1,
                "total_tokens": 3,
            },
        },
    )

    with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "sk-test-key"}):
        await chat_completion(
            provider=deepseek_provider,
            model="deepseek-chat",
            messages=[ChatMessage(role="user", content="Hi")],
        )

    request = httpx_mock.get_request()
    body = httpx.Response(200, content=request.content).json()
    assert body["max_tokens"] == 4096
    assert body["temperature"] == 0.1
