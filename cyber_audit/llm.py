"""Multi-provider LLM client — chat completion with DeepSeek and OpenAI.

Provides ProviderConfig, ChatMessage, ToolCall, LLMResponse dataclasses
and an async chat_completion() function with cost tracking.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ProviderConfig:
    """Configuration for an LLM provider."""

    base_url: str
    api_key_env: str
    default_model: str


# Built-in provider configs (class-level constants)
ProviderConfig.DEEPSEEK = ProviderConfig(
    base_url="https://api.deepseek.com/v1",
    api_key_env="DEEPSEEK_API_KEY",
    default_model="deepseek-chat",
)
ProviderConfig.OPENAI = ProviderConfig(
    base_url="https://api.openai.com/v1",
    api_key_env="OPENAI_API_KEY",
    default_model="gpt-4o",
)


@dataclass
class ChatMessage:
    """A single message in a chat conversation."""

    role: str  # system, user, assistant, tool
    content: str
    tool_call_id: Optional[str] = None
    name: Optional[str] = None


@dataclass
class ToolCall:
    """A tool/function call requested by the LLM."""

    id: str
    name: str
    arguments: Dict[str, Any]


@dataclass
class LLMResponse:
    """Complete response from an LLM chat completion."""

    content: Optional[str]
    tool_calls: List[ToolCall]
    finish_reason: str
    usage: Dict[str, int]  # input_tokens, output_tokens
    cost_usd: float


# ---------------------------------------------------------------------------
# Pricing tables (USD per 1M tokens)
# ---------------------------------------------------------------------------

# DeepSeek pricing: v4-pro $0.28/M input, $0.28/M output
DEEPSEEK_PRICE_INPUT = 0.28
DEEPSEEK_PRICE_OUTPUT = 0.28

# OpenAI pricing by model prefix
OPENAI_PRICING = {
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4o": {"input": 2.50, "output": 10.00},
}
OPENAI_DEFAULT_PRICING = {"input": 2.50, "output": 10.00}


def _calculate_cost(
    provider: ProviderConfig, model: str, input_tokens: int, output_tokens: int
) -> float:
    """Calculate USD cost based on provider, model, and token usage."""
    if provider is ProviderConfig.DEEPSEEK:
        input_cost = (input_tokens / 1_000_000) * DEEPSEEK_PRICE_INPUT
        output_cost = (output_tokens / 1_000_000) * DEEPSEEK_PRICE_OUTPUT
        return input_cost + output_cost
    elif provider is ProviderConfig.OPENAI:
        # Match by model prefix (e.g., "gpt-4o-mini" matches "gpt-4o-mini-2024-07-18")
        pricing = OPENAI_DEFAULT_PRICING
        for prefix, rates in OPENAI_PRICING.items():
            if model.startswith(prefix):
                pricing = rates
                break
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        return input_cost + output_cost
    else:
        return 0.0


# ---------------------------------------------------------------------------
# Chat completion
# ---------------------------------------------------------------------------


async def chat_completion(
    provider: ProviderConfig,
    model: str,
    messages: List[ChatMessage],
    *,
    system_prompt: Optional[str] = None,
    tools: Optional[List[Dict[str, Any]]] = None,
    max_tokens: int = 4096,
    temperature: float = 0.1,
) -> LLMResponse:
    """Send a chat completion request to the provider and return the response.

    Args:
        provider: ProviderConfig with base_url and api_key_env.
        model: Model name (e.g., "deepseek-chat", "gpt-4o").
        messages: List of ChatMessage objects.
        system_prompt: Optional system prompt prepended to messages.
        tools: Optional list of tool definitions for function calling.
        max_tokens: Maximum tokens in the response (default 4096).
        temperature: Sampling temperature (default 0.1).

    Returns:
        LLMResponse with content, tool_calls, finish_reason, usage, and cost.

    Raises:
        ValueError: If the API key environment variable is not set.
        httpx.HTTPStatusError: If the API returns an error status.
    """
    # --- Read API key -------------------------------------------------------
    api_key = os.environ.get(provider.api_key_env)
    if not api_key:
        raise ValueError(
            f"API key not found: environment variable "
            f"{provider.api_key_env!r} is not set"
        )

    # --- Build messages list ------------------------------------------------
    api_messages: List[Dict[str, Any]] = []
    if system_prompt:
        api_messages.append({"role": "system", "content": system_prompt})
    for msg in messages:
        msg_dict: Dict[str, Any] = {"role": msg.role, "content": msg.content}
        if msg.tool_call_id is not None:
            msg_dict["tool_call_id"] = msg.tool_call_id
        if msg.name is not None:
            msg_dict["name"] = msg.name
        api_messages.append(msg_dict)

    # --- Build request body -------------------------------------------------
    body: Dict[str, Any] = {
        "model": model,
        "messages": api_messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if tools:
        body["tools"] = tools

    # --- Send request -------------------------------------------------------
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{provider.base_url}/chat/completions",
            headers=headers,
            json=body,
        )
        response.raise_for_status()
        data = response.json()

    # --- Parse response -----------------------------------------------------
    choice = data["choices"][0]
    message = choice["message"]
    finish_reason = choice.get("finish_reason", "stop")

    content: Optional[str] = message.get("content")
    tool_calls: List[ToolCall] = []

    if message.get("tool_calls"):
        for tc in message["tool_calls"]:
            func = tc["function"]
            try:
                arguments = json.loads(func["arguments"])
            except (json.JSONDecodeError, TypeError):
                arguments = {}
            tool_calls.append(
                ToolCall(
                    id=tc["id"],
                    name=func["name"],
                    arguments=arguments,
                )
            )

    usage_raw = data.get("usage", {})
    input_tokens = usage_raw.get("prompt_tokens", 0)
    output_tokens = usage_raw.get("completion_tokens", 0)

    usage = {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }

    cost_usd = _calculate_cost(provider, model, input_tokens, output_tokens)

    return LLMResponse(
        content=content,
        tool_calls=tool_calls,
        finish_reason=finish_reason,
        usage=usage,
        cost_usd=cost_usd,
    )
