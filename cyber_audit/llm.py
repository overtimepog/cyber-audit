"""Multi-provider LLM client — chat completion with DeepSeek and OpenAI.

Provides ProviderConfig, ChatMessage, ToolCall, LLMResponse dataclasses
and an async chat_completion() function with cost tracking.

API keys are read from environment variables.  If a key is not found in
the live environment, ~/.hermes/.env is loaded as a fallback so the
tool works out-of-the-box with the same keys Hermes Agent uses.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx


# ---------------------------------------------------------------------------
# Auto-load Hermes .env so cyber-audit sees the same keys as Hermes Agent
# ---------------------------------------------------------------------------

def _load_hermes_env() -> None:
    """Load ~/.hermes/.env into os.environ if the file exists."""
    env_path = Path.home() / ".hermes" / ".env"
    if not env_path.exists():
        return
    with env_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip("\"'")
            if key and val and key not in os.environ:
                os.environ[key] = val


_load_hermes_env()


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
# OpenRouter — serves OpenAI models (gpt-4o, gpt-4o-mini) when you don't
# have a direct OpenAI key.  Uses the same OPENROUTER_API_KEY that
# Hermes Agent is configured with.
ProviderConfig.OPENROUTER = ProviderConfig(
    base_url="https://openrouter.ai/api/v1",
    api_key_env="OPENROUTER_API_KEY",
    default_model="openai/gpt-4o",
)
# Codex — uses the local codex CLI (ChatGPT subscription, not API keys).
# No HTTP calls; shells out to `codex exec` which handles tools natively.
ProviderConfig.CODEX = ProviderConfig(
    base_url="codex://local",
    api_key_env="CODEX_SKIP_AUTH",  # dummy — codex uses its own OAuth
    default_model="gpt-5.4",
)


@dataclass
class ChatMessage:
    """A single message in a chat conversation."""

    role: str  # system, user, assistant, tool
    content: str
    tool_call_id: Optional[str] = None
    name: Optional[str] = None
    tool_calls: Optional[List["ToolCall"]] = None


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
    "gpt-5.5-pro": {"input": 30.0, "output": 180.0},
    "gpt-5.5": {"input": 5.0, "output": 30.0},
    "gpt-5.4-mini": {"input": 0.15, "output": 0.60},
    "gpt-5.4": {"input": 2.50, "output": 10.00},
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
    elif provider is ProviderConfig.OPENAI or provider is ProviderConfig.OPENROUTER:
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


# OpenRouter-style model name → (ProviderConfig, api_model_name) mapping.
# Stages.yaml uses "deepseek/deepseek-v4-pro" etc.; this resolves to the
# actual provider and the API-facing model name.

_MODEL_PROVIDER_MAP: dict[str, tuple[ProviderConfig, str]] = {}


def _resolve_model(model: str) -> tuple[ProviderConfig, str]:
    """Parse an OpenRouter-style model name into (provider, api_model).

    ``deepseek/deepseek-v4-pro`` → (DEEPSEEK, ``deepseek-chat``)
    ``deepseek/deepseek-flash``  → (DEEPSEEK, ``deepseek-chat``)
    ``openai/gpt-5.4``          → (CODEX,   ``gpt-5.4``)
    ``openai/gpt-4o``           → (CODEX,   ``gpt-4o``)

    Falls back to DEEPSEEK for unknown providers.
    """
    if "/" in model:
        prefix, _, rest = model.partition("/")
        prefix = prefix.lower()
        if prefix == "deepseek":
            # DeepSeek API only exposes deepseek-chat and deepseek-reasoner
            api_model = "deepseek-chat"
            return ProviderConfig.DEEPSEEK, api_model
        elif prefix == "openai":
            return ProviderConfig.CODEX, rest
    # Bare model name → default to DeepSeek
    return ProviderConfig.DEEPSEEK, model


async def _codex_completion(
    model: str,
    system_prompt: str,
    user_message: str,
    cwd: Path,
    max_tokens: int = 4096,
) -> tuple[str, int, int]:
    """Run a single codex exec call and return (output_text, in_est, out_est)."""
    import asyncio

    # Build prompt and pipe via stdin (avoids shell argument size limits)
    prompt = system_prompt + "\n\n" + user_message

    proc = await asyncio.create_subprocess_exec(
        "codex", "exec",
        "--skip-git-repo-check",
        "--model", model,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(cwd),
    )
    stdout, stderr = await asyncio.wait_for(
        proc.communicate(input=prompt.encode("utf-8")),
        timeout=300,
    )
    output = stdout.decode("utf-8", errors="replace")

    # Try to extract the tokens-used line from stderr (Codex prints it there)
    tokens_line = ""
    for line in stderr.decode("utf-8", errors="replace").split("\n"):
        if "tokens used" in line.lower():
            tokens_line = line.strip()

    # Estimate token counts — Codex doesn't expose exact counts per call
    input_est = len(prompt) // 3  # rough: ~3 chars per token
    output_est = len(output) // 3

    return output, input_est, output_est


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
    # --- Codex provider: shell out to codex CLI ---------------------------
    if provider is ProviderConfig.CODEX:
        # Build the full user message from all messages
        user_text = ""
        for msg in messages:
            user_text += f"[{msg.role}] {msg.content}\n"
        if not user_text:
            user_text = "Proceed."

        system_text = system_prompt or ""
        output, in_est, out_est = await _codex_completion(
            model=model,
            system_prompt=system_text,
            user_message=user_text,
            cwd=Path.cwd(),
            max_tokens=max_tokens,
        )
        return LLMResponse(
            content=output.strip(),
            tool_calls=[],
            finish_reason="stop",
            usage={"input_tokens": in_est, "output_tokens": out_est},
            cost_usd=0.0,  # included in ChatGPT subscription
        )

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
        if msg.tool_calls is not None:
            msg_dict["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments),
                    },
                }
                for tc in msg.tool_calls
            ]
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

    # --- Send request (with retry) ------------------------------------------
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    import asyncio as _asyncio
    last_error = None
    for attempt in range(3):
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(60.0)) as client:
                response = await client.post(
                    f"{provider.base_url}/chat/completions",
                    headers=headers,
                    json=body,
                )
                response.raise_for_status()
                data = response.json()
            break
        except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.RemoteProtocolError) as exc:
            last_error = exc
            if attempt < 2:
                await _asyncio.sleep(2 ** attempt)  # 1s, 2s, 4s
    else:
        raise last_error  # type: ignore[misc]

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
