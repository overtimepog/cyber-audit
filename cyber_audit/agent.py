"""Agent loop — run one LLM agent for a pipeline stage.

Replaces the Claude Agent SDK with a custom tool-use loop:
system prompt + user input → LLM → parse tool calls or text →
execute tools → loop → schema validate → repair → AgentResult.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyber_audit.json_utils import extract_json, validate_schema
from cyber_audit.llm import (
    ChatMessage,
    LLMResponse,
    ProviderConfig,
    ToolCall,
    chat_completion,
)
from cyber_audit.tools import ToolsSession

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class AgentResult:
    payload: dict
    cost_usd: float | None
    input_tokens: int | None
    output_tokens: int | None
    num_turns: int | None
    duration_ms: int | None
    session_id: str | None
    artifact_path: Path
    repair_used: bool


class AgentRunError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Tool definitions (OpenAI function-calling schema)
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS: dict[str, dict] = {
    "Read": {
        "type": "function",
        "function": {
            "name": "Read",
            "description": "Read a file from the repository. Returns content with line numbers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Repo-relative path to the file to read.",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Line number to start reading from (1-indexed, default: 1).",
                        "default": 1,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum lines to read (default: 500).",
                        "default": 500,
                    },
                },
                "required": ["path"],
            },
        },
    },
    "Grep": {
        "type": "function",
        "function": {
            "name": "Grep",
            "description": "Search for a regex pattern in files. Returns matching lines with file and line number.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regex pattern to search for.",
                    },
                    "path": {
                        "type": "string",
                        "description": "Repo-relative file or directory to search in.",
                    },
                    "glob": {
                        "type": "string",
                        "description": "Optional file glob filter (e.g. '*.py').",
                    },
                },
                "required": ["pattern", "path"],
            },
        },
    },
    "Glob": {
        "type": "function",
        "function": {
            "name": "Glob",
            "description": "Find files matching a glob pattern. Returns relative file paths.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Glob pattern (e.g. '**/*.py', '*.md').",
                    },
                    "path": {
                        "type": "string",
                        "description": "Repo-relative directory to search in.",
                    },
                },
                "required": ["pattern", "path"],
            },
        },
    },
    "Bash": {
        "type": "function",
        "function": {
            "name": "Bash",
            "description": "Execute a shell command in the repository. Use for compile/run of PoCs, git log, ls, find, cat, file, wc -l, language tool listings. Do NOT modify files outside the scratch directory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute.",
                    },
                    "workdir": {
                        "type": "string",
                        "description": "Working directory (repo-relative, default: '.').",
                        "default": ".",
                    },
                },
                "required": ["command"],
            },
        },
    },
}

# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------


async def run_agent(
    *,
    stage: str,
    prompt_file: Path,
    user_input: dict,
    schema_file: Path,
    allowed_tools: list[str],
    model: str,
    provider: ProviderConfig,
    cwd: Path,
    add_dirs: list[Path] | None = None,
    max_turns: int = 25,
    artifact_dir: Path,
    artifact_name: str,
    repair_attempts: int = 1,
) -> AgentResult:
    """Run one agent for one task / stage.

    The system prompt is the contents of *prompt_file*.  The user
    message is ``json.dumps(user_input)``.  On schema-validation
    failure up to *repair_attempts* follow-up turns are sent asking
    the model to fix the output.  Returns a validated ``AgentResult``.
    """
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"{artifact_name}.jsonl"
    cwd.mkdir(parents=True, exist_ok=True)

    # --- Build system prompt -----------------------------------------------
    system_prompt = prompt_file.read_text()
    schema_text = schema_file.read_text()
    system_prompt += (
        "\n\n# Output schema\n\n"
        "Your output MUST validate against this JSON Schema. "
        "Pay attention to nested objects, required fields, and "
        "`additionalProperties: false`.\n\n"
        f"```json\n{schema_text}\n```\n"
    )

    # --- Build tool definitions --------------------------------------------
    tools: list[dict] | None = None
    if allowed_tools:
        tools = [TOOL_DEFINITIONS[t] for t in allowed_tools if t in TOOL_DEFINITIONS]
        if not tools:
            tools = None

    # --- Create tool session -----------------------------------------------
    ts = ToolsSession(str(cwd))

    # --- Conversation history ----------------------------------------------
    messages: list[ChatMessage] = []
    initial_prompt = json.dumps(user_input, ensure_ascii=False)

    started_at = time.time()
    total_input_tokens = 0
    total_output_tokens = 0
    total_cost = 0.0
    turn_count = 0
    last_text = ""
    repair_used = False
    errors: list[str] = []
    payload: dict = {}

    # --- Write JSONL artifact header --------------------------------------
    with artifact_path.open("w") as art:
        _write_artifact(
            art,
            {
                "kind": "meta",
                "stage": stage,
                "model": model,
                "provider": provider.base_url,
                "started_at": started_at,
            },
        )
        _write_artifact(art, {"kind": "user", "text": initial_prompt[:50000]})

        # --- Agent loop ----------------------------------------------------
        turn_count = 0
        while turn_count < max_turns:
            turn_count += 1

            # Determine current-user message for this turn
            current_messages = list(messages)
            current_messages.append(ChatMessage(role="user", content=initial_prompt))

            resp: LLMResponse = await chat_completion(
                provider=provider,
                model=model,
                messages=current_messages,
                system_prompt=system_prompt,
                tools=tools,
            )

            total_input_tokens += resp.usage.get("input_tokens", 0)
            total_output_tokens += resp.usage.get("output_tokens", 0)
            total_cost += resp.cost_usd

            # Write assistant message to artifact
            _write_artifact(
                art,
                {
                    "kind": "assistant",
                    "content": resp.content,
                    "tool_calls": [
                        {"id": tc.id, "name": tc.name, "arguments": tc.arguments}
                        for tc in resp.tool_calls
                    ],
                    "usage": resp.usage,
                    "cost_usd": resp.cost_usd,
                },
            )

            # --- Handle tool calls ------------------------------------------
            if resp.tool_calls:
                for tc in resp.tool_calls:
                    result = await _execute_tool(ts, tc)
                    _write_artifact(
                        art,
                        {
                            "kind": "tool_result",
                            "tool_call_id": tc.id,
                            "name": tc.name,
                            "result": result,
                        },
                    )
                    # Append assistant tool_call + tool result to messages
                    messages.append(
                        ChatMessage(
                            role="assistant",
                            content="",
                            tool_calls=[tc],
                        )
                    )
                    messages.append(
                        ChatMessage(
                            role="tool",
                            content=json.dumps(result, ensure_ascii=False),
                            tool_call_id=tc.id,
                            name=tc.name,
                        )
                    )

                # After tool calls, clear initial_prompt so we don't re-send it
                initial_prompt = ""
                continue

            # --- Text response — try to extract JSON -----------------------
            last_text = resp.content or ""
            errors = _validate(last_text, schema_file)
            if not errors:
                break  # valid JSON, done

            # --- Schema repair loop ----------------------------------------
            for attempt in range(repair_attempts):
                repair_used = True
                repair_prompt = _build_repair_prompt(last_text, errors, schema_file)
                _write_artifact(
                    art, {"kind": "repair_request", "text": repair_prompt[:50000]}
                )

                messages.append(
                    ChatMessage(role="assistant", content=last_text)
                )
                messages.append(
                    ChatMessage(role="user", content=repair_prompt)
                )

                resp = await chat_completion(
                    provider=provider,
                    model=model,
                    messages=list(messages),
                    system_prompt=system_prompt,
                )

                turn_count += 1
                total_input_tokens += resp.usage.get("input_tokens", 0)
                total_output_tokens += resp.usage.get("output_tokens", 0)
                total_cost += resp.cost_usd

                _write_artifact(
                    art,
                    {
                        "kind": "assistant",
                        "content": resp.content,
                        "tool_calls": [],
                        "usage": resp.usage,
                        "cost_usd": resp.cost_usd,
                    },
                )

                last_text = resp.content or ""
                errors = _validate(last_text, schema_file)
                if not errors:
                    break

            break  # exit the main loop after repair attempt(s)

        # --- After loop exit — check for max_turns exceeded -----------------
        if turn_count >= max_turns:
            _write_artifact(art, {"kind": "max_turns_exceeded", "turns": turn_count})
            raise AgentRunError(
                f"[{stage}/{artifact_name}] exceeded max_turns ({max_turns}) "
                f"without producing valid output"
            )

        # --- Final validation ----------------------------------------------
        if errors:
            _write_artifact(art, {"kind": "schema_errors", "errors": errors})
            raise AgentRunError(
                f"[{stage}/{artifact_name}] schema validation failed after "
                f"{repair_attempts} repair attempt(s): {errors[:5]}"
            )

        payload = extract_json(last_text)
        _write_artifact(art, {"kind": "final_payload", "payload": payload})

    duration_ms = int((time.time() - started_at) * 1000)

    return AgentResult(
        payload=payload,
        cost_usd=total_cost,
        input_tokens=total_input_tokens,
        output_tokens=total_output_tokens,
        num_turns=turn_count,
        duration_ms=duration_ms,
        session_id=None,
        artifact_path=artifact_path,
        repair_used=repair_used,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _execute_tool(ts: ToolsSession, tc: ToolCall) -> dict:
    """Execute a single tool call and return the result dict."""
    try:
        if tc.name == "Read":
            return await ts.tool_read(
                path=tc.arguments.get("path", ""),
                offset=tc.arguments.get("offset", 1),
                limit=tc.arguments.get("limit", 500),
            )
        elif tc.name == "Grep":
            return await ts.tool_grep(
                pattern=tc.arguments.get("pattern", ""),
                path=tc.arguments.get("path", ""),
                glob=tc.arguments.get("glob"),
            )
        elif tc.name == "Glob":
            return await ts.tool_glob(
                pattern=tc.arguments.get("pattern", ""),
                path=tc.arguments.get("path", ""),
            )
        elif tc.name == "Bash":
            return await ts.tool_bash(
                command=tc.arguments.get("command", ""),
                workdir=tc.arguments.get("workdir", "."),
            )
        else:
            return {"error": f"unknown tool: {tc.name}"}
    except Exception as exc:
        return {"error": str(exc)}


def _validate(text: str, schema_file: Path) -> list[str]:
    try:
        payload = extract_json(text)
    except ValueError as e:
        return [f"json_extract: {e}"]
    return validate_schema(payload, str(schema_file))


def _build_repair_prompt(
    prev_output: str, errors: list[str], schema_file: Path
) -> str:
    err_block = "\n".join(f"- {e}" for e in errors[:20])
    return (
        "Your previous output failed schema validation against "
        f"`{schema_file.name}`. Errors:\n"
        f"{err_block}\n\n"
        "Re-emit the same response, fixing ONLY these errors. Output a "
        "single JSON object — no prose, no markdown fence."
    )


def _write_artifact(fp, obj: Any) -> None:
    fp.write(json.dumps(obj, default=str, ensure_ascii=False) + "\n")
    fp.flush()
