"""Tests for cyber_audit.agent — the agent loop."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyber_audit.agent import AgentResult, run_agent
from cyber_audit.llm import ChatMessage, LLMResponse, ProviderConfig, ToolCall


# ── helpers ────────────────────────────────────────────────────────────


def _make_response(
    content: str | None = None,
    tool_calls: list | None = None,
    input_tokens: int = 100,
    output_tokens: int = 50,
    finish_reason: str = "stop",
) -> LLMResponse:
    return LLMResponse(
        content=content,
        tool_calls=tool_calls or [],
        finish_reason=finish_reason,
        usage={"input_tokens": input_tokens, "output_tokens": output_tokens},
        cost_usd=0.000042,
    )


def _make_tool_call(name: str, args: dict, call_id: str = "call_1") -> ToolCall:
    return ToolCall(id=call_id, name=name, arguments=args)


def _write_temp_schema() -> str:
    """Write a minimal JSON schema to a temp file, return path."""
    schema = {
        "type": "object",
        "required": ["result"],
        "additionalProperties": False,
        "properties": {
            "result": {"type": "string"},
        },
    }
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    with open(path, "w") as f:
        json.dump(schema, f)
    return path


def _write_temp_prompt() -> str:
    fd, path = tempfile.mkstemp(suffix=".md")
    os.close(fd)
    with open(path, "w") as f:
        f.write("You are a test agent.\n\nOutput valid JSON matching the schema.")
    return path


# ── fixture for a temp repo directory ──────────────────────────────────


@pytest.fixture
def repo_dir():
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "repo"
        repo.mkdir()
        (repo / "README.md").write_text("# Test Repo\n")
        (repo / "src").mkdir()
        (repo / "src" / "app.py").write_text("print('hello')\n")
        yield repo


@pytest.fixture
def artifact_dir():
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


# ── tests ──────────────────────────────────────────────────────────────


class TestAgentResult:
    def test_agent_result_creation(self):
        result = AgentResult(
            payload={"result": "ok"},
            cost_usd=0.001,
            input_tokens=100,
            output_tokens=50,
            num_turns=1,
            duration_ms=500,
            session_id="sess_1",
            artifact_path=Path("/tmp/test.jsonl"),
            repair_used=False,
        )
        assert result.payload == {"result": "ok"}
        assert result.cost_usd == 0.001
        assert result.repair_used is False


class TestRunAgentSimpleText:
    """Agent produces text → JSON extracted → validated → success."""

    @pytest.mark.asyncio
    async def test_simple_text_response(self, repo_dir, artifact_dir):
        schema_path = _write_temp_schema()
        prompt_path = _write_temp_prompt()

        # The LLM returns clean JSON
        response = _make_response(content='{"result": "hello"}')

        with patch("cyber_audit.agent.chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = response

            result = await run_agent(
                stage="recon",
                prompt_file=Path(prompt_path),
                user_input={"repo_path": str(repo_dir)},
                schema_file=Path(schema_path),
                allowed_tools=["Read"],
                model="deepseek-chat",
                provider=ProviderConfig.DEEPSEEK,
                cwd=repo_dir,
                artifact_dir=artifact_dir,
                artifact_name="test",
            )

        assert result.payload == {"result": "hello"}
        assert result.cost_usd is not None
        assert result.repair_used is False
        assert result.num_turns == 1

    @pytest.mark.asyncio
    async def test_json_in_markdown_fence(self, repo_dir, artifact_dir):
        """JSON wrapped in ```json``` fence."""
        schema_path = _write_temp_schema()
        prompt_path = _write_temp_prompt()

        response = _make_response(content='```json\n{"result": "fenced"}\n```')

        with patch("cyber_audit.agent.chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = response

            result = await run_agent(
                stage="hunt",
                prompt_file=Path(prompt_path),
                user_input={"task": "test"},
                schema_file=Path(schema_path),
                allowed_tools=["Read"],
                model="gpt-4o",
                provider=ProviderConfig.OPENAI,
                cwd=repo_dir,
                artifact_dir=artifact_dir,
                artifact_name="test",
            )

        assert result.payload == {"result": "fenced"}

    @pytest.mark.asyncio
    async def test_no_tools_allowed(self, repo_dir, artifact_dir):
        """Agent with empty allowed_tools should not pass tools to LLM."""
        schema_path = _write_temp_schema()
        prompt_path = _write_temp_prompt()

        response = _make_response(content='{"result": "no tools"}')

        with patch("cyber_audit.agent.chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = response

            result = await run_agent(
                stage="dedupe",
                prompt_file=Path(prompt_path),
                user_input={"data": "test"},
                schema_file=Path(schema_path),
                allowed_tools=[],
                model="gpt-4o-mini",
                provider=ProviderConfig.OPENAI,
                cwd=repo_dir,
                artifact_dir=artifact_dir,
                artifact_name="test",
            )

        assert result.payload == {"result": "no tools"}
        # Verify no tools were passed
        call_args = mock_chat.call_args
        assert call_args[1].get("tools") is None


class TestRunAgentToolUse:
    """Agent uses tools → gets results → continues → produces JSON."""

    @pytest.mark.asyncio
    async def test_single_tool_call_then_text(self, repo_dir, artifact_dir):
        schema_path = _write_temp_schema()
        prompt_path = _write_temp_prompt()

        # First response: tool call to read a file
        resp1 = _make_response(
            content=None,
            tool_calls=[_make_tool_call("Read", {"path": "README.md"})],
            finish_reason="tool_calls",
        )
        # Second response: text with JSON
        resp2 = _make_response(content='{"result": "read complete"}')

        with patch("cyber_audit.agent.chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.side_effect = [resp1, resp2]

            result = await run_agent(
                stage="hunt",
                prompt_file=Path(prompt_path),
                user_input={"task": "read and report"},
                schema_file=Path(schema_path),
                allowed_tools=["Read", "Grep", "Glob", "Bash"],
                model="gpt-4o",
                provider=ProviderConfig.OPENAI,
                cwd=repo_dir,
                artifact_dir=artifact_dir,
                artifact_name="test",
            )

        assert result.payload == {"result": "read complete"}
        assert result.num_turns == 2
        # Cost should accumulate across turns
        assert result.cost_usd == pytest.approx(0.000084)

    @pytest.mark.asyncio
    async def test_multiple_tool_calls(self, repo_dir, artifact_dir):
        """Multiple sequential tool calls before final text."""
        schema_path = _write_temp_schema()
        prompt_path = _write_temp_prompt()

        resp1 = _make_response(
            content=None,
            tool_calls=[_make_tool_call("Glob", {"pattern": "*.py", "path": "."})],
            finish_reason="tool_calls",
            input_tokens=100,
            output_tokens=30,
        )
        resp2 = _make_response(
            content=None,
            tool_calls=[_make_tool_call("Read", {"path": "src/app.py"})],
            finish_reason="tool_calls",
            input_tokens=150,
            output_tokens=20,
        )
        resp3 = _make_response(
            content='{"result": "found app.py"}',
            input_tokens=200,
            output_tokens=30,
        )

        with patch("cyber_audit.agent.chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.side_effect = [resp1, resp2, resp3]

            result = await run_agent(
                stage="hunt",
                prompt_file=Path(prompt_path),
                user_input={"task": "find files"},
                schema_file=Path(schema_path),
                allowed_tools=["Read", "Glob"],
                model="gpt-4o",
                provider=ProviderConfig.OPENAI,
                cwd=repo_dir,
                artifact_dir=artifact_dir,
                artifact_name="test",
            )

        assert result.payload == {"result": "found app.py"}
        assert result.num_turns == 3


class TestRunAgentSchemaRepair:
    """Schema validation fails → repair turn → success or failure."""

    @pytest.mark.asyncio
    async def test_repair_succeeds(self, repo_dir, artifact_dir):
        schema_path = _write_temp_schema()
        prompt_path = _write_temp_prompt()

        # First response: invalid JSON (missing "result")
        resp1 = _make_response(content='{"wrong_key": "oops"}')
        # Repair response: valid JSON
        resp2 = _make_response(content='{"result": "fixed"}')

        with patch("cyber_audit.agent.chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.side_effect = [resp1, resp2]

            result = await run_agent(
                stage="recon",
                prompt_file=Path(prompt_path),
                user_input={"repo_path": str(repo_dir)},
                schema_file=Path(schema_path),
                allowed_tools=["Read"],
                model="deepseek-chat",
                provider=ProviderConfig.DEEPSEEK,
                cwd=repo_dir,
                artifact_dir=artifact_dir,
                artifact_name="test",
                repair_attempts=2,
            )

        assert result.payload == {"result": "fixed"}
        assert result.repair_used is True
        assert result.num_turns == 2  # original + 1 repair

    @pytest.mark.asyncio
    async def test_repair_fails_exhausted(self, repo_dir, artifact_dir):
        """After all repair attempts, still invalid → AgentRunError."""
        schema_path = _write_temp_schema()
        prompt_path = _write_temp_prompt()

        from cyber_audit.agent import AgentRunError

        # Always return invalid JSON
        bad_response = _make_response(content='{"wrong": true}')

        with patch("cyber_audit.agent.chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = bad_response

            with pytest.raises(AgentRunError, match="schema validation failed"):
                await run_agent(
                    stage="recon",
                    prompt_file=Path(prompt_path),
                    user_input={"repo_path": str(repo_dir)},
                    schema_file=Path(schema_path),
                    allowed_tools=["Read"],
                    model="deepseek-chat",
                    provider=ProviderConfig.DEEPSEEK,
                    cwd=repo_dir,
                    artifact_dir=artifact_dir,
                    artifact_name="test",
                    repair_attempts=1,
                )

    @pytest.mark.asyncio
    async def test_no_repair_needed_when_valid(self, repo_dir, artifact_dir):
        """Valid JSON on first try — no repair turn."""
        schema_path = _write_temp_schema()
        prompt_path = _write_temp_prompt()

        response = _make_response(content='{"result": "valid"}')

        with patch("cyber_audit.agent.chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = response

            result = await run_agent(
                stage="recon",
                prompt_file=Path(prompt_path),
                user_input={"repo_path": str(repo_dir)},
                schema_file=Path(schema_path),
                allowed_tools=[],
                model="deepseek-chat",
                provider=ProviderConfig.DEEPSEEK,
                cwd=repo_dir,
                artifact_dir=artifact_dir,
                artifact_name="test",
                repair_attempts=1,
            )

        assert result.repair_used is False
        assert mock_chat.call_count == 1


class TestRunAgentMaxTurns:
    """Agent respects max_turns limit."""

    @pytest.mark.asyncio
    async def test_max_turns_enforced(self, repo_dir, artifact_dir):
        schema_path = _write_temp_schema()
        prompt_path = _write_temp_prompt()

        from cyber_audit.agent import AgentRunError

        # Every response is a tool call (infinite loop simulation)
        loop_resp = _make_response(
            content=None,
            tool_calls=[_make_tool_call("Read", {"path": "README.md"})],
            finish_reason="tool_calls",
        )

        with patch("cyber_audit.agent.chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = loop_resp

            with pytest.raises(AgentRunError, match="max_turns"):
                await run_agent(
                    stage="hunt",
                    prompt_file=Path(prompt_path),
                    user_input={"task": "loop"},
                    schema_file=Path(schema_path),
                    allowed_tools=["Read"],
                    model="gpt-4o",
                    provider=ProviderConfig.OPENAI,
                    cwd=repo_dir,
                    artifact_dir=artifact_dir,
                    artifact_name="test",
                    max_turns=3,
                )


class TestRunAgentArtifacts:
    """JSONL artifact file is written correctly."""

    @pytest.mark.asyncio
    async def test_artifact_file_written(self, repo_dir, artifact_dir):
        schema_path = _write_temp_schema()
        prompt_path = _write_temp_prompt()

        response = _make_response(content='{"result": "artifact test"}')

        with patch("cyber_audit.agent.chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = response

            result = await run_agent(
                stage="recon",
                prompt_file=Path(prompt_path),
                user_input={"repo_path": str(repo_dir)},
                schema_file=Path(schema_path),
                allowed_tools=["Read"],
                model="deepseek-chat",
                provider=ProviderConfig.DEEPSEEK,
                cwd=repo_dir,
                artifact_dir=artifact_dir,
                artifact_name="artifact_test",
            )

        # Check the artifact file exists and has expected content
        expected_path = artifact_dir / "artifact_test.jsonl"
        assert expected_path == result.artifact_path
        assert expected_path.exists()

        lines = expected_path.read_text().strip().split("\n")
        assert len(lines) >= 3  # meta, user, assistant, final
        assert json.loads(lines[0])["kind"] == "meta"
        assert json.loads(lines[-1])["kind"] == "final_payload"
        assert json.loads(lines[-1])["payload"] == {"result": "artifact test"}


class TestRunAgentToolFiltering:
    """Only allowed tools are passed to the LLM."""

    @pytest.mark.asyncio
    async def test_only_allowed_tools_passed(self, repo_dir, artifact_dir):
        schema_path = _write_temp_schema()
        prompt_path = _write_temp_prompt()

        response = _make_response(content='{"result": "ok"}')

        with patch("cyber_audit.agent.chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = response

            await run_agent(
                stage="dedupe",
                prompt_file=Path(prompt_path),
                user_input={"data": "test"},
                schema_file=Path(schema_path),
                allowed_tools=["Read"],
                model="gpt-4o-mini",
                provider=ProviderConfig.OPENAI,
                cwd=repo_dir,
                artifact_dir=artifact_dir,
                artifact_name="test",
            )

        # Verify the tools sent to chat_completion
        tools_sent = mock_chat.call_args[1].get("tools", [])
        tool_names = [t["function"]["name"] for t in tools_sent]
        assert "Read" in tool_names
        assert "Bash" not in tool_names
        assert "Grep" not in tool_names

    @pytest.mark.asyncio
    async def test_all_tools_passed(self, repo_dir, artifact_dir):
        schema_path = _write_temp_schema()
        prompt_path = _write_temp_prompt()

        response = _make_response(content='{"result": "all tools"}')

        with patch("cyber_audit.agent.chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = response

            await run_agent(
                stage="hunt",
                prompt_file=Path(prompt_path),
                user_input={"task": "explore"},
                schema_file=Path(schema_path),
                allowed_tools=["Read", "Grep", "Glob", "Bash"],
                model="gpt-4o",
                provider=ProviderConfig.OPENAI,
                cwd=repo_dir,
                artifact_dir=artifact_dir,
                artifact_name="test",
            )

        tools_sent = mock_chat.call_args[1].get("tools", [])
        tool_names = [t["function"]["name"] for t in tools_sent]
        assert set(tool_names) == {"Read", "Grep", "Glob", "Bash"}
