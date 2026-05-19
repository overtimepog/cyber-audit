"""Test recon stage — run_recon orchestrates the reconnaissance agent."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from cyber_audit.agent import AgentResult
from cyber_audit.config import HarnessConfig, StageConfig
from cyber_audit.state import StateDB, Task
from cyber_audit.stages._common import StageContext
from cyber_audit.stages.recon import run_recon


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_config() -> HarnessConfig:
    """Minimal HarnessConfig with recon stage configured."""
    stages = {}
    for name in ["recon", "hunt", "validate", "gapfill", "dedupe", "trace", "feedback", "report"]:
        stages[name] = StageConfig(
            model=f"test-model-{name}",
            concurrency=1,
            tools=["Read", "Grep"],
        )
    return HarnessConfig(
        gapfill_iterations=2,
        feedback_iterations=3,
        stages=stages,
    )


@pytest.fixture
def ctx(sample_config) -> StageContext:
    """StageContext pointing to a test repo."""
    return StageContext(
        run_id=1,
        repo_path=Path("/tmp/test-repo"),
        config=sample_config,
    )


@pytest.fixture
def db() -> StateDB:
    """Fresh in-memory StateDB."""
    sdb = StateDB(":memory:")
    sdb.create_run("/tmp/test-repo")
    return sdb


@pytest.fixture
def mock_agent_result() -> AgentResult:
    """A realistic AgentResult representing recon output."""
    return AgentResult(
        payload={
            "architecture_summary": "Flask web app with SQLite",
            "modules": [
                {
                    "name": "auth",
                    "files": ["auth.py", "session.py"],
                    "purpose": "User authentication",
                    "attack_surface": "high",
                },
            ],
            "tasks": [
                {
                    "attack_class": "sqli",
                    "scope_hint": "auth.py",
                    "target_files": ["auth.py", "db.py"],
                    "rationale": "SQL queries use string formatting",
                    "priority": 5,
                },
            ],
        },
        cost_usd=0.01,
        input_tokens=1000,
        output_tokens=500,
        num_turns=3,
        duration_ms=2000,
        session_id=None,
        artifact_path=Path("/tmp/artifact.jsonl"),
        repair_used=False,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestRunRecon:
    """run_recon calls the agent, saves output, and creates tasks."""

    @pytest.mark.asyncio
    async def test_run_recon_calls_run_agent(self, ctx, db, mock_agent_result):
        """run_recon should call run_agent with the recon prompt and schema."""
        with patch("cyber_audit.stages.recon.run_agent", new=AsyncMock(return_value=mock_agent_result)) as mock_run:
            await run_recon(ctx, db)

        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["stage"] == "recon"
        assert call_kwargs["model"] == "test-model-recon"

    @pytest.mark.asyncio
    async def test_run_recon_saves_output_to_db(self, ctx, db, mock_agent_result):
        """After run_recon, recon output should be in the database."""
        with patch("cyber_audit.stages.recon.run_agent", new=AsyncMock(return_value=mock_agent_result)):
            await run_recon(ctx, db)

        output = db.get_recon_output(ctx.run_id)
        assert output is not None
        assert output["architecture_summary"] == "Flask web app with SQLite"

    @pytest.mark.asyncio
    async def test_run_recon_creates_tasks(self, ctx, db, mock_agent_result):
        """run_recon should create tasks from the agent's payload."""
        with patch("cyber_audit.stages.recon.run_agent", new=AsyncMock(return_value=mock_agent_result)):
            await run_recon(ctx, db)

        tasks = db.get_all_tasks(ctx.run_id)
        assert len(tasks) == 1
        assert tasks[0].attack_class == "sqli"
        assert tasks[0].source == "recon"
        assert tasks[0].status == "pending"

    @pytest.mark.asyncio
    async def test_run_recon_creates_multiple_tasks(self, ctx, db):
        """When payload has multiple tasks, all should be created."""
        payload_with_many = AgentResult(
            payload={
                "architecture_summary": "Test app",
                "modules": [],
                "tasks": [
                    {
                        "attack_class": "sqli",
                        "scope_hint": "a.py",
                        "target_files": ["a.py"],
                        "rationale": "r1",
                        "priority": 5,
                    },
                    {
                        "attack_class": "xss",
                        "scope_hint": "b.py",
                        "target_files": ["b.py"],
                        "rationale": "r2",
                        "priority": 3,
                    },
                    {
                        "attack_class": "cmdi",
                        "scope_hint": "c.py",
                        "target_files": ["c.py"],
                        "rationale": "r3",
                        "priority": 4,
                    },
                ],
            },
            cost_usd=0.02,
            input_tokens=2000,
            output_tokens=800,
            num_turns=4,
            duration_ms=3000,
            session_id=None,
            artifact_path=Path("/tmp/art2.jsonl"),
            repair_used=False,
        )
        with patch("cyber_audit.stages.recon.run_agent", new=AsyncMock(return_value=payload_with_many)):
            await run_recon(ctx, db)

        tasks = db.get_all_tasks(ctx.run_id)
        assert len(tasks) == 3

    @pytest.mark.asyncio
    async def test_run_recon_uses_max_tasks_default(self, ctx, db, mock_agent_result):
        """run_recon should pass max_tasks=80 by default to run_agent."""
        with patch("cyber_audit.stages.recon.run_agent", new=AsyncMock(return_value=mock_agent_result)) as mock_run:
            await run_recon(ctx, db)

        # The user_input should contain max_tasks
        call_kwargs = mock_run.call_args.kwargs
        user_input = call_kwargs["user_input"]
        assert user_input.get("max_tasks") == 80

    @pytest.mark.asyncio
    async def test_run_recon_custom_max_tasks(self, ctx, db, mock_agent_result):
        """run_recon should respect a custom max_tasks value."""
        with patch("cyber_audit.stages.recon.run_agent", new=AsyncMock(return_value=mock_agent_result)) as mock_run:
            await run_recon(ctx, db, max_tasks=10)

        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["user_input"]["max_tasks"] == 10

    @pytest.mark.asyncio
    async def test_run_recon_task_has_correct_fields(self, ctx, db, mock_agent_result):
        """Each created task should have the correct fields from the payload."""
        with patch("cyber_audit.stages.recon.run_agent", new=AsyncMock(return_value=mock_agent_result)):
            await run_recon(ctx, db)

        task = db.get_all_tasks(ctx.run_id)[0]
        assert task.run_id == ctx.run_id
        assert task.source == "recon"
        assert task.attack_class == "sqli"
        assert task.scope_hint == "auth.py"
        assert task.target_files == ["auth.py", "db.py"]
        assert task.rationale == "SQL queries use string formatting"
        assert task.priority == 5
        assert task.status == "pending"

    @pytest.mark.asyncio
    async def test_run_recon_returns_none(self, ctx, db, mock_agent_result):
        """run_recon should return None (void function)."""
        with patch("cyber_audit.stages.recon.run_agent", new=AsyncMock(return_value=mock_agent_result)):
            result = await run_recon(ctx, db)
        assert result is None

    @pytest.mark.asyncio
    async def test_run_recon_records_cost(self, ctx, db, mock_agent_result):
        """run_recon should record the agent cost in the database."""
        with patch("cyber_audit.stages.recon.run_agent", new=AsyncMock(return_value=mock_agent_result)):
            await run_recon(ctx, db)

        total = db.total_cost(ctx.run_id)
        assert total > 0

    @pytest.mark.asyncio
    async def test_run_recon_handles_empty_tasks(self, ctx, db):
        """When payload has no tasks, no tasks should be created."""
        payload_no_tasks = AgentResult(
            payload={
                "architecture_summary": "Empty app",
                "modules": [],
                "tasks": [],
            },
            cost_usd=0.005,
            input_tokens=500,
            output_tokens=200,
            num_turns=2,
            duration_ms=1000,
            session_id=None,
            artifact_path=Path("/tmp/art3.jsonl"),
            repair_used=False,
        )
        with patch("cyber_audit.stages.recon.run_agent", new=AsyncMock(return_value=payload_no_tasks)):
            await run_recon(ctx, db)

        tasks = db.get_all_tasks(ctx.run_id)
        assert len(tasks) == 0

    @pytest.mark.asyncio
    async def test_run_recon_passes_prompt_and_schema_paths(self, ctx, db, mock_agent_result):
        """run_recon should pass correct prompt_file and schema_file from ctx."""
        with patch("cyber_audit.stages.recon.run_agent", new=AsyncMock(return_value=mock_agent_result)) as mock_run:
            await run_recon(ctx, db)

        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["prompt_file"] == ctx.prompt("recon")
        assert call_kwargs["schema_file"] == ctx.schema("recon")

    @pytest.mark.asyncio
    async def test_run_recon_passes_allowed_tools(self, ctx, db, mock_agent_result):
        """run_recon should pass the tools from StageConfig."""
        with patch("cyber_audit.stages.recon.run_agent", new=AsyncMock(return_value=mock_agent_result)) as mock_run:
            await run_recon(ctx, db)

        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["allowed_tools"] == ["Read", "Grep"]

    @pytest.mark.asyncio
    async def test_run_recon_uses_results_dir_for_artifact(self, ctx, db, mock_agent_result):
        """run_recon should use ctx.results_dir('recon') for the artifact dir."""
        with patch("cyber_audit.stages.recon.run_agent", new=AsyncMock(return_value=mock_agent_result)) as mock_run:
            await run_recon(ctx, db)

        call_kwargs = mock_run.call_args.kwargs
        expected_dir = ctx.results_dir("recon")
        # artifact_dir should be set to the results dir
        assert call_kwargs["artifact_dir"] == expected_dir
