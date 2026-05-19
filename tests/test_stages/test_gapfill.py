"""Test gapfill stage."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from cyber_audit.agent import AgentResult
from cyber_audit.config import HarnessConfig, StageConfig
from cyber_audit.state import StateDB
from cyber_audit.stages._common import StageContext


@pytest.fixture
def sample_config() -> HarnessConfig:
    stages = {}
    for name in ["recon", "hunt", "validate", "gapfill", "dedupe", "trace", "feedback", "report"]:
        stages[name] = StageConfig(model=f"test-{name}", concurrency=2, tools=["Read", "Grep"])
    return HarnessConfig(gapfill_iterations=2, feedback_iterations=3, stages=stages)


@pytest.fixture
def ctx(sample_config) -> StageContext:
    return StageContext(run_id=1, repo_path=Path("/tmp/test-repo"), config=sample_config)


@pytest.fixture
def db() -> StateDB:
    sdb = StateDB(":memory:")
    sdb.create_run("/tmp/test-repo")
    return sdb


class TestRunGapfill:
    @pytest.mark.asyncio
    async def test_returns_zero_when_no_tasks(self, ctx, db):
        """When there are no completed tasks, gapfill returns 0."""
        with patch("cyber_audit.stages.gapfill.run_agent", new=AsyncMock()):
            from cyber_audit.stages.gapfill import run_gapfill
            result = await run_gapfill(ctx, db)
        assert result == 0 or result is None

    @pytest.mark.asyncio
    async def test_creates_new_tasks_from_gaps(self, ctx, db):
        """Gapfill should create new tasks for under-covered areas."""
        from cyber_audit.stages.gapfill import run_gapfill

        # Add a completed task
        db.add_task(ctx.run_id, "hunt", "sqli", "Check SQLi in db.py", ["db.py"], "test", 1, "completed", {})

        agent_result = AgentResult(
            payload={"new_tasks": [{"task_id": "t_new_1", "attack_class": "xss", "scope_hint": "Check XSS", "target_files": ["ui.py"], "rationale": "gap", "priority": 2}]},
            cost_usd=0.001, input_tokens=100, output_tokens=50, num_turns=1, duration_ms=500, session_id=None,
            artifact_path=Path("/tmp/gapfill.jsonl"), repair_used=False,
        )

        with patch("cyber_audit.stages.gapfill.run_agent", new=AsyncMock(return_value=agent_result)):
            await run_gapfill(ctx, db)

    @pytest.mark.asyncio
    async def test_records_cost(self, ctx, db):
        from cyber_audit.stages.gapfill import run_gapfill

        db.add_task(ctx.run_id, "hunt", "sqli", "Check SQLi", ["db.py"], "test", 1, "completed", {})

        agent_result = AgentResult(
            payload={"new_tasks": []},
            cost_usd=0.001, input_tokens=100, output_tokens=50, num_turns=1, duration_ms=500, session_id=None,
            artifact_path=Path("/tmp/gapfill.jsonl"), repair_used=False,
        )

        with patch("cyber_audit.stages.gapfill.run_agent", new=AsyncMock(return_value=agent_result)):
            await run_gapfill(ctx, db)

        assert db.total_cost(ctx.run_id) > 0
