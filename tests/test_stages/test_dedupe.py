"""Test dedupe stage."""

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
        stages[name] = StageConfig(model=f"test-{name}", concurrency=2, tools=["Read"])
    return HarnessConfig(gapfill_iterations=2, feedback_iterations=3, stages=stages)


@pytest.fixture
def ctx(sample_config) -> StageContext:
    return StageContext(run_id=1, repo_path=Path("/tmp/test-repo"), config=sample_config)


@pytest.fixture
def db() -> StateDB:
    sdb = StateDB(":memory:")
    sdb.create_run("/tmp/test-repo")
    return sdb


class TestRunDedupe:
    @pytest.mark.asyncio
    async def test_handles_no_findings(self, ctx, db):
        from cyber_audit.stages.dedupe import run_dedupe
        with patch("cyber_audit.stages.dedupe.run_agent", new=AsyncMock()):
            result = await run_dedupe(ctx, db)
        assert result == 0 or result is None

    @pytest.mark.asyncio
    async def test_creates_dedupe_groups(self, ctx, db):
        from cyber_audit.stages.dedupe import run_dedupe

        task_id = db.add_task(ctx.run_id, "hunt", "sqli", "Check SQLi", ["db.py"], "test", 1, "completed", {})
        f1 = db.add_finding(task_id, ctx.run_id, "db.py", 10, 20, "sqli", "high", "SQLi in query", "evidence", False, 0.8, {})
        f2 = db.add_finding(task_id, ctx.run_id, "db.py", 30, 40, "sqli", "high", "Another SQLi", "evidence2", False, 0.7, {})
        db.set_finding_validation(f1, "confirmed", {"verdict": "confirmed"})
        db.set_finding_validation(f2, "confirmed", {"verdict": "confirmed"})

        payload = {
            "groups": [{
                "group_id": "g1",
                "root_cause": "Unsanitized user input in SQL queries",
                "canonical_finding_id": f1,
                "member_finding_ids": [f1, f2],
            }]
        }

        agent_result = AgentResult(
            payload=payload, cost_usd=0.001, input_tokens=100, output_tokens=50,
            num_turns=1, duration_ms=500, session_id=None,
            artifact_path=Path("/tmp/dedupe.jsonl"), repair_used=False,
        )

        with patch("cyber_audit.stages.dedupe.run_agent", new=AsyncMock(return_value=agent_result)):
            await run_dedupe(ctx, db)
