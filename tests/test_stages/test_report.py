"""Test report stage."""

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
        stages[name] = StageConfig(model=f"test-{name}", concurrency=1, tools=["Read"])
    return HarnessConfig(gapfill_iterations=2, feedback_iterations=3, stages=stages)


@pytest.fixture
def ctx(sample_config) -> StageContext:
    return StageContext(run_id=1, repo_path=Path("/tmp/test-repo"), config=sample_config)


@pytest.fixture
def db() -> StateDB:
    sdb = StateDB(":memory:")
    sdb.create_run("/tmp/test-repo")
    return sdb


class TestRunReport:
    @pytest.mark.asyncio
    async def test_returns_path(self, ctx, db):
        from cyber_audit.stages.report import run_report

        payload = {"report": "# Audit Report\n\nFindings: none\n"}
        agent_result = AgentResult(
            payload=payload, cost_usd=0.001, input_tokens=100, output_tokens=50,
            num_turns=1, duration_ms=500, session_id=None,
            artifact_path=Path("/tmp/report.jsonl"), repair_used=False,
        )

        with patch("cyber_audit.stages.report.run_agent", new=AsyncMock(return_value=agent_result)):
            result = await run_report(ctx, db)

        assert isinstance(result, Path)

    @pytest.mark.asyncio
    async def test_writes_report_file(self, ctx, db):
        from cyber_audit.stages.report import run_report

        payload = {"report": "# Test Report\n\nNo vulnerabilities found.\n"}
        agent_result = AgentResult(
            payload=payload, cost_usd=0.001, input_tokens=100, output_tokens=50,
            num_turns=1, duration_ms=500, session_id=None,
            artifact_path=Path("/tmp/report.jsonl"), repair_used=False,
        )

        with patch("cyber_audit.stages.report.run_agent", new=AsyncMock(return_value=agent_result)):
            result = await run_report(ctx, db)

        assert result.exists()
        content = result.read_text()
        assert "Test Report" in content
