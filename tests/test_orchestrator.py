"""Tests for the orchestrator — pipeline driver."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from cyber_audit.config import HarnessConfig, StageConfig
from cyber_audit.state import StateDB


@pytest.fixture
def sample_config() -> HarnessConfig:
    stages = {}
    for name in ["recon", "hunt", "validate", "gapfill", "dedupe", "trace", "feedback", "report"]:
        stages[name] = StageConfig(
            model=f"test-{name}",
            concurrency=2,
            tools=["Read", "Grep"],
        )
    return HarnessConfig(gapfill_iterations=1, feedback_iterations=1, stages=stages)


class TestOrchestrator:
    @pytest.mark.asyncio
    async def test_run_pipeline_runs_all_stages(self, sample_config):
        from cyber_audit.orchestrator import run_pipeline

        db = StateDB(":memory:")

        with patch("cyber_audit.orchestrator.stages.run_recon", new=AsyncMock()) as m_recon, \
             patch("cyber_audit.orchestrator.stages.run_hunt", new=AsyncMock(return_value=0)) as m_hunt, \
             patch("cyber_audit.orchestrator.stages.run_validate", new=AsyncMock()) as m_val, \
             patch("cyber_audit.orchestrator.stages.run_gapfill", new=AsyncMock(return_value=0)) as m_gap, \
             patch("cyber_audit.orchestrator.stages.run_dedupe", new=AsyncMock()) as m_ded, \
             patch("cyber_audit.orchestrator.stages.run_trace", new=AsyncMock()) as m_trace, \
             patch("cyber_audit.orchestrator.stages.run_feedback", new=AsyncMock(return_value=0)) as m_fb, \
             patch("cyber_audit.orchestrator.stages.run_report", new=AsyncMock(return_value=Path("/tmp/report.md"))) as m_rep:

            run_id, report_path = await run_pipeline(
                repo_path=Path("/tmp/test-repo"),
                db=db,
                config=sample_config,
            )

        m_recon.assert_called_once()
        m_hunt.assert_called()
        m_val.assert_called()
        m_gap.assert_called()
        m_ded.assert_called_once()
        m_trace.assert_called_once()
        m_fb.assert_called()
        m_rep.assert_called_once()
        assert report_path == Path("/tmp/report.md")
        assert isinstance(run_id, int)

    @pytest.mark.asyncio
    async def test_run_pipeline_sets_run_status_on_success(self, sample_config):
        from cyber_audit.orchestrator import run_pipeline

        db = StateDB(":memory:")

        with patch("cyber_audit.orchestrator.stages.run_recon", new=AsyncMock()), \
             patch("cyber_audit.orchestrator.stages.run_hunt", new=AsyncMock(return_value=0)), \
             patch("cyber_audit.orchestrator.stages.run_validate", new=AsyncMock()), \
             patch("cyber_audit.orchestrator.stages.run_gapfill", new=AsyncMock(return_value=0)), \
             patch("cyber_audit.orchestrator.stages.run_dedupe", new=AsyncMock()), \
             patch("cyber_audit.orchestrator.stages.run_trace", new=AsyncMock()), \
             patch("cyber_audit.orchestrator.stages.run_feedback", new=AsyncMock(return_value=0)), \
             patch("cyber_audit.orchestrator.stages.run_report", new=AsyncMock(return_value=Path("/tmp/report.md"))):

            run_id, _ = await run_pipeline(
                repo_path=Path("/tmp/test-repo"),
                db=db,
                config=sample_config,
            )

        run = db.get_run(run_id)
        assert run is not None
        assert run["status"] == "completed"

    @pytest.mark.asyncio
    async def test_run_pipeline_handles_error(self, sample_config):
        from cyber_audit.orchestrator import run_pipeline

        db = StateDB(":memory:")

        with patch("cyber_audit.orchestrator.stages.run_recon", new=AsyncMock(side_effect=RuntimeError("recon failed"))):

            with pytest.raises(RuntimeError):
                await run_pipeline(
                    repo_path=Path("/tmp/test-repo"),
                    db=db,
                    config=sample_config,
                )

    @pytest.mark.asyncio
    async def test_run_pipeline_budget_check_aborts(self, sample_config):
        from cyber_audit.orchestrator import CostExceeded, run_pipeline

        db = StateDB(":memory:")

        with patch("cyber_audit.orchestrator.stages.run_recon", new=AsyncMock()), \
             patch("cyber_audit.orchestrator.stages.run_hunt", new=AsyncMock(side_effect=CostExceeded("budget"))):

            with pytest.raises(CostExceeded):
                await run_pipeline(
                    repo_path=Path("/tmp/test-repo"),
                    db=db,
                    config=sample_config,
                    max_cost_usd=0.01,
                )
