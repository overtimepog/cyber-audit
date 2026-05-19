"""End-to-end integration test — full pipeline against vulnerable app.

All LLM calls are mocked; only the pipeline orchestration is tested.
"""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from cyber_audit.agent import AgentResult
from cyber_audit.config import HarnessConfig, load_config
from cyber_audit.orchestrator import run_pipeline
from cyber_audit.state import StateDB


def _make_agent_result(payload: dict) -> AgentResult:
    return AgentResult(
        payload=payload,
        cost_usd=0.001,
        input_tokens=100,
        output_tokens=50,
        num_turns=2,
        duration_ms=500,
        session_id=None,
        artifact_path=Path("/tmp/test.jsonl"),
        repair_used=False,
    )


@pytest.fixture
def config() -> HarnessConfig:
    return load_config(str(Path(__file__).parent.parent / "config" / "stages.yaml"))


class TestEndToEndPipeline:
    """Full 8-stage pipeline executed with mocked LLM calls."""

    @pytest.mark.asyncio
    async def test_e2e_pipeline_completes_all_eight_stages(self, config):
        """Verify all 8 stages execute and run completes successfully."""
        repo_path = Path(__file__).parent / "fixtures" / "vulnerable_app"
        db = StateDB(":memory:")

        # Recon: minimal architecture map + 1 task
        recon_payload = {
            "architecture": {"entry_points": [], "trust_boundaries": [], "external_inputs": []},
            "subsystems": [{"name": "web", "path": ".", "language": "python", "purpose": "Flask app"}],
            "tasks": [{"task_id": 1, "attack_class": "sqli", "scope_hint": "Check SQLi", "target_files": ["app.py"], "rationale": "test", "priority": 1}],
        }
        # Hunt: empty findings (stops gapfill loop)
        hunt_payload = {"findings": []}
        # Validate: nothing to validate
        validate_payload = {"verdict": "confirmed", "confidence": 0.9, "reasoning": "n/a", "corrections": []}
        # Gapfill: no new tasks
        gapfill_payload = {"new_tasks": []}
        # Dedupe: no groups
        dedupe_payload = {"groups": []}
        # Trace: no confirmed findings to trace
        trace_payload = {"traces": []}
        # Feedback: no reachable findings
        feedback_payload = {"tasks": []}
        # Report: minimal report
        report_payload = {"report": "# Audit Report\n\nNo findings.\n"}

        with patch("cyber_audit.stages.recon.run_agent", new=AsyncMock(return_value=_make_agent_result(recon_payload))), \
             patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock(return_value=_make_agent_result(hunt_payload))), \
             patch("cyber_audit.stages.validate.run_agent", new=AsyncMock(return_value=_make_agent_result(validate_payload))), \
             patch("cyber_audit.stages.gapfill.run_agent", new=AsyncMock(return_value=_make_agent_result(gapfill_payload))), \
             patch("cyber_audit.stages.dedupe.run_agent", new=AsyncMock(return_value=_make_agent_result(dedupe_payload))), \
             patch("cyber_audit.stages.trace.run_agent", new=AsyncMock(return_value=_make_agent_result(trace_payload))), \
             patch("cyber_audit.stages.feedback.run_agent", new=AsyncMock(return_value=_make_agent_result(feedback_payload))), \
             patch("cyber_audit.stages.report.run_agent", new=AsyncMock(return_value=_make_agent_result(report_payload))):

            run_id, report_path = await run_pipeline(
                repo_path=repo_path.resolve(),
                db=db,
                config=config,
            )

        run = db.get_run(run_id)
        assert run is not None
        assert run["status"] == "completed"
        assert report_path.exists()
        assert db.total_cost(run_id) > 0

    @pytest.mark.asyncio
    async def test_e2e_with_findings_flow(self, config):
        """Verify findings are saved and validated through the pipeline."""
        repo_path = Path(__file__).parent / "fixtures" / "vulnerable_app"
        db = StateDB(":memory:")

        recon_payload = {
            "architecture": {"entry_points": [], "trust_boundaries": [], "external_inputs": []},
            "subsystems": [{"name": "web", "path": ".", "language": "python", "purpose": "Flask app"}],
            "tasks": [{"task_id": 1, "attack_class": "sqli", "scope_hint": "Check SQLi in login", "target_files": ["app.py"], "rationale": "test", "priority": 1}],
        }
        hunt_payload = {"findings": [
            {"finding_id": 1, "file": "app.py", "line_start": 45, "line_end": 52, "vuln_class": "sqli", "severity": "high", "description": "SQLi in login", "evidence": "query = f\"SELECT...\"", "confidence": 0.9, "poc_succeeded": True},
        ]}
        validate_payload = {"verdict": "confirmed", "confidence": 0.9, "reasoning": "Confirmed", "corrections": []}
        gapfill_payload = {"new_tasks": []}
        dedupe_payload = {"groups": []}
        trace_payload = {"traces": []}
        feedback_payload = {"tasks": []}
        report_payload = {"report": "# Audit Report\n\n## Findings\n\n- SQLi in login\n"}

        with patch("cyber_audit.stages.recon.run_agent", new=AsyncMock(return_value=_make_agent_result(recon_payload))), \
             patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock(return_value=_make_agent_result(hunt_payload))), \
             patch("cyber_audit.stages.validate.run_agent", new=AsyncMock(return_value=_make_agent_result(validate_payload))), \
             patch("cyber_audit.stages.gapfill.run_agent", new=AsyncMock(return_value=_make_agent_result(gapfill_payload))), \
             patch("cyber_audit.stages.dedupe.run_agent", new=AsyncMock(return_value=_make_agent_result(dedupe_payload))), \
             patch("cyber_audit.stages.trace.run_agent", new=AsyncMock(return_value=_make_agent_result(trace_payload))), \
             patch("cyber_audit.stages.feedback.run_agent", new=AsyncMock(return_value=_make_agent_result(feedback_payload))), \
             patch("cyber_audit.stages.report.run_agent", new=AsyncMock(return_value=_make_agent_result(report_payload))):

            run_id, report_path = await run_pipeline(
                repo_path=repo_path.resolve(),
                db=db,
                config=config,
            )

        run = db.get_run(run_id)
        assert run["status"] == "completed"

        findings = db.get_findings(run_id)
        assert len(findings) == 1
        assert findings[0].validation_status == "confirmed"
        assert findings[0].vuln_class == "sqli"
        assert report_path.exists()
