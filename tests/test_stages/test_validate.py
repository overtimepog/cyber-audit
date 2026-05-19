"""Test validate stage — run_validate checks unvalidated findings."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from cyber_audit.agent import AgentResult
from cyber_audit.config import HarnessConfig, StageConfig
from cyber_audit.state import Finding, StateDB
from cyber_audit.stages._common import StageContext
from cyber_audit.stages.validate import run_validate


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_config() -> HarnessConfig:
    """Minimal HarnessConfig with validate stage configured at concurrency=2."""
    stages = {}
    for name in ["recon", "hunt", "validate", "gapfill", "dedupe", "trace", "feedback", "report"]:
        stages[name] = StageConfig(
            model=f"test-model-{name}",
            concurrency=2,
            tools=["Read", "Grep"],
        )
    return HarnessConfig(
        gapfill_iterations=2,
        feedback_iterations=3,
        stages=stages,
    )


@pytest.fixture
def ctx(sample_config) -> StageContext:
    """StageContext for validate tests."""
    return StageContext(
        run_id=1,
        repo_path=Path("/tmp/test-repo"),
        config=sample_config,
    )


@pytest.fixture
def db() -> StateDB:
    """Fresh in-memory StateDB with a run."""
    sdb = StateDB(":memory:")
    sdb.create_run("/tmp/test-repo")
    return sdb


def _add_finding(
    db: StateDB,
    run_id: int,
    task_id: int,
    vuln_class: str,
    file: str = "test.py",
    validation_status: str | None = None,
) -> int:
    """Helper to add a finding and return its finding_id."""
    return db.add_finding(
        task_id=task_id,
        run_id=run_id,
        file=file,
        line_start=10,
        line_end=20,
        vuln_class=vuln_class,
        severity="high",
        description=f"Description for {vuln_class}",
        evidence=f"Evidence for {vuln_class}",
        poc_succeeded=False,
        confidence=0.8,
        raw_json={},
        validation_status=validation_status,
    )


def _make_validation_payload(finding_id: int, verdict: str = "confirmed") -> dict:
    """Return a validation payload as the agent would produce."""
    return {
        "verdict": verdict,
        "confidence": 0.9,
        "reasoning": f"Validated finding {finding_id}",
        "corrections": [],
    }


def _make_agent_result(finding_id: int, verdict: str = "confirmed") -> AgentResult:
    """Return an AgentResult with validation payload."""
    return AgentResult(
        payload=_make_validation_payload(finding_id, verdict),
        cost_usd=0.005,
        input_tokens=500,
        output_tokens=200,
        num_turns=2,
        duration_ms=1000,
        session_id=None,
        artifact_path=Path(f"/tmp/validate_{finding_id}.jsonl"),
        repair_used=False,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestRunValidate:
    """run_validate checks unvalidated findings and updates them."""

    @pytest.mark.asyncio
    async def test_run_validate_no_findings_returns_zero(self, ctx, db):
        """When there are no findings, run_validate returns 0."""
        with patch("cyber_audit.stages.validate.run_agent", new=AsyncMock()) as mock_run:
            count = await run_validate(ctx, db)

        assert count == 0
        mock_run.assert_not_called()

    @pytest.mark.asyncio
    async def test_run_validate_skips_already_validated(self, ctx, db):
        """Findings that already have a validation_status should be skipped."""
        task_id = db.add_task(ctx.run_id, "hunt", "sqli", "x.py", ["x.py"], "r", 1, "completed", {})
        _add_finding(db, ctx.run_id, task_id, "sqli", validation_status="confirmed")

        with patch("cyber_audit.stages.validate.run_agent", new=AsyncMock()) as mock_run:
            count = await run_validate(ctx, db)

        assert count == 0
        mock_run.assert_not_called()

    @pytest.mark.asyncio
    async def test_run_validate_processes_unvalidated_finding(self, ctx, db):
        """An unvalidated finding should be processed by the validate agent."""
        task_id = db.add_task(ctx.run_id, "hunt", "sqli", "x.py", ["x.py"], "r", 1, "completed", {})
        finding_id = _add_finding(db, ctx.run_id, task_id, "sqli")

        agent_result = _make_agent_result(finding_id, "confirmed")
        with patch("cyber_audit.stages.validate.run_agent", new=AsyncMock(return_value=agent_result)):
            count = await run_validate(ctx, db)

        assert count == 1

    @pytest.mark.asyncio
    async def test_run_validate_updates_validation_status(self, ctx, db):
        """After validation, the finding's status should be updated."""
        task_id = db.add_task(ctx.run_id, "hunt", "sqli", "x.py", ["x.py"], "r", 1, "completed", {})
        finding_id = _add_finding(db, ctx.run_id, task_id, "sqli")

        agent_result = _make_agent_result(finding_id, "confirmed")
        with patch("cyber_audit.stages.validate.run_agent", new=AsyncMock(return_value=agent_result)):
            await run_validate(ctx, db)

        findings = db.get_findings(ctx.run_id)
        assert findings[0].validation_status == "confirmed"

    @pytest.mark.asyncio
    async def test_run_validate_false_positive_verdict(self, ctx, db):
        """Validate agent can mark findings as false_positive."""
        task_id = db.add_task(ctx.run_id, "hunt", "sqli", "x.py", ["x.py"], "r", 1, "completed", {})
        finding_id = _add_finding(db, ctx.run_id, task_id, "sqli")

        agent_result = _make_agent_result(finding_id, "false_positive")
        with patch("cyber_audit.stages.validate.run_agent", new=AsyncMock(return_value=agent_result)):
            await run_validate(ctx, db)

        findings = db.get_findings(ctx.run_id)
        assert findings[0].validation_status == "false_positive"

    @pytest.mark.asyncio
    async def test_run_validate_saves_validation_json(self, ctx, db):
        """The validation payload should be saved as validation_json."""
        task_id = db.add_task(ctx.run_id, "hunt", "sqli", "x.py", ["x.py"], "r", 1, "completed", {})
        finding_id = _add_finding(db, ctx.run_id, task_id, "sqli")

        agent_result = _make_agent_result(finding_id, "confirmed")
        with patch("cyber_audit.stages.validate.run_agent", new=AsyncMock(return_value=agent_result)):
            await run_validate(ctx, db)

        findings = db.get_findings(ctx.run_id)
        assert findings[0].validation_json is not None
        assert findings[0].validation_json["verdict"] == "confirmed"

    @pytest.mark.asyncio
    async def test_run_validate_multiple_findings(self, ctx, db):
        """All unvalidated findings should be processed."""
        task_id = db.add_task(ctx.run_id, "hunt", "sqli", "x.py", ["x.py"], "r", 1, "completed", {})
        f1 = _add_finding(db, ctx.run_id, task_id, "sqli")
        f2 = _add_finding(db, ctx.run_id, task_id, "xss")
        f3 = _add_finding(db, ctx.run_id, task_id, "cmdi")

        async def mock_side_effect(**kwargs):
            finding_id = kwargs["user_input"]["finding_id"]
            return _make_agent_result(finding_id, "confirmed")

        with patch("cyber_audit.stages.validate.run_agent", new=AsyncMock(side_effect=mock_side_effect)):
            count = await run_validate(ctx, db)

        assert count == 3
        findings = db.get_findings(ctx.run_id)
        assert all(f.validation_status == "confirmed" for f in findings)

    @pytest.mark.asyncio
    async def test_run_validate_concurrent_execution(self, ctx, db):
        """Validations should run concurrently."""
        task_id = db.add_task(ctx.run_id, "hunt", "sqli", "x.py", ["x.py"], "r", 1, "completed", {})
        f1 = _add_finding(db, ctx.run_id, task_id, "sqli")
        f2 = _add_finding(db, ctx.run_id, task_id, "xss")
        f3 = _add_finding(db, ctx.run_id, task_id, "cmdi")

        call_order = []

        async def tracked_run(**kwargs):
            finding_id = kwargs["user_input"]["finding_id"]
            call_order.append(finding_id)
            await asyncio.sleep(0.01)
            return _make_agent_result(finding_id, "confirmed")

        with patch("cyber_audit.stages.validate.run_agent", new=AsyncMock(side_effect=tracked_run)):
            count = await run_validate(ctx, db)

        assert count == 3
        assert len(call_order) == 3

    @pytest.mark.asyncio
    async def test_run_validate_respects_semaphore(self, ctx, db):
        """Concurrency should be limited by the stage config semaphore."""
        ctx.config.stages["validate"].concurrency = 1

        task_id = db.add_task(ctx.run_id, "hunt", "sqli", "x.py", ["x.py"], "r", 1, "completed", {})
        f1 = _add_finding(db, ctx.run_id, task_id, "sqli")
        f2 = _add_finding(db, ctx.run_id, task_id, "xss")

        concurrent_count = 0
        max_concurrent = 0

        async def tracked_run(**kwargs):
            nonlocal concurrent_count, max_concurrent
            concurrent_count += 1
            max_concurrent = max(max_concurrent, concurrent_count)
            await asyncio.sleep(0.02)
            concurrent_count -= 1
            return _make_agent_result(kwargs["user_input"]["finding_id"], "confirmed")

        with patch("cyber_audit.stages.validate.run_agent", new=AsyncMock(side_effect=tracked_run)):
            await run_validate(ctx, db)

        assert max_concurrent == 1

    @pytest.mark.asyncio
    async def test_run_validate_passes_correct_agent_args(self, ctx, db):
        """run_validate should pass correct arguments to run_agent."""
        task_id = db.add_task(ctx.run_id, "hunt", "sqli", "x.py", ["x.py"], "r", 1, "completed", {})
        finding_id = _add_finding(db, ctx.run_id, task_id, "sqli")

        agent_result = _make_agent_result(finding_id, "confirmed")
        with patch("cyber_audit.stages.validate.run_agent", new=AsyncMock(return_value=agent_result)) as mock_run:
            await run_validate(ctx, db)

        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["stage"] == "validate"
        assert call_kwargs["prompt_file"] == ctx.prompt("validate")
        assert call_kwargs["schema_file"] == ctx.schema("validate")
        assert call_kwargs["model"] == "test-model-validate"
        assert call_kwargs["allowed_tools"] == ["Read", "Grep"]
        assert call_kwargs["artifact_dir"] == ctx.results_dir("validate")
        assert "finding_id" in call_kwargs["user_input"]

    @pytest.mark.asyncio
    async def test_run_validate_sends_finding_data_to_agent(self, ctx, db):
        """The user_input passed to run_agent should contain full finding data."""
        task_id = db.add_task(ctx.run_id, "hunt", "sqli", "x.py", ["x.py"], "r", 1, "completed", {})
        finding_id = _add_finding(db, ctx.run_id, task_id, "sqli", file="vuln_file.py")

        agent_result = _make_agent_result(finding_id, "confirmed")
        with patch("cyber_audit.stages.validate.run_agent", new=AsyncMock(return_value=agent_result)) as mock_run:
            await run_validate(ctx, db)

        user_input = mock_run.call_args.kwargs["user_input"]
        assert user_input["finding_id"] == finding_id
        assert user_input["file"] == "vuln_file.py"
        assert user_input["vuln_class"] == "sqli"
        assert user_input["severity"] == "high"

    @pytest.mark.asyncio
    async def test_run_validate_records_cost(self, ctx, db):
        """Validation should record cost in the database."""
        task_id = db.add_task(ctx.run_id, "hunt", "sqli", "x.py", ["x.py"], "r", 1, "completed", {})
        finding_id = _add_finding(db, ctx.run_id, task_id, "sqli")

        agent_result = _make_agent_result(finding_id, "confirmed")
        with patch("cyber_audit.stages.validate.run_agent", new=AsyncMock(return_value=agent_result)):
            await run_validate(ctx, db)

        total = db.total_cost(ctx.run_id)
        assert total > 0

    @pytest.mark.asyncio
    async def test_run_validate_handles_agent_error_gracefully(self, ctx, db):
        """If one validation fails, others should still run."""
        task_id = db.add_task(ctx.run_id, "hunt", "sqli", "x.py", ["x.py"], "r", 1, "completed", {})
        f_good = _add_finding(db, ctx.run_id, task_id, "sqli")
        f_bad = _add_finding(db, ctx.run_id, task_id, "xss")

        async def flaky_run(**kwargs):
            finding_id = kwargs["user_input"]["finding_id"]
            if finding_id == f_bad:
                raise RuntimeError("Validation agent crashed")
            return _make_agent_result(finding_id, "confirmed")

        with patch("cyber_audit.stages.validate.run_agent", new=AsyncMock(side_effect=flaky_run)):
            count = await run_validate(ctx, db)

        # Only the good finding gets validated
        assert count == 1
        findings = db.get_findings(ctx.run_id)
        statuses = {f.finding_id: f.validation_status for f in findings}
        assert statuses[f_good] == "confirmed"
        # Bad finding should still be unvalidated (or marked as error)
        # The implementation should handle this gracefully

    @pytest.mark.asyncio
    async def test_run_validate_only_processes_current_run(self, ctx, db):
        """Only findings from the current run should be validated."""
        # Create a second run with its own findings
        db.create_run("/tmp/other-repo")
        run2_id = 2
        task_id_1 = db.add_task(ctx.run_id, "hunt", "sqli", "x.py", ["x.py"], "r", 1, "completed", {})
        task_id_2 = db.add_task(run2_id, "hunt", "xss", "y.py", ["y.py"], "r", 1, "completed", {})
        f1 = _add_finding(db, ctx.run_id, task_id_1, "sqli")
        f2 = _add_finding(db, run2_id, task_id_2, "xss")

        agent_result = _make_agent_result(f1, "confirmed")
        with patch("cyber_audit.stages.validate.run_agent", new=AsyncMock(return_value=agent_result)):
            count = await run_validate(ctx, db)

        # Only the finding in ctx.run_id should be processed
        assert count == 1
        f1_updated = db.get_findings(ctx.run_id)[0]
        assert f1_updated.validation_status == "confirmed"
        f2_updated = db.get_findings(run2_id)[0]
        assert f2_updated.validation_status is None
