"""Test hunt stage — run_hunt processes pending tasks concurrently."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from cyber_audit.agent import AgentResult
from cyber_audit.config import HarnessConfig, StageConfig
from cyber_audit.state import Finding, StateDB, Task
from cyber_audit.stages._common import StageContext
from cyber_audit.stages.hunt import run_hunt


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_config() -> HarnessConfig:
    """Minimal HarnessConfig with hunt stage configured."""
    stages = {}
    for name in ["recon", "hunt", "validate", "gapfill", "dedupe", "trace", "feedback", "report"]:
        stages[name] = StageConfig(
            model=f"test-model-{name}",
            concurrency=2,
            tools=["Read", "Grep", "Bash"],
        )
    return HarnessConfig(
        gapfill_iterations=2,
        feedback_iterations=3,
        stages=stages,
    )


@pytest.fixture
def ctx(sample_config) -> StageContext:
    """StageContext for hunt tests."""
    return StageContext(
        run_id=1,
        repo_path=Path("/tmp/test-repo"),
        config=sample_config,
    )


@pytest.fixture
def db() -> StateDB:
    """Fresh in-memory StateDB with a run and some pending tasks."""
    sdb = StateDB(":memory:")
    sdb.create_run("/tmp/test-repo")
    return sdb


def _add_pending_task(db: StateDB, run_id: int, attack_class: str, priority: int) -> int:
    """Helper to add a pending task and return its task_id."""
    return db.add_task(
        run_id=run_id,
        source="recon",
        attack_class=attack_class,
        scope_hint=f"test_{attack_class}.py",
        target_files=[f"test_{attack_class}.py"],
        rationale=f"Test rationale for {attack_class}",
        priority=priority,
        status="pending",
        raw_json={},
    )


def _make_finding_payload(task_id: int) -> dict:
    """Return a payload dict that looks like hunt agent output."""
    return {
        "findings": [
            {
                "file": "test_sqli.py",
                "line_start": 42,
                "line_end": 42,
                "vuln_class": "sqli",
                "severity": "critical",
                "description": "SQL injection in query",
                "evidence": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
                "poc_succeeded": True,
                "confidence": 0.95,
            },
        ],
    }


def _make_agent_result(task_id: int) -> AgentResult:
    """Return an AgentResult with finding payload."""
    return AgentResult(
        payload=_make_finding_payload(task_id),
        cost_usd=0.01,
        input_tokens=1000,
        output_tokens=500,
        num_turns=3,
        duration_ms=2000,
        session_id=None,
        artifact_path=Path(f"/tmp/artifact_{task_id}.jsonl"),
        repair_used=False,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestRunHunt:
    """run_hunt gets pending tasks, runs them concurrently, saves findings."""

    @pytest.mark.asyncio
    async def test_run_hunt_no_tasks_returns_zero(self, ctx, db):
        """When there are no pending tasks, run_hunt returns 0."""
        with patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock()) as mock_run:
            count = await run_hunt(ctx, db)

        assert count == 0
        mock_run.assert_not_called()

    @pytest.mark.asyncio
    async def test_run_hunt_single_task_creates_finding(self, ctx, db):
        """A single pending task should produce one finding."""
        task_id = _add_pending_task(db, ctx.run_id, "sqli", 5)
        agent_result = _make_agent_result(task_id)

        with patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock(return_value=agent_result)):
            count = await run_hunt(ctx, db)

        assert count == 1
        findings = db.get_findings(ctx.run_id)
        assert len(findings) == 1
        assert findings[0].vuln_class == "sqli"

    @pytest.mark.asyncio
    async def test_run_hunt_returns_count_of_findings_added(self, ctx, db):
        """run_hunt should return the total number of findings added."""
        _add_pending_task(db, ctx.run_id, "sqli", 5)
        _add_pending_task(db, ctx.run_id, "xss", 4)

        async def mock_run_side_effect(**kwargs):
            task_id_from_input = kwargs["user_input"]["task_id"]
            return _make_agent_result(task_id_from_input)

        with patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock(side_effect=mock_run_side_effect)):
            count = await run_hunt(ctx, db)

        assert count == 2

    @pytest.mark.asyncio
    async def test_run_hunt_updates_task_status(self, ctx, db):
        """After running, tasks should be marked as 'completed'."""
        task_id = _add_pending_task(db, ctx.run_id, "sqli", 5)
        agent_result = _make_agent_result(task_id)

        with patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock(return_value=agent_result)):
            await run_hunt(ctx, db)

        tasks = db.get_all_tasks(ctx.run_id)
        assert tasks[0].status == "completed"

    @pytest.mark.asyncio
    async def test_run_hunt_finding_has_correct_fields(self, ctx, db):
        """The finding saved should have fields from the agent payload."""
        task_id = _add_pending_task(db, ctx.run_id, "sqli", 5)
        agent_result = _make_agent_result(task_id)

        with patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock(return_value=agent_result)):
            await run_hunt(ctx, db)

        findings = db.get_findings(ctx.run_id)
        f = findings[0]
        assert f.task_id == task_id
        assert f.run_id == ctx.run_id
        assert f.file == "test_sqli.py"
        assert f.line_start == 42
        assert f.line_end == 42
        assert f.vuln_class == "sqli"
        assert f.severity == "critical"
        assert f.poc_succeeded is True
        assert f.confidence == 0.95

    @pytest.mark.asyncio
    async def test_run_hunt_multiple_findings_per_task(self, ctx, db):
        """A single agent can return multiple findings for one task."""
        task_id = _add_pending_task(db, ctx.run_id, "multi", 5)

        multi_result = AgentResult(
            payload={
                "findings": [
                    {
                        "file": "a.py", "line_start": 1, "line_end": 1,
                        "vuln_class": "sqli", "severity": "high",
                        "description": "d1", "evidence": "e1",
                        "poc_succeeded": True, "confidence": 0.9,
                    },
                    {
                        "file": "b.py", "line_start": 2, "line_end": 2,
                        "vuln_class": "xss", "severity": "medium",
                        "description": "d2", "evidence": "e2",
                        "poc_succeeded": False, "confidence": 0.5,
                    },
                ],
            },
            cost_usd=0.02,
            input_tokens=2000,
            output_tokens=800,
            num_turns=4,
            duration_ms=3000,
            session_id=None,
            artifact_path=Path("/tmp/art_multi.jsonl"),
            repair_used=False,
        )

        with patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock(return_value=multi_result)):
            count = await run_hunt(ctx, db)

        assert count == 2
        findings = db.get_findings(ctx.run_id)
        assert len(findings) == 2

    @pytest.mark.asyncio
    async def test_run_hunt_concurrent_execution(self, ctx, db):
        """Tasks should be run concurrently using asyncio.gather."""
        t1 = _add_pending_task(db, ctx.run_id, "sqli", 5)
        t2 = _add_pending_task(db, ctx.run_id, "xss", 4)
        t3 = _add_pending_task(db, ctx.run_id, "cmdi", 3)

        call_order = []

        async def tracked_run(**kwargs):
            task_id = kwargs["user_input"]["task_id"]
            call_order.append(task_id)
            await asyncio.sleep(0.01)  # simulate work
            return _make_agent_result(task_id)

        with patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock(side_effect=tracked_run)):
            count = await run_hunt(ctx, db)

        assert count == 3
        # All three should have been called
        assert len(call_order) == 3

    @pytest.mark.asyncio
    async def test_run_hunt_respects_semaphore(self, ctx, db):
        """Concurrency should be limited by the semaphore from stage config."""
        # Set concurrency=1 in the config
        ctx.config.stages["hunt"].concurrency = 1

        t1 = _add_pending_task(db, ctx.run_id, "sqli", 5)
        t2 = _add_pending_task(db, ctx.run_id, "xss", 4)

        concurrent_count = 0
        max_concurrent = 0

        async def tracked_run(**kwargs):
            nonlocal concurrent_count, max_concurrent
            concurrent_count += 1
            max_concurrent = max(max_concurrent, concurrent_count)
            await asyncio.sleep(0.02)
            concurrent_count -= 1
            return _make_agent_result(kwargs["user_input"]["task_id"])

        with patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock(side_effect=tracked_run)):
            await run_hunt(ctx, db)

        # With semaphore=1, max_concurrent should be 1
        assert max_concurrent == 1

    @pytest.mark.asyncio
    async def test_run_hunt_passes_correct_agent_args(self, ctx, db):
        """run_hunt should pass correct arguments to run_agent."""
        task_id = _add_pending_task(db, ctx.run_id, "sqli", 5)
        agent_result = _make_agent_result(task_id)

        with patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock(return_value=agent_result)) as mock_run:
            await run_hunt(ctx, db)

        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["stage"] == "hunt"
        assert call_kwargs["prompt_file"] == ctx.prompt("hunt")
        assert call_kwargs["schema_file"] == ctx.schema("hunt")
        assert call_kwargs["model"] == "test-model-hunt"
        assert call_kwargs["allowed_tools"] == ["Read", "Grep", "Bash"]
        assert call_kwargs["artifact_dir"] == ctx.results_dir("hunt")
        # user_input should contain task data
        assert "task_id" in call_kwargs["user_input"]

    @pytest.mark.asyncio
    async def test_run_hunt_records_cost(self, ctx, db):
        """Each task run should record cost."""
        _add_pending_task(db, ctx.run_id, "sqli", 5)
        agent_result = _make_agent_result(1)

        with patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock(return_value=agent_result)):
            await run_hunt(ctx, db)

        total = db.total_cost(ctx.run_id)
        assert total > 0

    @pytest.mark.asyncio
    async def test_run_hunt_budget_check_stops_processing(self, ctx, db):
        """If budget_check returns False before a task, it should not run."""
        _add_pending_task(db, ctx.run_id, "sqli", 5)
        _add_pending_task(db, ctx.run_id, "xss", 4)

        def budget_check():
            return False  # budget exhausted

        with patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock()) as mock_run:
            count = await run_hunt(ctx, db, budget_check=budget_check)

        assert count == 0
        mock_run.assert_not_called()

    @pytest.mark.asyncio
    async def test_run_hunt_budget_check_allows_processing(self, ctx, db):
        """If budget_check returns True, tasks should run normally."""
        _add_pending_task(db, ctx.run_id, "sqli", 5)
        agent_result = _make_agent_result(1)

        def budget_check():
            return True

        with patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock(return_value=agent_result)):
            count = await run_hunt(ctx, db, budget_check=budget_check)

        assert count == 1

    @pytest.mark.asyncio
    async def test_run_hunt_handles_task_with_empty_findings(self, ctx, db):
        """If agent returns no findings, task still gets completed."""
        task_id = _add_pending_task(db, ctx.run_id, "sqli", 5)

        empty_result = AgentResult(
            payload={"findings": []},
            cost_usd=0.005,
            input_tokens=500,
            output_tokens=200,
            num_turns=2,
            duration_ms=1000,
            session_id=None,
            artifact_path=Path("/tmp/art_empty.jsonl"),
            repair_used=False,
        )

        with patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock(return_value=empty_result)):
            count = await run_hunt(ctx, db)

        assert count == 0
        tasks = db.get_all_tasks(ctx.run_id)
        assert tasks[0].status == "completed"

    @pytest.mark.asyncio
    async def test_run_hunt_preserves_task_ordering_by_priority(self, ctx, db):
        """Tasks should be processed in priority-descending order."""
        t_low = _add_pending_task(db, ctx.run_id, "low", 1)
        t_high = _add_pending_task(db, ctx.run_id, "high", 10)
        t_mid = _add_pending_task(db, ctx.run_id, "mid", 5)

        call_order = []

        async def tracked_run(**kwargs):
            task_id = kwargs["user_input"]["task_id"]
            call_order.append(task_id)
            return _make_agent_result(task_id)

        with patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock(side_effect=tracked_run)):
            await run_hunt(ctx, db)

        # First called should be highest priority (even if gathered concurrently,
        # the tasks list should be ordered by priority)
        assert call_order[0] == t_high

    @pytest.mark.asyncio
    async def test_run_hunt_handles_agent_error_gracefully(self, ctx, db):
        """If one agent fails, others should still run and failed task marked as failed."""
        t1 = _add_pending_task(db, ctx.run_id, "good", 5)
        t2 = _add_pending_task(db, ctx.run_id, "bad", 4)

        async def flaky_run(**kwargs):
            task_id = kwargs["user_input"]["task_id"]
            if task_id == t2:
                raise RuntimeError("Agent crashed")
            return _make_agent_result(task_id)

        with patch("cyber_audit.stages.hunt.run_agent", new=AsyncMock(side_effect=flaky_run)):
            count = await run_hunt(ctx, db)

        # Only the good task produces a finding
        assert count == 1
        # Bad task should be marked as failed
        tasks = db.get_all_tasks(ctx.run_id)
        statuses = {t.task_id: t.status for t in tasks}
        assert statuses[t2] == "failed"
        assert statuses[t1] == "completed"
