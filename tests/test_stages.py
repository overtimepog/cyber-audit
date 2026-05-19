"""Tests for cyber_audit.stages — gapfill, dedupe, trace, feedback, report.

Strict TDD: these tests are written BEFORE the implementation modules.
All run_agent calls are mocked via AsyncMock.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyber_audit.agent import AgentResult
from cyber_audit.llm import ProviderConfig
from cyber_audit.state import Finding, StateDB, Task


# ---------------------------------------------------------------------------
# Shared context fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def db():
    """Fresh in-memory StateDB."""
    return StateDB(":memory:")


@pytest.fixture
def tmp_dir():
    """Temporary directory for artifacts / reports."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def run_id(db):
    """Create a run and return its id."""
    return db.create_run("/tmp/test-repo")


def _make_result(payload: dict) -> AgentResult:
    """Quick AgentResult builder for mock return values."""
    return AgentResult(
        payload=payload,
        cost_usd=0.001,
        input_tokens=100,
        output_tokens=50,
        num_turns=1,
        duration_ms=500,
        session_id="mock",
        artifact_path=Path("/tmp/mock.jsonl"),
        repair_used=False,
    )


def _add_task(db, run_id, **overrides):
    """Add a task with sensible defaults, return task_id."""
    defaults = dict(
        source="recon",
        attack_class="path-traversal",
        scope_hint="src/",
        target_files=["src/app.py"],
        rationale="test",
        priority=3,
        status="pending",
        raw_json={},
    )
    defaults.update(overrides)
    return db.add_task(run_id=run_id, **defaults)


def _add_finding(db, task_id, run_id, **overrides):
    """Add a finding with sensible defaults, return finding_id."""
    defaults = dict(
        file="src/app.py",
        line_start=10,
        line_end=20,
        vuln_class="path-traversal",
        severity="high",
        description="Unsanitized path",
        evidence="open(user_input)",
        poc_succeeded=True,
        confidence=0.9,
        raw_json={},
    )
    defaults.update(overrides)
    return db.add_finding(task_id=task_id, run_id=run_id, **defaults)


# ===================================================================
# gapfill
# ===================================================================


class TestGapfill:
    """run_gapfill(ctx, db) — reviews hunt tasks, emits new tasks for gaps."""

    @pytest.mark.asyncio
    async def test_no_gaps_when_all_covered(self, db, run_id, tmp_dir):
        """Agent reports no coverage gaps → no new tasks are created."""
        from cyber_audit.stages.gapfill import run_gapfill

        # Seed: several completed hunt tasks covering various areas
        t1 = _add_task(db, run_id, source="hunt", attack_class="sqli", scope_hint="db/",
                       target_files=["db/query.py"], status="completed")
        t2 = _add_task(db, run_id, source="hunt", attack_class="xss", scope_hint="views/",
                       target_files=["views/render.py"], status="completed")

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.gapfill.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({"new_tasks": []})

            await run_gapfill(ctx, db)

        # No new tasks should have been added
        all_tasks = db.get_all_tasks(run_id)
        assert len(all_tasks) == 2  # only the original two

    @pytest.mark.asyncio
    async def test_gap_discovered_creates_new_task(self, db, run_id, tmp_dir):
        """Agent discovers under-covered area → creates new hunt task."""
        from cyber_audit.stages.gapfill import run_gapfill

        t1 = _add_task(db, run_id, source="hunt", attack_class="sqli", scope_hint="db/",
                       target_files=["db/query.py"], status="completed")

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.gapfill.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({
                "new_tasks": [
                    {
                        "source": "gapfill",
                        "attack_class": "xss",
                        "scope_hint": "views/",
                        "target_files": ["views/render.py"],
                        "rationale": "views/ directory not audited yet",
                        "priority": 5,
                        "raw_json": {"gap": "views_not_covered"},
                    }
                ]
            })

            await run_gapfill(ctx, db)

        # Should now have 2 tasks (original + new gapfill)
        all_tasks = db.get_all_tasks(run_id)
        assert len(all_tasks) == 2
        new_task = [t for t in all_tasks if t.source == "gapfill"][0]
        assert new_task.attack_class == "xss"
        assert new_task.priority == 5
        assert new_task.status == "pending"
        assert new_task.target_files == ["views/render.py"]

    @pytest.mark.asyncio
    async def test_multiple_gaps_create_multiple_tasks(self, db, run_id, tmp_dir):
        """Agent returns multiple gaps → multiple new tasks created."""
        from cyber_audit.stages.gapfill import run_gapfill

        t1 = _add_task(db, run_id, source="hunt", attack_class="sqli", scope_hint="db/",
                       target_files=["db/query.py"], status="completed")

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.gapfill.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({
                "new_tasks": [
                    {"source": "gapfill", "attack_class": "xss", "scope_hint": "views/",
                     "target_files": ["views/a.py"], "rationale": "gap 1", "priority": 4, "raw_json": {}},
                    {"source": "gapfill", "attack_class": "idor", "scope_hint": "api/",
                     "target_files": ["api/users.py"], "rationale": "gap 2", "priority": 3, "raw_json": {}},
                ]
            })

            await run_gapfill(ctx, db)

        all_tasks = db.get_all_tasks(run_id)
        assert len(all_tasks) == 3
        gapfill_tasks = [t for t in all_tasks if t.source == "gapfill"]
        assert len(gapfill_tasks) == 2
        classes = {t.attack_class for t in gapfill_tasks}
        assert classes == {"xss", "idor"}

    @pytest.mark.asyncio
    async def test_handles_missing_new_tasks_key(self, db, run_id, tmp_dir):
        """Agent returns payload without 'new_tasks' key → no crash, no tasks."""
        from cyber_audit.stages.gapfill import run_gapfill

        t1 = _add_task(db, run_id, source="hunt", attack_class="sqli", status="completed")

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.gapfill.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({"summary": "all good"})

            await run_gapfill(ctx, db)

        # Should still only have the original
        all_tasks = db.get_all_tasks(run_id)
        assert len(all_tasks) == 1

    @pytest.mark.asyncio
    async def test_agent_passed_completed_tasks(self, db, run_id, tmp_dir):
        """Verify the agent receives the list of completed hunt tasks."""
        from cyber_audit.stages.gapfill import run_gapfill

        t1 = _add_task(db, run_id, attack_class="sqli", status="completed",
                       source="hunt")
        t2 = _add_task(db, run_id, attack_class="rce", status="pending",
                       source="hunt")  # pending — should NOT be included
        t3 = _add_task(db, run_id, attack_class="xss", status="completed",
                       source="hunt")

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.gapfill.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({"new_tasks": []})

            await run_gapfill(ctx, db)

        # Check what user_input was sent to the agent
        call_kwargs = mock_agent.call_args.kwargs
        user_input = call_kwargs["user_input"]
        assert "completed_tasks" in user_input
        assert len(user_input["completed_tasks"]) == 2  # only completed ones
        task_classes = {t["attack_class"] for t in user_input["completed_tasks"]}
        assert task_classes == {"sqli", "xss"}


# ===================================================================
# dedupe
# ===================================================================


class TestDedupe:
    """run_dedupe(ctx, db) — clusters findings by root cause, creates groups."""

    @pytest.mark.asyncio
    async def test_creates_dedupe_groups(self, db, run_id, tmp_dir):
        """Agent clusters findings → dedupe groups with canonical findings."""
        from cyber_audit.stages.dedupe import run_dedupe

        task_id = _add_task(db, run_id, status="completed")
        f1 = _add_finding(db, task_id, run_id, vuln_class="sqli", severity="critical",
                          validation_status="confirmed")
        f2 = _add_finding(db, task_id, run_id, vuln_class="sqli", severity="high",
                          file="db/other.py", validation_status="confirmed")
        f3 = _add_finding(db, task_id, run_id, vuln_class="xss", severity="medium",
                          file="views/page.py", validation_status="confirmed")

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.dedupe.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({
                "groups": [
                    {
                        "root_cause": "Unsafe SQL string concatenation in db layer",
                        "canonical_finding_id": f1,
                        "finding_ids": [f1, f2],
                    },
                    {
                        "root_cause": "User input rendered without escaping",
                        "canonical_finding_id": f3,
                        "finding_ids": [f3],
                    },
                ]
            })

            await run_dedupe(ctx, db)

        # Verify findings have been assigned to groups
        findings = db.get_findings(run_id)
        # f1 and f2 should be in same group, f3 in different group
        f1_obj = [f for f in findings if f.finding_id == f1][0]
        f2_obj = [f for f in findings if f.finding_id == f2][0]
        f3_obj = [f for f in findings if f.finding_id == f3][0]

        assert f1_obj.group_id is not None
        assert f2_obj.group_id is not None
        assert f3_obj.group_id is not None
        assert f1_obj.group_id == f2_obj.group_id  # same group
        assert f1_obj.group_id != f3_obj.group_id  # different group

        # f1 should be canonical
        assert f1_obj.is_canonical is True
        assert f2_obj.is_canonical is False
        assert f3_obj.is_canonical is True

    @pytest.mark.asyncio
    async def test_no_validated_findings_does_nothing(self, db, run_id, tmp_dir):
        """No validated findings → agent not called, no groups created."""
        from cyber_audit.stages.dedupe import run_dedupe

        task_id = _add_task(db, run_id, status="completed")
        _add_finding(db, task_id, run_id, vuln_class="sqli",
                     validation_status=None)  # unvalidated

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.dedupe.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({"groups": []})

            await run_dedupe(ctx, db)

        # Agent should not have been called
        mock_agent.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_already_grouped_findings(self, db, run_id, tmp_dir):
        """Findings that already have a group_id should be excluded."""
        from cyber_audit.stages.dedupe import run_dedupe

        task_id = _add_task(db, run_id, status="completed")
        f1 = _add_finding(db, task_id, run_id, vuln_class="sqli",
                          validation_status="confirmed")
        # Create a pre-existing group and assign f2 to it
        pre_group_id = db.add_dedupe_group(run_id, "pre-existing", None, {})
        f2 = _add_finding(db, task_id, run_id, vuln_class="xss",
                          validation_status="confirmed")
        db.assign_finding_group(f2, pre_group_id, is_canonical=True)

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.dedupe.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({
                "groups": [
                    {
                        "root_cause": "SQL injection",
                        "canonical_finding_id": f1,
                        "finding_ids": [f1],
                    }
                ]
            })

            await run_dedupe(ctx, db)

        # User input should only include f1 (not f2 which is already grouped)
        user_input = mock_agent.call_args.kwargs["user_input"]
        finding_ids_in_input = [f["finding_id"] for f in user_input["findings"]]
        assert f1 in finding_ids_in_input
        assert f2 not in finding_ids_in_input

    @pytest.mark.asyncio
    async def test_handles_empty_groups(self, db, run_id, tmp_dir):
        """Agent returns empty groups list → no crash, no groups."""
        from cyber_audit.stages.dedupe import run_dedupe

        task_id = _add_task(db, run_id, status="completed")
        _add_finding(db, task_id, run_id, vuln_class="sqli",
                     validation_status="confirmed")

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.dedupe.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({"groups": []})

            await run_dedupe(ctx, db)

        # Should not crash
        findings = db.get_findings(run_id)
        assert findings[0].group_id is None


# ===================================================================
# trace
# ===================================================================


class TestTrace:
    """run_trace(ctx, db) — traces attacker input path to sink for each validated finding."""

    @pytest.mark.asyncio
    async def test_traces_reachable_finding(self, db, run_id, tmp_dir):
        """Agent traces a finding and marks it reachable."""
        from cyber_audit.stages.trace import run_trace

        task_id = _add_task(db, run_id, status="completed")
        f1 = _add_finding(db, task_id, run_id, vuln_class="sqli",
                          file="db/query.py", validation_status="confirmed")

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.trace.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({
                "traces": [
                    {
                        "finding_id": f1,
                        "reachable": True,
                        "confidence": 0.95,
                        "rationale": "User-controlled 'id' param flows directly to SQL query",
                        "raw_json": {"path": ["views.py:42", "db/query.py:18"], "sink": "cursor.execute"},
                    }
                ]
            })

            await run_trace(ctx, db)

        trace = db.get_trace(f1)
        assert trace is not None
        assert trace["reachable"] is True
        assert trace["confidence"] == 0.95
        assert trace["rationale"] == "User-controlled 'id' param flows directly to SQL query"
        assert trace["raw_json"]["path"] == ["views.py:42", "db/query.py:18"]

    @pytest.mark.asyncio
    async def test_traces_unreachable_finding(self, db, run_id, tmp_dir):
        """Agent determines a finding is not reachable."""
        from cyber_audit.stages.trace import run_trace

        task_id = _add_task(db, run_id, status="completed")
        f1 = _add_finding(db, task_id, run_id, vuln_class="sqli",
                          validation_status="confirmed")

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.trace.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({
                "traces": [
                    {
                        "finding_id": f1,
                        "reachable": False,
                        "confidence": 0.8,
                        "rationale": "Input is sanitized before reaching sink",
                        "raw_json": {"sanitizer": "int() cast at line 15"},
                    }
                ]
            })

            await run_trace(ctx, db)

        trace = db.get_trace(f1)
        assert trace["reachable"] is False
        assert trace["rationale"] == "Input is sanitized before reaching sink"

    @pytest.mark.asyncio
    async def test_skips_unvalidated_findings(self, db, run_id, tmp_dir):
        """Only validated findings are traced."""
        from cyber_audit.stages.trace import run_trace

        task_id = _add_task(db, run_id, status="completed")
        f1 = _add_finding(db, task_id, run_id, vuln_class="sqli",
                          validation_status=None)  # unvalidated
        f2 = _add_finding(db, task_id, run_id, vuln_class="xss",
                          validation_status="confirmed")

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.trace.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({
                "traces": [
                    {"finding_id": f2, "reachable": True, "confidence": 0.9,
                     "rationale": "xss reachable", "raw_json": {}},
                ]
            })

            await run_trace(ctx, db)

        # f1 should have no trace
        assert db.get_trace(f1) is None
        # f2 should have a trace
        assert db.get_trace(f2) is not None

        # verify agent only received f2
        user_input = mock_agent.call_args.kwargs["user_input"]
        finding_ids = [f["finding_id"] for f in user_input["findings"]]
        assert f2 in finding_ids
        assert f1 not in finding_ids

    @pytest.mark.asyncio
    async def test_no_validated_findings_skips(self, db, run_id, tmp_dir):
        """No validated findings → agent not called."""
        from cyber_audit.stages.trace import run_trace

        task_id = _add_task(db, run_id, status="completed")
        _add_finding(db, task_id, run_id, vuln_class="sqli",
                     validation_status=None)

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.trace.run_agent", new_callable=AsyncMock) as mock_agent:
            await run_trace(ctx, db)

        mock_agent.assert_not_called()

    @pytest.mark.asyncio
    async def test_trace_missing_from_result(self, db, run_id, tmp_dir):
        """A finding in the list but missing in the result should be handled gracefully."""
        from cyber_audit.stages.trace import run_trace

        task_id = _add_task(db, run_id, status="completed")
        f1 = _add_finding(db, task_id, run_id, vuln_class="sqli",
                          validation_status="confirmed")
        f2 = _add_finding(db, task_id, run_id, vuln_class="xss",
                          validation_status="confirmed")

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.trace.run_agent", new_callable=AsyncMock) as mock_agent:
            # Only trace for f1 returned
            mock_agent.return_value = _make_result({
                "traces": [
                    {"finding_id": f1, "reachable": True, "confidence": 0.9,
                     "rationale": "traced", "raw_json": {}},
                ]
            })

            await run_trace(ctx, db)

        # f1 traced, f2 not — no crash
        assert db.get_trace(f1) is not None
        assert db.get_trace(f2) is None


# ===================================================================
# feedback
# ===================================================================


class TestFeedback:
    """run_feedback(ctx, db) — turns reachable traces into new hunt tasks."""

    @pytest.mark.asyncio
    async def test_creates_new_hunt_tasks_from_reachable(self, db, run_id, tmp_dir):
        """Reachable canonical findings → new hunt tasks in consumer repos."""
        from cyber_audit.stages.feedback import run_feedback

        task_id = _add_task(db, run_id, status="completed")
        f1 = _add_finding(db, task_id, run_id, vuln_class="sqli",
                          validation_status="confirmed", is_canonical=True)
        f2 = _add_finding(db, task_id, run_id, vuln_class="xss",
                          validation_status="confirmed", is_canonical=True)
        db.add_trace(f1, reachable=True, confidence=0.9, rationale="reachable sql",
                     raw_json={"path": ["a", "b"]})
        db.add_trace(f2, reachable=True, confidence=0.8, rationale="reachable xss",
                     raw_json={"path": ["c", "d"]})

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.feedback.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({
                "new_tasks": [
                    {
                        "source": "feedback",
                        "attack_class": "sqli",
                        "scope_hint": "src/db/",
                        "target_files": ["src/db/query.py"],
                        "rationale": "SQL injection in query builder",
                        "priority": 8,
                        "raw_json": {"original_finding": f1},
                    },
                    {
                        "source": "feedback",
                        "attack_class": "xss",
                        "scope_hint": "src/views/",
                        "target_files": ["src/views/render.py"],
                        "rationale": "XSS in template rendering",
                        "priority": 7,
                        "raw_json": {"original_finding": f2},
                    },
                ]
            })

            await run_feedback(ctx, db)

        # Should have 2 new feedback tasks
        all_tasks = db.get_all_tasks(run_id)
        feedback_tasks = [t for t in all_tasks if t.source == "feedback"]
        assert len(feedback_tasks) == 2
        assert {t.attack_class for t in feedback_tasks} == {"sqli", "xss"}
        assert all(t.status == "pending" for t in feedback_tasks)

    @pytest.mark.asyncio
    async def test_skips_unreachable_findings(self, db, run_id, tmp_dir):
        """Only reachable canonical findings are passed to agent."""
        from cyber_audit.stages.feedback import run_feedback

        task_id = _add_task(db, run_id, status="completed")
        f1 = _add_finding(db, task_id, run_id, vuln_class="sqli",
                          validation_status="confirmed", is_canonical=True)
        f2 = _add_finding(db, task_id, run_id, vuln_class="xss",
                          validation_status="confirmed", is_canonical=True)
        # f1 reachable, f2 not reachable
        db.add_trace(f1, reachable=True, confidence=0.9, rationale="reachable",
                     raw_json={})
        db.add_trace(f2, reachable=False, confidence=0.1, rationale="not reachable",
                     raw_json={})

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.feedback.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({
                "new_tasks": [
                    {"source": "feedback", "attack_class": "sqli", "scope_hint": "db/",
                     "target_files": ["db/query.py"], "rationale": "sqli feedback",
                     "priority": 8, "raw_json": {}},
                ]
            })

            await run_feedback(ctx, db)

        # Agent should only see f1
        user_input = mock_agent.call_args.kwargs["user_input"]
        passed_ids = [f["finding_id"] for f in user_input["findings"]]
        assert f1 in passed_ids
        assert f2 not in passed_ids

    @pytest.mark.asyncio
    async def test_no_reachable_findings_skips(self, db, run_id, tmp_dir):
        """No reachable canonical findings → agent not called."""
        from cyber_audit.stages.feedback import run_feedback

        task_id = _add_task(db, run_id, status="completed")
        f1 = _add_finding(db, task_id, run_id, vuln_class="sqli",
                          validation_status="confirmed", is_canonical=True)
        db.add_trace(f1, reachable=False, confidence=0.1, rationale="nope",
                     raw_json={})

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.feedback.run_agent", new_callable=AsyncMock) as mock_agent:
            await run_feedback(ctx, db)

        mock_agent.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_empty_new_tasks(self, db, run_id, tmp_dir):
        """Agent returns no new tasks → no crash, no extra tasks."""
        from cyber_audit.stages.feedback import run_feedback

        task_id = _add_task(db, run_id, status="completed")
        f1 = _add_finding(db, task_id, run_id, vuln_class="sqli",
                          validation_status="confirmed", is_canonical=True)
        db.add_trace(f1, reachable=True, confidence=0.9, rationale="reachable",
                     raw_json={})

        ctx = MagicMock()
        ctx.run_id = run_id

        with patch("cyber_audit.stages.feedback.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({"new_tasks": []})

            await run_feedback(ctx, db)

        all_tasks = db.get_all_tasks(run_id)
        feedback_tasks = [t for t in all_tasks if t.source == "feedback"]
        assert len(feedback_tasks) == 0


# ===================================================================
# report
# ===================================================================


class TestReport:
    """run_report(ctx, db) — writes structured markdown report, returns Path."""

    @pytest.mark.asyncio
    async def test_generates_report_file(self, db, run_id, tmp_dir):
        """Agent produces report markdown, stage writes it to a file."""
        from cyber_audit.stages.report import run_report

        task_id = _add_task(db, run_id, status="completed")
        f1 = _add_finding(db, task_id, run_id, vuln_class="sqli",
                          severity="critical",
                          description="SQL injection in login",
                          validation_status="confirmed", is_canonical=True)
        db.add_trace(f1, reachable=True, confidence=0.95,
                     rationale="User input flows to SQL",
                     raw_json={"sink": "cursor.execute"})

        ctx = MagicMock()
        ctx.run_id = run_id
        ctx.artifact_dir = tmp_dir

        with patch("cyber_audit.stages.report.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({
                "report": "# Cyber Audit Report\n\n## Summary\n\nFound 1 critical vulnerability.\n\n## Findings\n\n### SQL injection in login\n- **Severity**: critical\n- **File**: src/app.py\n- **Trace**: Reachable\n"
            })

            result_path = await run_report(ctx, db)

        # Should return a Path to the report
        assert isinstance(result_path, Path)
        assert result_path.exists()
        # Report should have markdown content
        content = result_path.read_text()
        assert "Cyber Audit Report" in content
        assert "SQL injection" in content

    @pytest.mark.asyncio
    async def test_report_includes_all_findings(self, db, run_id, tmp_dir):
        """Report contains all findings with traces."""
        from cyber_audit.stages.report import run_report

        task_id = _add_task(db, run_id, status="completed")
        f1 = _add_finding(db, task_id, run_id, vuln_class="sqli",
                          severity="critical", validation_status="confirmed")
        f2 = _add_finding(db, task_id, run_id, vuln_class="xss",
                          severity="high", validation_status="false_positive")
        db.add_trace(f1, reachable=True, confidence=0.9,
                     rationale="Reachable SQLi", raw_json={})

        ctx = MagicMock()
        ctx.run_id = run_id
        ctx.artifact_dir = tmp_dir

        with patch("cyber_audit.stages.report.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({
                "report": "# Report\n\n2 findings total.\n"
            })

            result_path = await run_report(ctx, db)

        # Verify agent received all findings
        user_input = mock_agent.call_args.kwargs["user_input"]
        assert len(user_input["findings"]) == 2
        finding_ids = {f["finding_id"] for f in user_input["findings"]}
        assert finding_ids == {f1, f2}
        # Verify traces were included for f1
        assert "traces" in user_input
        assert str(f1) in str(user_input["traces"])

    @pytest.mark.asyncio
    async def test_report_empty_run(self, db, run_id, tmp_dir):
        """Run with no findings still produces a report."""
        from cyber_audit.stages.report import run_report

        ctx = MagicMock()
        ctx.run_id = run_id
        ctx.artifact_dir = tmp_dir

        with patch("cyber_audit.stages.report.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({
                "report": "# Audit Report\n\nNo findings.\n"
            })

            result_path = await run_report(ctx, db)

        assert result_path.exists()
        content = result_path.read_text()
        assert "No findings" in content

    @pytest.mark.asyncio
    async def test_report_filename_includes_run_id(self, db, run_id, tmp_dir):
        """Report filename is predictable and includes run_id."""
        from cyber_audit.stages.report import run_report

        ctx = MagicMock()
        ctx.run_id = run_id
        ctx.artifact_dir = tmp_dir

        with patch("cyber_audit.stages.report.run_agent", new_callable=AsyncMock) as mock_agent:
            mock_agent.return_value = _make_result({
                "report": "# Report\n"
            })

            result_path = await run_report(ctx, db)

        assert f"report-{run_id}" in result_path.name
        assert result_path.suffix == ".md"
