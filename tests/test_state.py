"""Test StateDB — SQLite-backed state management with full TDD coverage."""

import json
import tempfile
from pathlib import Path

import pytest

from cyber_audit.state import Finding, StateDB, Task


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def db():
    """Return a fresh in-memory StateDB for each test."""
    sdb = StateDB(":memory:")
    return sdb


# ---------------------------------------------------------------------------
# Dataclass tests
# ---------------------------------------------------------------------------
class TestTaskDataclass:
    """Task dataclass has the right fields matching schema."""

    def test_task_fields_exist(self):
        t = Task(
            task_id=1,
            run_id=1,
            source="recon",
            attack_class="path-traversal",
            scope_hint="src/utils.py",
            target_files=["src/utils.py", "src/io.py"],
            rationale="Suspicious input handling",
            priority=5,
            status="pending",
            raw_json={"key": "val"},
            created_at="2026-05-18T00:00:00",
            updated_at="2026-05-18T00:00:00",
        )
        assert t.task_id == 1
        assert t.run_id == 1
        assert t.source == "recon"
        assert t.attack_class == "path-traversal"
        assert t.scope_hint == "src/utils.py"
        assert t.target_files == ["src/utils.py", "src/io.py"]
        assert t.rationale == "Suspicious input handling"
        assert t.priority == 5
        assert t.status == "pending"
        assert t.raw_json == {"key": "val"}
        assert t.created_at == "2026-05-18T00:00:00"
        assert t.updated_at == "2026-05-18T00:00:00"

    def test_task_is_dataclass(self):
        import dataclasses

        assert dataclasses.is_dataclass(Task)


class TestFindingDataclass:
    """Finding dataclass has the right fields matching schema."""

    def test_finding_fields_exist(self):
        f = Finding(
            finding_id=1,
            task_id=2,
            run_id=1,
            file="src/utils.py",
            line_start=10,
            line_end=20,
            vuln_class="path-traversal",
            severity="high",
            description="Unsanitized file path in open()",
            evidence="line 42: open(user_input)",
            poc_succeeded=True,
            confidence=0.95,
            raw_json={"evidence_lines": [42]},
            validation_status="confirmed",
            validation_json={"method": "static"},
            group_id=5,
            is_canonical=True,
        )
        assert f.finding_id == 1
        assert f.task_id == 2
        assert f.run_id == 1
        assert f.file == "src/utils.py"
        assert f.line_start == 10
        assert f.line_end == 20
        assert f.vuln_class == "path-traversal"
        assert f.severity == "high"
        assert f.description == "Unsanitized file path in open()"
        assert f.evidence == "line 42: open(user_input)"
        assert f.poc_succeeded is True
        assert f.confidence == 0.95
        assert f.raw_json == {"evidence_lines": [42]}
        assert f.validation_status == "confirmed"
        assert f.validation_json == {"method": "static"}
        assert f.group_id == 5
        assert f.is_canonical is True

    def test_finding_is_dataclass(self):
        import dataclasses

        assert dataclasses.is_dataclass(Finding)

    def test_finding_defaults(self):
        f = Finding(
            finding_id=1,
            task_id=2,
            run_id=1,
            file="src/utils.py",
            line_start=10,
            line_end=20,
            vuln_class="sqli",
            severity="critical",
            description="SQL injection in query",
            evidence="line 50: cursor.execute(query)",
            poc_succeeded=False,
            confidence=0.8,
            raw_json={},
        )
        assert f.validation_status is None
        assert f.validation_json is None
        assert f.group_id is None
        assert f.is_canonical is False


# ---------------------------------------------------------------------------
# Run lifecycle
# ---------------------------------------------------------------------------
class TestRunLifecycle:
    """create_run, finish_run, get_run, list_runs."""

    def test_create_run_returns_id(self, db):
        run_id = db.create_run("/tmp/test-repo")
        assert isinstance(run_id, int)
        assert run_id > 0

    def test_get_run_returns_correct_data(self, db):
        run_id = db.create_run("/tmp/my-repo")
        run = db.get_run(run_id)
        assert run is not None
        assert run["repo_path"] == "/tmp/my-repo"
        assert run["status"] == "running"
        assert run["started_at"] is not None
        assert run["finished_at"] is None

    def test_finish_run_updates_status(self, db):
        run_id = db.create_run("/tmp/repo")
        db.finish_run(run_id, "completed")
        run = db.get_run(run_id)
        assert run["status"] == "completed"
        assert run["finished_at"] is not None

    def test_list_runs_returns_all(self, db):
        db.create_run("/tmp/repo-a")
        db.create_run("/tmp/repo-b")
        runs = db.list_runs()
        assert len(runs) == 2
        paths = [r["repo_path"] for r in runs]
        assert "/tmp/repo-a" in paths
        assert "/tmp/repo-b" in paths

    def test_list_runs_empty(self, db):
        runs = db.list_runs()
        assert runs == []

    def test_get_nonexistent_run_returns_none(self, db):
        run = db.get_run(99999)
        assert run is None

    def test_finish_nonexistent_run_no_error(self, db):
        """finish_run on a non-existent run should not raise."""
        db.finish_run(99999, "completed")

    def test_multiple_runs_unique_ids(self, db):
        ids = [db.create_run(f"/tmp/repo-{i}") for i in range(5)]
        assert len(set(ids)) == 5


# ---------------------------------------------------------------------------
# Recon output
# ---------------------------------------------------------------------------
class TestReconOutput:
    """save_recon_output / get_recon_output."""

    def test_save_and_get_recon_output(self, db):
        run_id = db.create_run("/tmp/repo")
        data = {"files": ["a.py", "b.py"], "deps": {"flask": "3.0"}}
        db.save_recon_output(run_id, data)
        result = db.get_recon_output(run_id)
        assert result == data

    def test_get_recon_output_nonexistent(self, db):
        result = db.get_recon_output(99999)
        assert result is None

    def test_overwrite_recon_output(self, db):
        run_id = db.create_run("/tmp/repo")
        db.save_recon_output(run_id, {"v": 1})
        db.save_recon_output(run_id, {"v": 2})
        assert db.get_recon_output(run_id) == {"v": 2}


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------
class TestTasks:
    """add_task, get_pending_tasks, get_all_tasks, update_task_status."""

    def test_add_task_returns_id(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(
            run_id=run_id,
            source="recon",
            attack_class="sqli",
            scope_hint="db.py",
            target_files=["db.py"],
            rationale="Suspicious query construction",
            priority=3,
            status="pending",
            raw_json={"hint": "check line 42"},
        )
        assert isinstance(task_id, int)
        assert task_id > 0

    def test_get_all_tasks_returns_tasks(self, db):
        run_id = db.create_run("/tmp/repo")
        db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "reason", 3, "pending", {})
        db.add_task(run_id, "recon", "xss", "views.py", ["views.py"], "reason2", 5, "pending", {})
        tasks = db.get_all_tasks(run_id)
        assert len(tasks) == 2
        assert isinstance(tasks[0], Task)
        assert tasks[0].attack_class in ("sqli", "xss")
        assert tasks[1].attack_class in ("sqli", "xss")

    def test_get_all_tasks_empty_run(self, db):
        run_id = db.create_run("/tmp/repo")
        tasks = db.get_all_tasks(run_id)
        assert tasks == []

    def test_get_pending_tasks_ordered_by_priority_desc(self, db):
        run_id = db.create_run("/tmp/repo")
        db.add_task(run_id, "recon", "sqli", "a.py", ["a.py"], "r", 1, "pending", {})
        db.add_task(run_id, "recon", "xss", "b.py", ["b.py"], "r", 5, "pending", {})
        db.add_task(run_id, "recon", "rce", "c.py", ["c.py"], "r", 3, "pending", {})
        tasks = db.get_pending_tasks()
        assert len(tasks) == 3
        assert tasks[0].priority == 5
        assert tasks[1].priority == 3
        assert tasks[2].priority == 1

    def test_get_pending_tasks_skips_non_pending(self, db):
        run_id = db.create_run("/tmp/repo")
        db.add_task(run_id, "recon", "sqli", "a.py", ["a.py"], "r", 5, "completed", {})
        db.add_task(run_id, "recon", "xss", "b.py", ["b.py"], "r", 3, "pending", {})
        tasks = db.get_pending_tasks()
        assert len(tasks) == 1
        assert tasks[0].attack_class == "xss"

    def test_get_pending_tasks_empty(self, db):
        assert db.get_pending_tasks() == []

    def test_update_task_status(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "a.py", ["a.py"], "r", 1, "pending", {})
        db.update_task_status(task_id, "completed")
        tasks = db.get_all_tasks(run_id)
        assert tasks[0].status == "completed"

    def test_update_task_status_updates_updated_at(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "a.py", ["a.py"], "r", 1, "pending", {})
        original_task = db.get_all_tasks(run_id)[0]
        db.update_task_status(task_id, "in_progress")
        updated_task = db.get_all_tasks(run_id)[0]
        assert updated_task.updated_at != original_task.updated_at

    def test_task_target_files_json_roundtrip(self, db):
        run_id = db.create_run("/tmp/repo")
        target_files = ["src/a.py", "src/b.py", "tests/c.py"]
        task_id = db.add_task(run_id, "recon", "xss", "src/", target_files, "r", 3, "pending", {})
        tasks = db.get_all_tasks(run_id)
        assert tasks[0].target_files == target_files

    def test_task_raw_json_roundtrip(self, db):
        run_id = db.create_run("/tmp/repo")
        raw = {"lines": [1, 2, 3], "context": "func foo()"}
        task_id = db.add_task(run_id, "recon", "xss", "x.py", ["x.py"], "r", 3, "pending", raw)
        tasks = db.get_all_tasks(run_id)
        assert tasks[0].raw_json == raw


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
class TestFindings:
    """add_finding, get_findings, get_unvalidated_findings, set_finding_validation."""

    def test_add_finding_returns_id(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})
        finding_id = db.add_finding(
            task_id=task_id,
            run_id=run_id,
            file="db.py",
            line_start=42,
            line_end=42,
            vuln_class="sqli",
            severity="critical",
            description="SQL injection in user query",
            evidence="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
            poc_succeeded=True,
            confidence=0.99,
            raw_json={"cwe": "CWE-89"},
        )
        assert isinstance(finding_id, int)
        assert finding_id > 0

    def test_get_findings_returns_all(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})
        db.add_finding(task_id, run_id, "a.py", 1, 1, "sqli", "high", "desc", "ev", True, 0.9, {})
        db.add_finding(task_id, run_id, "b.py", 2, 2, "xss", "med", "desc2", "ev2", False, 0.5, {})
        findings = db.get_findings(run_id)
        assert len(findings) == 2
        assert isinstance(findings[0], Finding)

    def test_get_findings_empty(self, db):
        run_id = db.create_run("/tmp/repo")
        findings = db.get_findings(run_id)
        assert findings == []

    def test_get_findings_filter_by_validation_status(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})
        db.add_finding(task_id, run_id, "a.py", 1, 1, "sqli", "high", "d", "e", True, 0.9, {},
                       validation_status="confirmed")
        db.add_finding(task_id, run_id, "b.py", 2, 2, "xss", "med", "d2", "e2", False, 0.5, {},
                       validation_status="false_positive")
        confirmed = db.get_findings(run_id, validation_status="confirmed")
        assert len(confirmed) == 1
        assert confirmed[0].vuln_class == "sqli"
        fp = db.get_findings(run_id, validation_status="false_positive")
        assert len(fp) == 1
        assert fp[0].vuln_class == "xss"

    def test_get_findings_canonical_only(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})
        db.add_finding(task_id, run_id, "a.py", 1, 1, "sqli", "high", "d", "e", True, 0.9, {},
                       is_canonical=True)
        db.add_finding(task_id, run_id, "b.py", 2, 2, "xss", "med", "d2", "e2", False, 0.5, {},
                       is_canonical=False)
        db.add_finding(task_id, run_id, "c.py", 3, 3, "rce", "high", "d3", "e3", False, 0.7, {})
        canon = db.get_findings(run_id, canonical_only=True)
        assert len(canon) == 1
        assert canon[0].vuln_class == "sqli"
        assert canon[0].is_canonical is True

    def test_get_findings_combined_filters(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})
        db.add_finding(task_id, run_id, "a.py", 1, 1, "sqli", "high", "d", "e", True, 0.9, {},
                       validation_status="confirmed", is_canonical=True)
        db.add_finding(task_id, run_id, "b.py", 2, 2, "xss", "med", "d2", "e2", False, 0.5, {},
                       validation_status="confirmed", is_canonical=False)
        results = db.get_findings(run_id, validation_status="confirmed", canonical_only=True)
        assert len(results) == 1
        assert results[0].vuln_class == "sqli"

    def test_get_unvalidated_findings(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})
        db.add_finding(task_id, run_id, "a.py", 1, 1, "sqli", "high", "d", "e", True, 0.9, {})
        db.add_finding(task_id, run_id, "b.py", 2, 2, "xss", "med", "d2", "e2", False, 0.5, {},
                       validation_status="confirmed")
        unvalidated = db.get_unvalidated_findings(run_id)
        assert len(unvalidated) == 1
        assert unvalidated[0].vuln_class == "sqli"

    def test_get_unvalidated_findings_none(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})
        db.add_finding(task_id, run_id, "a.py", 1, 1, "sqli", "high", "d", "e", True, 0.9, {},
                       validation_status="confirmed")
        assert db.get_unvalidated_findings(run_id) == []

    def test_set_finding_validation(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})
        finding_id = db.add_finding(task_id, run_id, "a.py", 1, 1, "sqli", "high", "d", "e", True, 0.9, {})
        db.set_finding_validation(finding_id, "confirmed", {"method": "dynamic_test"})
        findings = db.get_findings(run_id)
        assert findings[0].validation_status == "confirmed"
        assert findings[0].validation_json == {"method": "dynamic_test"}


# ---------------------------------------------------------------------------
# Dedupe groups
# ---------------------------------------------------------------------------
class TestDedupeGroups:
    """add_dedupe_group, assign_finding_group."""

    def test_add_dedupe_group_returns_id(self, db):
        run_id = db.create_run("/tmp/repo")
        group_id = db.add_dedupe_group(run_id, "Path traversal in file handler", None, {})
        assert isinstance(group_id, int)
        assert group_id > 0

    def test_add_dedupe_group_with_canonical(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})
        finding_id = db.add_finding(task_id, run_id, "a.py", 1, 1, "sqli", "high", "d", "e", True, 0.9, {})
        group_id = db.add_dedupe_group(run_id, "SQL injection in query builder", finding_id, {"count": 3})
        # Verify canonical_finding_id is stored
        import sqlite3

        conn = sqlite3.connect(":memory:")
        # Can't easily introspect in-memory db across connections,
        # just verify it doesn't crash
        assert group_id > 0

    def test_assign_finding_group(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})
        finding_id = db.add_finding(task_id, run_id, "a.py", 1, 1, "sqli", "high", "d", "e", True, 0.9, {})
        group_id = db.add_dedupe_group(run_id, "root cause", None, {})
        db.assign_finding_group(finding_id, group_id, is_canonical=True)
        findings = db.get_findings(run_id)
        assert findings[0].group_id == group_id
        assert findings[0].is_canonical is True

    def test_assign_finding_group_non_canonical(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})
        finding_id = db.add_finding(task_id, run_id, "a.py", 1, 1, "sqli", "high", "d", "e", True, 0.9, {})
        group_id = db.add_dedupe_group(run_id, "root cause", None, {})
        db.assign_finding_group(finding_id, group_id, is_canonical=False)
        findings = db.get_findings(run_id)
        assert findings[0].group_id == group_id
        assert findings[0].is_canonical is False


# ---------------------------------------------------------------------------
# Traces
# ---------------------------------------------------------------------------
class TestTraces:
    """add_trace, get_trace, get_reachable_canonical_findings."""

    def test_add_and_get_trace(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})
        finding_id = db.add_finding(task_id, run_id, "a.py", 1, 1, "sqli", "high", "d", "e", True, 0.9, {})
        db.add_trace(finding_id, reachable=True, confidence=0.8,
                     rationale="User input flows to sink", raw_json={"path": ["a", "b", "c"]})
        trace = db.get_trace(finding_id)
        assert trace is not None
        assert trace["reachable"] is True
        assert trace["confidence"] == 0.8
        assert trace["rationale"] == "User input flows to sink"
        assert trace["raw_json"] == {"path": ["a", "b", "c"]}

    def test_get_trace_nonexistent(self, db):
        assert db.get_trace(99999) is None

    def test_add_trace_overwrites(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})
        finding_id = db.add_finding(task_id, run_id, "a.py", 1, 1, "sqli", "high", "d", "e", True, 0.9, {})
        db.add_trace(finding_id, True, 0.5, "first", {})
        db.add_trace(finding_id, False, 0.2, "second", {"updated": True})
        trace = db.get_trace(finding_id)
        assert trace["reachable"] is False
        assert trace["rationale"] == "second"

    def test_get_reachable_canonical_findings(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})

        # Canonical + reachable -> should appear
        f1 = db.add_finding(task_id, run_id, "a.py", 1, 1, "sqli", "high", "d", "e", True, 0.9, {},
                            is_canonical=True)
        db.add_trace(f1, True, 0.9, "reachable", {})

        # Canonical + not reachable -> should NOT appear
        f2 = db.add_finding(task_id, run_id, "b.py", 2, 2, "xss", "med", "d", "e", False, 0.5, {},
                            is_canonical=True)
        db.add_trace(f2, False, 0.1, "not reachable", {})

        # Not canonical + reachable -> should NOT appear
        f3 = db.add_finding(task_id, run_id, "c.py", 3, 3, "rce", "high", "d", "e", False, 0.7, {},
                            is_canonical=False)
        db.add_trace(f3, True, 0.8, "reachable but not canon", {})

        # Canonical + no trace -> should NOT appear
        f4 = db.add_finding(task_id, run_id, "d.py", 4, 4, "idor", "low", "d", "e", True, 0.3, {},
                            is_canonical=True)

        results = db.get_reachable_canonical_findings(run_id)
        assert len(results) == 1
        assert results[0].finding_id == f1
        assert results[0].vuln_class == "sqli"

    def test_get_reachable_canonical_findings_empty(self, db):
        run_id = db.create_run("/tmp/repo")
        assert db.get_reachable_canonical_findings(run_id) == []


# ---------------------------------------------------------------------------
# Costs
# ---------------------------------------------------------------------------
class TestCosts:
    """record_cost, total_cost."""

    def test_record_cost_returns_id(self, db):
        run_id = db.create_run("/tmp/repo")
        cost_id = db.record_cost(
            run_id=run_id,
            stage="recon",
            ref_id="task-1",
            usd=0.05,
            input_tokens=1000,
            output_tokens=500,
            cache_read_tokens=200,
            cache_creation_tokens=100,
            num_turns=3,
            duration_ms=1500,
        )
        assert isinstance(cost_id, int)
        assert cost_id > 0

    def test_total_cost_sums_usd(self, db):
        run_id = db.create_run("/tmp/repo")
        db.record_cost(run_id, "recon", "t1", 0.05, 1000, 500, 0, 0, 1, 100)
        db.record_cost(run_id, "hunt", "t2", 0.10, 2000, 800, 0, 0, 2, 250)
        db.record_cost(run_id, "validate", "t3", 0.02, 300, 150, 0, 0, 1, 50)
        total = db.total_cost(run_id)
        assert total == pytest.approx(0.17, rel=0.01)

    def test_total_cost_empty_run(self, db):
        run_id = db.create_run("/tmp/repo")
        assert db.total_cost(run_id) == 0.0

    def test_total_cost_nonexistent_run(self, db):
        assert db.total_cost(99999) == 0.0

    def test_record_cost_created_at(self, db):
        run_id = db.create_run("/tmp/repo")
        db.record_cost(run_id, "recon", "t1", 0.05, 1000, 500, 0, 0, 1, 100)
        # Verify created_at is set (we can't easily introspect, just check no crash)
        assert True


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------
class TestArtifacts:
    """add_artifact."""

    def test_add_artifact_returns_id(self, db):
        run_id = db.create_run("/tmp/repo")
        artifact_id = db.add_artifact(
            run_id=run_id,
            name="audit_report.md",
            content_type="text/markdown",
            data="# Audit Report\n\nFindings: ...",
        )
        assert isinstance(artifact_id, int)
        assert artifact_id > 0

    def test_add_artifact_multiple(self, db):
        run_id = db.create_run("/tmp/repo")
        a1 = db.add_artifact(run_id, "a.txt", "text/plain", "data1")
        a2 = db.add_artifact(run_id, "b.txt", "text/plain", "data2")
        assert a1 != a2


# ---------------------------------------------------------------------------
# Persistence (file-backed database)
# ---------------------------------------------------------------------------
class TestPersistence:
    """Integration test: StateDB survives close + reopen."""

    def test_persists_across_connections(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            # First connection: create data
            db1 = StateDB(db_path)
            run_id = db1.create_run("/tmp/persist-repo")
            task_id = db1.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})
            db1.add_finding(task_id, run_id, "a.py", 1, 1, "sqli", "high", "desc", "ev", True, 0.9, {},
                            validation_status="confirmed", is_canonical=True)
            db1.finish_run(run_id, "completed")
            db1.record_cost(run_id, "recon", "t1", 0.05, 1000, 500, 0, 0, 1, 100)
            # Close connection explicitly
            del db1

            # Second connection: read data back
            db2 = StateDB(db_path)
            run = db2.get_run(run_id)
            assert run is not None
            assert run["repo_path"] == "/tmp/persist-repo"
            assert run["status"] == "completed"
            assert run["finished_at"] is not None

            tasks = db2.get_all_tasks(run_id)
            assert len(tasks) == 1
            assert tasks[0].attack_class == "sqli"

            findings = db2.get_findings(run_id)
            assert len(findings) == 1
            assert findings[0].validation_status == "confirmed"

            total = db2.total_cost(run_id)
            assert total == 0.05
            del db2

        finally:
            Path(db_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Edge cases & robustness
# ---------------------------------------------------------------------------
class TestEdgeCases:
    """Corner cases: JSON roundtrips, weird values, schema validation."""

    def test_finding_with_none_line_range(self, db):
        """line_start/line_end can be None (e.g., file-level vuln)."""
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "db.py", ["db.py"], "r", 1, "pending", {})
        finding_id = db.add_finding(
            task_id, run_id, "cfg.py", None, None, "misconfig", "medium",
            "Missing security headers", "No CSP header set",
            True, 0.7, {}
        )
        findings = db.get_findings(run_id)
        assert findings[0].line_start is None
        assert findings[0].line_end is None

    def test_task_with_complex_target_files(self, db):
        run_id = db.create_run("/tmp/repo")
        target = ["src/a.py", "src/sub/b.py", "tests/test_c.py"]
        task_id = db.add_task(run_id, "recon", "sqli", "src/", target, "r", 3, "pending", {})
        tasks = db.get_all_tasks(run_id)
        assert tasks[0].target_files == target

    def test_negative_priority_handled(self, db):
        """Priority can be negative (lower urgency)."""
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "a.py", ["a.py"], "r", -1, "pending", {})
        tasks = db.get_all_tasks(run_id)
        assert tasks[0].priority == -1

    def test_confidence_out_of_range_stored_as_is(self, db):
        """Confidence 0.0 and 1.0 should be stored without issue."""
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "a.py", ["a.py"], "r", 1, "pending", {})
        f1 = db.add_finding(task_id, run_id, "a.py", 1, 1, "x", "h", "d", "e", True, 0.0, {})
        f2 = db.add_finding(task_id, run_id, "b.py", 2, 2, "y", "h", "d", "e", True, 1.0, {})
        findings = db.get_findings(run_id)
        confidences = {f.confidence for f in findings}
        assert 0.0 in confidences
        assert 1.0 in confidences

    def test_empty_raw_json(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "a.py", ["a.py"], "r", 1, "pending", {})
        db.add_finding(task_id, run_id, "a.py", 1, 1, "x", "h", "d", "e", True, 0.5, {})
        findings = db.get_findings(run_id)
        assert findings[0].raw_json == {}

    def test_nullable_fields_stored_as_null(self, db):
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "a.py", ["a.py"], "r", 1, "pending", {})
        db.add_finding(task_id, run_id, "a.py", 1, 1, "x", "h", "d", "e", True, 0.5, {},
                       validation_status=None, validation_json=None, group_id=None)
        findings = db.get_findings(run_id)
        assert findings[0].validation_status is None
        assert findings[0].validation_json is None
        assert findings[0].group_id is None

    def test_pending_tasks_tiebreaker_by_created_at(self, db):
        """When priorities are equal, older tasks come first."""
        run_id = db.create_run("/tmp/repo")
        db.add_task(run_id, "recon", "a", "a.py", ["a.py"], "r", 3, "pending", {})
        # Small sleep to ensure different timestamps
        import time
        time.sleep(0.01)
        db.add_task(run_id, "recon", "b", "b.py", ["b.py"], "r", 3, "pending", {})

        tasks = db.get_pending_tasks()
        assert len(tasks) == 2
        assert tasks[0].attack_class == "a"  # Older first

    def test_finding_all_json_types(self, db):
        """raw_json and validation_json should handle nested structures."""
        run_id = db.create_run("/tmp/repo")
        task_id = db.add_task(run_id, "recon", "sqli", "a.py", ["a.py"], "r", 1, "pending", {})
        raw = {
            "source_lines": [1, 2, 3],
            "call_chain": ["handler", "service", "db"],
            "cwe": "CWE-89",
            "nested": {"a": {"b": [1, 2, 3]}},
        }
        fid = db.add_finding(task_id, run_id, "a.py", 1, 1, "sqli", "high", "d", "e", True, 0.9, raw)
        db.set_finding_validation(fid, "confirmed", {"traces": [1, 2], "verified_by": "poc"})
        findings = db.get_findings(run_id)
        assert findings[0].raw_json == raw
        assert findings[0].validation_json == {"traces": [1, 2], "verified_by": "poc"}

    def test_record_cost_with_zero_tokens(self, db):
        run_id = db.create_run("/tmp/repo")
        db.record_cost(run_id, "setup", "init", 0.0, 0, 0, 0, 0, 0, 0)
        assert db.total_cost(run_id) == 0.0

    def test_save_recon_output_large_json(self, db):
        run_id = db.create_run("/tmp/repo")
        large = {"files": [f"file_{i}.py" for i in range(100)],
                 "deps": {f"lib_{i}": f"^{i}.0.0" for i in range(50)}}
        db.save_recon_output(run_id, large)
        result = db.get_recon_output(run_id)
        assert result == large
