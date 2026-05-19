"""StateDB — SQLite-backed state management for cyber audit pipeline."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------
@dataclass
class Task:
    """Task record matching the tasks table schema."""

    task_id: int
    run_id: int
    source: str
    attack_class: str
    scope_hint: str
    target_files: List[str]
    rationale: str
    priority: int
    status: str
    raw_json: dict
    created_at: str
    updated_at: str


@dataclass
class Finding:
    """Finding record matching the findings table schema."""

    finding_id: int
    task_id: int
    run_id: int
    file: str
    line_start: Optional[int]
    line_end: Optional[int]
    vuln_class: str
    severity: str
    description: str
    evidence: str
    poc_succeeded: bool
    confidence: float
    raw_json: dict
    validation_status: Optional[str] = None
    validation_json: Optional[dict] = None
    group_id: Optional[int] = None
    is_canonical: bool = False


# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_path TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(run_id),
    source TEXT NOT NULL,
    attack_class TEXT NOT NULL,
    scope_hint TEXT NOT NULL,
    target_files TEXT NOT NULL DEFAULT '[]',
    rationale TEXT NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    raw_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES tasks(task_id),
    run_id INTEGER NOT NULL REFERENCES runs(run_id),
    file TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    vuln_class TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '',
    poc_succeeded INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL DEFAULT 0.0,
    raw_json TEXT NOT NULL DEFAULT '{}',
    validation_status TEXT,
    validation_json TEXT,
    group_id INTEGER REFERENCES dedupe_groups(group_id),
    is_canonical INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS traces (
    finding_id INTEGER NOT NULL REFERENCES findings(finding_id),
    reachable INTEGER NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.0,
    rationale TEXT NOT NULL DEFAULT '',
    raw_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (finding_id)
);

CREATE TABLE IF NOT EXISTS dedupe_groups (
    group_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(run_id),
    root_cause TEXT NOT NULL DEFAULT '',
    canonical_finding_id INTEGER REFERENCES findings(finding_id),
    raw_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS costs (
    cost_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(run_id),
    stage TEXT NOT NULL,
    ref_id TEXT NOT NULL DEFAULT '',
    usd REAL NOT NULL DEFAULT 0.0,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens INTEGER NOT NULL DEFAULT 0,
    cache_creation_tokens INTEGER NOT NULL DEFAULT 0,
    num_turns INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recon_outputs (
    run_id INTEGER PRIMARY KEY REFERENCES runs(run_id),
    output_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(run_id),
    name TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    data TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tasks_run_id ON tasks(run_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_validation_status ON findings(validation_status);
CREATE INDEX IF NOT EXISTS idx_findings_group_id ON findings(group_id);
CREATE INDEX IF NOT EXISTS idx_dedupe_groups_run_id ON dedupe_groups(run_id);
CREATE INDEX IF NOT EXISTS idx_costs_run_id ON costs(run_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_run_id ON artifacts(run_id);
"""


def _now() -> str:
    """Return current UTC timestamp as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _json_serialize(obj: Any) -> str:
    """Serialize a Python object to a JSON string."""
    return json.dumps(obj, ensure_ascii=False)


def _json_deserialize(text: Optional[str]) -> Any:
    """Deserialize a JSON string to a Python object, with safe defaults."""
    if text is None:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def _row_to_task(row: sqlite3.Row) -> Task:
    """Convert a sqlite3.Row to a Task dataclass."""
    return Task(
        task_id=row["task_id"],
        run_id=row["run_id"],
        source=row["source"],
        attack_class=row["attack_class"],
        scope_hint=row["scope_hint"],
        target_files=_json_deserialize(row["target_files"]) or [],
        rationale=row["rationale"],
        priority=row["priority"],
        status=row["status"],
        raw_json=_json_deserialize(row["raw_json"]) or {},
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_finding(row: sqlite3.Row) -> Finding:
    """Convert a sqlite3.Row to a Finding dataclass."""
    return Finding(
        finding_id=row["finding_id"],
        task_id=row["task_id"],
        run_id=row["run_id"],
        file=row["file"],
        line_start=row["line_start"],
        line_end=row["line_end"],
        vuln_class=row["vuln_class"],
        severity=row["severity"],
        description=row["description"],
        evidence=row["evidence"],
        poc_succeeded=bool(row["poc_succeeded"]),
        confidence=float(row["confidence"]),
        raw_json=_json_deserialize(row["raw_json"]) or {},
        validation_status=row["validation_status"],
        validation_json=_json_deserialize(row["validation_json"]),
        group_id=row["group_id"],
        is_canonical=bool(row["is_canonical"]),
    )


# ---------------------------------------------------------------------------
# StateDB
# ---------------------------------------------------------------------------
class StateDB:
    """SQLite-backed state database for the cyber audit pipeline."""

    def __init__(self, db_path: str = ":memory:") -> None:
        """Open (or create) the SQLite database at *db_path*.

        Args:
            db_path: Path to the SQLite database file, or ``:memory:`` for
                     an in-memory database.
        """
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()

    # ------------------------------------------------------------------
    # Runs
    # ------------------------------------------------------------------
    def create_run(self, repo_path: str) -> int:
        """Create a new run and return its ``run_id``."""
        now = _now()
        cur = self._conn.execute(
            "INSERT INTO runs (repo_path, started_at, status) VALUES (?, ?, 'running')",
            (repo_path, now),
        )
        self._conn.commit()
        assert cur.lastrowid is not None
        return cur.lastrowid

    def finish_run(self, run_id: int, status: str) -> None:
        """Mark a run as finished with the given status."""
        now = _now()
        self._conn.execute(
            "UPDATE runs SET finished_at = ?, status = ? WHERE run_id = ?",
            (now, status, run_id),
        )
        self._conn.commit()

    def get_run(self, run_id: int) -> Optional[dict]:
        """Return a run as a dict, or None if not found."""
        row = self._conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def list_runs(self) -> List[dict]:
        """Return all runs as a list of dicts."""
        rows = self._conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Recon output
    # ------------------------------------------------------------------
    def save_recon_output(self, run_id: int, data: dict) -> None:
        """Save (or overwrite) the recon output for a run."""
        json_str = _json_serialize(data)
        self._conn.execute(
            "INSERT OR REPLACE INTO recon_outputs (run_id, output_json) VALUES (?, ?)",
            (run_id, json_str),
        )
        self._conn.commit()

    def get_recon_output(self, run_id: int) -> Optional[dict]:
        """Retrieve the recon output for a run, or None."""
        row = self._conn.execute(
            "SELECT output_json FROM recon_outputs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            return None
        return _json_deserialize(row["output_json"])

    # ------------------------------------------------------------------
    # Tasks
    # ------------------------------------------------------------------
    def add_task(
        self,
        run_id: int,
        source: str,
        attack_class: str,
        scope_hint: str,
        target_files: List[str],
        rationale: str,
        priority: int,
        status: str,
        raw_json: dict,
    ) -> int:
        """Add a task and return its ``task_id``."""
        now = _now()
        cur = self._conn.execute(
            """INSERT INTO tasks
               (run_id, source, attack_class, scope_hint, target_files,
                rationale, priority, status, raw_json, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                source,
                attack_class,
                scope_hint,
                _json_serialize(target_files),
                rationale,
                priority,
                status,
                _json_serialize(raw_json),
                now,
                now,
            ),
        )
        self._conn.commit()
        assert cur.lastrowid is not None
        return cur.lastrowid

    def get_pending_tasks(self) -> List[Task]:
        """Return all pending tasks ordered by priority DESC, created_at ASC."""
        rows = self._conn.execute(
            "SELECT * FROM tasks WHERE status = 'pending' "
            "ORDER BY priority DESC, created_at ASC"
        ).fetchall()
        return [_row_to_task(r) for r in rows]

    def get_all_tasks(self, run_id: int) -> List[Task]:
        """Return all tasks for a given run."""
        rows = self._conn.execute(
            "SELECT * FROM tasks WHERE run_id = ? ORDER BY created_at ASC",
            (run_id,),
        ).fetchall()
        return [_row_to_task(r) for r in rows]

    def update_task_status(self, task_id: int, status: str) -> None:
        """Update the status (and updated_at) of a task."""
        now = _now()
        self._conn.execute(
            "UPDATE tasks SET status = ?, updated_at = ? WHERE task_id = ?",
            (status, now, task_id),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    def add_finding(
        self,
        task_id: int,
        run_id: int,
        file: str,
        line_start: Optional[int],
        line_end: Optional[int],
        vuln_class: str,
        severity: str,
        description: str,
        evidence: str,
        poc_succeeded: bool,
        confidence: float,
        raw_json: dict,
        validation_status: Optional[str] = None,
        validation_json: Optional[dict] = None,
        group_id: Optional[int] = None,
        is_canonical: bool = False,
    ) -> int:
        """Add a finding and return its ``finding_id``."""
        cur = self._conn.execute(
            """INSERT INTO findings
               (task_id, run_id, file, line_start, line_end, vuln_class,
                severity, description, evidence, poc_succeeded, confidence,
                raw_json, validation_status, validation_json, group_id, is_canonical)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task_id,
                run_id,
                file,
                line_start,
                line_end,
                vuln_class,
                severity,
                description,
                evidence,
                int(poc_succeeded),
                confidence,
                _json_serialize(raw_json),
                validation_status,
                _json_serialize(validation_json) if validation_json is not None else None,
                group_id,
                int(is_canonical),
            ),
        )
        self._conn.commit()
        assert cur.lastrowid is not None
        return cur.lastrowid

    def get_findings(
        self,
        run_id: int,
        validation_status: Optional[str] = None,
        canonical_only: bool = False,
    ) -> List[Finding]:
        """Return findings for a run, with optional filters.

        Args:
            run_id: Filter by run.
            validation_status: If set, only return findings with this status.
            canonical_only: If True, only return canonical findings.
        """
        query = "SELECT * FROM findings WHERE run_id = ?"
        params: list = [run_id]

        if validation_status is not None:
            query += " AND validation_status = ?"
            params.append(validation_status)

        if canonical_only:
            query += " AND is_canonical = 1"

        query += " ORDER BY finding_id ASC"
        rows = self._conn.execute(query, params).fetchall()
        return [_row_to_finding(r) for r in rows]

    def get_unvalidated_findings(self, run_id: int) -> List[Finding]:
        """Return findings with no validation_status set."""
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE run_id = ? AND validation_status IS NULL "
            "ORDER BY finding_id ASC",
            (run_id,),
        ).fetchall()
        return [_row_to_finding(r) for r in rows]

    def set_finding_validation(
        self,
        finding_id: int,
        validation_status: str,
        validation_json: Optional[dict] = None,
    ) -> None:
        """Set the validation status and optional validation_json for a finding."""
        json_str = (
            _json_serialize(validation_json)
            if validation_json is not None
            else None
        )
        self._conn.execute(
            "UPDATE findings SET validation_status = ?, validation_json = ? "
            "WHERE finding_id = ?",
            (validation_status, json_str, finding_id),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Dedupe groups
    # ------------------------------------------------------------------
    def add_dedupe_group(
        self,
        run_id: int,
        root_cause: str,
        canonical_finding_id: Optional[int],
        raw_json: dict,
    ) -> int:
        """Add a deduplication group and return its ``group_id``."""
        cur = self._conn.execute(
            "INSERT INTO dedupe_groups (run_id, root_cause, canonical_finding_id, raw_json) "
            "VALUES (?, ?, ?, ?)",
            (run_id, root_cause, canonical_finding_id, _json_serialize(raw_json)),
        )
        self._conn.commit()
        assert cur.lastrowid is not None
        return cur.lastrowid

    def assign_finding_group(
        self,
        finding_id: int,
        group_id: int,
        is_canonical: bool = False,
    ) -> None:
        """Assign a finding to a deduplication group."""
        self._conn.execute(
            "UPDATE findings SET group_id = ?, is_canonical = ? WHERE finding_id = ?",
            (group_id, int(is_canonical), finding_id),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Traces
    # ------------------------------------------------------------------
    def add_trace(
        self,
        finding_id: int,
        reachable: bool,
        confidence: float,
        rationale: str,
        raw_json: dict,
    ) -> None:
        """Add or overwrite a trace for a finding."""
        self._conn.execute(
            """INSERT OR REPLACE INTO traces
               (finding_id, reachable, confidence, rationale, raw_json)
               VALUES (?, ?, ?, ?, ?)""",
            (
                finding_id,
                int(reachable),
                confidence,
                rationale,
                _json_serialize(raw_json),
            ),
        )
        self._conn.commit()

    def get_trace(self, finding_id: int) -> Optional[dict]:
        """Return trace info for a finding as a dict, or None."""
        row = self._conn.execute(
            "SELECT * FROM traces WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        if row is None:
            return None
        return {
            "finding_id": row["finding_id"],
            "reachable": bool(row["reachable"]),
            "confidence": row["confidence"],
            "rationale": row["rationale"],
            "raw_json": _json_deserialize(row["raw_json"]),
        }

    def get_reachable_canonical_findings(self, run_id: int) -> List[Finding]:
        """Return canonical findings that have a reachable trace."""
        rows = self._conn.execute(
            """SELECT f.* FROM findings f
               INNER JOIN traces t ON f.finding_id = t.finding_id
               WHERE f.run_id = ? AND f.is_canonical = 1 AND t.reachable = 1
               ORDER BY f.finding_id ASC""",
            (run_id,),
        ).fetchall()
        return [_row_to_finding(r) for r in rows]

    # ------------------------------------------------------------------
    # Costs
    # ------------------------------------------------------------------
    def record_cost(
        self,
        run_id: int,
        stage: str,
        ref_id: str,
        usd: float,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int,
        cache_creation_tokens: int,
        num_turns: int,
        duration_ms: int,
    ) -> int:
        """Record a cost entry and return its ``cost_id``."""
        now = _now()
        cur = self._conn.execute(
            """INSERT INTO costs
               (run_id, stage, ref_id, usd, input_tokens, output_tokens,
                cache_read_tokens, cache_creation_tokens, num_turns,
                duration_ms, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                stage,
                ref_id,
                usd,
                input_tokens,
                output_tokens,
                cache_read_tokens,
                cache_creation_tokens,
                num_turns,
                duration_ms,
                now,
            ),
        )
        self._conn.commit()
        assert cur.lastrowid is not None
        return cur.lastrowid

    def total_cost(self, run_id: int) -> float:
        """Return the total USD cost for a run."""
        row = self._conn.execute(
            "SELECT COALESCE(SUM(usd), 0) AS total FROM costs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        return float(row["total"])

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------
    def add_artifact(
        self,
        run_id: int,
        name: str,
        content_type: str,
        data: str,
    ) -> int:
        """Add an artifact and return its ``artifact_id``."""
        now = _now()
        cur = self._conn.execute(
            "INSERT INTO artifacts (run_id, name, content_type, data, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (run_id, name, content_type, data, now),
        )
        self._conn.commit()
        assert cur.lastrowid is not None
        return cur.lastrowid
