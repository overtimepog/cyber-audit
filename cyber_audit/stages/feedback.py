"""feedback stage — turns reachable traces into new hunt tasks in consumer
repos.

Usage::

    await run_feedback(ctx, db)
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from cyber_audit.agent import run_agent
from cyber_audit.llm import ProviderConfig
from cyber_audit.state import Finding, StateDB


def _finding_to_dict(f: Finding) -> dict:
    return {
        "finding_id": f.finding_id,
        "task_id": f.task_id,
        "file": f.file,
        "line_start": f.line_start,
        "line_end": f.line_end,
        "vuln_class": f.vuln_class,
        "severity": f.severity,
        "description": f.description,
        "evidence": f.evidence,
        "poc_succeeded": f.poc_succeeded,
        "confidence": f.confidence,
        "validation_status": f.validation_status,
        "validation_json": f.validation_json,
    }


async def run_feedback(ctx, db: StateDB) -> None:
    """Generate new hunt tasks from reachable canonical findings.

    Collects all canonical findings that have reachable traces, passes
    them to an LLM agent that synthesises consumer-appropriate hunt
    tasks, and inserts those tasks back into the database.

    Args:
        ctx: Object with ``run_id`` and attributes for ``run_agent``.
        db: StateDB instance.
    """
    # Gather reachable canonical findings
    findings = db.get_reachable_canonical_findings(ctx.run_id)
    if not findings:
        return

    # Build user input with trace data
    findings_data = []
    traces_data = {}
    for f in findings:
        findings_data.append(_finding_to_dict(f))
        trace = db.get_trace(f.finding_id)
        if trace:
            traces_data[str(f.finding_id)] = trace

    user_input = {
        "run_id": ctx.run_id,
        "findings": findings_data,
        "traces": traces_data,
    }


    result = await run_agent(
        stage="feedback",
        prompt_file=ctx.prompt("feedback"),
        user_input=user_input,
        schema_file=ctx.schema("feedback"),
        allowed_tools=list(ctx.stage("feedback").tools),
        model=getattr(ctx, "model", "gpt-4o-mini"),
        cwd=ctx.repo_path,
        artifact_dir=getattr(ctx, "artifact_dir", Path("artifacts")),
        artifact_name=f"feedback-{ctx.run_id}",
        max_turns=ctx.stage("feedback").max_turns,
    )

    # Process new tasks
    new_tasks: List[dict] = result.payload.get("new_tasks", [])
    for task_def in new_tasks:
        db.add_task(
            run_id=ctx.run_id,
            source="feedback",
            attack_class=task_def["attack_class"],
            scope_hint=task_def.get("scope_hint", ""),
            target_files=task_def.get("target_files", []),
            rationale=task_def.get("rationale", ""),
            priority=task_def.get("priority", 1),
            status="pending",
            raw_json=task_def.get("raw_json", {}),
        )

    # Record cost
    if result.cost_usd:
        db.record_cost(
            run_id=ctx.run_id,
            stage="feedback",
            ref_id=f"feedback-{ctx.run_id}",
            usd=result.cost_usd or 0.0,
            input_tokens=result.input_tokens or 0,
            output_tokens=result.output_tokens or 0,
            cache_read_tokens=0,
            cache_creation_tokens=0,
            num_turns=result.num_turns or 1,
            duration_ms=result.duration_ms or 0,
        )
