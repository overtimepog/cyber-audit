"""trace stage — for each validated finding, agent traces the attacker
input path to the sink and marks the finding as reachable or not.

Usage::

    await run_trace(ctx, db)
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

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


async def run_trace(ctx, db: StateDB) -> None:
    """Trace attacker input path to sink for each validated finding.

    For every finding with ``validation_status='confirmed'``, the agent
    traces the data flow from attacker-controlled input to the vulnerable
    sink.  Each finding gets a ``traces`` row with reachability.

    Args:
        ctx: Object with ``run_id`` and attributes for ``run_agent``.
        db: StateDB instance.
    """
    # Gather validated findings
    findings = db.get_findings(ctx.run_id, validation_status="confirmed")
    if not findings:
        return

    # Build a map for quick lookup
    finding_map: Dict[int, Finding] = {f.finding_id: f for f in findings}

    user_input = {
        "run_id": ctx.run_id,
        "findings": [_finding_to_dict(f) for f in findings],
    }


    result = await run_agent(
        stage="trace",
        prompt_file=ctx.prompt("trace"),
        user_input=user_input,
        schema_file=ctx.schema("trace"),
        allowed_tools=list(ctx.stage("trace").tools),
        model=getattr(ctx, "model", "deepseek-chat"),
        cwd=ctx.repo_path,
        artifact_dir=getattr(ctx, "artifact_dir", Path("artifacts")),
        artifact_name=f"trace-{ctx.run_id}",
        max_turns=ctx.stage("trace").max_turns,
    )

    # Process traces
    traces: List[dict] = result.payload.get("traces", [])
    for trace_def in traces:
        finding_id = trace_def.get("finding_id")
        if finding_id is None:
            continue
        db.add_trace(
            finding_id=finding_id,
            reachable=trace_def.get("reachable", False),
            confidence=trace_def.get("confidence", 0.0),
            rationale=trace_def.get("rationale", ""),
            raw_json=trace_def.get("raw_json", {}),
        )

    # Record cost
    if result.cost_usd:
        db.record_cost(
            run_id=ctx.run_id,
            stage="trace",
            ref_id=f"trace-{ctx.run_id}",
            usd=result.cost_usd or 0.0,
            input_tokens=result.input_tokens or 0,
            output_tokens=result.output_tokens or 0,
            cache_read_tokens=0,
            cache_creation_tokens=0,
            num_turns=result.num_turns or 1,
            duration_ms=result.duration_ms or 0,
        )
