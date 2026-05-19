"""report stage — agent writes a structured markdown report from all
findings and traces, returns the file Path.

Usage::

    report_path = await run_report(ctx, db)
"""

from __future__ import annotations

from pathlib import Path

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
        "group_id": f.group_id,
        "is_canonical": f.is_canonical,
    }


async def run_report(ctx, db: StateDB) -> Path:
    """Generate a structured markdown audit report.

    Collects all findings and associated traces for the run, passes them
    to an LLM agent that produces a markdown report, writes it to disk
    inside ``ctx.artifact_dir``, and returns the file path.

    Args:
        ctx: Object with ``run_id`` and attributes for ``run_agent``.
            Must have ``artifact_dir`` (Path).
        db: StateDB instance.

    Returns:
        Path to the generated markdown report file.
    """
    # Gather all findings and traces
    findings = db.get_findings(ctx.run_id)
    findings_data = [_finding_to_dict(f) for f in findings]

    traces_data = {}
    for f in findings:
        trace = db.get_trace(f.finding_id)
        if trace:
            traces_data[str(f.finding_id)] = trace

    user_input = {
        "run_id": ctx.run_id,
        "findings": findings_data,
        "traces": traces_data,
    }


    result = await run_agent(
        stage="report",
        prompt_file=ctx.prompt("report"),
        user_input=user_input,
        schema_file=ctx.schema("report"),
        allowed_tools=getattr(ctx, "allowed_tools", []),
        model=getattr(ctx, "model", "gpt-4o"),
        cwd=getattr(ctx, "cwd", Path(".")),
        artifact_dir=ctx.artifact_dir,
        artifact_name=f"report-{ctx.run_id}",
        max_turns=getattr(ctx, "max_turns", 25),
    )

    # Write the report markdown to a file
    report_content: str = result.payload.get("report", "")
    ctx.artifact_dir.mkdir(parents=True, exist_ok=True)
    report_path = ctx.artifact_dir / f"report-{ctx.run_id}.md"
    report_path.write_text(report_content, encoding="utf-8")

    # Record cost
    if result.cost_usd:
        db.record_cost(
            run_id=ctx.run_id,
            stage="report",
            ref_id=f"report-{ctx.run_id}",
            usd=result.cost_usd or 0.0,
            input_tokens=result.input_tokens or 0,
            output_tokens=result.output_tokens or 0,
            cache_read_tokens=0,
            cache_creation_tokens=0,
            num_turns=result.num_turns or 1,
            duration_ms=result.duration_ms or 0,
        )

    return report_path
