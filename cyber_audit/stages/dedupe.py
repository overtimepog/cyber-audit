"""dedupe stage — agent clusters findings by root cause, creates dedupe
groups, and assigns a canonical finding to each group.

Usage::

    await run_dedupe(ctx, db)
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


async def run_dedupe(ctx, db: StateDB) -> None:
    """Cluster validated findings by root cause and create dedupe groups.

    1. Collect all validated findings that are not yet assigned to a group.
    2. Pass them to an LLM agent that clusters by root cause.
    3. Create ``dedupe_groups`` rows and assign findings with a canonical
       finding per group.

    Args:
        ctx: Object with ``run_id`` and attributes for ``run_agent``.
        db: StateDB instance.
    """
    # Gather validated findings not yet in a group
    all_findings = db.get_findings(
        ctx.run_id, validation_status="confirmed"
    )
    ungrouped = [f for f in all_findings if f.group_id is None]
    if not ungrouped:
        return

    user_input = {
        "run_id": ctx.run_id,
        "findings": [_finding_to_dict(f) for f in ungrouped],
    }

    prompt_dir = getattr(ctx, "prompt_dir", Path("prompts"))
    schema_dir = getattr(ctx, "schema_dir", Path("schemas"))

    result = await run_agent(
        stage="dedupe",
        prompt_file=prompt_dir / "dedupe.md",
        user_input=user_input,
        schema_file=schema_dir / "dedupe.schema.json",
        allowed_tools=getattr(ctx, "allowed_tools", []),
        model=getattr(ctx, "model", "gpt-4o-mini"),
        cwd=getattr(ctx, "cwd", Path(".")),
        artifact_dir=getattr(ctx, "artifact_dir", Path("artifacts")),
        artifact_name=f"dedupe-{ctx.run_id}",
        max_turns=getattr(ctx, "max_turns", 25),
    )

    # Process groups
    groups: List[dict] = result.payload.get("groups", [])
    for group_def in groups:
        finding_ids = group_def.get("finding_ids", [])
        canonical_id = group_def.get("canonical_finding_id")
        root_cause = group_def.get("root_cause", "")

        # Create the dedupe group
        group_id = db.add_dedupe_group(
            run_id=ctx.run_id,
            root_cause=root_cause,
            canonical_finding_id=canonical_id,
            raw_json=group_def.get("raw_json", {}),
        )

        # Assign findings to the group
        for fid in finding_ids:
            is_canon = (fid == canonical_id)
            db.assign_finding_group(fid, group_id, is_canonical=is_canon)

    # Record cost
    if result.cost_usd:
        db.record_cost(
            run_id=ctx.run_id,
            stage="dedupe",
            ref_id=f"dedupe-{ctx.run_id}",
            usd=result.cost_usd or 0.0,
            input_tokens=result.input_tokens or 0,
            output_tokens=result.output_tokens or 0,
            cache_read_tokens=0,
            cache_creation_tokens=0,
            num_turns=result.num_turns or 1,
            duration_ms=result.duration_ms or 0,
        )
