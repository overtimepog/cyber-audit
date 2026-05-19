"""Validate stage — adversarial re-read of hunt findings.

Runs a different model than Hunt to implement "deliberate disagreement."
The validate agent tries to DISPROVE findings, not confirm them.
"""

from __future__ import annotations

import asyncio
from typing import Any

from cyber_audit.agent import run_agent
from cyber_audit.config import StageConfig
from cyber_audit.state import Finding, StateDB
from cyber_audit.stages._common import StageContext


async def _validate_one_finding(
    ctx: StageContext,
    db: StateDB,
    finding: Finding,
    stage_cfg: StageConfig,
    sem: asyncio.Semaphore,
) -> bool:
    """Validate a single finding. Returns True if validation succeeded."""
    async with sem:
        try:
            user_input: dict[str, Any] = {
                "finding_id": finding.finding_id,
                "task_id": finding.task_id,
                "file": finding.file,
                "line_start": finding.line_start,
                "line_end": finding.line_end,
                "vuln_class": finding.vuln_class,
                "severity": finding.severity,
                "description": finding.description,
                "evidence": finding.evidence,
                "repo_path": str(ctx.repo_path),
            }

            result = await run_agent(
                stage="validate",
                prompt_file=ctx.prompt("validate"),
                user_input=user_input,
                schema_file=ctx.schema("validate"),
                allowed_tools=list(stage_cfg.tools),
                model=stage_cfg.model,
                cwd=ctx.repo_path,
                max_turns=stage_cfg.max_turns,
                artifact_dir=ctx.results_dir("validate"),
                artifact_name=f"validate_{finding.finding_id}",
                repair_attempts=stage_cfg.repair_attempts,
            )

            payload = result.payload
            verdict = payload.get("verdict", "uncertain")

            db.record_cost(
                run_id=ctx.run_id, stage="validate",
                ref_id=str(finding.finding_id),
                usd=result.cost_usd or 0.0,
                input_tokens=result.input_tokens or 0,
                output_tokens=result.output_tokens or 0,
                cache_read_tokens=0, cache_creation_tokens=0,
                num_turns=result.num_turns or 0,
                duration_ms=result.duration_ms or 0,
            )

            db.set_finding_validation(finding.finding_id, verdict, payload)
            return True

        except Exception:
            return False


async def run_validate(
    ctx: StageContext,
    db: StateDB,
) -> int:
    """Run adversarial validation against unvalidated findings."""
    findings = db.get_unvalidated_findings(ctx.run_id)
    if not findings:
        return 0

    stage_cfg = ctx.stage("validate")
    sem = asyncio.Semaphore(stage_cfg.concurrency)

    results = await asyncio.gather(
        *(_validate_one_finding(ctx, db, f, stage_cfg, sem) for f in findings)
    )
    return sum(1 for r in results if r)
