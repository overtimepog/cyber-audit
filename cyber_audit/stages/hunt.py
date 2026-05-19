"""Hunt stage — process pending tasks concurrently and produce findings."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from cyber_audit.agent import run_agent
from cyber_audit.config import StageConfig
from cyber_audit.llm import ProviderConfig
from cyber_audit.state import StateDB, Task
from cyber_audit.stages._common import StageContext


async def _process_one_task(
    ctx: StageContext,
    db: StateDB,
    task: Task,
    stage_cfg: StageConfig,
    provider: ProviderConfig,
    sem: asyncio.Semaphore,
) -> int:
    """Process a single hunt task and return the number of findings added."""
    added = 0
    async with sem:
        try:
            user_input: dict[str, Any] = {
                "task_id": task.task_id,
                "attack_class": task.attack_class,
                "scope_hint": task.scope_hint,
                "target_files": task.target_files,
                "rationale": task.rationale,
                "priority": task.priority,
                "repo_path": str(ctx.repo_path),
            }

            artifact_name = f"hunt_task_{task.task_id}"

            result = await run_agent(
                stage="hunt",
                prompt_file=ctx.prompt("hunt"),
                user_input=user_input,
                schema_file=ctx.schema("hunt"),
                allowed_tools=list(stage_cfg.tools),
                model=stage_cfg.model,
                provider=provider,
                cwd=ctx.repo_path,
                max_turns=stage_cfg.max_turns,
                artifact_dir=ctx.results_dir("hunt"),
                artifact_name=artifact_name,
                repair_attempts=stage_cfg.repair_attempts,
            )

            # Record cost
            db.record_cost(
                run_id=ctx.run_id,
                stage="hunt",
                ref_id=str(task.task_id),
                usd=result.cost_usd or 0.0,
                input_tokens=result.input_tokens or 0,
                output_tokens=result.output_tokens or 0,
                cache_read_tokens=0,
                cache_creation_tokens=0,
                num_turns=result.num_turns or 0,
                duration_ms=result.duration_ms or 0,
            )

            # Save findings from the payload
            findings = result.payload.get("findings", [])
            for fdata in findings:
                db.add_finding(
                    task_id=task.task_id,
                    run_id=ctx.run_id,
                    file=fdata.get("file", ""),
                    line_start=fdata.get("line_start"),
                    line_end=fdata.get("line_end"),
                    vuln_class=fdata.get("vuln_class", "unknown"),
                    severity=fdata.get("severity", "info"),
                    description=fdata.get("description", ""),
                    evidence=fdata.get("evidence", ""),
                    poc_succeeded=bool(fdata.get("poc_succeeded", False)),
                    confidence=float(fdata.get("confidence", 0.0)),
                    raw_json=fdata,
                )
                added += 1

            # Mark task as completed
            db.update_task_status(task.task_id, "completed")

        except Exception:
            # Mark task as failed on any error
            db.update_task_status(task.task_id, "failed")

    return added


async def run_hunt(
    ctx: StageContext,
    db: StateDB,
    budget_check: Callable[[], bool] | None = None,
    *,
    provider: ProviderConfig | None = None,
) -> int:
    """Run hunt agents against all pending tasks concurrently.

    Each pending task is dispatched to an LLM agent that examines the
    specified files and produces vulnerability findings.  Tasks are
    processed with a concurrency limit from the stage config.

    Args:
        ctx: StageContext with run_id, repo_path, and config.
        db: StateDB for reading tasks and persisting findings.
        budget_check: Optional callable that returns ``False`` when the
                      budget has been exhausted; tasks are skipped if
                      the budget is exhausted *before* dispatch.
        provider: Optional ProviderConfig; defaults to OpenAI.

    Returns:
        The total number of findings added across all tasks.
    """
    tasks = db.get_pending_tasks()
    if not tasks:
        return 0

    stage_cfg = ctx.stage("hunt")
    if provider is None:
        provider = ProviderConfig.OPENAI

    sem = asyncio.Semaphore(stage_cfg.concurrency)

    async def _run_if_budget(task: Task) -> int:
        if budget_check is not None and not budget_check():
            return 0
        return await _process_one_task(ctx, db, task, stage_cfg, provider, sem)

    results = await asyncio.gather(*(_run_if_budget(t) for t in tasks))
    return sum(results)
