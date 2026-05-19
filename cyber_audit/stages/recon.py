"""Recon stage — map the repository and emit initial hunt tasks."""

from __future__ import annotations

from cyber_audit.agent import run_agent
from cyber_audit.config import StageConfig
from cyber_audit.state import StateDB
from cyber_audit.stages._common import StageContext


async def run_recon(
    ctx: StageContext,
    db: StateDB,
    max_tasks: int = 80,
) -> None:
    """Run the reconnaissance agent against the target repository."""
    stage_cfg: StageConfig = ctx.stage("recon")

    user_input = {
        "repo_path": str(ctx.repo_path),
        "max_tasks": max_tasks,
    }

    result = await run_agent(
        stage="recon",
        prompt_file=ctx.prompt("recon"),
        user_input=user_input,
        schema_file=ctx.schema("recon"),
        allowed_tools=list(stage_cfg.tools),
        model=stage_cfg.model,
        cwd=ctx.repo_path,
        max_turns=stage_cfg.max_turns,
        artifact_dir=ctx.results_dir("recon"),
        artifact_name="recon",
        repair_attempts=stage_cfg.repair_attempts,
    )

    db.save_recon_output(ctx.run_id, result.payload)
    db.record_cost(
        run_id=ctx.run_id, stage="recon", ref_id="recon",
        usd=result.cost_usd or 0.0, input_tokens=result.input_tokens or 0,
        output_tokens=result.output_tokens or 0, cache_read_tokens=0,
        cache_creation_tokens=0, num_turns=result.num_turns or 0,
        duration_ms=result.duration_ms or 0,
    )

    tasks = result.payload.get("tasks", [])
    for task_data in tasks:
        db.add_task(
            run_id=ctx.run_id, source="recon",
            attack_class=task_data.get("attack_class", "unknown"),
            scope_hint=task_data.get("scope_hint", ""),
            target_files=task_data.get("target_files", []),
            rationale=task_data.get("rationale", ""),
            priority=task_data.get("priority", 0),
            status="pending", raw_json=task_data,
        )
