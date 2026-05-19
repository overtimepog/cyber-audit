"""gapfill stage — agent reviews completed hunt tasks and emits new tasks
for under-covered areas.

Usage::

    await run_gapfill(ctx, db)

Where *ctx* is any object with ``run_id`` and the attributes needed to
call ``run_agent`` (model, provider, cwd, artifact_dir, prompt_dir,
schema_dir, allowed_tools, max_turns).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from cyber_audit.agent import run_agent
from cyber_audit.llm import ProviderConfig
from cyber_audit.state import StateDB, Task


def _task_to_dict(t: Task) -> dict:
    return {
        "task_id": t.task_id,
        "source": t.source,
        "attack_class": t.attack_class,
        "scope_hint": t.scope_hint,
        "target_files": t.target_files,
        "rationale": t.rationale,
        "priority": t.priority,
        "status": t.status,
        "raw_json": t.raw_json,
    }


async def run_gapfill(ctx, db: StateDB) -> None:
    """Review completed hunt tasks and create new tasks for coverage gaps.

    Gathers all completed tasks that originated from the *hunt* stage,
    passes them to an LLM agent for gap analysis, and inserts any
    recommended new tasks into the database.

    Args:
        ctx: Object with ``run_id`` and attributes for ``run_agent``.
        db: StateDB instance.
    """
    # Gather completed hunt-sourced tasks for this run
    all_tasks = db.get_all_tasks(ctx.run_id)
    completed_hunt_tasks = [
        t for t in all_tasks
        if t.source == "hunt" and t.status == "completed"
    ]
    if not completed_hunt_tasks:
        return

    # Build user input for the agent
    user_input = {
        "run_id": ctx.run_id,
        "completed_tasks": [_task_to_dict(t) for t in completed_hunt_tasks],
    }

    # Resolve prompt and schema paths
    prompt_dir = getattr(ctx, "prompt_dir", Path("prompts"))
    schema_dir = getattr(ctx, "schema_dir", Path("schemas"))

    # Call the agent
    result = await run_agent(
        stage="gapfill",
        prompt_file=prompt_dir / "gapfill.md",
        user_input=user_input,
        schema_file=schema_dir / "gapfill.schema.json",
        allowed_tools=getattr(ctx, "allowed_tools", []),
        model=getattr(ctx, "model", "gpt-4o-mini"),
        provider=getattr(ctx, "provider", ProviderConfig.OPENAI),
        cwd=getattr(ctx, "cwd", Path(".")),
        artifact_dir=getattr(ctx, "artifact_dir", Path("artifacts")),
        artifact_name=f"gapfill-{ctx.run_id}",
        max_turns=getattr(ctx, "max_turns", 25),
    )

    # Process agent output — insert new tasks
    new_tasks: List[dict] = result.payload.get("new_tasks", [])
    for task_def in new_tasks:
        db.add_task(
            run_id=ctx.run_id,
            source=task_def.get("source", "gapfill"),
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
            stage="gapfill",
            ref_id=f"gapfill-{ctx.run_id}",
            usd=result.cost_usd or 0.0,
            input_tokens=result.input_tokens or 0,
            output_tokens=result.output_tokens or 0,
            cache_read_tokens=0,
            cache_creation_tokens=0,
            num_turns=result.num_turns or 1,
            duration_ms=result.duration_ms or 0,
        )
