"""Pipeline orchestrator — drives all 8 stages in sequence.

Recon → (Hunt → Validate → Gapfill)* → Dedupe → Trace →
(Feedback → Hunt → Validate → Dedupe → Trace)* → Report
"""

from __future__ import annotations

import logging
from pathlib import Path

from cyber_audit import stages
from cyber_audit.config import HarnessConfig
from cyber_audit.state import StateDB
from cyber_audit.stages._common import StageContext

log = logging.getLogger(__name__)


class CostExceeded(RuntimeError):
    """Raised when the budget is exhausted mid-pipeline."""
    pass


async def run_pipeline(
    *,
    repo_path: Path,
    run_id: int | None = None,
    db: StateDB,
    config: HarnessConfig,
    max_cost_usd: float | None = None,
) -> tuple[int, Path]:
    """Run the complete 8-stage vulnerability discovery pipeline.

    Args:
        repo_path: Path to the target repository.
        run_id: Optional existing run ID; if None, a new run is created.
        db: StateDB instance for persistence.
        config: HarnessConfig with per-stage settings.
        max_cost_usd: Optional budget cap; raises CostExceeded if hit.

    Returns:
        Tuple of (run_id, report_path).
    """
    # --- Create or resume run -------------------------------------------
    if run_id is None:
        run_id = db.create_run(str(repo_path.resolve()))
    elif db.get_run(run_id) is None:
        run_id = db.create_run(str(repo_path.resolve()))
        log.info("starting fresh run %d against %s", run_id, repo_path)

    ctx = StageContext(run_id=run_id, repo_path=repo_path, config=config)

    def _budget_check(stage_name: str) -> None:
        if max_cost_usd is None:
            return
        spent = db.total_cost(run_id)  # type: ignore[arg-type]
        if spent >= max_cost_usd:
            raise CostExceeded(
                f"budget exhausted before {stage_name}: "
                f"${spent:.4f} >= ${max_cost_usd:.4f}"
            )

    try:
        # ---- Stage 1: Recon ----
        _budget_check("recon")
        await stages.run_recon(ctx, db)

        # ---- Stages 2-3-4 loop: Hunt → Validate → Gapfill ----
        for i in range(config.gapfill_iterations + 1):
            _budget_check(f"hunt(iter={i})")
            findings_added = await stages.run_hunt(ctx, db, budget_check=None)
            if findings_added == 0 and i > 0:
                log.info("no new findings — exiting Hunt/Gapfill loop")
                break

            _budget_check(f"validate(iter={i})")
            await stages.run_validate(ctx, db)

            if i >= config.gapfill_iterations:
                break
            _budget_check(f"gapfill(iter={i})")
            new_tasks = await stages.run_gapfill(ctx, db)
            if new_tasks == 0 or new_tasks is None:
                log.info("gapfill produced 0 tasks — exiting loop")
                break

        # ---- Stage 5: Dedupe ----
        _budget_check("dedupe")
        await stages.run_dedupe(ctx, db)

        # ---- Stage 6: Trace ----
        _budget_check("trace")
        await stages.run_trace(ctx, db)

        # ---- Stage 7: Feedback loop ----
        for i in range(config.feedback_iterations):
            _budget_check(f"feedback(iter={i})")
            new_tasks = await stages.run_feedback(ctx, db)
            if new_tasks == 0 or new_tasks is None:
                break
            _budget_check(f"feedback-hunt(iter={i})")
            await stages.run_hunt(ctx, db)
            _budget_check(f"feedback-validate(iter={i})")
            await stages.run_validate(ctx, db)
            _budget_check(f"feedback-dedupe(iter={i})")
            await stages.run_dedupe(ctx, db)
            _budget_check(f"feedback-trace(iter={i})")
            await stages.run_trace(ctx, db)

        # ---- Stage 8: Report ----
        _budget_check("report")
        report_path = await stages.run_report(ctx, db)

        db.finish_run(run_id, "completed")
        log.info(
            "pipeline complete: total cost $%.4f — report at %s",
            db.total_cost(run_id), report_path,
        )
        return run_id, report_path

    except CostExceeded:
        db.finish_run(run_id, "aborted")
        raise
    except Exception:
        db.finish_run(run_id, "failed")
        raise
