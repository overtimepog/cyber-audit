"""CLI — Click-based command-line interface for cyber-audit.

Usage:
    cyber-audit run --repo /path/to/target [--max-cost 30]
    cyber-audit status --run-id 1
    cyber-audit report --run-id 1 --format md
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click

from cyber_audit import __version__
from cyber_audit.config import load_config
from cyber_audit.orchestrator import run_pipeline
from cyber_audit.state import StateDB

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("cyber-audit")


def _find_config() -> Path:
    """Locate stages.yaml — looks in cwd/config/ then ../config/."""
    for candidate in [Path("config/stages.yaml"), Path("../config/stages.yaml")]:
        if candidate.exists():
            return candidate
    raise click.UsageError("stages.yaml not found in config/ or ../config/")


def _find_db() -> Path:
    return Path("state.db")


@click.group()
@click.version_option(__version__, prog_name="cyber-audit")
def main():
    """Cyber Audit — 8-stage vulnerability discovery agent.

    Powered by DeepSeek and OpenAI models.
    Architecture: Cloudflare Project Glasswing.
    """


@main.command()
@click.option("--repo", required=True, type=click.Path(exists=True), help="Path to target repository.")
@click.option("--run-id", type=int, default=None, help="Existing run ID to resume.")
@click.option("--max-cost", type=float, default=None, help="Budget cap in USD.")
@click.option("--config", "config_path", type=click.Path(exists=True), default=None, help="Path to stages.yaml.")
@click.option("--db-path", type=click.Path(), default=None, help="Path to state.db.")
def run(repo: str, run_id: int | None, max_cost: float | None, config_path: str | None, db_path: str | None):
    """Run the 8-stage vulnerability discovery pipeline."""
    config_file = Path(config_path) if config_path else _find_config()
    db_file = Path(db_path) if db_path else _find_db()

    click.echo(f"Config: {config_file}")
    click.echo(f"Target: {repo}")

    config = load_config(str(config_file))
    db = StateDB(str(db_file))

    try:
        run_id, report_path = asyncio.run(
            run_pipeline(
                repo_path=Path(repo).resolve(),
                run_id=run_id,
                db=db,
                config=config,
                max_cost_usd=max_cost,
            )
        )
        click.echo(f"\nPipeline complete. Run ID: {run_id}")
        click.echo(f"Report: {report_path}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(1)
    finally:
        db.close()


@main.command()
@click.option("--run-id", type=int, default=None, help="Run ID to show status for.")
@click.option("--db-path", type=click.Path(), default=None, help="Path to state.db.")
def status(run_id: int | None, db_path: str | None):
    """Show pipeline run status."""
    db_file = Path(db_path) if db_path else _find_db()
    db = StateDB(str(db_file))

    try:
        if run_id:
            run = db.get_run(run_id)
            if run is None:
                click.echo(f"No run found with ID {run_id}")
                return
            click.echo(f"Run {run['run_id']}: {run['status']}")
            click.echo(f"  Repo: {run['repo_path']}")
            click.echo(f"  Started: {run['started_at']}")
            if run["finished_at"]:
                click.echo(f"  Finished: {run['finished_at']}")
            click.echo(f"  Cost: ${db.total_cost(run_id):.4f}")
            findings = db.get_findings(run_id)
            validated = [f for f in findings if f.validation_status == "confirmed"]
            click.echo(f"  Findings: {len(findings)} total, {len(validated)} confirmed")
        else:
            runs = db.list_runs()
            if not runs:
                click.echo("No runs found.")
                return
            for r in runs:
                click.echo(f"Run {r['run_id']}: {r['status']} — {r['repo_path']}")
    finally:
        db.close()


@main.command()
@click.option("--run-id", type=int, required=True, help="Run ID to generate report for.")
@click.option("--format", "fmt", type=click.Choice(["md", "json"]), default="md", help="Output format.")
@click.option("--db-path", type=click.Path(), default=None, help="Path to state.db.")
def report(run_id: int, fmt: str, db_path: str | None):
    """Generate a vulnerability report from a completed run."""
    db_file = Path(db_path) if db_path else _find_db()
    db = StateDB(str(db_file))

    try:
        run = db.get_run(run_id)
        if run is None:
            click.echo(f"No run found with ID {run_id}", err=True)
            raise SystemExit(1)

        if fmt == "md":
            # Check for existing report file
            report_path = Path("results") / str(run_id) / f"report-{run_id}.md"
            if report_path.exists():
                click.echo(report_path.read_text())
            else:
                click.echo(f"No report file found at {report_path}. Run may not have completed report stage.", err=True)
        elif fmt == "json":
            import json
            findings = db.get_findings(run_id)
            data = {
                "run_id": run_id,
                "status": run["status"],
                "repo": run["repo_path"],
                "findings": [
                    {
                        "id": f.finding_id,
                        "file": f.file,
                        "vuln_class": f.vuln_class,
                        "severity": f.severity,
                        "description": f.description,
                        "validation": f.validation_status,
                    }
                    for f in findings
                ],
            }
            click.echo(json.dumps(data, indent=2))
    finally:
        db.close()
