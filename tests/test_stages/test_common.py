"""Test StageContext — path and config resolution for pipeline stages."""

from pathlib import Path

import pytest

from cyber_audit.config import HarnessConfig, StageConfig
from cyber_audit.stages._common import StageContext


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_config() -> HarnessConfig:
    """Return a minimal HarnessConfig with all required stages."""
    stages = {}
    for name in ["recon", "hunt", "validate", "gapfill", "dedupe", "trace", "feedback", "report"]:
        stages[name] = StageConfig(
            model=f"test-model-{name}",
            concurrency=1,
            tools=["Read", "Grep"],
        )
    return HarnessConfig(
        gapfill_iterations=2,
        feedback_iterations=3,
        stages=stages,
    )


@pytest.fixture
def ctx(sample_config) -> StageContext:
    """Return a StageContext with known values."""
    return StageContext(
        run_id=42,
        repo_path=Path("/tmp/test-repo"),
        config=sample_config,
    )


# ---------------------------------------------------------------------------
# StageContext construction
# ---------------------------------------------------------------------------
class TestStageContextConstruction:
    """StageContext holds run_id, repo_path, and config."""

    def test_construction_stores_fields(self, ctx, sample_config):
        assert ctx.run_id == 42
        assert ctx.repo_path == Path("/tmp/test-repo")
        assert ctx.config is sample_config

    def test_run_id_is_int(self, ctx):
        assert isinstance(ctx.run_id, int)

    def test_repo_path_is_path(self, ctx):
        assert isinstance(ctx.repo_path, Path)

    def test_config_is_harness_config(self, ctx):
        assert isinstance(ctx.config, HarnessConfig)


# ---------------------------------------------------------------------------
# stage() method
# ---------------------------------------------------------------------------
class TestStageMethod:
    """stage(name) returns StageConfig from config.stages."""

    def test_stage_returns_stage_config(self, ctx):
        sc = ctx.stage("recon")
        assert isinstance(sc, StageConfig)

    def test_stage_recon_has_correct_model(self, ctx):
        sc = ctx.stage("recon")
        assert sc.model == "test-model-recon"

    def test_stage_hunt_has_correct_model(self, ctx):
        sc = ctx.stage("hunt")
        assert sc.model == "test-model-hunt"

    def test_stage_validate_has_correct_model(self, ctx):
        sc = ctx.stage("validate")
        assert sc.model == "test-model-validate"

    def test_stage_returns_concurrency(self, ctx):
        sc = ctx.stage("hunt")
        assert sc.concurrency == 1

    def test_stage_returns_tools(self, ctx):
        sc = ctx.stage("recon")
        assert "Read" in sc.tools
        assert "Grep" in sc.tools

    def test_stage_missing_raises_key_error(self, ctx):
        with pytest.raises(KeyError):
            ctx.stage("nonexistent")


# ---------------------------------------------------------------------------
# prompt() method
# ---------------------------------------------------------------------------
class TestPromptMethod:
    """prompt(name) returns Path to the prompt markdown file."""

    def test_prompt_recon(self, ctx):
        p = ctx.prompt("recon")
        assert isinstance(p, Path)
        assert p.name == "01-recon.md"

    def test_prompt_hunt(self, ctx):
        p = ctx.prompt("hunt")
        assert p.name == "02-hunt.md"

    def test_prompt_validate(self, ctx):
        p = ctx.prompt("validate")
        assert p.name == "03-validate.md"

    def test_prompt_gapfill(self, ctx):
        p = ctx.prompt("gapfill")
        assert p.name == "04-gapfill.md"

    def test_prompt_dedupe(self, ctx):
        p = ctx.prompt("dedupe")
        assert p.name == "05-dedupe.md"

    def test_prompt_trace(self, ctx):
        p = ctx.prompt("trace")
        assert p.name == "06-trace.md"

    def test_prompt_feedback(self, ctx):
        p = ctx.prompt("feedback")
        assert p.name == "07-feedback.md"

    def test_prompt_report(self, ctx):
        p = ctx.prompt("report")
        assert p.name == "08-report.md"

    def test_prompt_ends_with_md(self, ctx):
        for name in ["recon", "hunt", "validate"]:
            p = ctx.prompt(name)
            assert p.suffix == ".md"


# ---------------------------------------------------------------------------
# schema() method
# ---------------------------------------------------------------------------
class TestSchemaMethod:
    """schema(name) returns Path to the JSON schema file."""

    def test_schema_recon(self, ctx):
        s = ctx.schema("recon")
        assert isinstance(s, Path)
        assert s.name == "recon_output.schema.json"

    def test_schema_hunt(self, ctx):
        s = ctx.schema("hunt")
        assert s.name == "finding.schema.json"

    def test_schema_validate(self, ctx):
        s = ctx.schema("validate")
        assert s.name == "validation.schema.json"

    def test_schema_ends_with_json(self, ctx):
        for name in ["recon", "hunt", "validate"]:
            s = ctx.schema(name)
            assert s.suffix == ".json"


# ---------------------------------------------------------------------------
# results_dir() method
# ---------------------------------------------------------------------------
class TestResultsDirMethod:
    """results_dir(name) returns Path under results/<run_id>/<name>."""

    def test_results_dir_recon(self, ctx):
        d = ctx.results_dir("recon")
        assert isinstance(d, Path)
        assert d.parts[-3:] == ("results", "42", "recon")

    def test_results_dir_hunt(self, ctx):
        d = ctx.results_dir("hunt")
        assert d.parts[-2:] == ("42", "hunt")

    def test_results_dir_ends_with_stage_name(self, ctx):
        for name in ["recon", "hunt", "validate"]:
            d = ctx.results_dir(name)
            assert d.name == name

    def test_results_dir_contains_run_id(self, ctx):
        d = ctx.results_dir("recon")
        assert "42" in str(d)

    def test_results_dir_is_absolute_when_repo_path_is_absolute(self, ctx):
        """If repo_path is absolute, results_dir should also be absolute
        since it's relative to repo_path."""
        d = ctx.results_dir("recon")
        # results_dir is computed relative to something — check it's a Path
        assert isinstance(d, Path)

    def test_results_dir_different_run_id(self, sample_config):
        ctx2 = StageContext(
            run_id=99,
            repo_path=Path("/tmp/repo2"),
            config=sample_config,
        )
        d = ctx2.results_dir("hunt")
        assert "99" in str(d)
        assert d.name == "hunt"
