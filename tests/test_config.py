"""Test config module — HarnessConfig, StageConfig, and load_config."""

import tempfile
from pathlib import Path

import pytest

from cyber_audit.config import HarnessConfig, StageConfig, load_config


# ---------------------------------------------------------------------------
# StageConfig
# ---------------------------------------------------------------------------
class TestStageConfigFields:
    """StageConfig dataclass holds the right fields with correct types."""

    def test_stage_config_fields_exist(self):
        sc = StageConfig(
            model="openai/gpt-4o",
            concurrency=5,
            tools=["tool_a", "tool_b"],
            max_turns=25,
            permission_mode="acceptEdits",
            repair_attempts=1,
        )
        assert sc.model == "openai/gpt-4o"
        assert sc.concurrency == 5
        assert sc.tools == ["tool_a", "tool_b"]
        assert sc.max_turns == 25
        assert sc.permission_mode == "acceptEdits"
        assert sc.repair_attempts == 1

    def test_stage_config_is_dataclass(self):
        import dataclasses
        assert dataclasses.is_dataclass(StageConfig)


# ---------------------------------------------------------------------------
# HarnessConfig
# ---------------------------------------------------------------------------
class TestHarnessConfig:
    """HarnessConfig holds top-level fields + stage dict."""

    def test_harness_config_fields(self):
        sc = StageConfig(
            model="deepseek/deepseek-v4-pro",
            concurrency=1,
            tools=[],
        )
        hc = HarnessConfig(
            gapfill_iterations=3,
            feedback_iterations=2,
            stages={"recon": sc},
        )
        assert hc.gapfill_iterations == 3
        assert hc.feedback_iterations == 2
        assert hc.stages == {"recon": sc}
        assert hc.stages["recon"].model == "deepseek/deepseek-v4-pro"


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------
SAMPLE_YAML = """\
gapfill_iterations: 3
feedback_iterations: 2

stages:
  recon:
    model: deepseek/deepseek-v4-pro
    concurrency: 1
    tools:
      - web_search
      - read_file

  hunt:
    model: openai/gpt-4o
    concurrency: 5
    tools:
      - web_search
      - terminal
      - read_file

  validate:
    model: deepseek/deepseek-v4-pro
    concurrency: 3
    tools:
      - read_file
      - grep

  gapfill:
    model: openai/gpt-4o-mini
    concurrency: 1
    tools:
      - web_search

  dedupe:
    model: openai/gpt-4o-mini
    concurrency: 1
    tools:
      - read_file

  trace:
    model: deepseek/deepseek-v4-pro
    concurrency: 3
    tools:
      - read_file
      - grep
      - terminal

  feedback:
    model: openai/gpt-4o-mini
    concurrency: 1
    tools:
      - read_file

  report:
    model: openai/gpt-4o
    concurrency: 1
    tools:
      - write_file
"""


class TestLoadConfigValid:
    """load_config reads a valid YAML and returns a correct HarnessConfig."""

    def test_load_config_returns_harness_config(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(SAMPLE_YAML)
            f.flush()
            cfg = load_config(f.name)

        assert isinstance(cfg, HarnessConfig)

    def test_load_config_top_level_fields(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(SAMPLE_YAML)
            f.flush()
            cfg = load_config(f.name)

        assert cfg.gapfill_iterations == 3
        assert cfg.feedback_iterations == 2

    def test_load_config_all_stages_present(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(SAMPLE_YAML)
            f.flush()
            cfg = load_config(f.name)

        expected_stages = [
            "recon", "hunt", "validate", "gapfill",
            "dedupe", "trace", "feedback", "report",
        ]
        for stage_name in expected_stages:
            assert stage_name in cfg.stages, (
                f"Missing stage: {stage_name}"
            )
            assert isinstance(cfg.stages[stage_name], StageConfig)

    def test_load_config_stage_fields_correct(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(SAMPLE_YAML)
            f.flush()
            cfg = load_config(f.name)

        recon = cfg.stages["recon"]
        assert recon.model == "deepseek/deepseek-v4-pro"
        assert recon.concurrency == 1
        assert recon.tools == ["web_search", "read_file"]

        hunt = cfg.stages["hunt"]
        assert hunt.model == "openai/gpt-4o"
        assert hunt.concurrency == 5
        assert "web_search" in hunt.tools

        report = cfg.stages["report"]
        assert report.model == "openai/gpt-4o"
        assert report.concurrency == 1


class TestLoadConfigDefaults:
    """When YAML omits some fields, defaults are applied."""

    MINIMAL_YAML = """\
gapfill_iterations: 1
feedback_iterations: 1

stages:
  recon:
    model: deepseek/deepseek-v4-pro
    concurrency: 1
    tools: []
  hunt:
    model: openai/gpt-4o
    concurrency: 5
    tools: []
  validate:
    model: deepseek/deepseek-v4-pro
    concurrency: 3
    tools: []
  gapfill:
    model: openai/gpt-4o-mini
    concurrency: 1
    tools: []
  dedupe:
    model: openai/gpt-4o-mini
    concurrency: 1
    tools: []
  trace:
    model: deepseek/deepseek-v4-pro
    concurrency: 3
    tools: []
  feedback:
    model: openai/gpt-4o-mini
    concurrency: 1
    tools: []
  report:
    model: openai/gpt-4o
    concurrency: 1
    tools: []
"""

    def test_defaults_max_turns(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(self.MINIMAL_YAML)
            f.flush()
            cfg = load_config(f.name)

        assert cfg.stages["recon"].max_turns == 25

    def test_defaults_permission_mode(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(self.MINIMAL_YAML)
            f.flush()
            cfg = load_config(f.name)

        assert cfg.stages["recon"].permission_mode == "acceptEdits"

    def test_defaults_repair_attempts(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(self.MINIMAL_YAML)
            f.flush()
            cfg = load_config(f.name)

        assert cfg.stages["recon"].repair_attempts == 1

    def test_defaults_applied_when_field_completely_missing(self):
        """Defaults fill in any missing StageConfig fields."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(self.MINIMAL_YAML)
            f.flush()
            cfg = load_config(f.name)

        stage = cfg.stages["recon"]
        assert stage.max_turns == 25
        assert stage.permission_mode == "acceptEdits"
        assert stage.repair_attempts == 1


class TestLoadConfigErrors:
    """load_config raises errors on invalid/missing input."""

    def test_missing_stage_raises_error(self):
        """If a required stage is missing, raise an error."""
        bad_yaml = """\
gapfill_iterations: 1
feedback_iterations: 1

stages:
  recon:
    model: deepseek/deepseek-v4-pro
    concurrency: 1
    tools: []
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(bad_yaml)
            f.flush()
            with pytest.raises(ValueError, match="Missing required stage"):
                load_config(f.name)

    def test_missing_stages_key_raises_error(self):
        bad_yaml = """\
gapfill_iterations: 1
feedback_iterations: 1
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(bad_yaml)
            f.flush()
            with pytest.raises(ValueError):
                load_config(f.name)

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path/stages.yaml")

    def test_missing_model_raises_error(self):
        """Stage without model field should raise an error."""
        bad_yaml = """\
gapfill_iterations: 1
feedback_iterations: 1

stages:
  recon:
    concurrency: 1
    tools: []
  hunt:
    model: openai/gpt-4o
    concurrency: 5
    tools: []
  validate:
    model: deepseek/deepseek-v4-pro
    concurrency: 3
    tools: []
  gapfill:
    model: openai/gpt-4o-mini
    concurrency: 1
    tools: []
  dedupe:
    model: openai/gpt-4o-mini
    concurrency: 1
    tools: []
  trace:
    model: deepseek/deepseek-v4-pro
    concurrency: 3
    tools: []
  feedback:
    model: openai/gpt-4o-mini
    concurrency: 1
    tools: []
  report:
    model: openai/gpt-4o
    concurrency: 1
    tools: []
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(bad_yaml)
            f.flush()
            with pytest.raises(ValueError, match="model"):
                load_config(f.name)
