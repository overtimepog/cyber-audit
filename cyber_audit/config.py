"""Config loading — HarnessConfig, StageConfig dataclasses and YAML loader."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

import yaml


REQUIRED_STAGES = [
    "recon",
    "hunt",
    "validate",
    "gapfill",
    "dedupe",
    "trace",
    "feedback",
    "report",
]

DEFAULT_MAX_TURNS = 25
DEFAULT_PERMISSION_MODE = "acceptEdits"
DEFAULT_REPAIR_ATTEMPTS = 1


@dataclass
class StageConfig:
    """Configuration for a single agent stage."""

    model: str
    concurrency: int
    tools: List[str] = field(default_factory=list)
    max_turns: int = DEFAULT_MAX_TURNS
    permission_mode: str = DEFAULT_PERMISSION_MODE
    repair_attempts: int = DEFAULT_REPAIR_ATTEMPTS


@dataclass
class HarnessConfig:
    """Top-level audit harness configuration."""

    gapfill_iterations: int
    feedback_iterations: int
    stages: Dict[str, StageConfig]


def load_config(path: str | Path) -> HarnessConfig:
    """Load a stages.yaml file and return a HarnessConfig with defaults applied.

    Args:
        path: Path to the YAML configuration file.

    Returns:
        HarnessConfig populated from the YAML file.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If required stages or fields are missing.
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with open(path, "r") as fh:
        raw = yaml.safe_load(fh)

    if raw is None:
        raise ValueError("Configuration file is empty")

    if "stages" not in raw:
        raise ValueError("Configuration missing 'stages' key")

    gapfill_iterations = raw.get("gapfill_iterations", 1)
    feedback_iterations = raw.get("feedback_iterations", 1)

    # Validate all required stages are present
    for stage_name in REQUIRED_STAGES:
        if stage_name not in raw["stages"]:
            raise ValueError(
                f"Missing required stage: {stage_name}"
            )

    stages: Dict[str, StageConfig] = {}
    for stage_name, stage_data in raw["stages"].items():
        if "model" not in stage_data:
            raise ValueError(
                f"Stage '{stage_name}' is missing required field 'model'"
            )

        stages[stage_name] = StageConfig(
            model=stage_data["model"],
            concurrency=stage_data.get("concurrency", 1),
            tools=stage_data.get("tools", []),
            max_turns=stage_data.get(
                "max_turns", DEFAULT_MAX_TURNS
            ),
            permission_mode=stage_data.get(
                "permission_mode", DEFAULT_PERMISSION_MODE
            ),
            repair_attempts=stage_data.get(
                "repair_attempts", DEFAULT_REPAIR_ATTEMPTS
            ),
        )

    return HarnessConfig(
        gapfill_iterations=gapfill_iterations,
        feedback_iterations=feedback_iterations,
        stages=stages,
    )
