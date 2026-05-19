"""StageContext — shared configuration and path resolution for all stages."""

from __future__ import annotations

from pathlib import Path

from cyber_audit.config import HarnessConfig, StageConfig


# Mapping from stage name to prompt file name
_PROMPT_FILES: dict[str, str] = {
    "recon": "01-recon.md",
    "hunt": "02-hunt.md",
    "validate": "03-validate.md",
    "gapfill": "04-gapfill.md",
    "dedupe": "05-dedupe.md",
    "trace": "06-trace.md",
    "feedback": "07-feedback.md",
    "report": "08-report.md",
}

# Mapping from stage name to schema file name
_SCHEMA_FILES: dict[str, str] = {
    "recon": "recon_output.schema.json",
    "hunt": "finding.schema.json",
    "validate": "validation.schema.json",
    "gapfill": "gapfill_output.schema.json",
    "dedupe": "dedupe_output.schema.json",
    "trace": "trace.schema.json",
    "feedback": "feedback_output.schema.json",
    "report": "report.schema.json",
}


class StageContext:
    """Provides per-stage configuration, prompt/schema paths, and results dirs.

    Attributes:
        run_id: The current audit run ID.
        repo_path: Path to the repository being audited.
        config: The full harness configuration (HarnessConfig).
    """

    def __init__(
        self,
        run_id: int,
        repo_path: str | Path,
        config: HarnessConfig,
        prompts_dir: str | Path = "prompts",
        schemas_dir: str | Path = "schemas",
    ) -> None:
        self.run_id = run_id
        self.repo_path = Path(repo_path)
        self.config = config
        self._prompts_dir = Path(prompts_dir)
        self._schemas_dir = Path(schemas_dir)
        # Compatibility aliases for stages that access attributes directly
        self.prompt_dir = self._prompts_dir
        self.schema_dir = self._schemas_dir
        self.cwd = self.repo_path

    # Per-stage convenience: returns the StageConfig for the current stage
    # (callers that know their stage name should use .stage() instead)

    @property
    def artifact_dir(self) -> Path:
        """Default artifact directory (stages should prefer results_dir)."""
        return Path("results") / str(self.run_id)

    def stage(self, name: str) -> StageConfig:
        """Return the StageConfig for the named stage.

        Args:
            name: Stage name (e.g., ``"recon"``, ``"hunt"``).

        Returns:
            The StageConfig from ``config.stages[name]``.

        Raises:
            KeyError: If the stage name is not in the configuration.
        """
        return self.config.stages[name]

    def prompt(self, name: str) -> Path:
        """Return the path to the prompt markdown file for a stage.

        Args:
            name: Stage name (e.g., ``"recon"``).

        Returns:
            Path to the prompt file (e.g., ``prompts/01-recon.md``).
        """
        filename = _PROMPT_FILES[name]
        return self._prompts_dir / filename

    def schema(self, name: str) -> Path:
        """Return the path to the JSON schema file for a stage.

        Args:
            name: Stage name (e.g., ``"recon"``).

        Returns:
            Path to the schema file (e.g., ``schemas/recon_output.schema.json``).
        """
        filename = _SCHEMA_FILES[name]
        return self._schemas_dir / filename

    def results_dir(self, name: str) -> Path:
        """Return the path to the results directory for a stage.

        The directory follows the pattern ``results/<run_id>/<name>``.

        Args:
            name: Stage name (e.g., ``"recon"``).

        Returns:
            Path like ``results/42/recon``.
        """
        return Path("results") / str(self.run_id) / name
