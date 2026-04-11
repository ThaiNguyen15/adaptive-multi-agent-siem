"""
Experiment config defaults for the login domain.
"""

from dataclasses import dataclass, field
from pathlib import Path

from src.training.config import ExperimentConfig


@dataclass
class LoginExperimentConfig(ExperimentConfig):
    """Opinionated defaults for login-domain experiments."""

    label_col: str = "login_successful"
    feature_blocks: list = field(
        default_factory=lambda: [
            "temporal",
            "novelty",
            "continuity",
            "familiarity",
            "outcome_pressure",
            "diversity",
        ]
    )
    target_mode: str = "unsupervised_block_risk"
    reference_label_col: str = "login_successful"
    calibration_split: str = "val"
    alert_rate_target: float = 0.05
    score_clip: float = 5.0
    min_scale: float = 1e-3
    use_optional_token_block: bool = False

    def __post_init__(self) -> None:
        """Normalize inherited path fields and block settings."""
        if self.processed_data_dir is not None:
            self.processed_data_dir = Path(self.processed_data_dir)
        if self.experiment_dir is not None:
            self.experiment_dir = Path(self.experiment_dir)
