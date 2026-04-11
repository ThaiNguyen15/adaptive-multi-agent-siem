"""
Final holdout testing for the login domain.
"""

from ..evaluation.runner import LoginEvaluationRunner
from ..training.config import LoginExperimentConfig


class LoginTestRunner:
    """Run final holdout testing for the login-domain risk model."""

    def __init__(self, config: LoginExperimentConfig):
        """Initialize test runner state."""
        self.config = config
        self.evaluator = LoginEvaluationRunner(config)

    def run(self) -> dict:
        """Evaluate the configured test split."""
        return self.evaluator.evaluate_split(
            split_name=self.config.test_split,
            report_name="test_metrics.json",
        )
