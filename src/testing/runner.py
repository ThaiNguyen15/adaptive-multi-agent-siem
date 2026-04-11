"""
Final test-stage runner.
"""

from src.evaluation.runner import EvaluationRunner
from src.training.config import ExperimentConfig


class TestRunner:
    """Run the final holdout test report."""

    def __init__(self, config: ExperimentConfig):
        """Initialize test-stage state."""
        self.config = config
        self.evaluator = EvaluationRunner(config)

    def run(self) -> dict:
        """Evaluate the configured test split."""
        return self.evaluator.evaluate_split(
            split_name=self.config.test_split,
            report_name="test_metrics.json",
        )
