"""
Final test runner for API traffic retrieval experiments.
"""

from __future__ import annotations

from pathlib import Path

from ..evaluation.runner import APIEvaluationRunner


class APITestingRunner:
    """Run final holdout test split for API traffic."""

    def __init__(self, processed_data_dir: Path, experiment_dir: Path):
        self.evaluator = APIEvaluationRunner(
            processed_data_dir=processed_data_dir,
            experiment_dir=experiment_dir,
        )

    def run(self) -> dict:
        """Evaluate the test split."""
        return self.evaluator.evaluate_split("test")


__all__ = ["APITestingRunner"]
