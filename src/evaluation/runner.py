"""
Evaluation runner for saved experiment artifacts.
"""

from pathlib import Path
import json

import pandas as pd

from src.training.config import ExperimentConfig
from src.training.dataset import TabularDatasetLoader
from src.training.model import NumpyLogisticRegressionModel

from .metrics import binary_classification_metrics


class EvaluationRunner:
    """Evaluate a saved model on any processed split."""

    def __init__(self, config: ExperimentConfig):
        """Initialize evaluation state."""
        self.config = config
        self.loader = TabularDatasetLoader(config)
        self.model = NumpyLogisticRegressionModel.load(config.experiment_dir)
        self.threshold = self._load_selected_threshold()

    def _load_selected_threshold(self) -> float:
        """Load the tuned threshold if training persisted one."""
        threshold_path = self.config.experiment_dir / "selected_threshold.json"
        if not threshold_path.exists():
            return self.config.classification_threshold

        with open(threshold_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return float(payload.get("threshold", self.config.classification_threshold))

    def evaluate_split(self, split_name: str, report_name: str) -> dict:
        """Evaluate one split and persist metrics + predictions."""
        df = self.loader.load_split_df(split_name)
        X, y, metadata = self.loader.build_matrix(df, self.model.feature_columns)
        y_score = self.model.predict_proba(X)

        metrics = binary_classification_metrics(
            y_true=y,
            y_score=y_score,
            threshold=self.threshold,
        )
        metrics["split"] = split_name

        report_path = self.config.experiment_dir / "reports" / report_name
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(metrics, handle, indent=2)

        predictions = metadata.copy()
        predictions["y_true"] = y
        predictions["y_score"] = y_score
        predictions["y_pred"] = (y_score >= self.threshold).astype(int)
        predictions.to_parquet(
            self.config.experiment_dir / "predictions" / f"{split_name}.parquet",
            index=False,
        )

        return metrics
