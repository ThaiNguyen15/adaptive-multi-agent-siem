"""
Domain-specific training runner for login risk scoring.
"""

import json
import numpy as np

from src.evaluation.metrics import binary_classification_metrics

from .config import LoginExperimentConfig
from .dataset import LoginDatasetLoader
from .model import LoginBlockRiskModel


class LoginTrainingRunner:
    """Fit block-specific behavioral baselines and calibrate a fusion threshold."""

    def __init__(self, config: LoginExperimentConfig):
        """Initialize training state."""
        self.config = config
        self.config.ensure_dirs()
        self.loader = LoginDatasetLoader(config)

    @staticmethod
    def _risk_summary(risk_scores: np.ndarray, alerts: np.ndarray) -> dict:
        """Summarize risk-score behavior on one split."""
        return {
            "num_rows": int(len(risk_scores)),
            "mean_risk_score": float(np.mean(risk_scores)) if len(risk_scores) else 0.0,
            "median_risk_score": float(np.median(risk_scores)) if len(risk_scores) else 0.0,
            "p90_risk_score": float(np.percentile(risk_scores, 90)) if len(risk_scores) else 0.0,
            "p95_risk_score": float(np.percentile(risk_scores, 95)) if len(risk_scores) else 0.0,
            "alert_rate": float(np.mean(alerts)) if len(alerts) else 0.0,
        }

    def _choose_threshold(self, calibration_scores: np.ndarray) -> float:
        """Choose the final alert threshold from the calibration split."""
        if len(calibration_scores) == 0:
            return 1.0
        quantile = max(0.0, min(1.0, 1.0 - self.config.alert_rate_target))
        return float(np.quantile(calibration_scores, quantile))

    def _reference_metrics(self, df, risk_scores: np.ndarray, alerts: np.ndarray) -> dict:
        """Compute optional reference metrics against a binary column, if available."""
        column = self.config.reference_label_col
        if not column or column not in df.columns:
            return {}

        y_true = df[column].fillna(0).astype(int).to_numpy()
        unique_values = set(np.unique(y_true).tolist())
        if not unique_values.issubset({0, 1}):
            return {}

        metrics = binary_classification_metrics(
            y_true=y_true,
            y_score=risk_scores,
            threshold=self.config.classification_threshold,
        )
        metrics["reference_label_col"] = column
        metrics["reference_only"] = True
        metrics["alert_precision"] = float(
            (y_true[alerts == 1] == 1).mean() if np.any(alerts == 1) else 0.0
        )
        return metrics

    def _save_block_scores(self, split_name: str, df, risk_scores, block_scores, alerts) -> None:
        """Save per-event block-score outputs for debugging and slicing."""
        output_df = df[[column for column in ["user_id", "login_timestamp"] if column in df.columns]].copy()
        output_df["risk_score"] = risk_scores
        output_df["alert"] = alerts
        for block_name, values in block_scores.items():
            output_df[f"{block_name}_score"] = values
        output_df.to_parquet(
            self.config.experiment_dir / "predictions" / f"{split_name}.parquet",
            index=False,
        )

    def run(self) -> dict:
        """Train a block-risk model and persist calibration reports."""
        train_df = self.loader.load_split_df(self.config.train_split)
        calibration_df = self.loader.load_split_df(self.config.calibration_split)
        block_columns = self.loader.get_block_columns()

        provisional_model = LoginBlockRiskModel.fit(
            train_df=train_df,
            block_columns=block_columns,
            score_clip=self.config.score_clip,
            min_scale=self.config.min_scale,
            risk_threshold=1.0,
        )

        calibration_scores, _, _ = provisional_model.predict(calibration_df)
        selected_threshold = self._choose_threshold(calibration_scores)

        model = LoginBlockRiskModel.fit(
            train_df=train_df,
            block_columns=block_columns,
            score_clip=self.config.score_clip,
            min_scale=self.config.min_scale,
            risk_threshold=selected_threshold,
        )
        model.save(self.config.experiment_dir)
        self.config.classification_threshold = selected_threshold
        self.config.save()

        train_scores, train_block_scores, train_alerts = model.predict(train_df)
        calibration_scores, calibration_block_scores, calibration_alerts = model.predict(calibration_df)

        train_report = {
            "split": self.config.train_split,
            "target_mode": self.config.target_mode,
            "selected_threshold": selected_threshold,
            "feature_blocks": {name: len(columns) for name, columns in block_columns.items()},
            "risk_summary": self._risk_summary(train_scores, train_alerts),
            "reference_metrics": self._reference_metrics(train_df, train_scores, train_alerts),
        }
        calibration_report = {
            "split": self.config.calibration_split,
            "target_mode": self.config.target_mode,
            "selected_threshold": selected_threshold,
            "feature_blocks": {name: len(columns) for name, columns in block_columns.items()},
            "risk_summary": self._risk_summary(calibration_scores, calibration_alerts),
            "reference_metrics": self._reference_metrics(
                calibration_df, calibration_scores, calibration_alerts
            ),
        }

        with open(self.config.experiment_dir / "reports" / "train_metrics.json", "w", encoding="utf-8") as handle:
            json.dump(train_report, handle, indent=2)
        with open(self.config.experiment_dir / "reports" / "val_metrics.json", "w", encoding="utf-8") as handle:
            json.dump(calibration_report, handle, indent=2)
        with open(
            self.config.experiment_dir / "reports" / "block_structure.json",
            "w",
            encoding="utf-8",
        ) as handle:
            json.dump(
                {
                    "feature_blocks": block_columns,
                    "selected_threshold": selected_threshold,
                    "alert_rate_target": self.config.alert_rate_target,
                },
                handle,
                indent=2,
            )

        self._save_block_scores(self.config.train_split, train_df, train_scores, train_block_scores, train_alerts)
        self._save_block_scores(
            self.config.calibration_split,
            calibration_df,
            calibration_scores,
            calibration_block_scores,
            calibration_alerts,
        )

        return {
            "feature_count": int(sum(len(columns) for columns in block_columns.values())),
            "train_metrics": train_report,
            "val_metrics": calibration_report,
            "selected_threshold": selected_threshold,
            "best_experiment_name": "block_risk_fusion",
            "experiment_dir": str(self.config.experiment_dir),
        }
