"""
Evaluation runner for login-domain risk scoring.
"""

import json

from ..training.config import LoginExperimentConfig
from ..training.dataset import LoginDatasetLoader
from ..training.model import LoginBlockRiskModel
from .metrics import optional_reference_metrics, summarize_login_risk


class LoginEvaluationRunner:
    """Evaluate a saved login-domain risk model on any split."""

    def __init__(self, config: LoginExperimentConfig):
        """Initialize evaluation state."""
        self.config = config
        self.loader = LoginDatasetLoader(config)
        self.model = LoginBlockRiskModel.load(config.experiment_dir)

    def evaluate_split(self, split_name: str, report_name: str) -> dict:
        """Evaluate one split and persist risk-centric outputs."""
        df = self.loader.load_split_df(split_name)
        risk_scores, block_scores, alerts = self.model.predict(df)

        report = {
            "split": split_name,
            "target_mode": self.config.target_mode,
            "selected_threshold": self.model.risk_threshold,
            "risk_summary": summarize_login_risk(risk_scores, alerts),
            "reference_metrics": optional_reference_metrics(
                df=df,
                column=self.config.reference_label_col,
                risk_scores=risk_scores,
                threshold=self.model.risk_threshold,
            ),
        }

        with open(self.config.experiment_dir / "reports" / report_name, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)

        output_df = df[[column for column in ["user_id", "login_timestamp"] if column in df.columns]].copy()
        output_df["risk_score"] = risk_scores
        output_df["alert"] = alerts
        for block_name, values in block_scores.items():
            output_df[f"{block_name}_score"] = values
        output_df.to_parquet(
            self.config.experiment_dir / "predictions" / f"{split_name}.parquet",
            index=False,
        )

        return report
