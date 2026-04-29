"""
Evaluation and scoring runner for API traffic retrieval experiments.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

import pandas as pd

from src.evaluation.metrics import binary_classification_metrics

from ..training.model import APIRetrievalModel


class APIEvaluationRunner:
    """Evaluate or score processed API splits with a retrieval model."""

    def __init__(
        self,
        processed_data_dir: Path,
        experiment_dir: Path,
        model: APIRetrievalModel = None,
    ):
        self.processed_data_dir = Path(processed_data_dir)
        self.experiment_dir = Path(experiment_dir)
        self.model = model or APIRetrievalModel.load(self.experiment_dir)
        (self.experiment_dir / "reports").mkdir(parents=True, exist_ok=True)
        (self.experiment_dir / "predictions").mkdir(parents=True, exist_ok=True)

    def evaluate_split(self, split_name: str) -> dict:
        """Load and evaluate one processed split."""
        df = self.load_split(split_name)
        return self.evaluate_dataframe(df, split_name)

    def evaluate_dataframe(self, df: pd.DataFrame, split_name: str) -> dict:
        """Evaluate one dataframe and save metrics/predictions."""
        predictions = self.model.predict_dataframe(df)
        predictions.to_parquet(self.experiment_dir / "predictions" / f"{split_name}.parquet", index=False)
        predictions.to_csv(self.experiment_dir / "predictions" / f"{split_name}.csv", index=False)

        has_labels = "y_true" in predictions.columns and not predictions["y_true"].isna().any()
        if not has_labels:
            return {
                "split": split_name,
                "num_rows": int(len(predictions)),
                "labeled": False,
                "finding_counts": predictions["security_finding"].value_counts().to_dict(),
            }

        y_true = pd.to_numeric(predictions["y_true"], errors="coerce").fillna(0).astype(int).to_numpy()
        y_score = predictions["y_score"].to_numpy(dtype=float)
        metrics = binary_classification_metrics(y_true=y_true, y_score=y_score, threshold=self.model.threshold)
        metrics["split"] = split_name
        metrics["attack_type_report"] = self.attack_type_report(predictions)
        metrics["warnings"] = self.attack_type_warnings(metrics["attack_type_report"])
        metrics["finding_counts"] = predictions["security_finding"].value_counts().to_dict()
        self.save_json(f"reports/{split_name}_metrics.json", metrics)
        return metrics

    def load_split(self, split_name: str) -> pd.DataFrame:
        """Load a processed split from parquet shards."""
        split_dir = self.processed_data_dir / "splits" / split_name
        shard_paths = sorted(split_dir.glob("shard_*.parquet"))
        if not shard_paths:
            raise FileNotFoundError(f"No parquet shards found in {split_dir}")
        return pd.concat([pd.read_parquet(path) for path in shard_paths], ignore_index=True)

    @staticmethod
    def attack_type_report(predictions: pd.DataFrame) -> Dict[str, Dict[str, int]]:
        """Summarize anomaly coverage by true attack type."""
        report = {}
        if "attack_type_true" not in predictions.columns:
            return report
        for attack_type, group in predictions.groupby("attack_type_true"):
            report[str(attack_type)] = {
                "rows": int(len(group)),
                "predicted_anomaly": int((group["y_pred"] == 1).sum()),
                "recall": float((group["y_pred"] == 1).sum() / max(len(group), 1))
                if str(attack_type) != "Benign"
                else None,
                "top_predicted_attack_type": str(group["predicted_attack_type"].mode().iloc[0])
                if len(group)
                else "Unknown",
            }
        return report

    @staticmethod
    def attack_type_warnings(attack_type_report: Dict[str, Dict[str, int]]) -> list:
        """Warn when an attack type is completely missed."""
        warnings = []
        for attack_type, report in attack_type_report.items():
            if attack_type == "Benign":
                continue
            if report.get("rows", 0) > 0 and report.get("predicted_anomaly", 0) == 0:
                warnings.append(
                    {
                        "type": "attack_type_missed",
                        "attack_type": attack_type,
                        "rows": int(report["rows"]),
                        "message": f"{attack_type} has zero anomaly recall on this split.",
                    }
                )
        return warnings

    def save_json(self, relative_path: str, payload: dict) -> None:
        """Save JSON relative to experiment directory."""
        output_path = self.experiment_dir / relative_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)


__all__ = ["APIEvaluationRunner"]
