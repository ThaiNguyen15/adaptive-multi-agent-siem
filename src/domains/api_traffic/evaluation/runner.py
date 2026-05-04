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

    def evaluate_split_without_hints(self, split_name: str) -> dict:
        """Evaluate with semantic tokens and static attack flags removed."""
        df = self.load_split(split_name)
        return self.evaluate_dataframe(self.without_security_hints(df), f"{split_name}_no_hints")

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
        metrics["attack_type_metrics"] = self.attack_type_metrics(predictions)
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
    def attack_type_metrics(predictions: pd.DataFrame) -> dict:
        """Measure attack-type routing separately from binary anomaly detection."""
        if "attack_type_true" not in predictions.columns:
            return {}

        labeled_attacks = predictions[predictions["attack_type_true"].fillna("Benign").astype(str) != "Benign"]
        if labeled_attacks.empty:
            return {
                "attack_rows": 0,
                "attack_type_accuracy": None,
                "strict_attack_accuracy": None,
            }

        type_correct = labeled_attacks["predicted_attack_type"].astype(str) == labeled_attacks["attack_type_true"].astype(str)
        strict_correct = type_correct & (labeled_attacks["y_pred"] == 1)
        by_type = {}
        for attack_type, group in labeled_attacks.groupby("attack_type_true"):
            group_type_correct = group["predicted_attack_type"].astype(str) == str(attack_type)
            by_type[str(attack_type)] = {
                "rows": int(len(group)),
                "type_correct": int(group_type_correct.sum()),
                "type_accuracy": float(group_type_correct.mean()) if len(group) else 0.0,
                "strict_correct": int((group_type_correct & (group["y_pred"] == 1)).sum()),
            }

        return {
            "attack_rows": int(len(labeled_attacks)),
            "attack_type_accuracy": float(type_correct.mean()),
            "strict_attack_accuracy": float(strict_correct.mean()),
            "by_attack_type": by_type,
        }

    @staticmethod
    def without_security_hints(df: pd.DataFrame) -> pd.DataFrame:
        """Remove shortcut-prone semantic hints for payload-generalization audits."""
        scrubbed = df.copy()
        if "semantic_tokens" in scrubbed.columns:
            scrubbed["semantic_tokens"] = ""
        hint_columns = [
            "request_contains_sql_keywords",
            "request_contains_traversal",
            "request_contains_xss",
            "request_contains_log4j",
            "request_header_contains_log4j",
            "request_contains_rce",
            "request_contains_log_forging",
            "suspicious_request_got_2xx",
            "suspicious_request_got_4xx",
            "suspicious_request_got_5xx",
            "sql_request_got_2xx",
            "traversal_request_got_2xx",
            "xss_request_got_2xx",
            "log4j_request_got_2xx",
            "rce_request_got_2xx",
            "log_forging_request_got_2xx",
        ]
        for column in hint_columns:
            if column in scrubbed.columns:
                scrubbed[column] = 0
        return scrubbed

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
