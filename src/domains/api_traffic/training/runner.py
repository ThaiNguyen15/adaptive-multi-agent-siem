"""
Training runner for API traffic retrieval experiments.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from src.domains.api_traffic.evaluation.runner import APIEvaluationRunner
from src.evaluation.metrics import select_best_threshold

from .model import APIRetrievalModel


class APITrainingRunner:
    """Train, tune, evaluate, and persist API retrieval model artifacts."""

    def __init__(
        self,
        processed_data_dir: Path,
        experiment_dir: Path,
        dimension: int = 512,
        max_benign_refs: int = 20000,
        max_attack_refs: int = 20000,
    ):
        self.processed_data_dir = Path(processed_data_dir)
        self.experiment_dir = Path(experiment_dir)
        self.dimension = dimension
        self.max_benign_refs = max_benign_refs
        self.max_attack_refs = max_attack_refs
        (self.experiment_dir / "reports").mkdir(parents=True, exist_ok=True)
        (self.experiment_dir / "predictions").mkdir(parents=True, exist_ok=True)

    def run(self) -> dict:
        """Train on train split and tune threshold on validation split."""
        train_df = self.load_split("train")
        val_df = self.load_split("val")

        model = APIRetrievalModel(dimension=self.dimension)
        model.fit(
            train_df=train_df,
            max_benign_refs=self.max_benign_refs,
            max_attack_refs=self.max_attack_refs,
        )

        val_scores = model.predict_dataframe(val_df)["y_score"].to_numpy(dtype=float)
        y_val = pd.to_numeric(val_df["label_binary"], errors="coerce").fillna(0).astype(int).to_numpy()
        threshold_search = select_best_threshold(
            y_true=y_val,
            y_score=val_scores,
            thresholds=[
                0.005,
                0.01,
                0.015,
                0.02,
                0.025,
                0.03,
                0.035,
                0.04,
                0.045,
                0.05,
                0.1,
                0.15,
                0.2,
                0.25,
                0.3,
                0.35,
                0.4,
                0.45,
                0.5,
            ],
            metric_name="f1",
        )
        model.threshold = float(threshold_search["best_threshold"])
        model.save(self.experiment_dir)

        self.save_json("reports/threshold_search.json", threshold_search)

        evaluator = APIEvaluationRunner(
            processed_data_dir=self.processed_data_dir,
            experiment_dir=self.experiment_dir,
            model=model,
        )
        train_metrics = evaluator.evaluate_dataframe(train_df, "train")
        val_metrics = evaluator.evaluate_dataframe(val_df, "val")

        config = {
            "processed_data_dir": str(self.processed_data_dir),
            "experiment_dir": str(self.experiment_dir),
            "dimension": self.dimension,
            "max_benign_refs": self.max_benign_refs,
            "max_attack_refs": self.max_attack_refs,
            "selected_threshold": model.threshold,
            "model_type": "endpoint_aware_hashed_semantic_retrieval",
            "training_policy": "fit_on_train_tune_on_val_do_not_touch_test",
        }
        self.save_json("config.json", config)
        return {
            "experiment_dir": str(self.experiment_dir),
            "selected_threshold": model.threshold,
            "train_metrics": train_metrics,
            "val_metrics": val_metrics,
        }

    def load_split(self, split_name: str) -> pd.DataFrame:
        """Load a processed split from parquet shards."""
        split_dir = self.processed_data_dir / "splits" / split_name
        shard_paths = sorted(split_dir.glob("shard_*.parquet"))
        if not shard_paths:
            raise FileNotFoundError(f"No parquet shards found in {split_dir}")
        return pd.concat([pd.read_parquet(path) for path in shard_paths], ignore_index=True)

    def save_json(self, relative_path: str, payload: dict) -> None:
        """Save JSON relative to experiment directory."""
        output_path = self.experiment_dir / relative_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)


__all__ = ["APITrainingRunner"]
