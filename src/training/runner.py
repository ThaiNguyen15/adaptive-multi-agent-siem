"""
Training runner for tabular processed datasets.
"""

import json
from pathlib import Path

from src.evaluation.metrics import binary_classification_metrics, select_best_threshold

from .config import ExperimentConfig
from .dataset import TabularDatasetLoader
from .model import NumpyLogisticRegressionModel


class TrainingRunner:
    """Train a baseline binary classifier on processed parquet splits."""

    def __init__(self, config: ExperimentConfig):
        """Initialize training state."""
        self.config = config
        self.config.ensure_dirs()
        self.loader = TabularDatasetLoader(config)

    def _resolve_feature_sets(self, train_df) -> list:
        """Resolve one or more feature-set experiments from the configured blocks."""
        full_feature_columns = self.loader.resolve_feature_columns(train_df)

        if self.config.ablation_mode != "per_block":
            return [{"name": "all_blocks", "feature_columns": full_feature_columns}]

        manifest_blocks = self.loader._manifest.get("feature_blocks", {})
        feature_sets = []
        for block_name in self.config.feature_blocks:
            block_columns = [
                column
                for column in manifest_blocks.get(block_name, [])
                if column in full_feature_columns
            ]
            if block_columns:
                feature_sets.append({"name": block_name, "feature_columns": block_columns})

        feature_sets.append({"name": "all_blocks", "feature_columns": full_feature_columns})
        return feature_sets

    def _fit_and_score(self, train_df, val_df, experiment_name: str, feature_columns: list) -> dict:
        """Train one feature-set experiment and score train/val."""
        X_train, y_train, _ = self.loader.build_matrix(train_df, feature_columns)
        X_val, y_val, _ = self.loader.build_matrix(val_df, feature_columns)

        model = NumpyLogisticRegressionModel.initialize(
            num_features=len(feature_columns),
            feature_columns=feature_columns,
        )
        model.fit(
            X=X_train,
            y=y_train,
            learning_rate=self.config.learning_rate,
            max_epochs=self.config.max_epochs,
            l2_reg=self.config.l2_reg,
            standardize=self.config.standardize,
        )

        val_scores = model.predict_proba(X_val)
        selected_threshold = self.config.classification_threshold
        threshold_search = None
        if self.config.tune_threshold_on_val and len(y_val) > 0:
            threshold_search = select_best_threshold(
                y_true=y_val,
                y_score=val_scores,
                thresholds=self.config.threshold_grid,
                metric_name=self.config.threshold_metric,
            )
            selected_threshold = threshold_search["best_threshold"]

        train_metrics = binary_classification_metrics(
            y_true=y_train,
            y_score=model.predict_proba(X_train),
            threshold=selected_threshold,
        )
        train_metrics["split"] = self.config.train_split
        train_metrics["experiment_name"] = experiment_name

        val_metrics = binary_classification_metrics(
            y_true=y_val,
            y_score=val_scores,
            threshold=selected_threshold,
        )
        val_metrics["split"] = self.config.val_split
        val_metrics["experiment_name"] = experiment_name

        return {
            "name": experiment_name,
            "feature_columns": feature_columns,
            "feature_count": len(feature_columns),
            "model": model,
            "selected_threshold": float(selected_threshold),
            "threshold_search": threshold_search,
            "train_metrics": train_metrics,
            "val_metrics": val_metrics,
        }

    def _save_threshold(self, threshold: float) -> None:
        """Persist the chosen classification threshold."""
        with open(self.config.experiment_dir / "selected_threshold.json", "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "threshold": threshold,
                    "source": "validation_optimization" if self.config.tune_threshold_on_val else "config",
                    "metric": self.config.threshold_metric,
                },
                handle,
                indent=2,
            )

    def run(self) -> dict:
        """Train on the configured train split and evaluate on val."""
        train_df = self.loader.load_split_df(self.config.train_split)
        val_df = self.loader.load_split_df(self.config.val_split)
        experiment_results = []
        for feature_set in self._resolve_feature_sets(train_df):
            experiment_results.append(
                self._fit_and_score(
                    train_df=train_df,
                    val_df=val_df,
                    experiment_name=feature_set["name"],
                    feature_columns=feature_set["feature_columns"],
                )
            )

        best_result = max(
            experiment_results,
            key=lambda item: (
                item["val_metrics"].get(self.config.threshold_metric, float("-inf")),
                item["train_metrics"].get(self.config.threshold_metric, float("-inf")),
            ),
        )

        best_result["model"].save(self.config.experiment_dir)
        self._save_threshold(best_result["selected_threshold"])
        self.config.classification_threshold = best_result["selected_threshold"]
        self.config.save()

        with open(self.config.experiment_dir / "reports" / "train_metrics.json", "w", encoding="utf-8") as handle:
            json.dump(best_result["train_metrics"], handle, indent=2)
        with open(self.config.experiment_dir / "reports" / "val_metrics.json", "w", encoding="utf-8") as handle:
            json.dump(best_result["val_metrics"], handle, indent=2)
        with open(self.config.experiment_dir / "feature_columns.json", "w", encoding="utf-8") as handle:
            json.dump(best_result["feature_columns"], handle, indent=2)
        with open(self.config.experiment_dir / "reports" / "ablation_summary.json", "w", encoding="utf-8") as handle:
            json.dump(
                [
                    {
                        "name": item["name"],
                        "feature_count": item["feature_count"],
                        "selected_threshold": item["selected_threshold"],
                        "train_metrics": item["train_metrics"],
                        "val_metrics": item["val_metrics"],
                    }
                    for item in experiment_results
                ],
                handle,
                indent=2,
            )
        if best_result["threshold_search"] is not None:
            with open(
                self.config.experiment_dir / "reports" / "threshold_search.json",
                "w",
                encoding="utf-8",
            ) as handle:
                json.dump(best_result["threshold_search"], handle, indent=2)

        return {
            "feature_count": best_result["feature_count"],
            "train_metrics": best_result["train_metrics"],
            "val_metrics": best_result["val_metrics"],
            "selected_threshold": best_result["selected_threshold"],
            "best_experiment_name": best_result["name"],
            "experiment_dir": str(self.config.experiment_dir),
        }
