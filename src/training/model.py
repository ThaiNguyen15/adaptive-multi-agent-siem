"""
NumPy-based binary tabular classifier.

This stays dependency-light, but it is no longer just a toy full-batch baseline:
it supports weighted loss, mini-batches, Adam, validation monitoring, and saved
training diagnostics.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np


@dataclass
class NumpyLogisticRegressionModel:
    """Binary logistic regression with saved normalization and diagnostics."""

    weights: np.ndarray
    bias: float
    mean: np.ndarray
    scale: np.ndarray
    feature_columns: list
    training_history: list = field(default_factory=list)
    model_config: dict = field(default_factory=dict)

    @staticmethod
    def _sigmoid(z: np.ndarray) -> np.ndarray:
        """Stable sigmoid."""
        z = np.clip(z, -30.0, 30.0)
        return 1.0 / (1.0 + np.exp(-z))

    @staticmethod
    def _weighted_log_loss(
        y_true: np.ndarray,
        y_score: np.ndarray,
        sample_weight: np.ndarray,
    ) -> float:
        """Numerically stable weighted binary cross-entropy."""
        eps = 1e-12
        y_score = np.clip(y_score, eps, 1.0 - eps)
        losses = -(y_true * np.log(y_score) + (1.0 - y_true) * np.log(1.0 - y_score))
        weight_sum = max(float(sample_weight.sum()), eps)
        return float((losses * sample_weight).sum() / weight_sum)

    @staticmethod
    def _resolve_sample_weight(
        y: np.ndarray,
        class_weight: str | dict | None,
        positive_class_weight: float | None = None,
    ) -> np.ndarray:
        """Build per-row weights for imbalanced binary datasets."""
        y_int = y.astype(int)
        sample_weight = np.ones(len(y_int), dtype=float)

        if positive_class_weight is not None:
            sample_weight[y_int == 1] = float(positive_class_weight)
            return sample_weight

        if class_weight in (None, "none"):
            return sample_weight

        if class_weight == "balanced":
            counts = np.bincount(y_int, minlength=2).astype(float)
            counts[counts == 0.0] = 1.0
            total = max(float(counts.sum()), 1.0)
            weights = total / (2.0 * counts)
            return weights[y_int]

        if isinstance(class_weight, dict):
            for label, weight in class_weight.items():
                sample_weight[y_int == int(label)] = float(weight)
            return sample_weight

        raise ValueError(f"Unsupported class_weight: {class_weight}")

    @classmethod
    def initialize(cls, num_features: int, feature_columns: list) -> "NumpyLogisticRegressionModel":
        """Create a zero-initialized model."""
        return cls(
            weights=np.zeros(num_features, dtype=float),
            bias=0.0,
            mean=np.zeros(num_features, dtype=float),
            scale=np.ones(num_features, dtype=float),
            feature_columns=list(feature_columns),
            training_history=[],
            model_config={},
        )

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        learning_rate: float,
        max_epochs: int,
        l2_reg: float,
        standardize: bool = True,
        X_val: np.ndarray | None = None,
        y_val: np.ndarray | None = None,
        class_weight: str | dict | None = "balanced",
        positive_class_weight: float | None = None,
        batch_size: int = 0,
        optimizer: str = "adam",
        early_stopping: bool = True,
        patience: int = 25,
        min_delta: float = 1e-5,
        random_seed: int = 42,
    ) -> list:
        """Fit logistic regression and return epoch-level diagnostics."""
        X_train = X.astype(float)
        y_train = y.astype(float)
        if standardize:
            self.mean = X_train.mean(axis=0)
            self.scale = X_train.std(axis=0)
            self.scale[self.scale == 0.0] = 1.0
            X_train = (X_train - self.mean) / self.scale
        else:
            self.mean = np.zeros(X_train.shape[1], dtype=float)
            self.scale = np.ones(X_train.shape[1], dtype=float)

        X_val_eval = None
        y_val_eval = None
        val_weight = None
        if X_val is not None and y_val is not None:
            X_val_eval = (X_val.astype(float) - self.mean) / self.scale
            y_val_eval = y_val.astype(float)
            val_weight = self._resolve_sample_weight(
                y_val_eval,
                class_weight=class_weight,
                positive_class_weight=positive_class_weight,
            )

        sample_weight = self._resolve_sample_weight(
            y_train,
            class_weight=class_weight,
            positive_class_weight=positive_class_weight,
        )
        n_rows = max(len(X_train), 1)
        effective_batch_size = n_rows if batch_size <= 0 else min(int(batch_size), n_rows)
        rng = np.random.default_rng(random_seed)
        optimizer = optimizer.lower()
        if optimizer not in {"sgd", "adam"}:
            raise ValueError("optimizer must be 'sgd' or 'adam'")

        adam_m_w = np.zeros_like(self.weights)
        adam_v_w = np.zeros_like(self.weights)
        adam_m_b = 0.0
        adam_v_b = 0.0
        adam_beta1 = 0.9
        adam_beta2 = 0.999
        adam_eps = 1e-8
        update_step = 0
        best_loss = float("inf")
        best_state = None
        epochs_without_improvement = 0
        self.training_history = []

        for epoch in range(1, max_epochs + 1):
            indices = rng.permutation(n_rows)
            for start in range(0, n_rows, effective_batch_size):
                batch_idx = indices[start : start + effective_batch_size]
                X_batch = X_train[batch_idx]
                y_batch = y_train[batch_idx]
                w_batch = sample_weight[batch_idx]
                batch_weight_sum = max(float(w_batch.sum()), 1.0)

                logits = X_batch @ self.weights + self.bias
                probs = self._sigmoid(logits)
                errors = (probs - y_batch) * w_batch

                grad_w = (X_batch.T @ errors) / batch_weight_sum + l2_reg * self.weights
                grad_b = float(errors.sum() / batch_weight_sum)

                if optimizer == "adam":
                    update_step += 1
                    adam_m_w = adam_beta1 * adam_m_w + (1.0 - adam_beta1) * grad_w
                    adam_v_w = adam_beta2 * adam_v_w + (1.0 - adam_beta2) * (grad_w**2)
                    adam_m_b = adam_beta1 * adam_m_b + (1.0 - adam_beta1) * grad_b
                    adam_v_b = adam_beta2 * adam_v_b + (1.0 - adam_beta2) * (grad_b**2)
                    m_w_hat = adam_m_w / (1.0 - adam_beta1**update_step)
                    v_w_hat = adam_v_w / (1.0 - adam_beta2**update_step)
                    m_b_hat = adam_m_b / (1.0 - adam_beta1**update_step)
                    v_b_hat = adam_v_b / (1.0 - adam_beta2**update_step)
                    self.weights -= learning_rate * m_w_hat / (np.sqrt(v_w_hat) + adam_eps)
                    self.bias -= learning_rate * m_b_hat / (np.sqrt(v_b_hat) + adam_eps)
                else:
                    self.weights -= learning_rate * grad_w
                    self.bias -= learning_rate * grad_b

            train_scores = self._sigmoid(X_train @ self.weights + self.bias)
            train_loss = self._weighted_log_loss(y_train, train_scores, sample_weight)
            train_loss += 0.5 * l2_reg * float(np.dot(self.weights, self.weights))
            history_item = {"epoch": epoch, "train_loss": train_loss}

            monitored_loss = train_loss
            if X_val_eval is not None and y_val_eval is not None and val_weight is not None:
                val_scores = self._sigmoid(X_val_eval @ self.weights + self.bias)
                val_loss = self._weighted_log_loss(y_val_eval, val_scores, val_weight)
                val_loss += 0.5 * l2_reg * float(np.dot(self.weights, self.weights))
                history_item["val_loss"] = val_loss
                monitored_loss = val_loss

            self.training_history.append(history_item)

            if not early_stopping:
                continue

            if monitored_loss < best_loss - min_delta:
                best_loss = monitored_loss
                best_state = (self.weights.copy(), float(self.bias), epoch)
                epochs_without_improvement = 0
            else:
                epochs_without_improvement += 1
                if epochs_without_improvement >= patience:
                    break

        if best_state is not None:
            self.weights = best_state[0]
            self.bias = best_state[1]

        self.model_config = {
            "learning_rate": learning_rate,
            "max_epochs": max_epochs,
            "epochs_trained": len(self.training_history),
            "l2_reg": l2_reg,
            "standardize": standardize,
            "class_weight": class_weight,
            "positive_class_weight": positive_class_weight,
            "batch_size": batch_size,
            "optimizer": optimizer,
            "early_stopping": early_stopping,
            "patience": patience,
            "min_delta": min_delta,
            "random_seed": random_seed,
        }
        return self.training_history

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict positive-class probability."""
        X_eval = (X - self.mean) / self.scale
        logits = X_eval @ self.weights + self.bias
        return self._sigmoid(logits)

    def feature_importance(self, top_k: int = 50) -> list:
        """Return largest absolute standardized coefficients."""
        items = [
            {
                "feature": feature,
                "weight": float(weight),
                "abs_weight": float(abs(weight)),
            }
            for feature, weight in zip(self.feature_columns, self.weights)
        ]
        return sorted(items, key=lambda item: item["abs_weight"], reverse=True)[:top_k]

    def save(self, output_dir: Path) -> None:
        """Save model weights and metadata."""
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "reports").mkdir(parents=True, exist_ok=True)
        np.savez(
            output_dir / "model.npz",
            weights=self.weights,
            bias=self.bias,
            mean=self.mean,
            scale=self.scale,
        )
        with open(output_dir / "model_meta.json", "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "feature_columns": self.feature_columns,
                    "model_config": self.model_config,
                },
                handle,
                indent=2,
            )
        with open(output_dir / "reports" / "training_history.json", "w", encoding="utf-8") as handle:
            json.dump(self.training_history, handle, indent=2)
        with open(output_dir / "reports" / "feature_importance.json", "w", encoding="utf-8") as handle:
            json.dump(self.feature_importance(), handle, indent=2)

    @classmethod
    def load(cls, model_dir: Path) -> "NumpyLogisticRegressionModel":
        """Load model weights and metadata."""
        arrays = np.load(model_dir / "model.npz")
        with open(model_dir / "model_meta.json", "r", encoding="utf-8") as handle:
            meta = json.load(handle)
        return cls(
            weights=arrays["weights"],
            bias=float(arrays["bias"]),
            mean=arrays["mean"],
            scale=arrays["scale"],
            feature_columns=meta["feature_columns"],
            training_history=[],
            model_config=meta.get("model_config", {}),
        )
