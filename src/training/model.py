"""
Simple NumPy-based baseline model for binary tabular classification.
"""

from dataclasses import dataclass
from pathlib import Path
import json

import numpy as np


@dataclass
class NumpyLogisticRegressionModel:
    """Minimal binary logistic regression model with saved normalization stats."""

    weights: np.ndarray
    bias: float
    mean: np.ndarray
    scale: np.ndarray
    feature_columns: list

    @staticmethod
    def _sigmoid(z: np.ndarray) -> np.ndarray:
        """Stable sigmoid."""
        z = np.clip(z, -30.0, 30.0)
        return 1.0 / (1.0 + np.exp(-z))

    @classmethod
    def initialize(cls, num_features: int, feature_columns: list) -> "NumpyLogisticRegressionModel":
        """Create a zero-initialized model."""
        return cls(
            weights=np.zeros(num_features, dtype=float),
            bias=0.0,
            mean=np.zeros(num_features, dtype=float),
            scale=np.ones(num_features, dtype=float),
            feature_columns=list(feature_columns),
        )

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        learning_rate: float,
        max_epochs: int,
        l2_reg: float,
        standardize: bool = True,
    ) -> None:
        """Fit logistic regression with batch gradient descent."""
        X_train = X.astype(float)
        if standardize:
            self.mean = X_train.mean(axis=0)
            self.scale = X_train.std(axis=0)
            self.scale[self.scale == 0.0] = 1.0
            X_train = (X_train - self.mean) / self.scale
        else:
            self.mean = np.zeros(X_train.shape[1], dtype=float)
            self.scale = np.ones(X_train.shape[1], dtype=float)

        n_rows = max(len(X_train), 1)
        for _ in range(max_epochs):
            logits = X_train @ self.weights + self.bias
            probs = self._sigmoid(logits)
            errors = probs - y

            grad_w = (X_train.T @ errors) / n_rows + l2_reg * self.weights
            grad_b = float(errors.mean())

            self.weights -= learning_rate * grad_w
            self.bias -= learning_rate * grad_b

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict positive-class probability."""
        X_eval = (X - self.mean) / self.scale
        logits = X_eval @ self.weights + self.bias
        return self._sigmoid(logits)

    def save(self, output_dir: Path) -> None:
        """Save model weights and metadata."""
        output_dir.mkdir(parents=True, exist_ok=True)
        np.savez(
            output_dir / "model.npz",
            weights=self.weights,
            bias=self.bias,
            mean=self.mean,
            scale=self.scale,
        )
        with open(output_dir / "model_meta.json", "w", encoding="utf-8") as handle:
            json.dump({"feature_columns": self.feature_columns}, handle, indent=2)

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
        )
