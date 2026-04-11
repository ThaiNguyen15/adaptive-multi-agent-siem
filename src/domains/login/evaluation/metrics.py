"""
Risk-centric evaluation helpers for the login domain.
"""

import numpy as np

from src.evaluation.metrics import binary_classification_metrics


def summarize_login_risk(risk_scores: np.ndarray, alerts: np.ndarray) -> dict:
    """Summarize risk-score behavior for one split."""
    return {
        "num_rows": int(len(risk_scores)),
        "mean_risk_score": float(np.mean(risk_scores)) if len(risk_scores) else 0.0,
        "median_risk_score": float(np.median(risk_scores)) if len(risk_scores) else 0.0,
        "p90_risk_score": float(np.percentile(risk_scores, 90)) if len(risk_scores) else 0.0,
        "p95_risk_score": float(np.percentile(risk_scores, 95)) if len(risk_scores) else 0.0,
        "alert_rate": float(np.mean(alerts)) if len(alerts) else 0.0,
    }


def optional_reference_metrics(df, column: str, risk_scores: np.ndarray, threshold: float) -> dict:
    """Compute reference-only metrics against a binary column when present."""
    if not column or column not in df.columns:
        return {}

    y_true = df[column].fillna(0).astype(int).to_numpy()
    unique_values = set(np.unique(y_true).tolist())
    if not unique_values.issubset({0, 1}):
        return {}

    metrics = binary_classification_metrics(y_true=y_true, y_score=risk_scores, threshold=threshold)
    metrics["reference_label_col"] = column
    metrics["reference_only"] = True
    return metrics
