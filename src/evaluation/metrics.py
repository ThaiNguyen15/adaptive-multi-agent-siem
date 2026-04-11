"""
Evaluation metrics for binary classification.
"""

import numpy as np


def binary_classification_metrics(
    y_true: np.ndarray, y_score: np.ndarray, threshold: float = 0.5
) -> dict:
    """Compute lightweight binary metrics without external ML dependencies."""
    y_true = y_true.astype(int)
    y_score = np.clip(y_score.astype(float), 1e-8, 1.0 - 1e-8)
    y_pred = (y_score >= threshold).astype(int)

    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    accuracy = (tp + tn) / max(len(y_true), 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-8)
    log_loss = float(-np.mean(y_true * np.log(y_score) + (1 - y_true) * np.log(1 - y_score)))
    brier = float(np.mean((y_score - y_true) ** 2))

    return {
        "threshold": threshold,
        "num_rows": int(len(y_true)),
        "positive_rate": float(y_true.mean()) if len(y_true) else 0.0,
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "log_loss": log_loss,
        "brier_score": brier,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def select_best_threshold(
    y_true: np.ndarray,
    y_score: np.ndarray,
    thresholds: list,
    metric_name: str = "f1",
) -> dict:
    """Choose the threshold that maximizes a metric on validation data."""
    candidates = []
    for threshold in thresholds:
        metrics = binary_classification_metrics(y_true=y_true, y_score=y_score, threshold=threshold)
        metrics["optimized_metric"] = metric_name
        candidates.append(metrics)

    best = max(candidates, key=lambda item: (item.get(metric_name, float("-inf")), -abs(item["threshold"] - 0.5)))
    return {
        "best_threshold": float(best["threshold"]),
        "best_metrics": best,
        "all_candidates": candidates,
    }
