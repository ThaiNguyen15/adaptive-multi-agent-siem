"""
Audit a login-domain experiment and recommend what to improve next.
"""

import argparse
from pathlib import Path
import json

import pandas as pd


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _count_split_rows(processed_dir: Path) -> dict:
    """Count rows in each processed split."""
    counts = {}
    for split in ["train", "val", "test"]:
        split_dir = processed_dir / "splits" / split
        shard_paths = sorted(split_dir.glob("shard_*.parquet"))
        counts[split] = int(sum(len(pd.read_parquet(path)) for path in shard_paths)) if shard_paths else 0
    return counts


def _diagnose(processed_dir: Path, experiment_dir: Path) -> dict:
    """Inspect reports and produce actionable recommendations."""
    train_report = _load_json(experiment_dir / "reports" / "train_metrics.json")
    val_report = _load_json(experiment_dir / "reports" / "val_metrics.json")
    test_report = _load_json(experiment_dir / "reports" / "test_metrics.json")
    config = _load_json(experiment_dir / "config.json")
    row_counts = _count_split_rows(processed_dir)

    findings = []
    recommendations = []
    process_priority = 0
    training_priority = 0

    target_mode = config.get("target_mode", "")
    if target_mode != "unsupervised_block_risk":
        findings.append(f"Target mode is `{target_mode}`, not the preferred unsupervised risk setup.")
        recommendations.append("Align training with block-risk scoring rather than current-outcome prediction.")
        training_priority += 2

    if row_counts["val"] < 100 or row_counts["test"] < 100:
        findings.append(
            f"Validation/test are still small for stable assessment (val={row_counts['val']}, test={row_counts['test']})."
        )
        recommendations.append("Process more data before treating metrics as stable.")
        process_priority += 2

    train_alert_rate = train_report.get("risk_summary", {}).get("alert_rate")
    val_alert_rate = val_report.get("risk_summary", {}).get("alert_rate")
    target_alert_rate = config.get("alert_rate_target")
    if train_alert_rate is not None and val_alert_rate is not None and target_alert_rate is not None:
        if abs(val_alert_rate - target_alert_rate) > 0.05:
            findings.append(
                f"Validation alert rate ({val_alert_rate:.3f}) drifts away from the target alert budget ({target_alert_rate:.3f})."
            )
            recommendations.append("Recalibrate thresholding or revisit block-score fusion.")
            training_priority += 1

    val_reference = val_report.get("reference_metrics", {})
    test_reference = test_report.get("reference_metrics", {})
    if val_reference and test_reference:
        val_f1 = val_reference.get("f1", 0.0)
        test_f1 = test_reference.get("f1", 0.0)
        if abs(val_f1 - test_f1) > 0.15:
            findings.append(
                f"Reference-only F1 moves noticeably between val and test ({val_f1:.3f} -> {test_f1:.3f})."
            )
            recommendations.append("Inspect score stability across time slices and refine calibration.")
            training_priority += 1

    if not findings:
        findings.append("No major structural issue detected from the available reports.")
        recommendations.append("Next step: run slice analysis on high-novelty and failure-heavy events.")

    primary_focus = "training" if training_priority >= process_priority else "process_more_data"

    return {
        "row_counts": row_counts,
        "train_report": train_report,
        "val_report": val_report,
        "test_report": test_report,
        "findings": findings,
        "recommendations": recommendations,
        "primary_focus": primary_focus,
        "process_priority": process_priority,
        "training_priority": training_priority,
    }


def main() -> None:
    """Run audit and persist summary."""
    parser = argparse.ArgumentParser(description="Audit a login-domain experiment")
    parser.add_argument("--processed-dir", type=Path, required=True, help="Processed login directory")
    parser.add_argument("--experiment-dir", type=Path, required=True, help="Experiment artifact directory")
    args = parser.parse_args()

    result = _diagnose(args.processed_dir, args.experiment_dir)
    output_path = args.experiment_dir / "reports" / "audit_summary.json"
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)

    print("LOGIN EXPERIMENT AUDIT")
    print(f"Primary focus: {result['primary_focus']}")
    print(
        f"Split rows: train={result['row_counts']['train']}, val={result['row_counts']['val']}, test={result['row_counts']['test']}"
    )
    for finding in result["findings"]:
        print(f"- {finding}")
    for recommendation in result["recommendations"]:
        print(f"* {recommendation}")


if __name__ == "__main__":
    main()
