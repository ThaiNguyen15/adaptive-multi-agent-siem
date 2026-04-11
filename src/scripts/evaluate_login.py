"""
Evaluate a saved login-domain experiment.
"""

import argparse
from pathlib import Path

from src.domains.login import LoginEvaluationRunner, LoginExperimentConfig


def main() -> None:
    """Parse args and run login evaluation."""
    parser = argparse.ArgumentParser(description="Evaluate a login-domain experiment")
    parser.add_argument("--processed-dir", type=Path, required=True, help="Processed login directory")
    parser.add_argument("--experiment-dir", type=Path, required=True, help="Experiment artifact directory")
    parser.add_argument("--split", type=str, default="val", help="Split to evaluate")
    args = parser.parse_args()

    config = LoginExperimentConfig(
        processed_data_dir=args.processed_dir,
        experiment_dir=args.experiment_dir,
    )
    metrics = LoginEvaluationRunner(config).evaluate_split(
        split_name=args.split,
        report_name=f"{args.split}_metrics.json",
    )

    print("LOGIN EVALUATION COMPLETED")
    print(f"Split: {metrics['split']}")
    print(f"Alert rate: {metrics['risk_summary']['alert_rate']:.4f}")
    print(f"P95 risk: {metrics['risk_summary']['p95_risk_score']:.4f}")
    if metrics["reference_metrics"]:
        print(f"Reference F1: {metrics['reference_metrics']['f1']:.4f}")


if __name__ == "__main__":
    main()
