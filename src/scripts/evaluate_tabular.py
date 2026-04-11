"""
Evaluate a saved tabular experiment on a chosen split.
"""

import argparse
from pathlib import Path

from src.evaluation import EvaluationRunner
from src.training.config import ExperimentConfig


def main() -> None:
    """Parse args and run evaluation."""
    parser = argparse.ArgumentParser(description="Evaluate a saved tabular experiment")
    parser.add_argument("--processed-dir", type=Path, required=True, help="Processed domain directory")
    parser.add_argument("--experiment-dir", type=Path, required=True, help="Experiment artifact directory")
    parser.add_argument("--label-col", type=str, required=True, help="Binary label column")
    parser.add_argument("--split", type=str, default="val", help="Split name to evaluate")
    args = parser.parse_args()

    config = ExperimentConfig(
        processed_data_dir=args.processed_dir,
        experiment_dir=args.experiment_dir,
        label_col=args.label_col,
    )
    metrics = EvaluationRunner(config).evaluate_split(
        split_name=args.split,
        report_name=f"{args.split}_metrics.json",
    )

    print("EVALUATION COMPLETED")
    print(f"Split: {metrics['split']}")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"F1: {metrics['f1']:.4f}")


if __name__ == "__main__":
    main()
