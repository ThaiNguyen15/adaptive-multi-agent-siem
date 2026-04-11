"""
Run the final holdout test stage for a saved experiment.
"""

import argparse
from pathlib import Path

from src.testing import TestRunner
from src.training.config import ExperimentConfig


def main() -> None:
    """Parse args and run final test evaluation."""
    parser = argparse.ArgumentParser(description="Run final test-stage evaluation")
    parser.add_argument("--processed-dir", type=Path, required=True, help="Processed domain directory")
    parser.add_argument("--experiment-dir", type=Path, required=True, help="Experiment artifact directory")
    parser.add_argument("--label-col", type=str, required=True, help="Binary label column")
    args = parser.parse_args()

    config = ExperimentConfig(
        processed_data_dir=args.processed_dir,
        experiment_dir=args.experiment_dir,
        label_col=args.label_col,
    )
    metrics = TestRunner(config).run()

    print("TEST COMPLETED")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"F1: {metrics['f1']:.4f}")


if __name__ == "__main__":
    main()
