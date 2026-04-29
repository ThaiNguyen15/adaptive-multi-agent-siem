"""
Run final holdout test for a trained API retrieval experiment.

Example:
    python -m src.scripts.test_api_retrieval \
        --processed-dir data/processed/api_traffic_d1 \
        --experiment-dir experiments/api_traffic_d1_retrieval
"""

import argparse
from pathlib import Path

from src.domains.api_traffic.testing import APITestingRunner


def main() -> None:
    """Parse args and run final API retrieval test."""
    parser = argparse.ArgumentParser(description="Run final API retrieval test split")
    parser.add_argument("--processed-dir", type=Path, required=True, help="Processed API traffic directory")
    parser.add_argument("--experiment-dir", type=Path, required=True, help="Experiment artifact directory")
    args = parser.parse_args()

    metrics = APITestingRunner(
        processed_data_dir=args.processed_dir,
        experiment_dir=args.experiment_dir,
    ).run()

    print("API RETRIEVAL TEST COMPLETED")
    print(f"Rows: {metrics['num_rows']}")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"F1: {metrics['f1']:.4f}")


if __name__ == "__main__":
    main()
