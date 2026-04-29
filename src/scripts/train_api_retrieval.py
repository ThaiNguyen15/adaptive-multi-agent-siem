"""
Train and evaluate endpoint-aware retrieval for API traffic.

Example:
    python -m src.scripts.train_api_retrieval \
        --processed-dir data/processed/api_traffic_smoke \
        --experiment-dir experiments/api_traffic_retrieval_smoke
"""

import argparse
from pathlib import Path

from src.domains.api_traffic.training import APITrainingRunner


def main() -> None:
    """Parse args and run API retrieval experiment."""
    parser = argparse.ArgumentParser(description="Train API endpoint-aware retrieval model")
    parser.add_argument("--processed-dir", type=Path, required=True, help="Processed API traffic directory")
    parser.add_argument("--experiment-dir", type=Path, required=True, help="Output experiment directory")
    parser.add_argument("--dimension", type=int, default=512, help="Hashed vector dimension")
    parser.add_argument("--max-benign-refs", type=int, default=20000, help="Maximum benign reference rows")
    parser.add_argument("--max-attack-refs", type=int, default=20000, help="Maximum attack reference rows")
    args = parser.parse_args()

    result = APITrainingRunner(
        processed_data_dir=args.processed_dir,
        experiment_dir=args.experiment_dir,
        dimension=args.dimension,
        max_benign_refs=args.max_benign_refs,
        max_attack_refs=args.max_attack_refs,
    ).run()

    print("API RETRIEVAL TRAIN/EVAL COMPLETED")
    print(f"Experiment dir: {result['experiment_dir']}")
    print(f"Selected threshold: {result['selected_threshold']:.4f}")
    print(f"Train F1: {result['train_metrics']['f1']:.4f}")
    print(f"Val F1: {result['val_metrics']['f1']:.4f}")


if __name__ == "__main__":
    main()
