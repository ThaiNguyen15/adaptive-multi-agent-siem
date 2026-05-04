"""
Score a processed API split with a trained retrieval model.

Useful for labeled test splits and unlabeled challenge validation:
    python -m src.scripts.score_api_retrieval \
        --processed-dir data/processed/api_traffic \
        --experiment-dir experiments/api_traffic_retrieval \
        --split unlabeled_validation
"""

import argparse
from pathlib import Path

from src.domains.api_traffic.evaluation import APIEvaluationRunner


def main() -> None:
    """Parse args and score one API split."""
    parser = argparse.ArgumentParser(description="Score API split with retrieval model")
    parser.add_argument("--processed-dir", type=Path, required=True, help="Processed API traffic directory")
    parser.add_argument("--experiment-dir", type=Path, required=True, help="Experiment artifact directory")
    parser.add_argument("--split", type=str, required=True, help="Split name under processed-dir/splits")
    parser.add_argument(
        "--no-hints",
        action="store_true",
        help="Zero semantic tokens and static attack flags before scoring",
    )
    args = parser.parse_args()

    runner = APIEvaluationRunner(
        processed_data_dir=args.processed_dir,
        experiment_dir=args.experiment_dir,
    )
    metrics = runner.evaluate_split_without_hints(args.split) if args.no_hints else runner.evaluate_split(args.split)
    if metrics.get("labeled", True):
        print(f"F1: {metrics['f1']:.4f}")

    print("API RETRIEVAL SCORING COMPLETED")
    print(f"Rows: {metrics['num_rows']}")
    print(f"Predictions: {args.experiment_dir / 'predictions' / f'{args.split}.csv'}")


if __name__ == "__main__":
    main()
