"""
Train a baseline tabular model from processed parquet splits.
"""

import argparse
from pathlib import Path

from src.training import ExperimentConfig, TrainingRunner


def main() -> None:
    """Parse args and launch training."""
    parser = argparse.ArgumentParser(description="Train a baseline tabular experiment")
    parser.add_argument("--processed-dir", type=Path, required=True, help="Processed domain directory")
    parser.add_argument("--experiment-dir", type=Path, required=True, help="Output directory for model artifacts")
    parser.add_argument("--label-col", type=str, required=True, help="Binary label column")
    parser.add_argument(
        "--feature-blocks",
        nargs="+",
        default=["temporal", "novelty", "continuity", "familiarity", "outcome_pressure", "diversity"],
        help="Feature blocks to use from feature_manifest.json",
    )
    parser.add_argument("--learning-rate", type=float, default=0.1, help="Gradient descent learning rate")
    parser.add_argument("--max-epochs", type=int, default=300, help="Training epochs")
    parser.add_argument("--l2-reg", type=float, default=1e-4, help="L2 regularization strength")
    args = parser.parse_args()

    config = ExperimentConfig(
        processed_data_dir=args.processed_dir,
        experiment_dir=args.experiment_dir,
        label_col=args.label_col,
        feature_blocks=args.feature_blocks,
        learning_rate=args.learning_rate,
        max_epochs=args.max_epochs,
        l2_reg=args.l2_reg,
    )
    result = TrainingRunner(config).run()

    print("TRAINING COMPLETED")
    print(f"Experiment dir: {result['experiment_dir']}")
    print(f"Feature count: {result['feature_count']}")
    print(f"Train F1: {result['train_metrics']['f1']:.4f}")
    print(f"Val F1: {result['val_metrics']['f1']:.4f}")


if __name__ == "__main__":
    main()
