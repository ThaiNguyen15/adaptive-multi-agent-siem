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
    parser.add_argument("--optimizer", choices=["adam", "sgd"], default="adam", help="Optimizer")
    parser.add_argument("--batch-size", type=int, default=2048, help="Mini-batch size; <=0 uses full batch")
    parser.add_argument(
        "--class-weight",
        choices=["balanced", "none"],
        default="balanced",
        help="Class weighting policy for imbalanced data",
    )
    parser.add_argument(
        "--positive-class-weight",
        type=float,
        default=0.0,
        help="Explicit positive-class weight; overrides --class-weight when >0",
    )
    parser.add_argument(
        "--disable-early-stopping",
        action="store_true",
        help="Run all epochs instead of stopping on validation loss plateau",
    )
    parser.add_argument("--early-stopping-patience", type=int, default=25, help="Validation-loss patience")
    parser.add_argument("--early-stopping-min-delta", type=float, default=1e-5, help="Minimum validation-loss improvement")
    parser.add_argument("--max-rows-per-split", type=int, default=0, help="Optional smoke-test row cap per split")
    parser.add_argument("--ablation-mode", choices=["off", "per_block"], default="off", help="Feature ablation mode")
    args = parser.parse_args()

    config = ExperimentConfig(
        processed_data_dir=args.processed_dir,
        experiment_dir=args.experiment_dir,
        label_col=args.label_col,
        feature_blocks=args.feature_blocks,
        learning_rate=args.learning_rate,
        max_epochs=args.max_epochs,
        l2_reg=args.l2_reg,
        optimizer=args.optimizer,
        batch_size=args.batch_size,
        class_weight=args.class_weight,
        positive_class_weight=args.positive_class_weight,
        early_stopping=not args.disable_early_stopping,
        early_stopping_patience=args.early_stopping_patience,
        early_stopping_min_delta=args.early_stopping_min_delta,
        max_rows_per_split=args.max_rows_per_split,
        ablation_mode=args.ablation_mode,
    )
    result = TrainingRunner(config).run()

    print("TRAINING COMPLETED")
    print(f"Experiment dir: {result['experiment_dir']}")
    print(f"Feature count: {result['feature_count']}")
    print(f"Train F1: {result['train_metrics']['f1']:.4f}")
    print(f"Val F1: {result['val_metrics']['f1']:.4f}")


if __name__ == "__main__":
    main()
