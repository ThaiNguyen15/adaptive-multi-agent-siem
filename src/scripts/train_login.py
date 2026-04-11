"""
Train a login-domain baseline experiment.
"""

import argparse
from pathlib import Path

from src.domains.login import LoginExperimentConfig, LoginTrainingRunner


def main() -> None:
    """Parse args and run login training."""
    parser = argparse.ArgumentParser(description="Train the login-domain baseline model")
    parser.add_argument("--processed-dir", type=Path, required=True, help="Processed login directory")
    parser.add_argument("--experiment-dir", type=Path, required=True, help="Output experiment directory")
    parser.add_argument(
        "--feature-blocks",
        nargs="+",
        default=["temporal", "novelty", "continuity", "familiarity", "outcome_pressure", "diversity"],
        help="Behavior blocks to include in block-risk fusion",
    )
    parser.add_argument(
        "--max-rows-per-split",
        type=int,
        default=0,
        help="Cap rows per split for quick smoke tests; 0 means use the full split",
    )
    parser.add_argument(
        "--alert-rate-target",
        type=float,
        default=0.05,
        help="Target alert fraction used to calibrate the final threshold on the validation split",
    )
    args = parser.parse_args()

    config = LoginExperimentConfig(
        processed_data_dir=args.processed_dir,
        experiment_dir=args.experiment_dir,
        feature_blocks=args.feature_blocks,
        max_rows_per_split=args.max_rows_per_split,
        alert_rate_target=args.alert_rate_target,
    )
    result = LoginTrainingRunner(config).run()

    print("LOGIN TRAINING COMPLETED")
    print(f"Experiment dir: {result['experiment_dir']}")
    print(f"Feature count: {result['feature_count']}")
    print(f"Selected threshold: {result['selected_threshold']:.2f}")
    print(f"Train alert rate: {result['train_metrics']['risk_summary']['alert_rate']:.4f}")
    print(f"Val alert rate: {result['val_metrics']['risk_summary']['alert_rate']:.4f}")


if __name__ == "__main__":
    main()
