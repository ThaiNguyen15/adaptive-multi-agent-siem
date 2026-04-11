"""
Run final holdout testing for the login domain.
"""

import argparse
from pathlib import Path

from src.domains.login import LoginExperimentConfig, LoginTestRunner


def main() -> None:
    """Parse args and run login test."""
    parser = argparse.ArgumentParser(description="Run login-domain holdout testing")
    parser.add_argument("--processed-dir", type=Path, required=True, help="Processed login directory")
    parser.add_argument("--experiment-dir", type=Path, required=True, help="Experiment artifact directory")
    args = parser.parse_args()

    config = LoginExperimentConfig(
        processed_data_dir=args.processed_dir,
        experiment_dir=args.experiment_dir,
    )
    metrics = LoginTestRunner(config).run()

    print("LOGIN TEST COMPLETED")
    print(f"Alert rate: {metrics['risk_summary']['alert_rate']:.4f}")
    print(f"P95 risk: {metrics['risk_summary']['p95_risk_score']:.4f}")
    if metrics["reference_metrics"]:
        print(f"Reference F1: {metrics['reference_metrics']['f1']:.4f}")


if __name__ == "__main__":
    main()
