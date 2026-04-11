"""
Script to process login domain data.

Usage:
    python -m src.scripts.process_login --raw-dir data/raw/login --output-dir data/processed/login
"""

import argparse
from pathlib import Path

from src.domains.login import LoginConfig, LoginPipeline


def main():
    """Run login pipeline from command line."""
    parser = argparse.ArgumentParser(description="Process login domain data")
    parser.add_argument(
        "--raw-dir", type=Path, required=True, help="Directory containing raw login CSV files"
    )
    parser.add_argument(
        "--output-dir", type=Path, required=True, help="Output directory for processed data"
    )
    parser.add_argument(
        "--num-shards", type=int, default=256, help="Number of shards (default: 256)"
    )
    parser.add_argument(
        "--batch-size", type=int, default=10000, help="Batch size for processing (default: 10000)"
    )
    parser.add_argument(
        "--feature-windows",
        type=int,
        nargs="+",
        default=[1, 7, 30],
        help="Rolling history windows in days (default: 1 7 30)",
    )

    args = parser.parse_args()

    # Create config
    config = LoginConfig(
        raw_data_dir=args.raw_dir,
        processed_data_dir=args.output_dir,
        num_shards=args.num_shards,
        batch_size=args.batch_size,
        feature_windows=args.feature_windows,
    )

    # Run pipeline
    pipeline = LoginPipeline(config)
    pipeline.run(args.raw_dir)


if __name__ == "__main__":
    main()
