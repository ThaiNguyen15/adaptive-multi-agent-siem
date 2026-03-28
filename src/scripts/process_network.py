"""
Script to process CICIDS 2018 network domain data.

Usage:
    python -m src.scripts.process_network --raw-dir data/raw/cicflowmeter --output-dir data/processed/cicids2018
"""

import argparse
from pathlib import Path
from src.domains.cicids2018 import CICIDS2018Config, CICIDS2018Pipeline


def main():
    """Run CICIDS2018 pipeline from command line."""
    parser = argparse.ArgumentParser(description="Process CICIDS 2018 network domain data")
    parser.add_argument(
        "--raw-dir",
        type=Path,
        required=True,
        help="Directory containing raw network flow CSV files",
    )
    parser.add_argument(
        "--output-dir", type=Path, required=True, help="Output directory for processed data"
    )
    parser.add_argument(
        "--num-shards", type=int, default=512, help="Number of shards (default: 512)"
    )
    parser.add_argument(
        "--batch-size", type=int, default=50000, help="Batch size for processing (default: 50000)"
    )
    parser.add_argument(
        "--label-mode",
        type=str,
        default="binary",
        choices=["binary", "family", "raw"],
        help="Primary downstream label view metadata",
    )

    args = parser.parse_args()

    # Create config
    config = CICIDS2018Config(
        raw_data_dir=args.raw_dir,
        processed_data_dir=args.output_dir,
        num_shards=args.num_shards,
        batch_size=args.batch_size,
        label_mode=args.label_mode,
    )

    # Run pipeline
    pipeline = CICIDS2018Pipeline(config)
    pipeline.run(args.raw_dir)


if __name__ == "__main__":
    main()
