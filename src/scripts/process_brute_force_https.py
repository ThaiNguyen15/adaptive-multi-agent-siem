"""
Script to process the CESNET HTTPS brute-force dataset.
"""

import argparse
from pathlib import Path

from src.domains.brute_force_https import BruteForceHTTPSConfig, BruteForceHTTPSPipeline


def main():
    """Run brute-force HTTPS pipeline from command line."""
    parser = argparse.ArgumentParser(description="Process HTTPS brute-force dataset")
    parser.add_argument(
        "--raw-dir",
        type=Path,
        required=True,
        help="Directory containing flows.csv / aggregated_flows.csv / samples.csv",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Output directory for processed data",
    )
    parser.add_argument(
        "--input-view",
        type=str,
        default="aggregated_flows",
        choices=["flows", "aggregated_flows", "samples"],
        help="Which source file to process",
    )
    parser.add_argument(
        "--num-shards",
        type=int,
        default=128,
        help="Number of shards (default: 128)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=25000,
        help="Batch size for processing metadata (default: 25000)",
    )
    parser.add_argument(
        "--label-mode",
        type=str,
        default="binary",
        choices=["binary", "scenario", "tool", "app", "raw"],
        help="Primary downstream label view",
    )

    args = parser.parse_args()

    config = BruteForceHTTPSConfig(
        raw_data_dir=args.raw_dir,
        processed_data_dir=args.output_dir,
        input_view=args.input_view,
        num_shards=args.num_shards,
        batch_size=args.batch_size,
        label_mode=args.label_mode,
    )

    pipeline = BruteForceHTTPSPipeline(config)
    pipeline.run(args.raw_dir)


if __name__ == "__main__":
    main()
