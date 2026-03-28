"""
Script to process API traffic domain data.

Usage:
    python -m src.scripts.process_api_traffic \
        --raw-dir data/raw/Cisco_Ariel_Uni_API_security_challenge/Datasets \
        --output-dir data/processed/api_traffic
"""

import argparse
from pathlib import Path

from src.domains.api_traffic import APITrafficConfig, APITrafficPipeline


def main():
    """Run API traffic pipeline from command line."""
    parser = argparse.ArgumentParser(description="Process API traffic domain data")
    parser.add_argument(
        "--raw-dir",
        type=Path,
        required=True,
        help="Directory containing raw JSON or 7z API traffic files",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Output directory for processed data",
    )
    parser.add_argument(
        "--num-shards",
        type=int,
        default=256,
        help="Number of shards (default: 256)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=5000,
        help="Batch size for processing (default: 5000)",
    )
    parser.add_argument(
        "--task-type",
        type=str,
        default="binary",
        choices=["binary", "attack_type"],
        help="Primary downstream task metadata",
    )
    parser.add_argument(
        "--feature-mode",
        type=str,
        default="request_only",
        choices=["request_only", "response_only", "combined"],
        help="Choose request-centric, response-only, or combined feature views",
    )
    parser.add_argument(
        "--text-mode",
        type=str,
        default="hybrid",
        choices=["lexical", "tokenized", "hybrid"],
        help="Choose lexical features, token statistics, or both",
    )

    args = parser.parse_args()

    config = APITrafficConfig(
        raw_data_dir=args.raw_dir,
        processed_data_dir=args.output_dir,
        num_shards=args.num_shards,
        batch_size=args.batch_size,
        task_type=args.task_type,
        feature_mode=args.feature_mode,
        text_mode=args.text_mode,
    )

    pipeline = APITrafficPipeline(config)
    pipeline.run(args.raw_dir)


if __name__ == "__main__":
    main()
