"""
Script to process API traffic domain data.

Usage:
    python -m src.scripts.process_api_traffic \
        --raw-dir data/raw/Cisco_Ariel_Uni_API_security_challenge/Datasets \
        --output-dir data/processed/api_traffic

    python -m src.scripts.process_api_traffic \
        --raw-file data/raw/Cisco_Ariel_Uni_API_security_challenge/Datasets/dataset_1_train.7z \
        --output-dir data/processed/api_traffic_d1_train
"""

import argparse
from pathlib import Path

from src.domains.api_traffic import APITrafficConfig, APITrafficPipeline


def main():
    """Run API traffic pipeline from command line."""
    parser = argparse.ArgumentParser(description="Process API traffic domain data")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--raw-dir",
        type=Path,
        help="Directory containing raw JSON or 7z API traffic files",
    )
    input_group.add_argument(
        "--raw-file",
        type=Path,
        help="Single raw JSON or 7z API traffic file",
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
    parser.add_argument(
        "--static-view",
        type=str,
        default="request_response",
        choices=["request_only", "request_response"],
        help="Choose static training split view: request_only or request_response",
    )

    args = parser.parse_args()
    input_path = args.raw_file or args.raw_dir
    raw_data_dir = input_path.parent if input_path.is_file() else input_path

    config = APITrafficConfig(
        raw_data_dir=raw_data_dir,
        processed_data_dir=args.output_dir,
        num_shards=args.num_shards,
        batch_size=args.batch_size,
        task_type=args.task_type,
        feature_mode=args.feature_mode,
        text_mode=args.text_mode,
        static_view=args.static_view,
    )

    pipeline = APITrafficPipeline(config)
    pipeline.run(input_path)


if __name__ == "__main__":
    main()
