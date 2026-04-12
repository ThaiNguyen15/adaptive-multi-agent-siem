"""
API traffic pipeline orchestrator.
"""

from pathlib import Path

import pandas as pd

from src.core.sharding import HashSharding
from src.core.splitter import TimeBasedSplitter

from .config import APITrafficConfig
from .feature_builder import APITrafficFeatureBuilder
from .normalizer import APITrafficNormalizer


class APITrafficPipeline:
    """End-to-end pipeline for API traffic data processing."""

    def __init__(self, config: APITrafficConfig):
        self.config = config
        self.config.ensure_dirs()

        self.normalizer = APITrafficNormalizer(config)
        self.sharding = HashSharding(num_shards=config.num_shards, shard_key=config.shard_key)
        self.feature_builder = APITrafficFeatureBuilder(config)
        self.splitter = TimeBasedSplitter(
            train_ratio=config.train_ratio,
            val_ratio=config.val_ratio,
            test_ratio=config.test_ratio,
            timestamp_col="event_timestamp",
        )

    def step1_normalize(self, input_dir: Path) -> pd.DataFrame:
        """Step 1: Normalize raw JSON API events."""
        print("[Step 1] Normalizing raw API traffic...")

        normalized_df = self.normalizer.process_batch(input_dir)

        normalized_path = self.config.processed_data_dir / "normalized.parquet"
        normalized_df.to_parquet(normalized_path, index=False, compression="snappy")
        print(f"  Saved normalized data: {normalized_path}")

        return normalized_df

    def step2_shard(self, df: pd.DataFrame) -> None:
        """Step 2: Shard by event_id for scalable batch processing."""
        print("[Step 2] Sharding normalized API events...")

        shards_dir = self.config.get_shards_dir()
        self.sharding.save_shards(df, shards_dir, format="parquet")
        print(f"  Saved shards to: {shards_dir}")

    def step3_build_features(self) -> None:
        """Step 3: Build event-level API features."""
        print("[Step 3] Building API traffic features...")

        shards_dir = self.config.get_shards_dir()
        features_dir = self.config.get_features_dir()

        self.feature_builder.process_all_shards(shards_dir, features_dir)
        print(f"  Saved features to: {features_dir}")

    def step4_split(self) -> None:
        """Step 4: Create train/val/test splits using request timestamps."""
        print("[Step 4] Creating train/val/test splits...")

        features_dir = self.config.get_features_dir()
        splits_dir = self.config.get_splits_dir()

        self.splitter.split_shards(features_dir, splits_dir)
        print(f"  Saved splits to: {splits_dir}")

    def run(self, input_dir: Path) -> None:
        """Run the full API traffic pipeline."""
        print("\n" + "=" * 60)
        print("API TRAFFIC PROCESSING PIPELINE")
        print("=" * 60 + "\n")

        normalized_df = self.step1_normalize(input_dir)
        print(f"  → {len(normalized_df)} records\n")

        self.step2_shard(normalized_df)
        print()

        self.step3_build_features()
        print()

        self.step4_split()
        print()

        print("=" * 60)
        print("PIPELINE COMPLETED SUCCESSFULLY")
        print("=" * 60)


__all__ = ["APITrafficPipeline"]
