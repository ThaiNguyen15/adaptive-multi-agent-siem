"""
HTTPS brute-force dataset pipeline orchestrator.
"""

from pathlib import Path

import pandas as pd

from src.core.sharding import HashSharding
from src.core.splitter import TimeBasedSplitter
from .config import BruteForceHTTPSConfig
from .feature_builder import BruteForceHTTPSFeatureBuilder
from .normalizer import BruteForceHTTPSNormalizer


class BruteForceHTTPSPipeline:
    """End-to-end pipeline for the CESNET HTTPS brute-force dataset."""

    def __init__(self, config: BruteForceHTTPSConfig):
        self.config = config
        self.config.ensure_dirs()

        self.normalizer = BruteForceHTTPSNormalizer(config)
        self.sharding = HashSharding(num_shards=config.num_shards, shard_key=config.shard_key)
        self.feature_builder = BruteForceHTTPSFeatureBuilder(config)
        self.splitter = TimeBasedSplitter(
            train_ratio=config.train_ratio,
            val_ratio=config.val_ratio,
            test_ratio=config.test_ratio,
            timestamp_col=config.timestamp_col,
        )

    def step1_normalize(self, input_dir: Path) -> pd.DataFrame:
        print(f"[Step 1] Normalizing HTTPS brute-force data ({self.config.input_view})...")
        normalized_df = self.normalizer.process_batch(input_dir)

        normalized_path = self.config.processed_data_dir / "normalized.parquet"
        normalized_df.to_parquet(normalized_path, index=False, compression="snappy")
        print(f"  Saved normalized data: {normalized_path}")
        return normalized_df

    def step2_shard(self, df: pd.DataFrame) -> None:
        print("[Step 2] Sharding by service_key...")
        shards_dir = self.config.get_shards_dir()
        self.sharding.save_shards(df, shards_dir, format="parquet")
        print(f"  Saved shards to: {shards_dir}")

    def step3_build_features(self) -> None:
        print("[Step 3] Building HTTPS brute-force features...")
        shards_dir = self.config.get_shards_dir()
        features_dir = self.config.get_features_dir()
        self.feature_builder.process_all_shards(shards_dir, features_dir)
        print(f"  Saved features to: {features_dir}")

    def step4_split(self) -> None:
        print("[Step 4] Creating train/val/test splits...")
        features_dir = self.config.get_features_dir()
        splits_dir = self.config.get_splits_dir()
        self.splitter.split_shards(features_dir, splits_dir)
        print(f"  Saved splits to: {splits_dir}")

    def run(self, input_dir: Path) -> None:
        print("\n" + "=" * 60)
        print("HTTPS BRUTE-FORCE PROCESSING PIPELINE")
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
