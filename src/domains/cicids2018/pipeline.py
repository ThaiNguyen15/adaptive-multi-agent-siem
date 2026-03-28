"""
CICIDS 2018 Network domain pipeline orchestrator.

Example showing how to adapt the pipeline pattern for a different domain.
Follows the same 4-step pattern as login domain.
"""

from pathlib import Path
import pandas as pd
from src.core.sharding import HashSharding
from src.core.splitter import TimeBasedSplitter
from .config import CICIDS2018Config
from .normalizer import CICIDS2018Normalizer
from .feature_builder import CICIDS2018FeatureBuilder


class CICIDS2018Pipeline:
    """End-to-end pipeline for CICIDS2018 network data processing."""

    def __init__(self, config: CICIDS2018Config):
        """Initialize pipeline.

        Args:
            config: CICIDS2018Config instance
        """
        self.config = config
        self.config.ensure_dirs()

        self.normalizer = CICIDS2018Normalizer(config)
        self.sharding = HashSharding(
            num_shards=config.num_shards, shard_key=config.shard_key  # src_ip for network
        )
        self.feature_builder = CICIDS2018FeatureBuilder(config)
        self.splitter = TimeBasedSplitter(
            train_ratio=config.train_ratio,
            val_ratio=config.val_ratio,
            test_ratio=config.test_ratio,
            timestamp_col="timestamp",
        )

    def step1_normalize(self, input_dir: Path) -> pd.DataFrame:
        """Step 1: Normalize raw network traffic logs.

        Args:
            input_dir: Directory containing raw CSV files

        Returns:
            Normalized dataframe
        """
        print("[Step 1] Normalizing raw network flows...")

        normalized_df = self.normalizer.process_batch(input_dir)

        # Save normalized data
        normalized_path = self.config.processed_data_dir / "normalized.parquet"
        normalized_df.to_parquet(normalized_path, index=False, compression="snappy")
        print(f"  Saved normalized data: {normalized_path}")

        return normalized_df

    def step2_shard(self, df: pd.DataFrame) -> None:
        """Step 2: Shard by source IP.

        Args:
            df: Normalized dataframe
        """
        print("[Step 2] Sharding by source IP...")

        shards_dir = self.config.get_shards_dir()
        self.sharding.save_shards(df, shards_dir, format="parquet")
        print(f"  Saved shards to: {shards_dir}")

    def step3_build_features(self) -> None:
        """Step 3: Build network features for each shard."""
        print("[Step 3] Building network features...")

        shards_dir = self.config.get_shards_dir()
        features_dir = self.config.get_features_dir()

        self.feature_builder.process_all_shards(shards_dir, features_dir)
        print(f"  Saved features to: {features_dir}")

    def step4_split(self) -> None:
        """Step 4: Split into train/val/test."""
        print("[Step 4] Creating train/val/test splits...")

        features_dir = self.config.get_features_dir()
        splits_dir = self.config.get_splits_dir()

        self.splitter.split_shards(features_dir, splits_dir)
        print(f"  Saved splits to: {splits_dir}")

    def run(self, input_dir: Path) -> None:
        """Run full pipeline.

        Args:
            input_dir: Directory containing raw network data
        """
        print("\n" + "=" * 60)
        print("CICIDS 2018 NETWORK PROCESSING PIPELINE")
        print("=" * 60 + "\n")

        # Step 1: Normalize
        normalized_df = self.step1_normalize(input_dir)
        print(f"  → {len(normalized_df)} records\n")

        # Step 2: Shard
        self.step2_shard(normalized_df)
        print()

        # Step 3: Build features
        self.step3_build_features()
        print()

        # Step 4: Split
        self.step4_split()
        print()

        print("=" * 60)
        print("PIPELINE COMPLETED SUCCESSFULLY")
        print("=" * 60)
