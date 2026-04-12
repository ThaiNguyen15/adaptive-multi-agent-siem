"""
CICIDS 2018 network-flow pipeline orchestrator.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from src.core.sharding import HashSharding
from src.core.splitter import TimeBasedSplitter

from .config import CICIDS2018Config
from .feature_builder import CICIDS2018FeatureBuilder
from .normalizer import CICIDS2018Normalizer
from .profiling import CICIDS2018DatasetProfiler


class CICIDS2018Pipeline:
    """End-to-end pipeline for CICFlowMeter network-flow processing."""

    def __init__(self, config: CICIDS2018Config):
        self.config = config
        self.config.ensure_dirs()

        self.normalizer = CICIDS2018Normalizer(config)
        self.profiler = CICIDS2018DatasetProfiler()
        self.sharding = HashSharding(num_shards=config.num_shards, shard_key=config.shard_key)
        self.feature_builder = CICIDS2018FeatureBuilder(config)
        self.splitter = TimeBasedSplitter(
            train_ratio=config.train_ratio,
            val_ratio=config.val_ratio,
            test_ratio=config.test_ratio,
            timestamp_col="timestamp",
        )

    def step1_normalize(self, input_dir: Path) -> pd.DataFrame:
        """Step 1: Normalize raw network traffic logs."""
        print("[Step 1] Normalizing raw network flows...")

        normalized_df = self.normalizer.process_batch(input_dir)

        normalized_path = self.config.processed_data_dir / "normalized.parquet"
        normalized_df.to_parquet(normalized_path, index=False, compression="snappy")
        print(f"  Saved normalized data: {normalized_path}")

        return normalized_df

    def step2_profile(self, normalized_df: pd.DataFrame) -> None:
        """Step 2: Profile normalized numeric fields and save transform guidance."""
        print("[Step 2] Profiling field ranges and scaling recommendations...")

        profile = self.profiler.profile_dataframe(normalized_df)
        profile_path = self.config.processed_data_dir / "processing_profile.json"
        with open(profile_path, "w", encoding="utf-8") as handle:
            json.dump(profile, handle, indent=2)

        print(f"  Saved processing profile: {profile_path}")

    def step3_shard(self, df: pd.DataFrame) -> None:
        """Step 3: Shard by destination port."""
        print("[Step 3] Sharding by destination port...")

        shards_dir = self.config.get_shards_dir()
        self.sharding.save_shards(df, shards_dir, format="parquet")
        print(f"  Saved shards to: {shards_dir}")

    def step4_build_features(self) -> None:
        """Step 4: Build derived network-flow features for each shard."""
        print("[Step 4] Building network-flow features...")

        shards_dir = self.config.get_shards_dir()
        features_dir = self.config.get_features_dir()

        self.feature_builder.process_all_shards(shards_dir, features_dir)
        self._save_feature_manifest()
        print(f"  Saved features to: {features_dir}")

    def step5_split(self) -> None:
        """Step 5: Split into train/val/test."""
        print("[Step 5] Creating train/val/test splits...")

        features_dir = self.config.get_features_dir()
        splits_dir = self.config.get_splits_dir()

        self.splitter.split_shards(features_dir, splits_dir)
        print(f"  Saved splits to: {splits_dir}")

    def _save_run_metadata(self) -> None:
        """Persist the processing config."""
        self.config.save(self.config.processed_data_dir / "config.json")

    def _save_feature_manifest(self) -> None:
        """Persist grouped feature metadata for downstream training."""
        manifest_path = self.config.processed_data_dir / "feature_manifest.json"
        manifest = {
            "domain": self.config.domain_name,
            "feature_windows": self.config.feature_windows,
            "feature_blocks": self.feature_builder.get_feature_blocks(),
            "token_columns": ["protocol_token", "port_token", "transport_token"],
            "notes": {
                "processing_profile_emitted": True,
                "transport_tokens_optional_for_training": True,
                "raw_transport_integers_have_shortcut_risk": True,
            },
        }
        with open(manifest_path, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2)

    def run(self, input_dir: Path) -> None:
        """Run full pipeline."""
        print("\n" + "=" * 60)
        print("CICIDS 2018 NETWORK-FLOW PROCESSING PIPELINE")
        print("=" * 60 + "\n")

        self._save_run_metadata()

        normalized_df = self.step1_normalize(input_dir)
        print(f"  → {len(normalized_df)} records\n")

        self.step2_profile(normalized_df)
        print()

        self.step3_shard(normalized_df)
        print()

        self.step4_build_features()
        print()

        self.step5_split()
        print()

        print("=" * 60)
        print("PIPELINE COMPLETED SUCCESSFULLY")
        print("=" * 60)


__all__ = ["CICIDS2018Pipeline"]
