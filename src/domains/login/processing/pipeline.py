"""
Login domain pipeline orchestrator.

Orchestrates end-to-end processing:
1. Normalize raw logs
2. Shard by user_id
3. Build features for each shard
4. Split into train/val/test
"""

import json
from pathlib import Path

import pandas as pd

from src.core.sharding import HashSharding
from src.core.splitter import TimeBasedSplitter

from .config import LoginConfig
from .feature_builder import LoginFeatureBuilder
from .normalizer import LoginNormalizer


class LoginPipeline:
    """End-to-end pipeline for login data processing."""

    def __init__(self, config: LoginConfig):
        """Initialize pipeline.

        Args:
            config: LoginConfig instance
        """
        self.config = config
        self.config.ensure_dirs()

        self.normalizer = LoginNormalizer(config)
        self.sharding = HashSharding(num_shards=config.num_shards, shard_key=config.shard_key)
        self.feature_builder = LoginFeatureBuilder(config)
        self.splitter = TimeBasedSplitter(
            train_ratio=config.train_ratio,
            val_ratio=config.val_ratio,
            test_ratio=config.test_ratio,
            timestamp_col="login_timestamp",
        )

    def _merge_shard_parts(self, shards_dir: Path) -> None:
        """Merge chunked shard parts into final shard parquet files."""
        for shard_id in range(self.config.num_shards):
            part_paths = sorted(shards_dir.glob(f"shard_{shard_id:03d}_part_*.parquet"))
            if not part_paths:
                continue

            shard_df = pd.concat([pd.read_parquet(path) for path in part_paths], ignore_index=True)
            shard_df = shard_df.sort_values(["user_id", "login_timestamp"]).reset_index(drop=True)
            final_path = shards_dir / f"shard_{shard_id:03d}.parquet"
            shard_df.to_parquet(final_path, index=False, compression="snappy")

            for part_path in part_paths:
                part_path.unlink()

    def step1_normalize_and_shard(self, input_dir: Path) -> int:
        """Step 1+2: Stream raw files, normalize them, and shard directly to disk."""
        print("[Step 1] Normalizing raw logs...")
        print("[Step 2] Sharding by user_id...")

        input_dir = Path(input_dir)
        raw_files = sorted(input_dir.glob("*.csv")) + sorted(input_dir.glob("*.parquet"))
        if not raw_files:
            raise FileNotFoundError(f"No raw CSV/parquet files found in {input_dir}")

        shards_dir = self.config.get_shards_dir()
        normalized_dir = self.config.processed_data_dir / "normalized"
        normalized_dir.mkdir(parents=True, exist_ok=True)

        total_rows = 0
        chunk_id = 0

        for raw_file in raw_files:
            for normalized_chunk in self.normalizer.iter_normalized_chunks(
                raw_file, chunk_size=self.config.batch_size
            ):
                if normalized_chunk.empty:
                    continue

                total_rows += len(normalized_chunk)
                normalized_chunk.to_parquet(
                    normalized_dir / f"normalized_part_{chunk_id:06d}.parquet",
                    index=False,
                    compression="snappy",
                )
                self.sharding.append_partitioned_shards(
                    normalized_chunk,
                    shards_dir,
                    chunk_id=chunk_id,
                    format="parquet",
                )
                chunk_id += 1

        self._merge_shard_parts(shards_dir)
        print(f"  Saved normalized chunks to: {normalized_dir}")
        print(f"  Saved shards to: {shards_dir}")
        return total_rows

    def step3_build_features(self) -> None:
        """Step 3: Build features for each shard."""
        print("[Step 3] Building features...")

        shards_dir = self.config.get_shards_dir()
        features_dir = self.config.get_features_dir()

        self.feature_builder.process_all_shards(shards_dir, features_dir)
        self._save_feature_manifest()
        print(f"  Saved features to: {features_dir}")

    def step4_split(self) -> None:
        """Step 4: Split into train/val/test."""
        print("[Step 4] Creating train/val/test splits...")

        features_dir = self.config.get_features_dir()
        splits_dir = self.config.get_splits_dir()

        self.splitter.split_shards(features_dir, splits_dir)
        print(f"  Saved splits to: {splits_dir}")

    def _save_run_metadata(self) -> None:
        """Persist config and feature-group metadata for downstream training."""
        self.config.save(self.config.processed_data_dir / "config.json")

    def _save_feature_manifest(self) -> None:
        """Save feature groups so downstream code can train per-head models easily."""
        manifest_path = self.config.processed_data_dir / "feature_manifest.json"
        manifest = {
            "domain": self.config.domain_name,
            "feature_windows": self.config.feature_windows,
            "feature_blocks": self.feature_builder.get_feature_blocks(),
            "token_columns": ["ip_token", "device_token", "geo_token", "context_token"],
            "notes": {
                "strictly_past_only": True,
                "token_block_optional_for_training": True,
                "raw_context_kept_for_audit": True,
            },
        }
        with open(manifest_path, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2)

    def run(self, input_dir: Path) -> None:
        """Run full pipeline.

        Args:
            input_dir: Directory containing raw data
        """
        print("\n" + "=" * 60)
        print("LOGIN PROCESSING PIPELINE")
        print("=" * 60 + "\n")

        self._save_run_metadata()

        # Step 1 + 2: Normalize and shard in a streaming-friendly way.
        total_rows = self.step1_normalize_and_shard(input_dir)
        print(f"  → {total_rows} records\n")
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
