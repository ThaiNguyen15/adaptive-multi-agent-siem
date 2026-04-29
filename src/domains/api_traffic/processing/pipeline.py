"""
API traffic pipeline orchestrator.
"""

import json
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
        self._save_feature_manifest()
        print(f"  Saved features to: {features_dir}")

    def step4_split(self) -> None:
        """Step 4: Create train/val/test splits using request timestamps."""
        print("[Step 4] Creating train/val/test splits...")

        features_dir = self.config.get_features_dir()
        splits_dir = self.config.get_splits_dir()

        self._split_labeled_and_unlabeled(features_dir, splits_dir)
        print(f"  Saved splits to: {splits_dir}")

    def _split_labeled_and_unlabeled(self, features_dir: Path, splits_dir: Path) -> None:
        """Create supervised splits from labeled rows and preserve unlabeled rows for inference."""
        labeled_features_dir = self.config.processed_data_dir / "features_labeled"
        static_features_dir = self.config.processed_data_dir / "features_static"
        unlabeled_dir = splits_dir / "unlabeled_validation"
        labeled_features_dir.mkdir(parents=True, exist_ok=True)
        static_features_dir.mkdir(parents=True, exist_ok=True)
        unlabeled_dir.mkdir(parents=True, exist_ok=True)

        for shard_path in sorted(features_dir.glob("shard_*.parquet")):
            shard_df = pd.read_parquet(shard_path)
            label_known = pd.to_numeric(shard_df.get("label_known", 1), errors="coerce").fillna(0)

            labeled_df = shard_df[label_known == 1].copy()
            if not labeled_df.empty:
                labeled_df.to_parquet(
                    labeled_features_dir / shard_path.name,
                    index=False,
                    compression="snappy",
                )

            unlabeled_df = shard_df[label_known != 1].copy()
            if not unlabeled_df.empty:
                self._select_static_output_columns(unlabeled_df).to_parquet(
                    unlabeled_dir / shard_path.name,
                    index=False,
                    compression="snappy",
                )

            static_labeled_df = self._select_static_output_columns(labeled_df)
            if not static_labeled_df.empty:
                static_labeled_df.to_parquet(
                    static_features_dir / shard_path.name,
                    index=False,
                    compression="snappy",
                )

        self.splitter.split_shards(static_features_dir, splits_dir)

    def _select_static_output_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Keep only static structural columns plus static binary features and labels."""
        static_metadata_columns = [
            "event_id",
            "dataset_id",
            "data_split",
            "source_file",
            "record_index",
            "event_timestamp",
            "method",
            "host",
            "path_template",
            "query_key_set",
            "request_header_names",
            "content_type",
            "status",
            "status_code",
            "endpoint_key",
            "semantic_tokens",
            "parse_status",
            "label_known",
            "is_benign_reference",
            "label_binary",
            "attack_type",
        ]
        static_feature_columns = self.feature_builder.get_static_feature_list()
        selected_columns = [
            column for column in [*static_metadata_columns, *static_feature_columns] if column in df.columns
        ]
        return df[selected_columns].copy()

    def _save_run_metadata(self) -> None:
        """Persist the processing config."""
        self.config.save(self.config.processed_data_dir / "config.json")

    def _save_feature_manifest(self) -> None:
        """Persist grouped feature metadata for downstream training."""
        manifest_path = self.config.processed_data_dir / "feature_manifest.json"
        manifest = {
            "domain": self.config.domain_name,
            "dataset_name": self.config.dataset_name,
            "task_type": self.config.task_type,
            "feature_mode": self.config.feature_mode,
            "text_mode": self.config.text_mode,
            "static_view": self.config.static_view,
            "label_column": "label_binary",
            "feature_blocks": self.feature_builder.get_feature_blocks(),
            "default_training_blocks": ["static"],
            "text_columns": ["request_text", "response_text", "combined_text", "model_text"],
            "metadata_columns": [
                "event_id",
                "dataset_id",
                "data_split",
                "source_file",
                "record_index",
                "event_timestamp",
                "endpoint_key",
                "path_template",
                "attack_type",
            ],
            "notes": {
                "supervised_splits_use_label_known_rows_only": True,
                "splits_are_static_only": True,
                "full_dynamic_feature_artifacts_remain_in_features": True,
                "unlabeled_challenge_validation_written_to_splits_unlabeled_validation": True,
                "endpoint_context_is_first_class": True,
            },
        }
        with open(manifest_path, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2)

    def run(self, input_dir: Path) -> None:
        """Run the full API traffic pipeline."""
        print("\n" + "=" * 60)
        print("API TRAFFIC PROCESSING PIPELINE")
        print("=" * 60 + "\n")

        self._save_run_metadata()

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
