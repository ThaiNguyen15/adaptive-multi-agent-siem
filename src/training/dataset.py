"""
Dataset loading utilities for training/evaluation stages.
"""

from pathlib import Path
from typing import Dict, List, Tuple
import json

import numpy as np
import pandas as pd

from .config import ExperimentConfig


class TabularDatasetLoader:
    """Load processed parquet splits and resolve model feature columns."""

    DEFAULT_METADATA_COLUMNS = {
        "user_id",
        "login_timestamp",
        "timestamp",
        "event_id",
        "source_file",
        "row_index",
        "ip",
        "country",
        "region",
        "city",
        "device",
        "ip_token",
        "device_token",
        "geo_token",
        "context_token",
    }

    def __init__(self, config: ExperimentConfig):
        """Initialize the loader."""
        self.config = config
        self._manifest = self._load_feature_manifest()

    def _load_feature_manifest(self) -> Dict:
        """Load the feature manifest if the processing pipeline emitted one."""
        manifest_path = self.config.processed_data_dir / "feature_manifest.json"
        if not manifest_path.exists():
            return {}

        with open(manifest_path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def load_split_df(self, split_name: str) -> pd.DataFrame:
        """Load all shards for a named split."""
        split_dir = self.config.processed_data_dir / "splits" / split_name
        shard_paths = sorted(split_dir.glob("shard_*.parquet"))
        if not shard_paths:
            raise FileNotFoundError(f"No parquet shards found in {split_dir}")

        frames = [pd.read_parquet(path) for path in shard_paths]
        df = pd.concat(frames, ignore_index=True)

        # A capped sample is useful for smoke-testing the modeling stack before full training.
        if self.config.max_rows_per_split and len(df) > self.config.max_rows_per_split:
            sort_columns = [column for column in ["login_timestamp", "timestamp"] if column in df.columns]
            if sort_columns:
                df = df.sort_values(sort_columns)
            df = df.head(self.config.max_rows_per_split)
            df = df.reset_index(drop=True)

        return df

    def resolve_feature_columns(self, df: pd.DataFrame) -> List[str]:
        """Resolve the model feature set from manifest blocks and dataframe schema."""
        selected_columns = []
        feature_blocks = self._manifest.get("feature_blocks", {})

        for block_name in self.config.feature_blocks:
            selected_columns.extend(feature_blocks.get(block_name, []))

        if self.config.include_columns:
            selected_columns.extend(self.config.include_columns)

        selected_columns = [column for column in dict.fromkeys(selected_columns) if column in df.columns]

        if not selected_columns:
            # Fallback for domains that do not expose feature manifests yet.
            selected_columns = [
                column
                for column in df.columns
                if column != self.config.label_col
                and column not in self.DEFAULT_METADATA_COLUMNS
                and pd.api.types.is_numeric_dtype(df[column])
            ]

        excluded = set(self.config.exclude_columns)
        excluded.add(self.config.label_col)

        resolved_columns = []
        for column in selected_columns:
            if column in excluded:
                continue
            if not pd.api.types.is_numeric_dtype(df[column]):
                continue
            resolved_columns.append(column)

        if not resolved_columns:
            raise ValueError("No numeric feature columns resolved for the experiment")

        return resolved_columns

    def build_matrix(
        self, df: pd.DataFrame, feature_columns: List[str]
    ) -> Tuple[np.ndarray, np.ndarray, pd.DataFrame]:
        """Extract model matrix, binary labels, and lightweight metadata."""
        if self.config.label_col not in df.columns:
            raise ValueError(f"Label column '{self.config.label_col}' not found in dataset")

        y = pd.to_numeric(df[self.config.label_col], errors="coerce")
        if y.isna().any():
            raise ValueError(f"Label column '{self.config.label_col}' contains non-numeric values")

        unique_labels = set(y.astype(int).unique().tolist())
        if not unique_labels.issubset({0, 1}):
            raise ValueError(
                f"Only binary labels are supported right now; found values: {sorted(unique_labels)}"
            )

        X = (
            df[feature_columns]
            .apply(pd.to_numeric, errors="coerce")
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0.0)
            .astype(float)
            .to_numpy()
        )

        metadata_columns = [
            column for column in self.DEFAULT_METADATA_COLUMNS if column in df.columns
        ]
        metadata_df = df[metadata_columns].copy() if metadata_columns else pd.DataFrame(index=df.index)

        return X, y.astype(int).to_numpy(), metadata_df
