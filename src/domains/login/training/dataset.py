"""
Dataset helpers for login-domain training.
"""

from pathlib import Path
import json

import pandas as pd

from .config import LoginExperimentConfig


class LoginDatasetLoader:
    """Load login splits and resolve block-oriented feature sets."""

    def __init__(self, config: LoginExperimentConfig):
        """Initialize loader state."""
        self.config = config
        self.manifest = self._load_manifest()

    def _load_manifest(self) -> dict:
        """Load the emitted feature manifest from processing."""
        manifest_path = self.config.processed_data_dir / "feature_manifest.json"
        with open(manifest_path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def load_split_df(self, split_name: str) -> pd.DataFrame:
        """Load a processed split from parquet shards."""
        split_dir = self.config.processed_data_dir / "splits" / split_name
        shard_paths = sorted(split_dir.glob("shard_*.parquet"))
        if not shard_paths:
            raise FileNotFoundError(f"No parquet shards found in {split_dir}")

        df = pd.concat([pd.read_parquet(path) for path in shard_paths], ignore_index=True)
        if self.config.max_rows_per_split and len(df) > self.config.max_rows_per_split:
            df = df.sort_values(
                [column for column in ["login_timestamp"] if column in df.columns]
            ).head(self.config.max_rows_per_split)
            df = df.reset_index(drop=True)
        return df

    def get_block_columns(self) -> dict:
        """Resolve feature columns for each selected behavior block."""
        feature_blocks = self.manifest.get("feature_blocks", {})
        selected_blocks = {}
        for block_name in self.config.feature_blocks:
            block_columns = feature_blocks.get(block_name, [])
            if block_columns:
                selected_blocks[block_name] = block_columns

        if self.config.use_optional_token_block:
            token_columns = feature_blocks.get("optional_token_block", [])
            if token_columns:
                selected_blocks["optional_token_block"] = token_columns

        return selected_blocks
