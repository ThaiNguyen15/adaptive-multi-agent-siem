"""
Time-based train/val/test splitting without data leakage.

Splits by timestamp to prevent temporal data leakage.
"""

from pathlib import Path
from typing import Tuple
import pandas as pd
import numpy as np
import logging


logger = logging.getLogger(__name__)


class TimeBasedSplitter:
    """Splits data by time windows (no randomness, no leakage).

    Ensures test data is always in the future relative to train/val.
    """

    def __init__(
        self,
        train_ratio: float = 0.75,
        val_ratio: float = 0.08,
        test_ratio: float = 0.17,
        timestamp_col: str = "timestamp",
    ):
        """Initialize splitter.

        Args:
            train_ratio: Fraction for training (default 0.75)
            val_ratio: Fraction for validation (default 0.08)
            test_ratio: Fraction for testing (default 0.17)
            timestamp_col: Name of timestamp column
        """
        assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6, "Ratios must sum to 1.0"

        self.train_ratio = train_ratio
        self.val_ratio = val_ratio
        self.test_ratio = test_ratio
        self.timestamp_col = timestamp_col
        self.logger = logging.getLogger(self.__class__.__name__)

    def split(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Split dataframe by time windows.

        Args:
            df: Dataframe with timestamp_col

        Returns:
            Tuple of (train_df, val_df, test_df)
        """
        # Sort by timestamp
        df = df.sort_values(self.timestamp_col).reset_index(drop=True)

        # Convert to datetime if needed
        if not pd.api.types.is_datetime64_any_dtype(df[self.timestamp_col]):
            df[self.timestamp_col] = pd.to_datetime(df[self.timestamp_col])

        total_records = len(df)
        train_size = int(total_records * self.train_ratio)
        val_size = int(total_records * self.val_ratio)

        train_df = df[:train_size].copy()
        val_df = df[train_size : train_size + val_size].copy()
        test_df = df[train_size + val_size :].copy()

        self.logger.info(f"Split {total_records} records:")
        self.logger.info(f"  Train: {len(train_df)} ({100*len(train_df)/total_records:.1f}%)")
        self.logger.info(f"  Val:   {len(val_df)} ({100*len(val_df)/total_records:.1f}%)")
        self.logger.info(f"  Test:  {len(test_df)} ({100*len(test_df)/total_records:.1f}%)")

        return train_df, val_df, test_df

    def get_split_info(self, df: pd.DataFrame) -> dict:
        """Get split timestamp boundaries.

        Args:
            df: Dataframe with timestamp_col

        Returns:
            Dict with split boundaries
        """
        df = df.sort_values(self.timestamp_col).reset_index(drop=True)

        if not pd.api.types.is_datetime64_any_dtype(df[self.timestamp_col]):
            df[self.timestamp_col] = pd.to_datetime(df[self.timestamp_col])

        total_records = len(df)
        train_size = int(total_records * self.train_ratio)
        val_size = int(total_records * self.val_ratio)

        train_end = df.iloc[train_size - 1][self.timestamp_col]
        val_end = df.iloc[train_size + val_size - 1][self.timestamp_col]

        return {
            "train_end": train_end,
            "val_end": val_end,
            "test_start": val_end,
            "test_end": df.iloc[-1][self.timestamp_col],
            "train_records": train_size,
            "val_records": val_size,
            "test_records": total_records - train_size - val_size,
        }

    def split_shards(self, shards_dir: Path, output_dir: Path) -> None:
        """Split all feature shards into train/val/test.

        Args:
            shards_dir: Directory containing featured shards
            output_dir: Directory to save splits
        """
        output_dir = Path(output_dir)
        train_dir = output_dir / "train"
        val_dir = output_dir / "val"
        test_dir = output_dir / "test"

        train_dir.mkdir(parents=True, exist_ok=True)
        val_dir.mkdir(parents=True, exist_ok=True)
        test_dir.mkdir(parents=True, exist_ok=True)

        shard_files = sorted(Path(shards_dir).glob("shard_*.parquet"))

        if not shard_files:
            self.logger.warning(f"No shard files found in {shards_dir}")
            return

        self.logger.info(f"Splitting {len(shard_files)} shards...")

        split_stats = []

        for shard_path in shard_files:
            # Load shard
            shard_df = pd.read_parquet(shard_path)

            # Split by time
            train_df, val_df, test_df = self.split(shard_df)

            # Save to respective directories
            shard_name = shard_path.name
            train_df.to_parquet(train_dir / shard_name, index=False, compression="snappy")
            val_df.to_parquet(val_dir / shard_name, index=False, compression="snappy")
            test_df.to_parquet(test_dir / shard_name, index=False, compression="snappy")

            split_stats.append(
                {
                    "shard": shard_name,
                    "train": len(train_df),
                    "val": len(val_df),
                    "test": len(test_df),
                }
            )

        # Save split statistics
        stats_df = pd.DataFrame(split_stats)
        stats_path = output_dir / "split_stats.csv"
        stats_df.to_csv(stats_path, index=False)

        self.logger.info(f"Split statistics saved to {stats_path}")
        self.logger.info(f"Total train: {stats_df['train'].sum()}")
        self.logger.info(f"Total val:   {stats_df['val'].sum()}")
        self.logger.info(f"Total test:  {stats_df['test'].sum()}")
