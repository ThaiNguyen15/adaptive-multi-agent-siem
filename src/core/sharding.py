"""
Sharding logic for distributing data across shards.

Supports hash-based sharding for parallel processing.
"""

from pathlib import Path
from typing import Callable
import pandas as pd
import numpy as np
import logging


logger = logging.getLogger(__name__)


class HashSharding:
    """Hash-based sharding for data distribution.

    Partitions data uniformly across N shards using hash function.
    Enables parallel processing while keeping related data together.
    """

    def __init__(self, num_shards: int = 256, shard_key: str = None):
        """Initialize sharding.

        Args:
            num_shards: Number of shards (default 256)
            shard_key: Column name to use for sharding key
        """
        if shard_key is None:
            raise ValueError("shard_key must be provided")

        self.num_shards = num_shards
        self.shard_key = shard_key
        self.logger = logging.getLogger(self.__class__.__name__)

    def compute_shard_id(self, key_value: str) -> int:
        """Compute shard ID for a key value.

        Args:
            key_value: Value to hash (e.g., user_id)

        Returns:
            Shard ID in range [0, num_shards)
        """
        return hash(str(key_value)) % self.num_shards

    def get_shard_column(self, df: pd.DataFrame) -> pd.Series:
        """Compute shard ID for each row.

        Args:
            df: Dataframe with shard_key column

        Returns:
            Series of shard IDs
        """
        if self.shard_key not in df.columns:
            raise ValueError(f"Column '{self.shard_key}' not found in dataframe")

        return df[self.shard_key].apply(self.compute_shard_id)

    def partition(self, df: pd.DataFrame) -> dict:
        """Partition dataframe by shard.

        Args:
            df: Input dataframe

        Returns:
            Dict mapping shard_id -> dataframe
        """
        shard_ids = self.get_shard_column(df)

        shards = {}
        for shard_id in range(self.num_shards):
            shard_df = df[shard_ids == shard_id].reset_index(drop=True)
            if len(shard_df) > 0:
                shards[shard_id] = shard_df

        self.logger.info(f"Partitioned {len(df)} rows into {len(shards)} non-empty shards")

        return shards

    def save_shards(self, df: pd.DataFrame, output_dir: Path, format: str = "parquet") -> None:
        """Partition and save shards to disk.

        Args:
            df: Input dataframe
            output_dir: Directory to save shards
            format: 'parquet' or 'csv'
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        shards = self.partition(df)

        for shard_id, shard_df in shards.items():
            if format == "parquet":
                filename = output_dir / f"shard_{shard_id:03d}.parquet"
                shard_df.to_parquet(filename, index=False, compression="snappy")
            elif format == "csv":
                filename = output_dir / f"shard_{shard_id:03d}.csv"
                shard_df.to_csv(filename, index=False)
            else:
                raise ValueError(f"Unsupported format: {format}")

        self.logger.info(f"Saved {len(shards)} shards to {output_dir}")

    def load_shard(self, shard_id: int, input_dir: Path, format: str = "parquet") -> pd.DataFrame:
        """Load single shard from disk.

        Args:
            shard_id: ID of shard to load
            input_dir: Directory containing shards
            format: 'parquet' or 'csv'

        Returns:
            Dataframe for that shard
        """
        if format == "parquet":
            filename = Path(input_dir) / f"shard_{shard_id:03d}.parquet"
            df = pd.read_parquet(filename)
        elif format == "csv":
            filename = Path(input_dir) / f"shard_{shard_id:03d}.csv"
            df = pd.read_csv(filename)
        else:
            raise ValueError(f"Unsupported format: {format}")

        return df

    def get_shard_files(self, input_dir: Path, format: str = "parquet") -> list:
        """List all shard files in directory.

        Args:
            input_dir: Directory containing shards
            format: 'parquet' or 'csv'

        Returns:
            Sorted list of shard file paths
        """
        pattern = f"shard_*.{format}" if format == "csv" else "shard_*.parquet"
        files = sorted(Path(input_dir).glob(pattern))
        return files
