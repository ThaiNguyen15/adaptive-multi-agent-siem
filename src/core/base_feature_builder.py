"""
Base feature builder class for creating rolling window features.

Each domain implements:
- Define feature list
- Build features for single shard
- Handle state management
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Set
import pandas as pd
import numpy as np
import logging


logger = logging.getLogger(__name__)


class BaseFeatureBuilder(ABC):
    """Abstract base class for building features from shards.

    Implement for each domain:
    - get_feature_list()
    - build_features()
    """

    def __init__(self, config):
        """Initialize with domain config.

        Args:
            config: Domain-specific configuration
        """
        self.config = config
        self.logger = logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}")
        self.windows = config.feature_windows  # [1, 7, 30] days

    @abstractmethod
    def get_feature_list(self) -> List[str]:
        """Return list of feature names to compute.

        Naming convention: feature_window{d} where d is number of days
        E.g.: login_count_window1, login_count_window7, unique_locations_window30

        Returns:
            List of feature names
        """
        pass

    @abstractmethod
    def build_features(self, shard_df: pd.DataFrame) -> pd.DataFrame:
        """Build features for a single shard.

        Must implement to:
        - Sort by timestamp within shard
        - Compute rolling window features
        - Handle edge cases (new users, sparse data)
        - Return dataframe with features

        Args:
            shard_df: Dataframe for single shard (all rows for one entity)

        Returns:
            Dataframe with original columns + feature columns
        """
        pass

    def process_shard(self, shard_path: Path) -> pd.DataFrame:
        """Load shard, build features, save results.

        Args:
            shard_path: Path to shard parquet file

        Returns:
            Dataframe with features
        """
        # Load shard
        shard_df = pd.read_parquet(shard_path)
        self.logger.debug(f"Loaded shard {shard_path.name}: {len(shard_df)} records")

        # Build features
        featured_df = self.build_features(shard_df)

        self.logger.debug(f"Built features for shard {shard_path.name}: {len(featured_df)} records")

        return featured_df

    def process_all_shards(self, shards_dir: Path, output_dir: Path = None) -> None:
        """Process all shards and save feature files.

        Args:
            shards_dir: Directory containing shard files
            output_dir: Directory to save featured shards (default: same as input)
        """
        if output_dir is None:
            output_dir = shards_dir / "featured"

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        shard_files = sorted(Path(shards_dir).glob("shard_*.parquet"))

        if not shard_files:
            self.logger.warning(f"No shard files found in {shards_dir}")
            return

        self.logger.info(f"Processing {len(shard_files)} shards...")

        for i, shard_path in enumerate(shard_files):
            try:
                featured_df = self.process_shard(shard_path)

                # Save featured shard
                output_path = output_dir / shard_path.name
                featured_df.to_parquet(output_path, index=False, compression="snappy")

                if (i + 1) % max(1, len(shard_files) // 10) == 0:
                    self.logger.info(f"Processed {i + 1}/{len(shard_files)} shards")

            except Exception as e:
                self.logger.error(f"Error processing {shard_path.name}: {e}")
                raise

        self.logger.info(f"Completed feature building for {len(shard_files)} shards")

    def _compute_rolling_features(
        self, group_df: pd.DataFrame, timestamp_col: str, count_col: str = None
    ) -> Dict[str, np.ndarray]:
        """Helper for computing rolling window features.

        Args:
            group_df: Data for one entity (sorted by timestamp)
            timestamp_col: Name of timestamp column
            count_col: Optional column to count values in each window

        Returns:
            Dict of feature_name -> array
        """
        features = {}

        # Sort by timestamp
        group_df = group_df.sort_values(timestamp_col).reset_index(drop=True)

        # Convert timestamp to datetime if needed
        if not pd.api.types.is_datetime64_any_dtype(group_df[timestamp_col]):
            group_df[timestamp_col] = pd.to_datetime(group_df[timestamp_col])

        for window_days in self.windows:
            window_td = pd.Timedelta(days=window_days)

            for idx, row in group_df.iterrows():
                current_time = row[timestamp_col]
                window_start = current_time - window_td

                # Count records in window
                window_mask = (group_df[timestamp_col] >= window_start) & (
                    group_df[timestamp_col] <= current_time
                )
                count = window_mask.sum()

                feature_name = f"count_window{window_days}"
                if feature_name not in features:
                    features[feature_name] = []
                features[feature_name].append(count)

        # Convert lists to arrays
        for key in features:
            features[key] = np.array(features[key])

        return features
