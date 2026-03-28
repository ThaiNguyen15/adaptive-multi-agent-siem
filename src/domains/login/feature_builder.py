"""
Login domain feature builder.

Builds features including:
- Login counts per window
- Success/failure rates
- Unique IPs/devices/locations
- Entropy (diversity of sources)
"""

import pandas as pd
import numpy as np
from src.core.base_feature_builder import BaseFeatureBuilder


class LoginFeatureBuilder(BaseFeatureBuilder):
    """Build features from login shards."""

    def get_feature_list(self) -> list:
        """Return list of feature names.

        Returns:
            List of feature column names
        """
        features = []

        # For each window size
        for window in self.windows:
            # Count features
            features.extend(
                [
                    f"login_count_window{window}",
                    f"success_count_window{window}",
                    f"failure_count_window{window}",
                ]
            )

            # Rate features
            features.extend(
                [
                    f"success_rate_window{window}",
                    f"failure_rate_window{window}",
                ]
            )

            # Diversity features
            features.extend(
                [
                    f"unique_ips_window{window}",
                    f"unique_devices_window{window}",
                    f"unique_locations_window{window}",
                ]
            )

            # Entropy features
            features.extend(
                [
                    f"entropy_ips_window{window}",
                    f"entropy_devices_window{window}",
                ]
            )

        return features

    def build_features(self, shard_df: pd.DataFrame) -> pd.DataFrame:
        """Build features for shard (all records for set of users).

        Args:
            shard_df: Shard dataframe

        Returns:
            Dataframe with added feature columns
        """
        df = shard_df.copy()

        # Ensure login timestamp is datetime.
        if not pd.api.types.is_datetime64_any_dtype(df["login_timestamp"]):
            df["login_timestamp"] = pd.to_datetime(df["login_timestamp"], errors="coerce", utc=True)

        df["_location_key"] = (
            df[["country", "region", "city"]]
            .fillna("unknown")
            .astype(str)
            .agg(" | ".join, axis=1)
        )

        # Sort by user and timestamp.
        df = df.sort_values(["user_id", "login_timestamp"]).reset_index(drop=True)

        # Initialize feature columns
        for feature_name in self.get_feature_list():
            df[feature_name] = np.nan

        # Build features per user
        for user_id in df["user_id"].unique():
            user_df = df[df["user_id"] == user_id].copy()
            # Build features for each row
            for row_idx, row in user_df.iterrows():
                current_time = row["login_timestamp"]

                # Get records within each window
                for window_days in self.windows:
                    window_start = current_time - pd.Timedelta(days=window_days)

                    window_records = user_df[
                        (user_df["login_timestamp"] >= window_start)
                        & (user_df["login_timestamp"] <= current_time)
                    ]

                    if len(window_records) == 0:
                        continue

                    # Count metrics
                    df.loc[row_idx, f"login_count_window{window_days}"] = len(window_records)

                    successes = (window_records["login_successful"] == 1).sum()
                    failures = (window_records["login_successful"] == 0).sum()

                    df.loc[row_idx, f"success_count_window{window_days}"] = successes
                    df.loc[row_idx, f"failure_count_window{window_days}"] = failures

                    # Rate metrics
                    total = len(window_records)
                    df.loc[row_idx, f"success_rate_window{window_days}"] = (
                        successes / total if total > 0 else 0
                    )
                    df.loc[row_idx, f"failure_rate_window{window_days}"] = (
                        failures / total if total > 0 else 0
                    )

                    # Unique values
                    df.loc[row_idx, f"unique_ips_window{window_days}"] = window_records["ip"].nunique()
                    df.loc[row_idx, f"unique_devices_window{window_days}"] = window_records[
                        "device"
                    ].nunique()
                    df.loc[row_idx, f"unique_locations_window{window_days}"] = window_records[
                        "_location_key"
                    ].nunique()

                    # Entropy metrics
                    ip_counts = window_records["ip"].value_counts()
                    ip_probs = ip_counts / ip_counts.sum()
                    entropy_ip = -np.sum(ip_probs * np.log2(ip_probs + 1e-10))
                    df.loc[row_idx, f"entropy_ips_window{window_days}"] = entropy_ip

                    device_counts = window_records["device"].value_counts()
                    device_probs = device_counts / device_counts.sum()
                    entropy_device = -np.sum(device_probs * np.log2(device_probs + 1e-10))
                    df.loc[row_idx, f"entropy_devices_window{window_days}"] = entropy_device

        # Fill NaN with 0 for counts, 1 for rates (no anomaly)
        for col in df.columns:
            if "count" in col or "unique" in col or "entropy" in col:
                df[col] = df[col].fillna(0)
            elif "rate" in col:
                df[col] = df[col].fillna(1)  # No failures = normal

        return df.drop(columns="_location_key")
