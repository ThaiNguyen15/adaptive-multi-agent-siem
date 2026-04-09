"""
Login domain feature builder.

Builds features including:
- Strictly-past behavioral history per user
- Novelty flags for IP/device/location changes
- Temporal context for the current login event
- Multi-resolution counts/diversity features
- Stable abstraction features for mixed categorical context
"""

from collections import Counter

import pandas as pd
import numpy as np
from src.core.base_feature_builder import BaseFeatureBuilder


class LoginFeatureBuilder(BaseFeatureBuilder):
    """Build features from login shards."""

    COUNT_BIN_EDGES = [0, 1, 3, 10, 30]
    RATE_BIN_EDGES = [0.0, 0.01, 0.2, 0.5, 0.8, 1.0]
    GAP_BIN_EDGES = [0, 60, 300, 1800, 21600, 86400, 604800]

    def get_feature_list(self) -> list:
        """Return list of feature names.

        Returns:
            List of feature column names
        """
        features = [
            "has_prior_login",
            "seconds_since_prev_login",
            "seconds_since_prev_login_log",
            "seconds_since_prev_login_bin",
            "seconds_since_prev_success",
            "seconds_since_prev_success_log",
            "seconds_since_prev_success_bin",
            "seconds_since_prev_failure",
            "seconds_since_prev_failure_log",
            "seconds_since_prev_failure_bin",
            "hour_of_day",
            "day_of_week",
            "is_weekend",
            "geo_resolution_level",
            "is_new_ip",
            "is_new_device",
            "is_new_country",
            "is_new_region",
            "is_new_city",
            "is_new_geo_token",
            "is_new_context_token",
            "prev_login_same_ip",
            "prev_login_same_device",
            "prev_login_same_country",
            "prev_login_same_region",
            "prev_login_same_city",
            "prior_success_streak",
            "prior_failure_streak",
            "current_ip_prior_count",
            "current_device_prior_count",
            "current_country_prior_count",
            "current_context_prior_count",
            "current_ip_prior_rate",
            "current_device_prior_rate",
            "current_country_prior_rate",
            "current_context_prior_rate",
        ]

        # For each window size
        for window in self.windows:
            # Count features
            features.extend(
                [
                    f"login_count_window{window}",
                    f"log_login_count_window{window}",
                    f"login_count_bin_window{window}",
                    f"success_count_window{window}",
                    f"failure_count_window{window}",
                ]
            )

            # Rate features
            features.extend(
                [
                    f"success_rate_window{window}",
                    f"failure_rate_window{window}",
                    f"success_rate_bin_window{window}",
                    f"failure_rate_bin_window{window}",
                ]
            )

            # Diversity features
            features.extend(
                [
                    f"unique_ips_window{window}",
                    f"unique_ips_bin_window{window}",
                    f"unique_devices_window{window}",
                    f"unique_devices_bin_window{window}",
                    f"unique_countries_window{window}",
                    f"unique_regions_window{window}",
                    f"unique_cities_window{window}",
                    f"unique_context_tokens_window{window}",
                    f"unique_context_tokens_bin_window{window}",
                ]
            )

            # Entropy features
            features.extend(
                [
                    f"entropy_ips_window{window}",
                    f"entropy_devices_window{window}",
                    f"entropy_countries_window{window}",
                ]
            )

        return features

    @classmethod
    def _count_to_bin(cls, count: int) -> int:
        """Map raw count to a small ordinal bin."""
        return int(np.digitize([count], cls.COUNT_BIN_EDGES, right=False)[0])

    @classmethod
    def _rate_to_bin(cls, value: float) -> int:
        """Map a probability-like value to a coarse ordinal bin."""
        bounded = float(np.clip(value, 0.0, 1.0))
        return int(np.digitize([bounded], cls.RATE_BIN_EDGES, right=True)[0])

    @classmethod
    def _gap_to_bin(cls, seconds: float) -> int:
        """Map recency values to coarse time-scale bins."""
        bounded = max(float(seconds), 0.0)
        return int(np.digitize([bounded], cls.GAP_BIN_EDGES, right=False)[0])

    @staticmethod
    def _gap_log(seconds: float) -> float:
        """Stabilize heavy-tailed recency values."""
        return float(np.log1p(max(seconds, 0.0)))

    @staticmethod
    def _compute_entropy(series: pd.Series) -> float:
        """Compute entropy for a categorical series."""
        if len(series) == 0:
            return 0.0

        counts = series.value_counts()
        probs = counts / counts.sum()
        return float(-np.sum(probs * np.log2(probs + 1e-10)))

    @staticmethod
    def _geo_resolution_level(row: pd.Series) -> int:
        """Measure how complete the geo context is for this event."""
        level = 0
        if row["country"] != "unknown":
            level += 1
        if row["region"] != "unknown":
            level += 1
        if row["city"] != "unknown":
            level += 1
        return level

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

        # Sort by user and timestamp.
        df = df.sort_values(["user_id", "login_timestamp"]).reset_index(drop=True)

        # Older normalized files may not contain the abstraction tokens yet.
        for column, fallback in {
            "ip_token": "unknown_ip",
            "device_token": "unknown_device",
            "geo_token": "geo_unknown",
        }.items():
            if column not in df.columns:
                df[column] = fallback
        if "context_token" not in df.columns:
            df["context_token"] = (
                df["ip_token"].astype(str)
                + "|"
                + df["device_token"].astype(str)
                + "|"
                + df["geo_token"].astype(str)
            )

        # Initialize feature columns
        for feature_name in self.get_feature_list():
            df[feature_name] = np.nan

        # Build features per user using strictly-past history only.
        for user_id in df["user_id"].unique():
            user_df = df[df["user_id"] == user_id].copy()
            seen_ips = set()
            seen_devices = set()
            seen_countries = set()
            seen_regions = set()
            seen_cities = set()
            seen_geo_tokens = set()
            seen_context_tokens = set()
            ip_counts = Counter()
            device_counts = Counter()
            country_counts = Counter()
            context_counts = Counter()
            prev_timestamp = None
            prev_success_timestamp = None
            prev_failure_timestamp = None
            prev_row = None
            prior_success_streak = 0
            prior_failure_streak = 0

            # Build features for each row
            for position, (row_idx, row) in enumerate(user_df.iterrows()):
                current_time = row["login_timestamp"]
                history_df = user_df.iloc[:position]
                has_prior = int(len(history_df) > 0)

                df.loc[row_idx, "has_prior_login"] = has_prior
                df.loc[row_idx, "hour_of_day"] = current_time.hour
                df.loc[row_idx, "day_of_week"] = current_time.dayofweek
                df.loc[row_idx, "is_weekend"] = int(current_time.dayofweek >= 5)

                if prev_timestamp is not None:
                    df.loc[row_idx, "seconds_since_prev_login"] = (
                        current_time - prev_timestamp
                    ).total_seconds()
                else:
                    df.loc[row_idx, "seconds_since_prev_login"] = 0.0
                df.loc[row_idx, "seconds_since_prev_login_log"] = self._gap_log(
                    df.loc[row_idx, "seconds_since_prev_login"]
                )
                df.loc[row_idx, "seconds_since_prev_login_bin"] = self._gap_to_bin(
                    df.loc[row_idx, "seconds_since_prev_login"]
                )

                if prev_success_timestamp is not None:
                    df.loc[row_idx, "seconds_since_prev_success"] = (
                        current_time - prev_success_timestamp
                    ).total_seconds()
                else:
                    df.loc[row_idx, "seconds_since_prev_success"] = 0.0
                df.loc[row_idx, "seconds_since_prev_success_log"] = self._gap_log(
                    df.loc[row_idx, "seconds_since_prev_success"]
                )
                df.loc[row_idx, "seconds_since_prev_success_bin"] = self._gap_to_bin(
                    df.loc[row_idx, "seconds_since_prev_success"]
                )

                if prev_failure_timestamp is not None:
                    df.loc[row_idx, "seconds_since_prev_failure"] = (
                        current_time - prev_failure_timestamp
                    ).total_seconds()
                else:
                    df.loc[row_idx, "seconds_since_prev_failure"] = 0.0
                df.loc[row_idx, "seconds_since_prev_failure_log"] = self._gap_log(
                    df.loc[row_idx, "seconds_since_prev_failure"]
                )
                df.loc[row_idx, "seconds_since_prev_failure_bin"] = self._gap_to_bin(
                    df.loc[row_idx, "seconds_since_prev_failure"]
                )

                df.loc[row_idx, "geo_resolution_level"] = self._geo_resolution_level(row)
                df.loc[row_idx, "is_new_ip"] = int(row["ip"] not in seen_ips)
                df.loc[row_idx, "is_new_device"] = int(row["device"] not in seen_devices)
                df.loc[row_idx, "is_new_country"] = int(row["country"] not in seen_countries)
                df.loc[row_idx, "is_new_region"] = int(row["region"] not in seen_regions)
                df.loc[row_idx, "is_new_city"] = int(row["city"] not in seen_cities)
                df.loc[row_idx, "is_new_geo_token"] = int(row["geo_token"] not in seen_geo_tokens)
                df.loc[row_idx, "is_new_context_token"] = int(
                    row["context_token"] not in seen_context_tokens
                )

                df.loc[row_idx, "prev_login_same_ip"] = int(
                    prev_row is not None and row["ip"] == prev_row["ip"]
                )
                df.loc[row_idx, "prev_login_same_device"] = int(
                    prev_row is not None and row["device"] == prev_row["device"]
                )
                df.loc[row_idx, "prev_login_same_country"] = int(
                    prev_row is not None and row["country"] == prev_row["country"]
                )
                df.loc[row_idx, "prev_login_same_region"] = int(
                    prev_row is not None and row["region"] == prev_row["region"]
                )
                df.loc[row_idx, "prev_login_same_city"] = int(
                    prev_row is not None and row["city"] == prev_row["city"]
                )

                df.loc[row_idx, "prior_success_streak"] = prior_success_streak
                df.loc[row_idx, "prior_failure_streak"] = prior_failure_streak

                prior_total = len(history_df)
                df.loc[row_idx, "current_ip_prior_count"] = ip_counts[row["ip"]]
                df.loc[row_idx, "current_device_prior_count"] = device_counts[row["device"]]
                df.loc[row_idx, "current_country_prior_count"] = country_counts[row["country"]]
                df.loc[row_idx, "current_context_prior_count"] = context_counts[row["context_token"]]
                df.loc[row_idx, "current_ip_prior_rate"] = (
                    ip_counts[row["ip"]] / prior_total if prior_total > 0 else 0.0
                )
                df.loc[row_idx, "current_device_prior_rate"] = (
                    device_counts[row["device"]] / prior_total if prior_total > 0 else 0.0
                )
                df.loc[row_idx, "current_country_prior_rate"] = (
                    country_counts[row["country"]] / prior_total if prior_total > 0 else 0.0
                )
                df.loc[row_idx, "current_context_prior_rate"] = (
                    context_counts[row["context_token"]] / prior_total if prior_total > 0 else 0.0
                )

                # Get records within each window
                for window_days in self.windows:
                    window_start = current_time - pd.Timedelta(days=window_days)

                    window_records = history_df[
                        (history_df["login_timestamp"] >= window_start)
                        & (history_df["login_timestamp"] < current_time)
                    ]

                    # Count metrics
                    login_count = len(window_records)
                    df.loc[row_idx, f"login_count_window{window_days}"] = login_count
                    df.loc[row_idx, f"log_login_count_window{window_days}"] = np.log1p(login_count)
                    df.loc[row_idx, f"login_count_bin_window{window_days}"] = self._count_to_bin(
                        login_count
                    )

                    successes = (window_records["login_successful"] == 1).sum()
                    failures = (window_records["login_successful"] == 0).sum()

                    df.loc[row_idx, f"success_count_window{window_days}"] = successes
                    df.loc[row_idx, f"failure_count_window{window_days}"] = failures

                    # Rate metrics
                    total = login_count
                    df.loc[row_idx, f"success_rate_window{window_days}"] = (
                        successes / total if total > 0 else 0
                    )
                    df.loc[row_idx, f"failure_rate_window{window_days}"] = (
                        failures / total if total > 0 else 0
                    )
                    df.loc[row_idx, f"success_rate_bin_window{window_days}"] = self._rate_to_bin(
                        df.loc[row_idx, f"success_rate_window{window_days}"]
                    )
                    df.loc[row_idx, f"failure_rate_bin_window{window_days}"] = self._rate_to_bin(
                        df.loc[row_idx, f"failure_rate_window{window_days}"]
                    )

                    # Unique values
                    df.loc[row_idx, f"unique_ips_window{window_days}"] = window_records["ip"].nunique()
                    df.loc[row_idx, f"unique_ips_bin_window{window_days}"] = self._count_to_bin(
                        df.loc[row_idx, f"unique_ips_window{window_days}"]
                    )
                    df.loc[row_idx, f"unique_devices_window{window_days}"] = window_records[
                        "device"
                    ].nunique()
                    df.loc[row_idx, f"unique_devices_bin_window{window_days}"] = (
                        self._count_to_bin(df.loc[row_idx, f"unique_devices_window{window_days}"])
                    )
                    df.loc[row_idx, f"unique_countries_window{window_days}"] = window_records[
                        "country"
                    ].nunique()
                    df.loc[row_idx, f"unique_regions_window{window_days}"] = window_records[
                        "region"
                    ].nunique()
                    df.loc[row_idx, f"unique_cities_window{window_days}"] = window_records[
                        "city"
                    ].nunique()
                    df.loc[row_idx, f"unique_context_tokens_window{window_days}"] = window_records[
                        "context_token"
                    ].nunique()
                    df.loc[row_idx, f"unique_context_tokens_bin_window{window_days}"] = (
                        self._count_to_bin(
                            df.loc[row_idx, f"unique_context_tokens_window{window_days}"]
                        )
                    )

                    # Entropy metrics
                    df.loc[row_idx, f"entropy_ips_window{window_days}"] = self._compute_entropy(
                        window_records["ip"]
                    )
                    df.loc[row_idx, f"entropy_devices_window{window_days}"] = self._compute_entropy(
                        window_records["device"]
                    )
                    df.loc[row_idx, f"entropy_countries_window{window_days}"] = (
                        self._compute_entropy(window_records["country"])
                    )

                seen_ips.add(row["ip"])
                seen_devices.add(row["device"])
                seen_countries.add(row["country"])
                seen_regions.add(row["region"])
                seen_cities.add(row["city"])
                seen_geo_tokens.add(row["geo_token"])
                seen_context_tokens.add(row["context_token"])
                ip_counts[row["ip"]] += 1
                device_counts[row["device"]] += 1
                country_counts[row["country"]] += 1
                context_counts[row["context_token"]] += 1
                prev_timestamp = current_time
                prev_row = row

                if row["login_successful"] == 1:
                    prev_success_timestamp = current_time
                    prior_success_streak += 1
                    prior_failure_streak = 0
                else:
                    prev_failure_timestamp = current_time
                    prior_failure_streak += 1
                    prior_success_streak = 0

        # Fill NaN deterministically. No prior history should resolve to zero history, not optimistic rates.
        for col in df.columns:
            if (
                "count" in col
                or "unique" in col
                or "entropy" in col
                or col.startswith("is_")
                or col.startswith("prev_login_same_")
                or col in {"has_prior_login", "hour_of_day", "day_of_week", "is_weekend"}
            ):
                df[col] = df[col].fillna(0)
            elif "rate" in col:
                df[col] = df[col].fillna(0)
            elif col.endswith("_streak") or col.endswith("_level") or col.endswith("_bin"):
                df[col] = df[col].fillna(0)
            elif col.startswith("seconds_since_"):
                df[col] = df[col].fillna(0.0)
            elif col.startswith("log_") or col.endswith("_log"):
                df[col] = df[col].fillna(0.0)

        return df
