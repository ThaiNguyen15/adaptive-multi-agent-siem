"""
Login domain feature builder.

The login domain is treated as a behavioral trigger layer:
- features must use strictly-past user history only
- high-cardinality raw context is reduced into stable tokens first
- counts, recency, and diversity signals are expanded into raw/log/bin views
"""

from collections import Counter
from typing import Dict

import numpy as np
import pandas as pd

from src.core.base_feature_builder import BaseFeatureBuilder


class LoginFeatureBuilder(BaseFeatureBuilder):
    """Build login features from normalized shards."""

    COUNT_BIN_EDGES = [0, 1, 3, 10, 30]
    RATE_BIN_EDGES = [0.0, 0.01, 0.2, 0.5, 0.8, 1.0]
    GAP_BIN_EDGES = [0, 60, 300, 1800, 21600, 86400, 604800]
    ENTROPY_BIN_EDGES = [0.0, 0.2, 0.8, 1.5, 2.5, 4.0]

    NOVELTY_FIELDS = {
        "ip": "is_new_ip",
        "device": "is_new_device",
        "country": "is_new_country",
        "region": "is_new_region",
        "city": "is_new_city",
        "geo_token": "is_new_geo_token",
        "context_token": "is_new_context_token",
    }

    CONTINUITY_FIELDS = {
        "ip": "prev_login_same_ip",
        "device": "prev_login_same_device",
        "country": "prev_login_same_country",
        "region": "prev_login_same_region",
        "city": "prev_login_same_city",
        "geo_token": "prev_login_same_geo_token",
        "context_token": "prev_login_same_context_token",
    }

    PRIOR_TOKEN_FIELDS = {
        "ip_token": "current_ip_token_prior",
        "device_token": "current_device_token_prior",
        "geo_token": "current_geo_token_prior",
        "context_token": "current_context_prior",
    }

    DIVERSITY_FIELDS = {
        "ip_token": "unique_ip_tokens",
        "device_token": "unique_device_tokens",
        "geo_token": "unique_geo_tokens",
        "context_token": "unique_context_tokens",
    }

    ENTROPY_FIELDS = {
        "ip_token": "entropy_ip_tokens",
        "device_token": "entropy_device_tokens",
        "geo_token": "entropy_geo_tokens",
        "context_token": "entropy_context_tokens",
    }

    def get_feature_list(self) -> list:
        """Return the full behavioral feature schema."""
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
            "prior_success_streak",
            "prior_success_streak_log",
            "prior_success_streak_bin",
            "prior_failure_streak",
            "prior_failure_streak_log",
            "prior_failure_streak_bin",
        ]

        features.extend(self.NOVELTY_FIELDS.values())
        features.extend(self.CONTINUITY_FIELDS.values())

        for feature_prefix in self.PRIOR_TOKEN_FIELDS.values():
            features.extend(
                [
                    f"{feature_prefix}_count",
                    f"{feature_prefix}_count_log",
                    f"{feature_prefix}_count_bin",
                    f"{feature_prefix}_rate",
                    f"{feature_prefix}_rate_bin",
                ]
            )

        # These alias columns preserve compatibility with older downstream notebooks.
        features.extend(
            [
                "current_ip_prior_count",
                "current_ip_prior_rate",
                "current_device_prior_count",
                "current_device_prior_rate",
                "current_country_prior_count",
                "current_country_prior_rate",
            ]
        )

        for window in self.windows:
            features.extend(
                [
                    f"login_count_window{window}",
                    f"log_login_count_window{window}",
                    f"login_count_bin_window{window}",
                    f"success_count_window{window}",
                    f"log_success_count_window{window}",
                    f"success_count_bin_window{window}",
                    f"failure_count_window{window}",
                    f"log_failure_count_window{window}",
                    f"failure_count_bin_window{window}",
                    f"success_rate_window{window}",
                    f"failure_rate_window{window}",
                    f"success_rate_bin_window{window}",
                    f"failure_rate_bin_window{window}",
                ]
            )

            for diversity_prefix in self.DIVERSITY_FIELDS.values():
                features.extend(
                    [
                        f"{diversity_prefix}_window{window}",
                        f"log_{diversity_prefix}_window{window}",
                        f"{diversity_prefix}_bin_window{window}",
                    ]
                )

            for entropy_prefix in self.ENTROPY_FIELDS.values():
                features.extend(
                    [
                        f"{entropy_prefix}_window{window}",
                        f"{entropy_prefix}_bin_window{window}",
                    ]
                )

        return features

    def get_feature_blocks(self) -> Dict[str, list]:
        """Expose grouped features for head-based downstream training."""
        blocks = {
            "temporal": [
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
            ],
            "novelty": list(self.NOVELTY_FIELDS.values()),
            "continuity": list(self.CONTINUITY_FIELDS.values()),
            "familiarity": [],
            "outcome_pressure": [
                "prior_success_streak",
                "prior_success_streak_log",
                "prior_success_streak_bin",
                "prior_failure_streak",
                "prior_failure_streak_log",
                "prior_failure_streak_bin",
            ],
            "diversity": [],
            "optional_token_block": ["ip_token", "device_token", "geo_token", "context_token"],
        }

        for feature_prefix in self.PRIOR_TOKEN_FIELDS.values():
            blocks["familiarity"].extend(
                [
                    f"{feature_prefix}_count",
                    f"{feature_prefix}_count_log",
                    f"{feature_prefix}_count_bin",
                    f"{feature_prefix}_rate",
                    f"{feature_prefix}_rate_bin",
                ]
            )

        for window in self.windows:
            blocks["outcome_pressure"].extend(
                [
                    f"login_count_window{window}",
                    f"log_login_count_window{window}",
                    f"login_count_bin_window{window}",
                    f"success_count_window{window}",
                    f"log_success_count_window{window}",
                    f"success_count_bin_window{window}",
                    f"failure_count_window{window}",
                    f"log_failure_count_window{window}",
                    f"failure_count_bin_window{window}",
                    f"success_rate_window{window}",
                    f"failure_rate_window{window}",
                    f"success_rate_bin_window{window}",
                    f"failure_rate_bin_window{window}",
                ]
            )

            for diversity_prefix in self.DIVERSITY_FIELDS.values():
                blocks["diversity"].extend(
                    [
                        f"{diversity_prefix}_window{window}",
                        f"log_{diversity_prefix}_window{window}",
                        f"{diversity_prefix}_bin_window{window}",
                    ]
                )

            for entropy_prefix in self.ENTROPY_FIELDS.values():
                blocks["diversity"].extend(
                    [
                        f"{entropy_prefix}_window{window}",
                        f"{entropy_prefix}_bin_window{window}",
                    ]
                )

        return blocks

    @classmethod
    def _count_to_bin(cls, count: int) -> int:
        """Map count-like values to a small ordinal scale."""
        return int(np.digitize([count], cls.COUNT_BIN_EDGES, right=False)[0])

    @classmethod
    def _rate_to_bin(cls, value: float) -> int:
        """Map bounded rates to a coarse ordinal scale."""
        bounded = float(np.clip(value, 0.0, 1.0))
        return int(np.digitize([bounded], cls.RATE_BIN_EDGES, right=True)[0])

    @classmethod
    def _gap_to_bin(cls, seconds: float) -> int:
        """Map recency values to coarse time-scale bins."""
        bounded = max(float(seconds), 0.0)
        return int(np.digitize([bounded], cls.GAP_BIN_EDGES, right=False)[0])

    @classmethod
    def _entropy_to_bin(cls, value: float) -> int:
        """Map entropy values to a coarse ordinal scale."""
        bounded = max(float(value), 0.0)
        return int(np.digitize([bounded], cls.ENTROPY_BIN_EDGES, right=False)[0])

    @staticmethod
    def _log1p(value: float) -> float:
        """Stabilize heavy-tailed positive signals."""
        return float(np.log1p(max(value, 0.0)))

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
        """Measure how complete the raw geo context is for this event."""
        level = 0
        if row["country"] != "unknown":
            level += 1
        if row["region"] != "unknown":
            level += 1
        if row["city"] != "unknown":
            level += 1
        return level

    @classmethod
    def _assign_count_triplet(cls, df: pd.DataFrame, row_idx: int, prefix: str, value: int) -> None:
        """Write raw/log/bin columns for count-like features."""
        df.loc[row_idx, prefix] = value
        df.loc[row_idx, f"{prefix}_log"] = cls._log1p(value)
        df.loc[row_idx, f"{prefix}_bin"] = cls._count_to_bin(value)

    @classmethod
    def _assign_prior_triplet(
        cls, df: pd.DataFrame, row_idx: int, prefix: str, count_value: int, rate_value: float
    ) -> None:
        """Write raw/log/bin count features plus raw/bin rate features."""
        df.loc[row_idx, f"{prefix}_count"] = count_value
        df.loc[row_idx, f"{prefix}_count_log"] = cls._log1p(count_value)
        df.loc[row_idx, f"{prefix}_count_bin"] = cls._count_to_bin(count_value)
        df.loc[row_idx, f"{prefix}_rate"] = rate_value
        df.loc[row_idx, f"{prefix}_rate_bin"] = cls._rate_to_bin(rate_value)

    @classmethod
    def _assign_window_count_triplet(
        cls, df: pd.DataFrame, row_idx: int, prefix: str, window: int, value: int
    ) -> None:
        """Write raw/log/bin count features for a rolling window."""
        df.loc[row_idx, f"{prefix}_window{window}"] = value
        df.loc[row_idx, f"log_{prefix}_window{window}"] = cls._log1p(value)
        df.loc[row_idx, f"{prefix}_bin_window{window}"] = cls._count_to_bin(value)

    @classmethod
    def _assign_window_rate_pair(
        cls, df: pd.DataFrame, row_idx: int, prefix: str, window: int, value: float
    ) -> None:
        """Write raw/bin rate features for a rolling window."""
        df.loc[row_idx, f"{prefix}_window{window}"] = value
        df.loc[row_idx, f"{prefix}_bin_window{window}"] = cls._rate_to_bin(value)

    @classmethod
    def _assign_window_entropy_pair(
        cls, df: pd.DataFrame, row_idx: int, prefix: str, window: int, value: float
    ) -> None:
        """Write raw/bin entropy features for a rolling window."""
        df.loc[row_idx, f"{prefix}_window{window}"] = value
        df.loc[row_idx, f"{prefix}_bin_window{window}"] = cls._entropy_to_bin(value)

    def build_features(self, shard_df: pd.DataFrame) -> pd.DataFrame:
        """Build strictly-past behavioral features for a login shard."""
        df = shard_df.copy()

        if not pd.api.types.is_datetime64_any_dtype(df["login_timestamp"]):
            df["login_timestamp"] = pd.to_datetime(df["login_timestamp"], errors="coerce", utc=True)

        df = df.dropna(subset=["user_id", "login_timestamp"]).copy()
        df = df.sort_values(["user_id", "login_timestamp"]).reset_index(drop=True)

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

        feature_frame = pd.DataFrame(np.nan, index=df.index, columns=self.get_feature_list())
        df = pd.concat([df, feature_frame], axis=1)

        for user_id in df["user_id"].unique():
            user_df = df[df["user_id"] == user_id].copy()

            seen_values = {column: set() for column in self.NOVELTY_FIELDS}
            prior_counters = {column: Counter() for column in self.PRIOR_TOKEN_FIELDS}

            prev_timestamp = None
            prev_success_timestamp = None
            prev_failure_timestamp = None
            prev_row = None
            prior_success_streak = 0
            prior_failure_streak = 0

            for position, (row_idx, row) in enumerate(user_df.iterrows()):
                current_time = row["login_timestamp"]
                history_df = user_df.iloc[:position]
                prior_total = len(history_df)

                df.loc[row_idx, "has_prior_login"] = int(prior_total > 0)
                df.loc[row_idx, "hour_of_day"] = current_time.hour
                df.loc[row_idx, "day_of_week"] = current_time.dayofweek
                df.loc[row_idx, "is_weekend"] = int(current_time.dayofweek >= 5)
                df.loc[row_idx, "geo_resolution_level"] = self._geo_resolution_level(row)

                seconds_since_prev_login = (
                    (current_time - prev_timestamp).total_seconds() if prev_timestamp is not None else 0.0
                )
                df.loc[row_idx, "seconds_since_prev_login"] = seconds_since_prev_login
                df.loc[row_idx, "seconds_since_prev_login_log"] = self._log1p(
                    seconds_since_prev_login
                )
                df.loc[row_idx, "seconds_since_prev_login_bin"] = self._gap_to_bin(
                    seconds_since_prev_login
                )

                seconds_since_prev_success = (
                    (current_time - prev_success_timestamp).total_seconds()
                    if prev_success_timestamp is not None
                    else 0.0
                )
                df.loc[row_idx, "seconds_since_prev_success"] = seconds_since_prev_success
                df.loc[row_idx, "seconds_since_prev_success_log"] = self._log1p(
                    seconds_since_prev_success
                )
                df.loc[row_idx, "seconds_since_prev_success_bin"] = self._gap_to_bin(
                    seconds_since_prev_success
                )

                seconds_since_prev_failure = (
                    (current_time - prev_failure_timestamp).total_seconds()
                    if prev_failure_timestamp is not None
                    else 0.0
                )
                df.loc[row_idx, "seconds_since_prev_failure"] = seconds_since_prev_failure
                df.loc[row_idx, "seconds_since_prev_failure_log"] = self._log1p(
                    seconds_since_prev_failure
                )
                df.loc[row_idx, "seconds_since_prev_failure_bin"] = self._gap_to_bin(
                    seconds_since_prev_failure
                )

                self._assign_count_triplet(
                    df, row_idx, "prior_success_streak", int(prior_success_streak)
                )
                self._assign_count_triplet(
                    df, row_idx, "prior_failure_streak", int(prior_failure_streak)
                )

                for column_name, feature_name in self.NOVELTY_FIELDS.items():
                    df.loc[row_idx, feature_name] = int(row[column_name] not in seen_values[column_name])

                for column_name, feature_name in self.CONTINUITY_FIELDS.items():
                    df.loc[row_idx, feature_name] = int(
                        prev_row is not None and row[column_name] == prev_row[column_name]
                    )

                for column_name, feature_prefix in self.PRIOR_TOKEN_FIELDS.items():
                    prior_count = prior_counters[column_name][row[column_name]]
                    prior_rate = prior_count / prior_total if prior_total > 0 else 0.0
                    self._assign_prior_triplet(
                        df, row_idx, feature_prefix, prior_count, prior_rate
                    )

                # Keep old column names as aliases, but back them with token-based statistics.
                df.loc[row_idx, "current_ip_prior_count"] = df.loc[
                    row_idx, "current_ip_token_prior_count"
                ]
                df.loc[row_idx, "current_ip_prior_rate"] = df.loc[
                    row_idx, "current_ip_token_prior_rate"
                ]
                df.loc[row_idx, "current_device_prior_count"] = df.loc[
                    row_idx, "current_device_token_prior_count"
                ]
                df.loc[row_idx, "current_device_prior_rate"] = df.loc[
                    row_idx, "current_device_token_prior_rate"
                ]
                df.loc[row_idx, "current_country_prior_count"] = df.loc[
                    row_idx, "current_geo_token_prior_count"
                ]
                df.loc[row_idx, "current_country_prior_rate"] = df.loc[
                    row_idx, "current_geo_token_prior_rate"
                ]
                for window_days in self.windows:
                    window_start = current_time - pd.Timedelta(days=window_days)
                    window_records = history_df[
                        (history_df["login_timestamp"] >= window_start)
                        & (history_df["login_timestamp"] < current_time)
                    ]

                    login_count = int(len(window_records))
                    success_count = int((window_records["login_successful"] == 1).sum())
                    failure_count = int((window_records["login_successful"] == 0).sum())

                    self._assign_window_count_triplet(
                        df, row_idx, "login_count", window_days, login_count
                    )
                    self._assign_window_count_triplet(
                        df, row_idx, "success_count", window_days, success_count
                    )
                    self._assign_window_count_triplet(
                        df, row_idx, "failure_count", window_days, failure_count
                    )

                    total = login_count
                    self._assign_window_rate_pair(
                        df,
                        row_idx,
                        "success_rate",
                        window_days,
                        success_count / total if total > 0 else 0.0,
                    )
                    self._assign_window_rate_pair(
                        df,
                        row_idx,
                        "failure_rate",
                        window_days,
                        failure_count / total if total > 0 else 0.0,
                    )

                    for column_name, feature_prefix in self.DIVERSITY_FIELDS.items():
                        diversity_count = int(window_records[column_name].nunique())
                        self._assign_window_count_triplet(
                            df, row_idx, feature_prefix, window_days, diversity_count
                        )

                    for column_name, feature_prefix in self.ENTROPY_FIELDS.items():
                        entropy_value = self._compute_entropy(window_records[column_name])
                        self._assign_window_entropy_pair(
                            df, row_idx, feature_prefix, window_days, entropy_value
                        )

                for column_name in self.NOVELTY_FIELDS:
                    seen_values[column_name].add(row[column_name])
                for column_name in self.PRIOR_TOKEN_FIELDS:
                    prior_counters[column_name][row[column_name]] += 1

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

        for col in df.columns:
            if (
                "count" in col
                or "entropy" in col
                or col.startswith("is_")
                or col.startswith("prev_login_same_")
                or col in {"has_prior_login", "hour_of_day", "day_of_week", "is_weekend"}
            ):
                df[col] = df[col].fillna(0)
            elif "rate" in col:
                df[col] = df[col].fillna(0.0)
            elif col.endswith("_level") or col.endswith("_bin"):
                df[col] = df[col].fillna(0)
            elif col.startswith("seconds_since_"):
                df[col] = df[col].fillna(0.0)
            elif col.startswith("log_") or col.endswith("_log"):
                df[col] = df[col].fillna(0.0)

        return df
