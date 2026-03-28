"""
Feature builder for the CESNET HTTPS brute-force dataset.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from src.core.base_feature_builder import BaseFeatureBuilder


class BruteForceHTTPSFeatureBuilder(BaseFeatureBuilder):
    """Build event-level features for brute-force HTTPS detection."""

    def get_feature_list(self) -> list:
        return [
            "total_bytes",
            "total_packets",
            "bytes_per_packet",
            "bytes_ratio_rev_to_fwd",
            "packets_ratio_rev_to_fwd",
            "bytes_per_second_log1p",
            "packets_per_second_log1p",
            "duration_log1p",
            "roundtrips_per_second_log1p",
            "is_tcp",
            "is_tls_port",
            "has_tls_sni",
            "has_tls_ja3",
            "is_benign_scenario",
        ]

    def build_features(self, shard_df: pd.DataFrame) -> pd.DataFrame:
        df = shard_df.copy()

        numeric_defaults = {
            "bytes": 0,
            "bytes_rev": 0,
            "packets": 0,
            "packets_rev": 0,
            "duration": 0,
            "roundtrips": 0,
            "roundtrips_per_sec": 0,
            "bytes_per_sec": 0,
            "packets_per_sec": 0,
            "dst_port": 0,
            "protocol": 0,
        }
        for column, default in numeric_defaults.items():
            if column not in df.columns:
                df[column] = default

        total_bytes = df["bytes"] + df["bytes_rev"]
        total_packets = df["packets"] + df["packets_rev"]

        df["total_bytes"] = total_bytes
        df["total_packets"] = total_packets
        df["bytes_per_packet"] = total_bytes / total_packets.replace(0, np.nan)
        df["bytes_ratio_rev_to_fwd"] = df["bytes_rev"] / df["bytes"].replace(0, np.nan)
        df["packets_ratio_rev_to_fwd"] = df["packets_rev"] / df["packets"].replace(0, np.nan)

        if "bytes_per_sec" in df.columns and (df["bytes_per_sec"] != 0).any():
            df["bytes_per_second_log1p"] = np.log1p(df["bytes_per_sec"].clip(lower=0))
        else:
            rate = total_bytes / df["duration"].replace(0, np.nan)
            df["bytes_per_second_log1p"] = np.log1p(rate.clip(lower=0))

        if "packets_per_sec" in df.columns and (df["packets_per_sec"] != 0).any():
            df["packets_per_second_log1p"] = np.log1p(df["packets_per_sec"].clip(lower=0))
        else:
            pkt_rate = total_packets / df["duration"].replace(0, np.nan)
            df["packets_per_second_log1p"] = np.log1p(pkt_rate.clip(lower=0))

        if "roundtrips_per_sec" in df.columns and (df["roundtrips_per_sec"] != 0).any():
            df["roundtrips_per_second_log1p"] = np.log1p(df["roundtrips_per_sec"].clip(lower=0))
        else:
            roundtrip_rate = df["roundtrips"] / df["duration"].replace(0, np.nan)
            df["roundtrips_per_second_log1p"] = np.log1p(roundtrip_rate.clip(lower=0))

        df["duration_log1p"] = np.log1p(df["duration"].clip(lower=0))
        df["is_tcp"] = (df["protocol"] == 6).astype(int)
        df["is_tls_port"] = (df["dst_port"] == 443).astype(int)
        df["has_tls_sni"] = df["tls_sni"].fillna("").astype(str).ne("").astype(int)
        df["has_tls_ja3"] = df["tls_ja3"].fillna("").astype(str).ne("").astype(int)
        df["is_benign_scenario"] = df["scenario"].fillna("").astype(str).str.startswith(
            "backbone_capture_"
        ).astype(int)

        derived_columns = self.get_feature_list()
        df[derived_columns] = df[derived_columns].replace([np.inf, -np.inf], np.nan).fillna(0)
        return df
