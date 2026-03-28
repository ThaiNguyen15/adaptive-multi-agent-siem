"""
CICIDS 2018 Network domain feature builder.

Different features than login domain:
- Packet statistics
- Traffic rates per protocol
- Attack pattern indicators
"""

import pandas as pd
import numpy as np
from src.core.base_feature_builder import BaseFeatureBuilder


class CICIDS2018FeatureBuilder(BaseFeatureBuilder):
    """Build features from network traffic shards."""

    def get_feature_list(self) -> list:
        """Return list of network traffic features.

        Returns:
            List of feature column names
        """
        features = []

        for window in self.windows:
            # Flow count features
            features.extend(
                [
                    f"flow_count_window{window}",
                    f"benign_flows_window{window}",
                    f"attack_flows_window{window}",
                ]
            )

            # Packet statistics
            features.extend(
                [
                    f"total_fwd_packets_window{window}",
                    f"total_bwd_packets_window{window}",
                    f"avg_fwd_packet_rate_window{window}",
                ]
            )

            # Training rate features
            features.extend(
                [
                    f"attack_rate_window{window}",
                    f"benign_rate_window{window}",
                ]
            )

            # Destination diversity
            features.extend(
                [
                    f"unique_dst_ips_window{window}",
                    f"unique_protocols_window{window}",
                    f"protocol_entropy_window{window}",
                ]
            )

        return features

    def build_features(self, shard_df: pd.DataFrame) -> pd.DataFrame:
        """Build network features for shard (all flows from source IP).

        Args:
            shard_df: Shard dataframe (all flows from specific src_ip)

        Returns:
            Dataframe with added feature columns
        """
        df = shard_df.copy()

        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
            df["timestamp"] = pd.to_datetime(df["timestamp"])

        # Sort by src_ip and timestamp
        df = df.sort_values(["src_ip", "timestamp"]).reset_index(drop=True)

        # Initialize feature columns
        for feature_name in self.get_feature_list():
            df[feature_name] = np.nan

        # Build features per source IP
        for src_ip in df["src_ip"].unique():
            src_df = df[df["src_ip"] == src_ip].copy()

            # Build features for each flow
            for idx, (row_idx, row) in enumerate(src_df.iterrows()):
                current_time = row["timestamp"]

                # Get flows within each window
                for window_hours in self.windows:
                    window_start = current_time - pd.Timedelta(hours=window_hours)

                    window_flows = src_df[
                        (src_df["timestamp"] >= window_start)
                        & (src_df["timestamp"] <= current_time)
                    ]

                    if len(window_flows) == 0:
                        continue

                    # Count metrics
                    df.loc[row_idx, f"flow_count_window{window_hours}"] = len(window_flows)

                    benign_count = (window_flows["label"] == "benign").sum()
                    attack_count = (window_flows["label"] == "attack").sum()

                    df.loc[row_idx, f"benign_flows_window{window_hours}"] = benign_count
                    df.loc[row_idx, f"attack_flows_window{window_hours}"] = attack_count

                    # Packet statistics
                    df.loc[row_idx, f"total_fwd_packets_window{window_hours}"] = window_flows[
                        "fwd_packets"
                    ].sum()
                    df.loc[row_idx, f"total_bwd_packets_window{window_hours}"] = window_flows[
                        "bwd_packets"
                    ].sum()

                    total_duration = window_flows["duration"].sum()
                    avg_rate = (
                        (window_flows["fwd_packets"].sum() / total_duration)
                        if total_duration > 0
                        else 0
                    )
                    df.loc[row_idx, f"avg_fwd_packet_rate_window{window_hours}"] = avg_rate

                    # Rate metrics
                    total = len(window_flows)
                    df.loc[row_idx, f"attack_rate_window{window_hours}"] = (
                        attack_count / total if total > 0 else 0
                    )
                    df.loc[row_idx, f"benign_rate_window{window_hours}"] = (
                        benign_count / total if total > 0 else 0
                    )

                    # Destination diversity
                    df.loc[row_idx, f"unique_dst_ips_window{window_hours}"] = window_flows[
                        "dst_ip"
                    ].nunique()
                    df.loc[row_idx, f"unique_protocols_window{window_hours}"] = window_flows[
                        "protocol"
                    ].nunique()

                    # Protocol entropy
                    protocol_counts = window_flows["protocol"].value_counts()
                    protocol_probs = protocol_counts / protocol_counts.sum()
                    entropy = -np.sum(protocol_probs * np.log2(protocol_probs + 1e-10))
                    df.loc[row_idx, f"protocol_entropy_window{window_hours}"] = entropy

        # Fill NaN with 0 for counts and rates
        for col in df.columns:
            if col not in [
                "timestamp",
                "src_ip",
                "dst_ip",
                "protocol",
                "duration",
                "fwd_packets",
                "bwd_packets",
                "label",
            ]:
                if (
                    "count" in col
                    or "rate" in col
                    or "packets" in col
                    or "unique" in col
                    or "entropy" in col
                ):
                    df[col] = df[col].fillna(0)

        return df
