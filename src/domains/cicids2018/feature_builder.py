"""
CICIDS 2018 network-flow feature builder.

Builds derived flow-level features that are useful for O3/O4 network detection.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from src.core.base_feature_builder import BaseFeatureBuilder


class CICIDS2018FeatureBuilder(BaseFeatureBuilder):
    """Build derived features from CICFlowMeter flows."""

    BASE_COLUMNS = {
        "event_id",
        "source_file",
        "row_index",
        "timestamp",
        "dst_port",
        "protocol",
        "attack_label_raw",
        "attack_family",
        "label_binary",
        "label_known",
    }

    def get_feature_list(self) -> list:
        """Return derived feature names."""
        return [
            "total_packets",
            "total_bytes",
            "bytes_per_packet",
            "fwd_bwd_packet_ratio",
            "fwd_bwd_bytes_ratio",
            "flow_bytes_per_second_log1p",
            "flow_packets_per_second_log1p",
            "avg_packet_length_delta",
            "header_length_ratio",
            "down_up_ratio_clipped",
            "active_idle_ratio",
            "bulk_forward_indicator",
            "bulk_backward_indicator",
            "is_tcp",
            "is_udp",
            "is_well_known_port",
            "is_high_port",
            "syn_ack_flag_ratio",
            "reset_flag_present",
            "urgent_flag_present",
        ]

    def build_features(self, shard_df: pd.DataFrame) -> pd.DataFrame:
        """Build derived flow features for a shard."""
        df = shard_df.copy()

        numeric_defaults = {
            "tot_fwd_pkts": 0,
            "tot_bwd_pkts": 0,
            "totlen_fwd_pkts": 0,
            "totlen_bwd_pkts": 0,
            "flow_byts_per_s": 0,
            "flow_pkts_per_s": 0,
            "fwd_pkt_len_mean": 0,
            "bwd_pkt_len_mean": 0,
            "fwd_header_len": 0,
            "bwd_header_len": 0,
            "down_up_ratio": 0,
            "active_mean": 0,
            "idle_mean": 0,
            "fwd_byts_b_avg": 0,
            "bwd_byts_b_avg": 0,
            "protocol": 0,
            "dst_port": 0,
            "syn_flag_cnt": 0,
            "ack_flag_cnt": 0,
            "rst_flag_cnt": 0,
            "urg_flag_cnt": 0,
        }

        for column, default in numeric_defaults.items():
            if column not in df.columns:
                df[column] = default

        total_packets = df["tot_fwd_pkts"] + df["tot_bwd_pkts"]
        total_bytes = df["totlen_fwd_pkts"] + df["totlen_bwd_pkts"]

        df["total_packets"] = total_packets
        df["total_bytes"] = total_bytes
        df["bytes_per_packet"] = total_bytes / total_packets.replace(0, np.nan)
        df["fwd_bwd_packet_ratio"] = df["tot_fwd_pkts"] / df["tot_bwd_pkts"].replace(0, np.nan)
        df["fwd_bwd_bytes_ratio"] = df["totlen_fwd_pkts"] / df["totlen_bwd_pkts"].replace(0, np.nan)
        df["flow_bytes_per_second_log1p"] = np.log1p(df["flow_byts_per_s"].clip(lower=0))
        df["flow_packets_per_second_log1p"] = np.log1p(df["flow_pkts_per_s"].clip(lower=0))
        df["avg_packet_length_delta"] = df["fwd_pkt_len_mean"] - df["bwd_pkt_len_mean"]
        df["header_length_ratio"] = df["fwd_header_len"] / df["bwd_header_len"].replace(0, np.nan)
        df["down_up_ratio_clipped"] = df["down_up_ratio"].clip(lower=0, upper=1000)
        df["active_idle_ratio"] = df["active_mean"] / df["idle_mean"].replace(0, np.nan)
        df["bulk_forward_indicator"] = (df["fwd_byts_b_avg"] > 0).astype(int)
        df["bulk_backward_indicator"] = (df["bwd_byts_b_avg"] > 0).astype(int)
        df["is_tcp"] = (df["protocol"] == 6).astype(int)
        df["is_udp"] = (df["protocol"] == 17).astype(int)
        df["is_well_known_port"] = (df["dst_port"] <= 1024).astype(int)
        df["is_high_port"] = (df["dst_port"] >= 49152).astype(int)
        df["syn_ack_flag_ratio"] = df["syn_flag_cnt"] / df["ack_flag_cnt"].replace(0, np.nan)
        df["reset_flag_present"] = (df["rst_flag_cnt"] > 0).astype(int)
        df["urgent_flag_present"] = (df["urg_flag_cnt"] > 0).astype(int)

        derived_columns = self.get_feature_list()
        df[derived_columns] = df[derived_columns].replace([np.inf, -np.inf], np.nan).fillna(0)

        return df
