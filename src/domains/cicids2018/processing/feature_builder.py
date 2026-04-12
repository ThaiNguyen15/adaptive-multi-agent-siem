"""
CICIDS 2018 network-flow feature builder.

The feature set is organized around behavior blocks instead of one flat list of
raw numeric columns. Raw flow metrics stay in the dataset for audit, but the
main derived features focus on transport, volume, directionality, timing, and
flag behavior.
"""

from __future__ import annotations

from typing import Dict

import numpy as np
import pandas as pd

from src.core.base_feature_builder import BaseFeatureBuilder


class CICIDS2018FeatureBuilder(BaseFeatureBuilder):
    """Build behavior-oriented features from CICFlowMeter flows."""

    def get_feature_list(self) -> list:
        """Return the derived feature schema."""
        return [
            "total_packets",
            "total_packets_log1p",
            "total_bytes",
            "total_bytes_log1p",
            "flow_duration_log1p",
            "bytes_per_packet",
            "bytes_per_packet_log1p",
            "fwd_packet_share",
            "bwd_packet_share",
            "fwd_byte_share",
            "bwd_byte_share",
            "packet_imbalance",
            "byte_imbalance",
            "fwd_bwd_packet_ratio",
            "fwd_bwd_packet_ratio_log1p",
            "fwd_bwd_bytes_ratio",
            "fwd_bwd_bytes_ratio_log1p",
            "flow_bytes_per_second_log1p",
            "flow_packets_per_second_log1p",
            "avg_packet_length_delta",
            "avg_packet_length_delta_abs_log1p",
            "header_length_ratio",
            "header_length_ratio_log1p",
            "down_up_ratio_clipped",
            "down_up_ratio_log1p",
            "active_mean_log1p",
            "idle_mean_log1p",
            "active_idle_ratio",
            "active_idle_ratio_log1p",
            "tcp_flag_pressure_log1p",
            "syn_flag_share",
            "ack_flag_share",
            "reset_flag_present",
            "urgent_flag_present",
            "is_tcp",
            "is_udp",
            "is_icmp",
            "is_system_port",
            "is_registered_port",
            "is_dynamic_port",
        ]

    def get_feature_blocks(self) -> Dict[str, list]:
        """Expose grouped feature blocks for downstream ablations."""
        return {
            "transport": [
                "is_tcp",
                "is_udp",
                "is_icmp",
                "is_system_port",
                "is_registered_port",
                "is_dynamic_port",
            ],
            "volume": [
                "total_packets",
                "total_packets_log1p",
                "total_bytes",
                "total_bytes_log1p",
                "bytes_per_packet",
                "bytes_per_packet_log1p",
                "avg_packet_length_delta",
                "avg_packet_length_delta_abs_log1p",
            ],
            "directionality": [
                "fwd_packet_share",
                "bwd_packet_share",
                "fwd_byte_share",
                "bwd_byte_share",
                "packet_imbalance",
                "byte_imbalance",
                "fwd_bwd_packet_ratio",
                "fwd_bwd_packet_ratio_log1p",
                "fwd_bwd_bytes_ratio",
                "fwd_bwd_bytes_ratio_log1p",
                "header_length_ratio",
                "header_length_ratio_log1p",
                "down_up_ratio_clipped",
                "down_up_ratio_log1p",
            ],
            "timing": [
                "flow_duration_log1p",
                "flow_bytes_per_second_log1p",
                "flow_packets_per_second_log1p",
                "active_mean_log1p",
                "idle_mean_log1p",
                "active_idle_ratio",
                "active_idle_ratio_log1p",
            ],
            "flags": [
                "tcp_flag_pressure_log1p",
                "syn_flag_share",
                "ack_flag_share",
                "reset_flag_present",
                "urgent_flag_present",
            ],
            "optional_token_block": [
                "protocol_token",
                "port_token",
                "transport_token",
            ],
        }

    def build_features(self, shard_df: pd.DataFrame) -> pd.DataFrame:
        """Build derived flow features for a shard."""
        df = shard_df.copy()

        numeric_defaults = {
            "flow_duration": 0.0,
            "tot_fwd_pkts": 0.0,
            "tot_bwd_pkts": 0.0,
            "totlen_fwd_pkts": 0.0,
            "totlen_bwd_pkts": 0.0,
            "flow_byts_per_s": 0.0,
            "flow_bytes_per_s": 0.0,
            "flow_pkts_per_s": 0.0,
            "fwd_pkt_len_mean": 0.0,
            "bwd_pkt_len_mean": 0.0,
            "fwd_header_len": 0.0,
            "bwd_header_len": 0.0,
            "down_up_ratio": 0.0,
            "active_mean": 0.0,
            "idle_mean": 0.0,
            "protocol": 0.0,
            "dst_port": 0.0,
            "syn_flag_cnt": 0.0,
            "ack_flag_cnt": 0.0,
            "rst_flag_cnt": 0.0,
            "urg_flag_cnt": 0.0,
        }

        for column, default in numeric_defaults.items():
            if column not in df.columns:
                df[column] = default

        flow_bytes_per_second = df["flow_byts_per_s"].where(
            df["flow_byts_per_s"] > 0, df["flow_bytes_per_s"]
        )

        total_packets = df["tot_fwd_pkts"] + df["tot_bwd_pkts"]
        total_bytes = df["totlen_fwd_pkts"] + df["totlen_bwd_pkts"]

        fwd_packet_share = self._safe_ratio(df["tot_fwd_pkts"], total_packets)
        bwd_packet_share = self._safe_ratio(df["tot_bwd_pkts"], total_packets)
        fwd_byte_share = self._safe_ratio(df["totlen_fwd_pkts"], total_bytes)
        bwd_byte_share = self._safe_ratio(df["totlen_bwd_pkts"], total_bytes)

        packet_imbalance = fwd_packet_share - bwd_packet_share
        byte_imbalance = fwd_byte_share - bwd_byte_share

        fwd_bwd_packet_ratio = self._safe_ratio(df["tot_fwd_pkts"], df["tot_bwd_pkts"])
        fwd_bwd_bytes_ratio = self._safe_ratio(df["totlen_fwd_pkts"], df["totlen_bwd_pkts"])
        header_length_ratio = self._safe_ratio(df["fwd_header_len"], df["bwd_header_len"])
        active_idle_ratio = self._safe_ratio(df["active_mean"], df["idle_mean"])

        tcp_flag_pressure = df["syn_flag_cnt"] + df["ack_flag_cnt"] + df["rst_flag_cnt"] + df["urg_flag_cnt"]

        df["total_packets"] = total_packets
        df["total_packets_log1p"] = self._log1p(total_packets)
        df["total_bytes"] = total_bytes
        df["total_bytes_log1p"] = self._log1p(total_bytes)
        df["flow_duration_log1p"] = self._log1p(df["flow_duration"])
        bytes_per_packet = self._safe_ratio(total_bytes, total_packets)
        df["bytes_per_packet"] = bytes_per_packet
        df["bytes_per_packet_log1p"] = self._log1p(bytes_per_packet)

        df["fwd_packet_share"] = fwd_packet_share
        df["bwd_packet_share"] = bwd_packet_share
        df["fwd_byte_share"] = fwd_byte_share
        df["bwd_byte_share"] = bwd_byte_share
        df["packet_imbalance"] = packet_imbalance
        df["byte_imbalance"] = byte_imbalance

        df["fwd_bwd_packet_ratio"] = self._clip_ratio(fwd_bwd_packet_ratio)
        df["fwd_bwd_packet_ratio_log1p"] = self._log1p(df["fwd_bwd_packet_ratio"])
        df["fwd_bwd_bytes_ratio"] = self._clip_ratio(fwd_bwd_bytes_ratio)
        df["fwd_bwd_bytes_ratio_log1p"] = self._log1p(df["fwd_bwd_bytes_ratio"])

        df["flow_bytes_per_second_log1p"] = self._log1p(flow_bytes_per_second)
        df["flow_packets_per_second_log1p"] = self._log1p(df["flow_pkts_per_s"])

        avg_packet_length_delta = df["fwd_pkt_len_mean"] - df["bwd_pkt_len_mean"]
        df["avg_packet_length_delta"] = avg_packet_length_delta
        df["avg_packet_length_delta_abs_log1p"] = self._log1p(avg_packet_length_delta.abs())

        df["header_length_ratio"] = self._clip_ratio(header_length_ratio)
        df["header_length_ratio_log1p"] = self._log1p(df["header_length_ratio"])

        down_up_ratio_clipped = df["down_up_ratio"].clip(lower=0, upper=1_000)
        df["down_up_ratio_clipped"] = down_up_ratio_clipped
        df["down_up_ratio_log1p"] = self._log1p(down_up_ratio_clipped)

        df["active_mean_log1p"] = self._log1p(df["active_mean"])
        df["idle_mean_log1p"] = self._log1p(df["idle_mean"])
        df["active_idle_ratio"] = self._clip_ratio(active_idle_ratio)
        df["active_idle_ratio_log1p"] = self._log1p(df["active_idle_ratio"])

        df["tcp_flag_pressure_log1p"] = self._log1p(tcp_flag_pressure)
        df["syn_flag_share"] = self._safe_ratio(df["syn_flag_cnt"], tcp_flag_pressure)
        df["ack_flag_share"] = self._safe_ratio(df["ack_flag_cnt"], tcp_flag_pressure)
        df["reset_flag_present"] = (df["rst_flag_cnt"] > 0).astype(int)
        df["urgent_flag_present"] = (df["urg_flag_cnt"] > 0).astype(int)

        df["is_tcp"] = (df["protocol"] == 6).astype(int)
        df["is_udp"] = (df["protocol"] == 17).astype(int)
        df["is_icmp"] = (df["protocol"] == 1).astype(int)
        df["is_system_port"] = (df["dst_port"] <= 1023).astype(int)
        df["is_registered_port"] = ((df["dst_port"] >= 1024) & (df["dst_port"] <= 49151)).astype(int)
        df["is_dynamic_port"] = (df["dst_port"] >= 49152).astype(int)

        derived_columns = self.get_feature_list()
        df[derived_columns] = (
            df[derived_columns]
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0.0)
            .astype(float)
        )

        for indicator_column in [
            "reset_flag_present",
            "urgent_flag_present",
            "is_tcp",
            "is_udp",
            "is_icmp",
            "is_system_port",
            "is_registered_port",
            "is_dynamic_port",
        ]:
            df[indicator_column] = df[indicator_column].astype(int)

        return df

    @staticmethod
    def _safe_ratio(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
        """Divide safely and return zeros where the denominator is zero."""
        denominator = denominator.replace(0, np.nan)
        return numerator / denominator

    @staticmethod
    def _clip_ratio(series: pd.Series, upper: float = 1_000.0) -> pd.Series:
        """Clip unstable positive ratios caused by tiny denominators."""
        return series.clip(lower=0.0, upper=upper)

    @staticmethod
    def _log1p(series: pd.Series) -> pd.Series:
        """Stabilize heavy-tailed positive-valued flow metrics."""
        return np.log1p(series.clip(lower=0.0))


__all__ = ["CICIDS2018FeatureBuilder"]
