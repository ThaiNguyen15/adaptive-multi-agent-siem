"""
CICIDS 2018 network-flow normalizer.

This version is designed for CICFlowMeter CSV exports such as the local
`data/raw/cicflowmeter/Processed Traffic Data for ML Algorithms` subset.
"""

from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pandas as pd

from src.core.base_normalizer import BaseNormalizer


def _snake_case(value: str) -> str:
    """Convert CICFlowMeter headers to normalized snake_case names."""
    value = value.strip()
    value = value.replace("/", "_per_")
    value = value.replace("(", "").replace(")", "")
    value = value.replace("-", "_")
    value = value.replace(".", "_")
    value = re.sub(r"[^0-9a-zA-Z]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value.lower()


class CICIDS2018Normalizer(BaseNormalizer):
    """Normalize CICFlowMeter CSV files to a training-friendly schema."""

    ATTACK_FAMILY_RULES = [
        ("benign", "Benign"),
        ("bot", "Bot"),
        ("brute force", "Brute Force"),
        ("ftp_bruteforce", "Brute Force"),
        ("ssh_bruteforce", "Brute Force"),
        ("ddos", "DDoS"),
        ("dos", "DoS"),
        ("web attack", "Web Attack"),
        ("sql injection", "Web Attack"),
        ("xss", "Web Attack"),
        ("infilteration", "Infiltration"),
        ("infiltration", "Infiltration"),
        ("heartbleed", "Heartbleed"),
    ]

    REQUIRED_COLUMNS_NORMALIZED = [
        "dst_port",
        "protocol",
        "timestamp",
        "flow_duration",
        "tot_fwd_pkts",
        "tot_bwd_pkts",
        "totlen_fwd_pkts",
        "totlen_bwd_pkts",
        "attack_label_raw",
    ]

    def validate_raw_schema(self, df: pd.DataFrame) -> bool:
        """Validate required columns exist in the raw CSV."""
        required = self.config.required_columns
        missing = set(required) - set(df.columns)
        if missing:
            raise ValueError(f"Missing required columns: {missing}")
        return True

    def normalize(self, df: pd.DataFrame) -> pd.DataFrame:
        """Normalize CICFlowMeter flow data."""
        df = df.copy()

        self.validate_raw_schema(df)

        # Drop duplicated header rows sometimes embedded inside large CSVs.
        if "Label" in df.columns:
            df = df[df["Label"].astype(str).str.strip() != "Label"].copy()

        rename_map = {column: _snake_case(column) for column in df.columns}
        df = df.rename(columns=rename_map)

        if "label" not in df.columns:
            raise ValueError("Expected 'Label' column after normalization")

        df = df.rename(columns={"label": "attack_label_raw"})
        df["attack_label_raw"] = df["attack_label_raw"].fillna("Unknown").astype(str).str.strip()

        # Parse timestamp using day-first because local files use DD/MM/YYYY.
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", dayfirst=True)

        df["source_file"] = "unknown"
        df["row_index"] = np.arange(len(df), dtype=np.int64)
        df["event_id"] = "unknown"

        # Convert all non-metadata, non-label columns to numeric where possible.
        metadata_columns = {"event_id", "source_file", "row_index", "timestamp", "attack_label_raw"}
        for column in df.columns:
            if column in metadata_columns:
                continue
            df[column] = pd.to_numeric(df[column], errors="coerce")

        df = df.replace([np.inf, -np.inf], np.nan)
        numeric_columns = df.select_dtypes(include=["number"]).columns.tolist()
        fill_exclusions = {"label_binary"}
        for column in numeric_columns:
            if column in fill_exclusions:
                continue
            df[column] = df[column].fillna(0)

        df["dst_port"] = df["dst_port"].astype(int)
        df["protocol"] = df["protocol"].astype(int)

        df["attack_family"] = df["attack_label_raw"].apply(self._map_attack_family)
        df["label_binary"] = (df["attack_family"] != "Benign").astype(int)
        df["label_known"] = 1
        df["target_label"] = self._build_target_label(df)

        required_after = set(self.REQUIRED_COLUMNS_NORMALIZED) - set(df.columns)
        if required_after:
            raise ValueError(f"Missing normalized columns: {required_after}")

        # Reorder key columns first, keep the rest of the numeric flow metrics.
        priority_columns = [
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
            "target_label",
        ]
        remaining_columns = [column for column in df.columns if column not in priority_columns]
        df = df[priority_columns + remaining_columns]

        df = df.sort_values(["timestamp", "row_index"]).reset_index(drop=True)
        return df

    def process_file(self, input_path: Path) -> pd.DataFrame:
        """Load, normalize, and annotate a single CSV file."""
        df = pd.read_csv(input_path, low_memory=False)
        normalized_df = self.normalize(df)
        normalized_df["source_file"] = input_path.name
        normalized_df["event_id"] = normalized_df.apply(
            lambda row: f"{Path(input_path.name).stem}:{int(row['row_index'])}",
            axis=1,
        )
        self.logger.info(f"Normalized {len(normalized_df)} rows from {input_path.name}")
        return normalized_df

    def get_output_schema(self) -> dict:
        """Return the core normalized schema for key columns."""
        return {
            "event_id": "object",
            "source_file": "object",
            "row_index": "int64",
            "timestamp": "datetime64[ns]",
            "dst_port": "int64",
            "protocol": "int64",
            "attack_label_raw": "object",
            "attack_family": "object",
            "label_binary": "int64",
            "label_known": "int64",
            "target_label": "object",
        }

    def _map_attack_family(self, label: str) -> str:
        """Map raw labels to coarser attack families."""
        lowered = str(label).strip().lower()
        for token, family in self.ATTACK_FAMILY_RULES:
            if token in lowered:
                return family
        return "Unknown"

    def _build_target_label(self, df: pd.DataFrame) -> pd.Series:
        """Build the downstream target column requested by label_mode."""
        if self.config.label_mode == "binary":
            return df["label_binary"].astype(str)
        if self.config.label_mode == "family":
            return df["attack_family"].astype(str)
        return df["attack_label_raw"].astype(str)
