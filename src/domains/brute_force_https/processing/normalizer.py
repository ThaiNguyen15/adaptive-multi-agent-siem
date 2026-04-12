"""
Normalizer for the CESNET HTTPS brute-force dataset.
"""

from __future__ import annotations

from pathlib import Path
import re

import numpy as np
import pandas as pd

from src.core.base_normalizer import BaseNormalizer


def _snake_case(value: str) -> str:
    """Convert source headers to normalized snake_case names."""
    value = value.strip()
    value = value.replace("/", "_per_")
    value = value.replace("-", "_")
    value = value.replace(".", "_")
    value = re.sub(r"[^0-9a-zA-Z]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value.lower()


class BruteForceHTTPSNormalizer(BaseNormalizer):
    """Normalize flow-level and sample-level brute-force CSV exports."""

    FILE_NAME_BY_VIEW = {
        "flows": "flows.csv",
        "aggregated_flows": "aggregated_flows.csv",
        "samples": "samples.csv",
    }

    BASE_NUMERIC_COLUMNS = [
        "dst_port",
        "protocol",
        "bytes",
        "bytes_rev",
        "packets",
        "packets_rev",
        "class",
    ]

    def validate_raw_schema(self, df: pd.DataFrame) -> bool:
        required = self.config.required_columns
        missing = set(required) - set(df.columns)
        if missing:
            raise ValueError(f"Missing required columns: {missing}")
        return True

    def normalize(self, df: pd.DataFrame) -> pd.DataFrame:
        """Normalize the selected brute-force source view."""
        df = df.copy()
        self.validate_raw_schema(df)

        rename_map = {column: _snake_case(column) for column in df.columns}
        df = df.rename(columns=rename_map)

        df["time_first"] = pd.to_datetime(df["time_first"], errors="coerce", utc=True)
        df["time_last"] = pd.to_datetime(df["time_last"], errors="coerce", utc=True)
        df["event_timestamp"] = df["time_first"]

        for column in self.BASE_NUMERIC_COLUMNS:
            if column in df.columns:
                df[column] = pd.to_numeric(df[column], errors="coerce")

        extra_numeric = [
            "roundtrips",
            "duration",
            "ppi_duration",
            "roundtrips_per_sec",
            "packets_per_sec",
            "bytes_per_sec",
            "max_idle",
            "download_ratio",
        ]
        for column in extra_numeric:
            if column in df.columns:
                df[column] = pd.to_numeric(df[column], errors="coerce")

        df = df.replace([np.inf, -np.inf], np.nan)

        for column in df.select_dtypes(include=["number"]).columns:
            df[column] = df[column].fillna(0)

        for column in ["dst_port", "protocol", "class"]:
            if column in df.columns:
                df[column] = df[column].astype(int)

        df["class"] = df["class"].astype(int)
        df["label_binary"] = df["class"]
        df["label_known"] = 1
        df["scenario"] = df["scenario"].fillna("unknown").astype(str).str.strip()
        df["attack_tool"] = df["scenario"].apply(self._extract_attack_tool)
        df["target_app"] = df["scenario"].apply(self._extract_target_app)
        df["attack_label_raw"] = df["scenario"]
        df["target_label"] = self._build_target_label(df)

        for text_col in ["src_ip", "dst_ip", "src_port", "tls_sni", "tls_ja3"]:
            if text_col not in df.columns:
                df[text_col] = ""
            df[text_col] = df[text_col].fillna("").astype(str)

        df["service_key"] = df.apply(
            lambda row: self._build_service_key(
                row.get("tls_sni", ""),
                row.get("dst_ip", ""),
                row.get("dst_port", 0),
                row.get("protocol", 0),
            ),
            axis=1,
        )
        df["event_id"] = np.arange(len(df), dtype=np.int64).astype(str)
        df["source_file"] = self.FILE_NAME_BY_VIEW[self.config.input_view]
        df["input_view"] = self.config.input_view

        if "duration" not in df.columns:
            duration = (df["time_last"] - df["time_first"]).dt.total_seconds()
            df["duration"] = duration.fillna(0).clip(lower=0)

        df = df.sort_values(["event_timestamp", "service_key"]).reset_index(drop=True)

        priority_columns = [
            "event_id",
            "source_file",
            "input_view",
            "event_timestamp",
            "time_first",
            "time_last",
            "duration",
            "service_key",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "tls_sni",
            "tls_ja3",
            "scenario",
            "attack_tool",
            "target_app",
            "attack_label_raw",
            "label_binary",
            "label_known",
            "target_label",
        ]
        remaining = [column for column in df.columns if column not in priority_columns]
        return df[priority_columns + remaining]

    def process_batch(self, input_dir: Path, pattern: str = "*.csv") -> pd.DataFrame:
        """Process only the selected source view from the dataset directory."""
        input_dir = Path(input_dir)
        selected_name = self.FILE_NAME_BY_VIEW[self.config.input_view]
        input_path = input_dir / selected_name
        if not input_path.exists():
            raise FileNotFoundError(f"Expected dataset view not found: {input_path}")
        return self.process_file(input_path)

    def process_file(self, input_path: Path) -> pd.DataFrame:
        """Load, normalize, and annotate the selected CSV."""
        df = pd.read_csv(input_path, low_memory=False)
        normalized_df = self.normalize(df)
        normalized_df["source_file"] = input_path.name
        normalized_df["event_id"] = normalized_df.index.astype(str).map(
            lambda idx: f"{Path(input_path.name).stem}:{idx}"
        )
        self.logger.info(f"Normalized {len(normalized_df)} rows from {input_path.name}")
        return normalized_df

    def get_output_schema(self) -> dict:
        """Return the core normalized output schema."""
        return {
            "event_id": "object",
            "source_file": "object",
            "input_view": "object",
            "event_timestamp": "datetime64[ns, UTC]",
            "time_first": "datetime64[ns, UTC]",
            "time_last": "datetime64[ns, UTC]",
            "duration": "float64",
            "service_key": "object",
            "scenario": "object",
            "attack_tool": "object",
            "target_app": "object",
            "label_binary": "int64",
            "label_known": "int64",
            "target_label": "object",
        }

    def _build_target_label(self, df: pd.DataFrame) -> pd.Series:
        if self.config.label_mode == "binary":
            return df["label_binary"].astype(str)
        if self.config.label_mode == "scenario":
            return df["scenario"].astype(str)
        if self.config.label_mode == "tool":
            return df["attack_tool"].astype(str)
        if self.config.label_mode == "app":
            return df["target_app"].astype(str)
        return df["attack_label_raw"].astype(str)

    @staticmethod
    def _extract_attack_tool(scenario: str) -> str:
        scenario = str(scenario).strip().lower()
        if scenario.startswith("backbone_capture_"):
            return "benign"
        for tool in ["hydra", "patator", "ncrack"]:
            if scenario.endswith(f"_{tool}"):
                return tool
        return "unknown"

    @staticmethod
    def _extract_target_app(scenario: str) -> str:
        scenario = str(scenario).strip().lower()
        if scenario.startswith("backbone_capture_"):
            return "backbone_capture"
        for suffix in ["_hydra", "_patator", "_ncrack"]:
            if scenario.endswith(suffix):
                return scenario[: -len(suffix)]
        return scenario or "unknown"

    @staticmethod
    def _build_service_key(tls_sni: str, dst_ip: str, dst_port: int, protocol: int) -> str:
        service_name = tls_sni or dst_ip or "unknown"
        return f"{service_name}:{int(dst_port)}:{int(protocol)}"


__all__ = ["BruteForceHTTPSNormalizer"]
