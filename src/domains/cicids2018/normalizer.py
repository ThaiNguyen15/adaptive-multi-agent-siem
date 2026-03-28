"""
CICIDS 2018 Network domain normalizer.

Normalizes network flow data to standard schema.
Different normalization logic compared to login domain.
"""

import pandas as pd
from src.core.base_normalizer import BaseNormalizer


class CICIDS2018Normalizer(BaseNormalizer):
    """Normalize CICIDS2018 network flows to standard schema.

    Example showing different normalization logic for network domain.
    """

    STANDARD_COLUMNS = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "protocol",
        "duration",
        "fwd_packets",
        "bwd_packets",
        "label",  # benign or attack type
    ]

    def validate_raw_schema(self, df: pd.DataFrame) -> bool:
        """Validate CICIDS2018 required columns exist.

        Args:
            df: Raw dataframe

        Returns:
            True if valid

        Raises:
            ValueError if validation fails
        """
        required = self.config.required_columns
        missing = set(required) - set(df.columns)

        if missing:
            raise ValueError(f"Missing required columns: {missing}")

        return True

    def normalize(self, df: pd.DataFrame) -> pd.DataFrame:
        """Normalize network flow data to standard schema.

        Args:
            df: Raw dataframe from CICIDS2018 CSV

        Returns:
            Normalized dataframe
        """
        df = df.copy()

        # Rename columns to standard names
        rename_map = {
            "Timestamp": "timestamp",
            "Src IP": "src_ip",
            "Dst IP": "dst_ip",
            "Protocol": "protocol",
            "Flow Duration": "duration",
            "Tot Fwd Pkts": "fwd_packets",
            "Tot Bwd Pkts": "bwd_packets",
            "Label": "label",
        }

        df = df.rename(columns=rename_map)
        df = df[self.STANDARD_COLUMNS]

        # Convert timestamp to datetime
        df["timestamp"] = pd.to_datetime(df["timestamp"])

        # Convert IPs to string
        df["src_ip"] = df["src_ip"].astype(str)
        df["dst_ip"] = df["dst_ip"].astype(str)

        # Standardize labels (benign or specific attack)
        label_lower = df["label"].astype(str).str.lower()
        df["label"] = label_lower.apply(
            lambda x: "benign" if x == "benign" else "attack" if x != "benign" else "unknown"
        )

        # Convert numeric columns
        df["duration"] = pd.to_numeric(df["duration"], errors="coerce").fillna(0)
        df["fwd_packets"] = pd.to_numeric(df["fwd_packets"], errors="coerce").fillna(0).astype(int)
        df["bwd_packets"] = pd.to_numeric(df["bwd_packets"], errors="coerce").fillna(0).astype(int)

        # Sort by src_ip and timestamp
        df = df.sort_values(["src_ip", "timestamp"]).reset_index(drop=True)

        return df

    def get_output_schema(self) -> dict:
        """Return normalized schema.

        Returns:
            Column -> dtype mapping
        """
        return {
            "timestamp": "datetime64[ns]",
            "src_ip": "object",
            "dst_ip": "object",
            "protocol": "object",
            "duration": "float64",
            "fwd_packets": "int64",
            "bwd_packets": "int64",
            "label": "object",
        }
