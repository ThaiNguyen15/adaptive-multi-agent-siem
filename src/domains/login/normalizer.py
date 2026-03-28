"""
Login domain normalizer.

Normalizes raw login logs to standard schema:
- user_id (string)
- ip (string)
- country (string)
- region (string)
- city (string)
- device (string)
- login_timestamp (datetime)
- login_successful (int)
"""

import pandas as pd
from src.core.base_normalizer import BaseNormalizer


class LoginNormalizer(BaseNormalizer):
    """Normalize login logs to standard schema."""

    COLUMN_MAP = {
        "User ID": "user_id",
        "IP Address": "ip",
        "Country": "country",
        "Region": "region",
        "City": "city",
        "Device Type": "device",
        "Login Timestamp": "login_timestamp",
        "Login Successful": "login_successful",
    }

    STANDARD_COLUMNS = [
        "user_id",
        "ip",
        "country",
        "region",
        "city",
        "device",
        "login_timestamp",
        "login_successful",
    ]

    @staticmethod
    def _to_binary(series: pd.Series, default: int = 0) -> pd.Series:
        """Convert common boolean-like values to 0/1 integers."""
        normalized = series.astype(str).str.strip().str.lower().map(
            {"true": 1, "false": 0, "1": 1, "0": 0, "yes": 1, "no": 0}
        )
        numeric = pd.to_numeric(series, errors="coerce")
        return normalized.fillna(numeric).fillna(default).astype(int)

    def validate_raw_schema(self, df: pd.DataFrame) -> bool:
        """Validate required columns exist.

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
        """Normalize to standard schema.

        Args:
            df: Raw dataframe

        Returns:
            Normalized dataframe
        """
        df = df.copy()

        # Rename raw dataset columns to the login domain schema.
        df = df.rename(columns=self.COLUMN_MAP)
        df = df[self.STANDARD_COLUMNS]

        df["login_timestamp"] = pd.to_datetime(df["login_timestamp"], errors="coerce", utc=True)

        df["user_id"] = df["user_id"].astype(str)
        df["ip"] = df["ip"].fillna("unknown").astype(str)
        df["country"] = df["country"].fillna("unknown").astype(str)
        df["region"] = df["region"].fillna("unknown").astype(str)
        df["city"] = df["city"].fillna("unknown").astype(str)
        df["device"] = df["device"].fillna("unknown").astype(str)
        df["login_successful"] = self._to_binary(df["login_successful"])

        df = df.sort_values(["user_id", "login_timestamp"]).reset_index(drop=True)

        return df

    def get_output_schema(self) -> dict:
        """Return normalized schema.

        Returns:
            Column -> dtype mapping
        """
        return {
            "user_id": "object",
            "ip": "object",
            "country": "object",
            "region": "object",
            "city": "object",
            "device": "object",
            "login_timestamp": "datetime64[ns, UTC]",
            "login_successful": "int64",
        }
