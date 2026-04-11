"""
Login domain normalizer.

Normalizes raw login logs to standard schema:
- user_id (string)
- ip (string)
- country (string)
- region (string)
- city (string)
- device (string)
- ip_token (string)
- device_token (string)
- geo_token (string)
- context_token (string)
- login_timestamp (datetime)
- login_successful (int)
"""

import ipaddress
import re

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

    RAW_COLUMNS = [
        "user_id",
        "ip",
        "country",
        "region",
        "city",
        "device",
        "login_timestamp",
        "login_successful",
    ]

    STANDARD_COLUMNS = [
        "user_id",
        "ip",
        "country",
        "region",
        "city",
        "device",
        "ip_token",
        "device_token",
        "geo_token",
        "context_token",
        "login_timestamp",
        "login_successful",
    ]

    DEVICE_PATTERNS = [
        ("mobile", ("android", "iphone", "ios", "mobile", "phone")),
        ("tablet", ("ipad", "tablet")),
        ("desktop", ("windows", "mac", "linux", "desktop", "laptop", "pc")),
        ("server", ("server", "vm", "container", "bot", "crawler")),
    ]

    @staticmethod
    def _to_binary(series: pd.Series, default: int = 0) -> pd.Series:
        """Convert common boolean-like values to 0/1 integers."""
        normalized = series.astype(str).str.strip().str.lower().map(
            {"true": 1, "false": 0, "1": 1, "0": 0, "yes": 1, "no": 0}
        )
        numeric = pd.to_numeric(series, errors="coerce")
        return normalized.fillna(numeric).fillna(default).astype(int)

    @staticmethod
    def _normalize_text(series: pd.Series, unknown: str = "unknown") -> pd.Series:
        """Normalize noisy categorical text into a stable lowercase form."""
        normalized = (
            series.fillna(unknown)
            .astype(str)
            .str.strip()
            .str.lower()
            .replace(
                {
                    "": unknown,
                    "-": unknown,
                    "--": unknown,
                    "n/a": unknown,
                    "na": unknown,
                    "nan": unknown,
                    "none": unknown,
                    "null": unknown,
                }
            )
        )
        return normalized.str.replace(r"\s+", " ", regex=True)

    @staticmethod
    def _map_ip_token(ip_value: str) -> str:
        """Map raw IP strings to a low-cardinality token."""
        if ip_value in {"", "unknown", "nan", "none", "null"}:
            return "unknown_ip"

        try:
            parsed_ip = ipaddress.ip_address(ip_value)
        except ValueError:
            return "invalid_ip"

        version = f"ipv{parsed_ip.version}"
        if parsed_ip.is_private:
            return f"{version}_private"
        if parsed_ip.is_loopback:
            return f"{version}_loopback"
        if parsed_ip.is_multicast:
            return f"{version}_multicast"
        if parsed_ip.is_reserved:
            return f"{version}_reserved"
        return f"{version}_public"

    @classmethod
    def _map_device_token(cls, device_value: str) -> str:
        """Reduce raw device descriptions to a stable device-family token."""
        if device_value in {"", "unknown", "nan", "none", "null"}:
            return "unknown_device"

        compact = re.sub(r"\s+", " ", device_value.strip().lower())
        for token, patterns in cls.DEVICE_PATTERNS:
            if any(pattern in compact for pattern in patterns):
                return token
        return "other_device"

    @staticmethod
    def _build_geo_token(country: str, region: str, city: str) -> str:
        """Represent the resolution of geo context without memorizing the exact location."""
        known_country = country != "unknown"
        known_region = region != "unknown"
        known_city = city != "unknown"

        if known_country and known_region and known_city:
            return "geo_country_region_city"
        if known_country and known_region:
            return "geo_country_region"
        if known_country:
            return "geo_country_only"
        return "geo_unknown"

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
        df = df[self.RAW_COLUMNS]

        df["login_timestamp"] = pd.to_datetime(df["login_timestamp"], errors="coerce", utc=True)

        df["user_id"] = self._normalize_text(df["user_id"])
        df["ip"] = self._normalize_text(df["ip"])
        df["country"] = self._normalize_text(df["country"])
        df["region"] = self._normalize_text(df["region"])
        df["city"] = self._normalize_text(df["city"])
        df["device"] = self._normalize_text(df["device"])
        df["ip_token"] = df["ip"].map(self._map_ip_token)
        df["device_token"] = df["device"].map(self._map_device_token)
        df["geo_token"] = [
            self._build_geo_token(country, region, city)
            for country, region, city in zip(df["country"], df["region"], df["city"])
        ]
        df["context_token"] = (
            df["ip_token"] + "|" + df["device_token"] + "|" + df["geo_token"]
        )
        df["login_successful"] = self._to_binary(df["login_successful"])
        df = df[self.STANDARD_COLUMNS]

        # Strictly-past feature building depends on valid timestamps and a stable user key.
        df = df.dropna(subset=["login_timestamp"]).copy()
        df = df[df["user_id"] != "unknown"].copy()
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
            "ip_token": "object",
            "device_token": "object",
            "geo_token": "object",
            "context_token": "object",
            "login_timestamp": "datetime64[ns, UTC]",
            "login_successful": "int64",
        }
