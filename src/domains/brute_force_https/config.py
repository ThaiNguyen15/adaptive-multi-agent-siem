"""
HTTPS brute-force dataset domain configuration.
"""

from dataclasses import dataclass, field

from src.core.base_config import BaseConfig


@dataclass
class BruteForceHTTPSConfig(BaseConfig):
    """Configuration for the CESNET HTTPS brute-force dataset."""

    domain_name: str = "brute_force_https"
    shard_key: str = "service_key"
    num_shards: int = 128
    batch_size: int = 25000
    timestamp_col: str = "event_timestamp"
    feature_windows: list = field(default_factory=list)

    input_view: str = "aggregated_flows"  # samples, aggregated_flows, flows
    label_mode: str = "binary"  # binary, scenario, tool, app, raw

    required_columns_by_view: dict = field(
        default_factory=lambda: {
            "flows": [
                "SRC_IP",
                "DST_IP",
                "DST_PORT",
                "PROTOCOL",
                "TIME_FIRST",
                "TIME_LAST",
                "BYTES",
                "BYTES_REV",
                "PACKETS",
                "PACKETS_REV",
                "SCENARIO",
                "CLASS",
            ],
            "aggregated_flows": [
                "SRC_IP",
                "DST_IP",
                "DST_PORT",
                "PROTOCOL",
                "TIME_FIRST",
                "TIME_LAST",
                "BYTES",
                "BYTES_REV",
                "PACKETS",
                "PACKETS_REV",
                "ROUNDTRIPS",
                "SCENARIO",
                "CLASS",
            ],
            "samples": [
                "SRC_IP",
                "DST_IP",
                "DST_PORT",
                "PROTOCOL",
                "TIME_FIRST",
                "TIME_LAST",
                "DURATION",
                "BYTES",
                "BYTES_REV",
                "PACKETS",
                "PACKETS_REV",
                "SCENARIO",
                "CLASS",
            ],
        }
    )

    def __post_init__(self):
        super().__post_init__()
        assert self.input_view in {"flows", "aggregated_flows", "samples"}, (
            "input_view must be one of: flows, aggregated_flows, samples"
        )
        assert self.label_mode in {"binary", "scenario", "tool", "app", "raw"}, (
            "label_mode must be one of: binary, scenario, tool, app, raw"
        )

    @property
    def required_columns(self) -> list:
        """Return required columns for the configured source view."""
        return self.required_columns_by_view[self.input_view]

