"""
CICIDS 2018 network-flow domain configuration.
"""

from dataclasses import dataclass, field
from src.core.base_config import BaseConfig


@dataclass
class CICIDS2018Config(BaseConfig):
    """Configuration for CICFlowMeter-based CICIDS2018 processing."""

    domain_name: str = "cicids2018"
    shard_key: str = "dst_port"
    num_shards: int = 256
    batch_size: int = 50000

    # This dataset is already aggregated into flows, so derived features are
    # mostly event-level rather than rolling-window features.
    feature_windows: list = field(default_factory=list)

    label_mode: str = "binary"  # binary, family, raw

    required_columns: list = field(
        default_factory=lambda: [
            "Dst Port",
            "Protocol",
            "Timestamp",
            "Flow Duration",
            "Tot Fwd Pkts",
            "Tot Bwd Pkts",
            "TotLen Fwd Pkts",
            "TotLen Bwd Pkts",
            "Label",
        ]
    )

    def __post_init__(self):
        """Validate network config."""
        super().__post_init__()
        assert self.shard_key == "dst_port", "CICFlowMeter subset should shard by dst_port"
        assert self.label_mode in {"binary", "family", "raw"}, "label_mode must be binary, family, or raw"
