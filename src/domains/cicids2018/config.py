"""
CICIDS 2018 Network domain configuration.

Example of configuring a different domain with:
- Different shard_key (src_ip instead of user_id)
- Different feature windows
- Different required columns
"""

from dataclasses import dataclass, field
from pathlib import Path
from src.core.base_config import BaseConfig


@dataclass
class CICIDS2018Config(BaseConfig):
    """Configuration specific to CICIDS 2018 network domain."""

    domain_name: str = "cicids2018"
    shard_key: str = "src_ip"  # Different from login (which uses user_id)
    num_shards: int = 512  # More shards for network traffic
    batch_size: int = 50000  # Larger batches for network data

    # Feature configuration - different windows for network
    feature_windows: list = field(default_factory=lambda: [0.01, 0.1, 1])  # Hours

    # CICIDS2018-specific required columns
    required_columns: list = field(
        default_factory=lambda: [
            "Timestamp",
            "Src IP",
            "Dst IP",
            "Protocol",
            "Flow Duration",
            "Tot Fwd Pkts",
            "Tot Bwd Pkts",
            "Label",  # Benign or Attack type
        ]
    )

    def __post_init__(self):
        """Validate network config."""
        super().__post_init__()
        assert self.shard_key == "src_ip", "Network must shard by src_ip"


@dataclass
class AgentLogsConfig(BaseConfig):
    """Configuration for agent logs domain.

    Placeholder for future implementation.
    """

    domain_name: str = "agent_logs"
    shard_key: str = "agent_id"
    num_shards: int = 128
    batch_size: int = 5000

    feature_windows: list = field(default_factory=lambda: [0.5, 4, 24])  # Hours

    required_columns: list = field(
        default_factory=lambda: [
            "timestamp",
            "agent_id",
            "event_type",
            "severity",
            "message",
            "context_id",
        ]
    )
