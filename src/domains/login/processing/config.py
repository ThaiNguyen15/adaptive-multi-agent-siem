"""
Login domain configuration.
"""

from dataclasses import dataclass, field
from src.core.base_config import BaseConfig


@dataclass
class LoginConfig(BaseConfig):
    """Configuration specific to login domain."""

    domain_name: str = "login"
    shard_key: str = "user_id"
    num_shards: int = 256
    batch_size: int = 10000

    # Feature configuration
    feature_windows: list = field(default_factory=lambda: [1, 7, 30])  # days

    # Login-specific columns
    required_columns: list = field(
        default_factory=lambda: [
            "User ID",
            "IP Address",
            "Country",
            "Region",
            "City",
            "Device Type",
            "Login Timestamp",
            "Login Successful",
        ]
    )

    def __post_init__(self):
        """Validate login config."""
        super().__post_init__()
        assert self.shard_key == "user_id", "Login must shard by user_id"
