"""
Base configuration class for all domains.

Provides centralized configuration management with:
- Input/output paths
- Processing parameters
- Feature engineering configs
- Split ratios
"""

from pathlib import Path
from typing import Dict, Any, Optional
import json
from dataclasses import dataclass, field, asdict


@dataclass
class BaseConfig:
    """Base configuration for log processing pipeline."""

    # Paths
    domain_name: str  # 'login', 'cicids2018', 'agent_logs'
    raw_data_dir: Path = None
    processed_data_dir: Path = None

    # Sharding
    num_shards: int = 256
    shard_key: str = None  # e.g., 'user_id', 'src_ip'

    # Processing
    batch_size: int = 10000

    # Splitting (time-based)
    train_ratio: float = 0.75
    val_ratio: float = 0.08
    test_ratio: float = 0.17
    timestamp_col: str = "timestamp"

    # Features
    feature_windows: list = field(default_factory=lambda: [1, 7, 30])  # days

    # Logging
    log_level: str = "INFO"
    verbose: bool = False

    def __post_init__(self):
        """Post-init config validation."""
        if self.raw_data_dir:
            self.raw_data_dir = Path(self.raw_data_dir)
        if self.processed_data_dir:
            self.processed_data_dir = Path(self.processed_data_dir)

        # Validate split ratios
        total = self.train_ratio + self.val_ratio + self.test_ratio
        assert abs(total - 1.0) < 1e-6, f"Split ratios must sum to 1.0, got {total}"

        if self.shard_key is None:
            raise ValueError(f"shard_key must be set for domain '{self.domain_name}'")

    def ensure_dirs(self) -> None:
        """Create required directories."""
        if self.raw_data_dir:
            self.raw_data_dir.mkdir(parents=True, exist_ok=True)
        if self.processed_data_dir:
            self.processed_data_dir.mkdir(parents=True, exist_ok=True)

    def get_shards_dir(self) -> Path:
        """Get shards output directory."""
        shard_dir = self.processed_data_dir / "shards"
        shard_dir.mkdir(parents=True, exist_ok=True)
        return shard_dir

    def get_features_dir(self) -> Path:
        """Get features output directory."""
        feat_dir = self.processed_data_dir / "features"
        feat_dir.mkdir(parents=True, exist_ok=True)
        return feat_dir

    def get_splits_dir(self) -> Path:
        """Get splits output directory."""
        splits_dir = self.processed_data_dir / "splits"
        splits_dir.mkdir(parents=True, exist_ok=True)
        return splits_dir

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        config_dict = asdict(self)
        if self.raw_data_dir:
            config_dict["raw_data_dir"] = str(self.raw_data_dir)
        if self.processed_data_dir:
            config_dict["processed_data_dir"] = str(self.processed_data_dir)
        return config_dict

    def save(self, filepath: Path) -> None:
        """Save config to JSON file."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    @classmethod
    def load(cls, filepath: Path) -> "BaseConfig":
        """Load config from JSON file."""
        with open(filepath, "r") as f:
            data = json.load(f)
        return cls(**data)
