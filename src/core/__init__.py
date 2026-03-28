"""
Core modules for multi-domain log processing pipeline.

Provides abstract base classes and shared utilities for:
- Configuration management
- Data normalization
- Sharding
- Feature engineering
- Train/Val/Test splitting
"""

from .base_config import BaseConfig
from .base_normalizer import BaseNormalizer
from .base_feature_builder import BaseFeatureBuilder
from .sharding import HashSharding
from .splitter import TimeBasedSplitter
from .utils import ensure_dir, load_config_yaml, save_config_yaml

__all__ = [
    "BaseConfig",
    "BaseNormalizer",
    "BaseFeatureBuilder",
    "HashSharding",
    "TimeBasedSplitter",
    "ensure_dir",
    "load_config_yaml",
    "save_config_yaml",
]
