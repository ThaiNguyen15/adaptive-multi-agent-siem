"""
CICIDS 2018 Network domain package.

Example structure for adding a new domain (network traffic classification).
Follow this template to add other domains (agent_logs, etc.)
"""

from .processing import (
    CICIDS2018Config,
    CICIDS2018Normalizer,
    CICIDS2018FeatureBuilder,
    CICIDS2018Pipeline,
    CICIDS2018DatasetProfiler,
)

__all__ = [
    "CICIDS2018Config",
    "CICIDS2018Normalizer",
    "CICIDS2018FeatureBuilder",
    "CICIDS2018Pipeline",
    "CICIDS2018DatasetProfiler",
]
