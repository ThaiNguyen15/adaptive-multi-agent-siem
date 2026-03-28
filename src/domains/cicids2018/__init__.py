"""
CICIDS 2018 Network domain package.

Example structure for adding a new domain (network traffic classification).
Follow this template to add other domains (agent_logs, etc.)
"""

from .config import CICIDS2018Config
from .normalizer import CICIDS2018Normalizer
from .feature_builder import CICIDS2018FeatureBuilder
from .pipeline import CICIDS2018Pipeline

__all__ = [
    "CICIDS2018Config",
    "CICIDS2018Normalizer",
    "CICIDS2018FeatureBuilder",
    "CICIDS2018Pipeline",
]
