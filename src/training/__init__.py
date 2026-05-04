"""
Training stage for tabular experiments.
"""

from .config import ExperimentConfig

__all__ = ["ExperimentConfig", "TrainingRunner"]


def __getattr__(name: str):
    """Import heavy training helpers only when requested."""
    if name == "TrainingRunner":
        from .runner import TrainingRunner

        return TrainingRunner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
