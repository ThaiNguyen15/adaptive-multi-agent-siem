"""Training stage for API traffic domain."""

from .model import APIRetrievalModel


def __getattr__(name):
    """Lazily import runner to avoid training/evaluation circular imports."""
    if name == "APITrainingRunner":
        from .runner import APITrainingRunner

        return APITrainingRunner
    raise AttributeError(name)

__all__ = ["APIRetrievalModel", "APITrainingRunner"]
