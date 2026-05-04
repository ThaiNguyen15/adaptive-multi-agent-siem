"""
Evaluation stage helpers.
"""

__all__ = ["EvaluationRunner"]


def __getattr__(name: str):
    """Import pandas-backed evaluation runner only when requested."""
    if name == "EvaluationRunner":
        from .runner import EvaluationRunner

        return EvaluationRunner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
