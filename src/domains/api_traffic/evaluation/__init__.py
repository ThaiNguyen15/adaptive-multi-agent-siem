"""Evaluation stage for API traffic domain."""

__all__ = ["APIEvaluationRunner"]


def __getattr__(name: str):
    """Import evaluation runner only when requested."""
    if name == "APIEvaluationRunner":
        from .runner import APIEvaluationRunner

        return APIEvaluationRunner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
