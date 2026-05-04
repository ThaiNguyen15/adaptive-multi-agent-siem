"""
API traffic domain package.
"""

from .training import APIRetrievalModel

__all__ = [
    "APITrafficConfig",
    "APITrafficNormalizer",
    "APITrafficFeatureBuilder",
    "APITrafficPipeline",
    "APIRetrievalExperiment",
    "APIRetrievalModel",
    "APITrainingRunner",
    "APIEvaluationRunner",
    "APITestingRunner",
]


def __getattr__(name: str):
    """Import pandas-backed domain helpers only when requested."""
    if name in {"APITrafficConfig", "APITrafficNormalizer", "APITrafficFeatureBuilder", "APITrafficPipeline"}:
        from . import processing

        return getattr(processing, name)
    if name in {"APITrainingRunner", "APIRetrievalExperiment"}:
        from .training import APITrainingRunner

        return APITrainingRunner
    if name == "APIEvaluationRunner":
        from .evaluation import APIEvaluationRunner

        return APIEvaluationRunner
    if name == "APITestingRunner":
        from .testing import APITestingRunner

        return APITestingRunner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
