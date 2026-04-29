"""
Backward-compatible imports for API retrieval model.

New code should import from:
- src.domains.api_traffic.training
- src.domains.api_traffic.evaluation
"""

from .evaluation import APIEvaluationRunner
from .training import APIRetrievalModel, APITrainingRunner

APIRetrievalExperiment = APITrainingRunner

__all__ = ["APIRetrievalModel", "APITrainingRunner", "APIEvaluationRunner", "APIRetrievalExperiment"]
