"""
API traffic domain configuration.
"""

from dataclasses import dataclass, field

from src.core.base_config import BaseConfig


@dataclass
class APITrafficConfig(BaseConfig):
    """Configuration specific to API traffic classification datasets."""

    domain_name: str = "api_traffic"
    shard_key: str = "event_id"
    num_shards: int = 256
    batch_size: int = 5000

    # Rolling windows are not the primary signal for this dataset.
    feature_windows: list = field(default_factory=list)

    # Dataset/task metadata for downstream training code.
    dataset_name: str = "atrdf"
    task_type: str = "binary"  # binary or attack_type
    feature_mode: str = "request_only"  # request_only, response_only, combined
    text_mode: str = "hybrid"  # lexical, tokenized, hybrid
    anomaly_reference_label: int = 0  # benign-only fallback training

    # Validation archives do not contain labels in this challenge.
    validation_name_markers: list = field(default_factory=lambda: ["_val", "validation"])

    required_request_keys: list = field(default_factory=lambda: ["headers", "method", "url", "body"])
    required_response_keys: list = field(
        default_factory=lambda: ["status", "headers", "status_code", "body"]
    )

    def __post_init__(self):
        """Validate API traffic config."""
        super().__post_init__()
        assert self.shard_key == "event_id", "API traffic should shard by event_id"
        assert self.task_type in {"binary", "attack_type"}, "task_type must be binary or attack_type"
        assert self.feature_mode in {
            "request_only",
            "response_only",
            "combined",
        }, "feature_mode must be request_only, response_only, or combined"
        assert self.text_mode in {
            "lexical",
            "tokenized",
            "hybrid",
        }, "text_mode must be lexical, tokenized, or hybrid"


__all__ = ["APITrafficConfig"]
