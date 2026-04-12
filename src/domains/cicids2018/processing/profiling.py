"""
Dataset profiling helpers for the CICIDS2018 network-flow domain.

The profiler groups numeric fields by observed scale and by semantic role so the
processing pipeline can persist explicit transform recommendations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, List

import pandas as pd


@dataclass
class NumericColumnProfile:
    """Compact summary for one numeric column."""

    dtype: str
    non_null_count: int
    missing_ratio: float
    zero_ratio: float
    negative_ratio: float
    unique_count: int
    min: float
    p50: float
    p95: float
    p99: float
    max: float
    mean: float
    std: float
    max_abs_reference: float
    range_bucket: str
    semantic_group: str
    transform_recommendation: str


class CICIDS2018DatasetProfiler:
    """Profile normalized CICIDS2018 data and recommend grouping/scaling policy."""

    METADATA_COLUMNS = {
        "event_id",
        "source_file",
        "row_index",
        "timestamp",
        "attack_label_raw",
        "attack_family",
        "target_label",
        "protocol_token",
        "port_token",
        "transport_token",
    }

    RANGE_BUCKET_LABELS = [
        (1.0, "range_le_1"),
        (10.0, "range_1_to_10"),
        (100.0, "range_10_to_100"),
        (1_000.0, "range_100_to_1e3"),
        (10_000.0, "range_1e3_to_1e4"),
        (1_000_000.0, "range_1e4_to_1e6"),
    ]

    def profile_dataframe(self, df: pd.DataFrame) -> Dict:
        """Build a serializable processing profile from a normalized dataframe."""
        numeric_columns = [
            column
            for column in df.columns
            if column not in self.METADATA_COLUMNS and pd.api.types.is_numeric_dtype(df[column])
        ]

        column_profiles = {
            column: asdict(self._profile_numeric_column(df[column], column))
            for column in numeric_columns
        }

        range_groups = self._invert_grouping(column_profiles, "range_bucket")
        semantic_groups = self._invert_grouping(column_profiles, "semantic_group")
        transform_groups = self._invert_grouping(column_profiles, "transform_recommendation")

        return {
            "row_count": int(len(df)),
            "numeric_column_count": len(numeric_columns),
            "token_columns": [
                column
                for column in ["protocol_token", "port_token", "transport_token"]
                if column in df.columns
            ],
            "range_groups": range_groups,
            "semantic_groups": semantic_groups,
            "transform_groups": transform_groups,
            "scaling_recommendations": self._build_scaling_recommendations(transform_groups),
            "numeric_column_profiles": column_profiles,
        }

    def _profile_numeric_column(self, series: pd.Series, column_name: str) -> NumericColumnProfile:
        """Compute summary statistics and transform recommendation for one column."""
        numeric = pd.to_numeric(series, errors="coerce")
        non_null = numeric.dropna()

        if non_null.empty:
            return NumericColumnProfile(
                dtype=str(series.dtype),
                non_null_count=0,
                missing_ratio=1.0,
                zero_ratio=0.0,
                negative_ratio=0.0,
                unique_count=0,
                min=0.0,
                p50=0.0,
                p95=0.0,
                p99=0.0,
                max=0.0,
                mean=0.0,
                std=0.0,
                max_abs_reference=0.0,
                range_bucket="all_missing",
                semantic_group=self._infer_semantic_group(column_name),
                transform_recommendation="drop_or_investigate",
            )

        min_value = float(non_null.min())
        p50 = float(non_null.quantile(0.50))
        p95 = float(non_null.quantile(0.95))
        p99 = float(non_null.quantile(0.99))
        max_value = float(non_null.max())
        mean_value = float(non_null.mean())
        std_value = float(non_null.std(ddof=0))
        max_abs_reference = max(abs(min_value), abs(p99), abs(max_value))
        semantic_group = self._infer_semantic_group(column_name)
        range_bucket = self._range_bucket(max_abs_reference, min_value)
        transform_recommendation = self._recommend_transform(
            column_name=column_name,
            semantic_group=semantic_group,
            min_value=min_value,
            max_value=max_value,
            p95=p95,
            p99=p99,
            unique_count=int(non_null.nunique(dropna=True)),
        )

        return NumericColumnProfile(
            dtype=str(series.dtype),
            non_null_count=int(non_null.shape[0]),
            missing_ratio=float(numeric.isna().mean()),
            zero_ratio=float((non_null == 0).mean()),
            negative_ratio=float((non_null < 0).mean()),
            unique_count=int(non_null.nunique(dropna=True)),
            min=min_value,
            p50=p50,
            p95=p95,
            p99=p99,
            max=max_value,
            mean=mean_value,
            std=std_value,
            max_abs_reference=float(max_abs_reference),
            range_bucket=range_bucket,
            semantic_group=semantic_group,
            transform_recommendation=transform_recommendation,
        )

    def _infer_semantic_group(self, column_name: str) -> str:
        """Classify a numeric field into a behavior-oriented semantic group."""
        lowered = column_name.lower()

        if lowered in {"protocol", "dst_port", "label_binary", "label_known"}:
            return "identifier_or_label"
        if "flag" in lowered:
            return "flags"
        if "port" in lowered or "protocol" in lowered:
            return "transport"
        if "duration" in lowered or "active" in lowered or "idle" in lowered:
            return "timing"
        if "ratio" in lowered or "share" in lowered or "imbalance" in lowered:
            return "directionality"
        if "rate" in lowered or "_per_s" in lowered or "_per_second" in lowered:
            return "timing"
        if "pkt" in lowered or "packet" in lowered:
            return "volume"
        if "byte" in lowered or "len" in lowered or "header" in lowered:
            return "volume"
        return "other_numeric"

    def _range_bucket(self, max_abs_reference: float, min_value: float) -> str:
        """Map a numeric field to a coarse observed scale bucket."""
        if min_value < 0:
            return "signed"

        for threshold, label in self.RANGE_BUCKET_LABELS:
            if max_abs_reference <= threshold:
                return label
        return "range_gt_1e6"

    def _recommend_transform(
        self,
        column_name: str,
        semantic_group: str,
        min_value: float,
        max_value: float,
        p95: float,
        p99: float,
        unique_count: int,
    ) -> str:
        """Choose a practical transform policy for one column."""
        lowered = column_name.lower()

        if unique_count <= 2 and min_value >= 0 and max_value <= 1:
            return "keep_binary_indicator"

        if semantic_group == "identifier_or_label":
            return "keep_raw_for_metadata_or_training_label_only"

        if min_value >= 0 and max_value <= 1:
            return "keep_bounded_ratio"

        if min_value < 0:
            return "robust_scale_signed_feature"

        tail_ratio = (p99 + 1.0) / (max(p95, 0.0) + 1.0)
        extreme_ratio = (max_value + 1.0) / (max(p99, 0.0) + 1.0)

        if "flag" in lowered:
            return "keep_indicator_and_optional_log1p_count"

        if semantic_group in {"volume", "timing"} and (
            p99 > 100.0 or tail_ratio > 1.5 or extreme_ratio > 5.0
        ):
            return "clip_high_percentile_then_log1p_then_standardize"

        if semantic_group == "directionality":
            return "clip_ratio_then_standardize"

        if max_value <= 100.0:
            return "keep_raw_or_standardize"

        return "standardize_after_basic_cleaning"

    @staticmethod
    def _invert_grouping(column_profiles: Dict[str, Dict], key: str) -> Dict[str, List[str]]:
        """Convert column-centric metadata into group -> columns form."""
        grouped: Dict[str, List[str]] = {}
        for column_name, profile in column_profiles.items():
            grouped.setdefault(profile[key], []).append(column_name)

        for columns in grouped.values():
            columns.sort()

        return dict(sorted(grouped.items(), key=lambda item: item[0]))

    @staticmethod
    def _build_scaling_recommendations(transform_groups: Dict[str, List[str]]) -> Dict[str, Dict]:
        """Expand transform groups into human-readable recommendations."""
        descriptions = {
            "keep_binary_indicator": {
                "steps": ["keep as 0/1", "skip scaling unless the downstream model requires it"],
                "reason": "Binary flags are already stable and interpretable.",
            },
            "keep_raw_for_metadata_or_training_label_only": {
                "steps": ["do not treat as a normal numeric feature", "use for metadata, sharding, or labels"],
                "reason": "Identifiers and labels carry shortcut risk.",
            },
            "keep_bounded_ratio": {
                "steps": ["clip to safe bounds if needed", "optionally standardize after clipping"],
                "reason": "Ratios in [0, 1] are already comparable across rows.",
            },
            "robust_scale_signed_feature": {
                "steps": ["keep raw signed value", "use robust scaling or z-score"],
                "reason": "Signed deltas should not receive direct log1p.",
            },
            "keep_indicator_and_optional_log1p_count": {
                "steps": ["keep presence indicator", "optionally add clipped count and log1p(count)"],
                "reason": "Sparse flags often matter as presence first, magnitude second.",
            },
            "clip_high_percentile_then_log1p_then_standardize": {
                "steps": ["clip at p99 or p99.5", "apply log1p", "standardize if needed"],
                "reason": "Positive long-tailed metrics dominate models in raw scale.",
            },
            "clip_ratio_then_standardize": {
                "steps": ["clip unstable ratios", "fill divide-by-zero cases safely", "standardize if needed"],
                "reason": "Directionality ratios can explode because of very small denominators.",
            },
            "keep_raw_or_standardize": {
                "steps": ["keep raw value", "optional standardization"],
                "reason": "Small-range numeric fields are already well behaved.",
            },
            "standardize_after_basic_cleaning": {
                "steps": ["clean inf and missing values", "standardize if used directly"],
                "reason": "The field is numeric but not obviously heavy-tailed.",
            },
            "drop_or_investigate": {
                "steps": ["inspect source data", "drop if still entirely missing"],
                "reason": "Fully missing columns do not contribute useful signal.",
            },
        }

        recommendations = {}
        for transform_name, columns in transform_groups.items():
            payload = descriptions.get(
                transform_name,
                {
                    "steps": ["inspect column distribution before training"],
                    "reason": "No explicit rule matched this column group.",
                },
            ).copy()
            payload["columns"] = columns
            recommendations[transform_name] = payload

        return recommendations


__all__ = ["CICIDS2018DatasetProfiler"]
