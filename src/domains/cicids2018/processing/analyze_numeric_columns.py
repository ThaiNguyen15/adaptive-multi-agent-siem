"""
Analyze raw CICIDS2018 CSV files and summarize numeric column ranges.

This version is designed for large CSV files and processes the input in chunks
instead of loading the full dataset into memory.

It:
- reads one CSV file in streaming mode
- profiles only numeric columns
- groups numeric columns by similar observed range
- writes text columns into a separate "not processed" note
- uses bounded reservoir samples to estimate percentiles for large files

Example:
    source .venv/bin/activate
    python -m src.domains.cicids2018.processing.analyze_numeric_columns \
        --input-csv data/raw/cicflowmeter/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv \
        --output-dir data/analysis/cicids2018_numeric_profile
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

import pandas as pd


NUMERIC_CONVERSION_THRESHOLD = 0.95
DEFAULT_CHUNK_SIZE = 100_000
DEFAULT_RESERVOIR_SIZE = 20_000
DEFAULT_UNIQUE_TRACK_LIMIT = 50_000


def _safe_float(value: float) -> float:
    """Convert numeric-like values to plain floats for JSON/CSV output."""
    if pd.isna(value):
        return 0.0
    return float(value)


def _range_bucket(max_abs_reference: float, min_value: float) -> str:
    """Group columns by coarse numeric magnitude."""
    if min_value < 0:
        return "signed"
    if max_abs_reference <= 1:
        return "range_le_1"
    if max_abs_reference <= 10:
        return "range_1_to_10"
    if max_abs_reference <= 100:
        return "range_10_to_100"
    if max_abs_reference <= 1_000:
        return "range_100_to_1e3"
    if max_abs_reference <= 10_000:
        return "range_1e3_to_1e4"
    if max_abs_reference <= 1_000_000:
        return "range_1e4_to_1e6"
    return "range_gt_1e6"


def _magnitude_group(max_abs_reference: float) -> str:
    """Group columns by order of magnitude using simple thresholds."""
    if max_abs_reference <= 1:
        return "10^0_or_less"
    if max_abs_reference <= 10:
        return "10^1"
    if max_abs_reference <= 100:
        return "10^2"
    if max_abs_reference <= 1_000:
        return "10^3"
    if max_abs_reference <= 10_000:
        return "10^4"
    if max_abs_reference <= 100_000:
        return "10^5"
    if max_abs_reference <= 1_000_000:
        return "10^6"
    return "gt_10^6"


def _infer_semantic_group(column_name: str) -> str:
    """Classify one raw CICIDS2018 column into a behavior-oriented group."""
    lowered = column_name.lower()

    if lowered in {"timestamp", "label"}:
        return "metadata_or_label"
    if lowered in {"protocol", "dst port"}:
        return "transport_context"
    if "flag" in lowered:
        return "flag_features"
    if "iat" in lowered or "duration" in lowered or "active" in lowered or "idle" in lowered:
        return "timing"
    if "pkts/s" in lowered or "byts/s" in lowered:
        return "rate"
    if "ratio" in lowered or "share" in lowered or "imbalance" in lowered:
        return "directionality_ratio"
    if "init " in lowered and "win" in lowered:
        return "signed_or_sentinel_window"
    if "subflow" in lowered or "tot " in lowered or "totlen" in lowered:
        return "flow_volume"
    if "len" in lowered or "size" in lowered or "header" in lowered:
        return "packet_shape"
    if "pkt" in lowered or "packet" in lowered:
        return "flow_volume"
    return "other_numeric"


def _recommend_transform(profile: Dict) -> str:
    """Choose a concrete preprocessing policy for one profiled column."""
    column_name = profile["column_name"]
    semantic_group = profile["semantic_group"]
    min_value = profile["min"]
    max_value = profile["max"]
    p95 = profile["p95"]
    p99 = profile["p99"]
    unique_count = profile["unique_count"]
    unique_count_is_approximate = profile["unique_count_is_approximate"]
    zero_ratio = profile["zero_ratio"]

    lowered = column_name.lower()

    if semantic_group == "metadata_or_label":
        return "metadata_or_target_only"

    if (not unique_count_is_approximate and unique_count <= 1) or min_value == max_value:
        return "drop_constant_feature"

    if unique_count <= 2 and min_value >= 0 and max_value <= 1:
        return "keep_binary_indicator"

    if semantic_group == "transport_context":
        return "bucketize_transport_context"

    if min_value < 0:
        return "treat_negative_as_sentinel_then_scale"

    if semantic_group == "flag_features":
        if zero_ratio >= 0.95 or unique_count <= 3:
            return "keep_indicator_and_drop_raw_count_if_sparse"
        return "clip_then_log1p_flag_count"

    if semantic_group == "directionality_ratio":
        return "clip_ratio_then_standardize"

    tail_ratio = (p99 + 1.0) / (max(p95, 0.0) + 1.0)
    extreme_ratio = (max_value + 1.0) / (max(p99, 0.0) + 1.0)
    is_heavy_tail = p99 > 100.0 or tail_ratio > 1.5 or extreme_ratio > 5.0

    if semantic_group in {"timing", "rate", "flow_volume"} and is_heavy_tail:
        return "clip_high_percentile_then_log1p_then_standardize"

    if semantic_group == "packet_shape":
        return "standardize_after_basic_cleaning"

    if max_value <= 100.0:
        return "keep_raw_or_standardize"

    return "standardize_after_basic_cleaning"


def _grouping_rationale(profile: Dict) -> str:
    """Explain why the column belongs to the chosen semantic and transform groups."""
    semantic_group = profile["semantic_group"]
    transform = profile["transform_recommendation"]
    range_bucket = profile["range_bucket"]

    semantic_reason_map = {
        "metadata_or_label": "Column is metadata or supervision, not a behavioral numeric feature.",
        "transport_context": "Column describes routing or protocol context rather than flow magnitude.",
        "flag_features": "Column represents sparse control or handshake flags.",
        "timing": "Column measures duration or inter-arrival timing behavior.",
        "rate": "Column is a per-second rate and is usually volatile with heavy right tail.",
        "directionality_ratio": "Column compares forward and backward behavior and can become unstable.",
        "signed_or_sentinel_window": "Column contains signed values that likely include sentinel semantics.",
        "flow_volume": "Column measures counts or totals that reflect traffic volume.",
        "packet_shape": "Column describes packet or segment size distribution.",
        "other_numeric": "Column is numeric but does not match a strong semantic family.",
    }
    transform_reason_map = {
        "metadata_or_target_only": "Keep for time split or target mapping only; do not feed raw into the model.",
        "drop_constant_feature": "Column has no usable variance in this analyzed file.",
        "keep_binary_indicator": "Observed values are effectively binary already.",
        "bucketize_transport_context": "Raw identifier values are shortcut-prone; coarse buckets generalize better.",
        "treat_negative_as_sentinel_then_scale": "Negative values should be treated carefully instead of applying direct log1p.",
        "keep_indicator_and_drop_raw_count_if_sparse": "Presence usually matters more than exact count for sparse flags.",
        "clip_then_log1p_flag_count": "Rare larger counts benefit from compression after clipping.",
        "clip_ratio_then_standardize": "Ratios need clipping because small denominators can inflate them.",
        "clip_high_percentile_then_log1p_then_standardize": "Observed tail is long enough that raw scale would dominate training.",
        "standardize_after_basic_cleaning": "Distribution looks numeric and usable after inf handling and scaling.",
        "keep_raw_or_standardize": "Observed range is already small and stable.",
    }
    return (
        f"{semantic_reason_map.get(semantic_group, 'Column was grouped by heuristic semantic rules.')} "
        f"Observed range bucket is `{range_bucket}`. "
        f"{transform_reason_map.get(transform, 'Transform was selected from profile heuristics.')}"
    )


def _transform_steps(transform_name: str) -> List[str]:
    """Return concrete preprocessing steps for one transform recommendation."""
    mapping = {
        "metadata_or_target_only": [
            "Use only for metadata, sorting, splitting, or labels",
            "Never feed raw values into the model matrix",
        ],
        "drop_constant_feature": [
            "Drop from training features",
            "Keep only in analysis output if needed for audit",
        ],
        "keep_binary_indicator": [
            "Keep as 0/1 indicator",
            "Skip scaling unless the downstream model requires a fully standardized matrix",
        ],
        "bucketize_transport_context": [
            "Convert protocol to coarse indicators such as is_tcp or is_udp",
            "Map dst_port to coarse buckets such as system, registered, or dynamic",
        ],
        "treat_negative_as_sentinel_then_scale": [
            "Treat negative values as sentinel or invalid if domain semantics confirm that",
            "Add validity indicator",
            "Scale valid values with robust scaling or z-score",
        ],
        "keep_indicator_and_drop_raw_count_if_sparse": [
            "Create presence indicator",
            "Drop raw count if it remains near-binary and sparse",
        ],
        "clip_then_log1p_flag_count": [
            "Clip high counts at p99 or p99.5",
            "Apply log1p to clipped count",
            "Optionally standardize transformed value",
        ],
        "clip_ratio_then_standardize": [
            "Clip to safe upper bound using p99 or domain cap",
            "Fill divide-by-zero artifacts safely",
            "Standardize if fed directly to the model",
        ],
        "clip_high_percentile_then_log1p_then_standardize": [
            "Replace inf or invalid values with NaN",
            "Clip at p99 or p99.5",
            "Apply log1p",
            "Standardize if the downstream model is scale-sensitive",
        ],
        "standardize_after_basic_cleaning": [
            "Replace inf with NaN if present",
            "Fill or impute missing values safely",
            "Standardize the cleaned feature",
        ],
        "keep_raw_or_standardize": [
            "Keep raw value",
            "Optionally standardize for linear models",
        ],
    }
    return mapping.get(transform_name, ["Inspect distribution before training"])


def _build_processing_recommendations(profiles: List[Dict]) -> Dict[str, Dict]:
    """Build grouped processing policy payload for downstream use."""
    grouped_profiles = _group_columns(profiles, "transform_recommendation")
    recommendations: Dict[str, Dict] = {}
    for transform_name, columns in grouped_profiles.items():
        recommendations[transform_name] = {
            "columns": columns,
            "steps": _transform_steps(transform_name),
        }
    return recommendations


@dataclass
class NumericColumnAccumulator:
    """Streaming accumulator for one potentially numeric column."""

    column_name: str
    dtype_hint: str = "object"
    total_rows_seen: int = 0
    non_null_original_count: int = 0
    numeric_non_null_count: int = 0
    zero_count: int = 0
    negative_count: int = 0
    sum_value: float = 0.0
    sum_sq_value: float = 0.0
    min_value: float = float("inf")
    max_value: float = float("-inf")
    reservoir_size: int = DEFAULT_RESERVOIR_SIZE
    unique_track_limit: int = DEFAULT_UNIQUE_TRACK_LIMIT
    reservoir: List[float] = field(default_factory=list)
    unique_values: set = field(default_factory=set)
    unique_tracking_stopped: bool = False

    def update(self, series: pd.Series) -> None:
        """Update the accumulator from one chunk column."""
        self.dtype_hint = str(series.dtype)
        self.total_rows_seen += int(len(series))

        non_null_original = series.notna() & series.astype(str).str.strip().ne("")
        self.non_null_original_count += int(non_null_original.sum())

        numeric = pd.to_numeric(series, errors="coerce")
        valid = numeric.dropna()
        if valid.empty:
            return

        self.numeric_non_null_count += int(valid.shape[0])
        self.zero_count += int((valid == 0).sum())
        self.negative_count += int((valid < 0).sum())
        self.sum_value += float(valid.sum())
        self.sum_sq_value += float((valid * valid).sum())
        self.min_value = min(self.min_value, float(valid.min()))
        self.max_value = max(self.max_value, float(valid.max()))

        self._update_unique_tracking(valid)
        self._update_reservoir(valid)

    def _update_unique_tracking(self, values: pd.Series) -> None:
        """Track exact unique values until the cap is reached."""
        if self.unique_tracking_stopped:
            return

        for value in values.tolist():
            self.unique_values.add(float(value))
            if len(self.unique_values) > self.unique_track_limit:
                self.unique_tracking_stopped = True
                self.unique_values = set()
                return

    def _update_reservoir(self, values: pd.Series) -> None:
        """Maintain a bounded random sample for approximate quantiles."""
        for value in values.tolist():
            value = float(value)
            seen_so_far = self.numeric_non_null_count
            if len(self.reservoir) < self.reservoir_size:
                self.reservoir.append(value)
                continue

            replace_idx = random.randint(0, seen_so_far - 1)
            if replace_idx < self.reservoir_size:
                self.reservoir[replace_idx] = value

    def to_profile(self) -> Dict:
        """Finalize the streaming profile for one column."""
        if self.numeric_non_null_count == 0:
            return {
                "column_name": self.column_name,
                "dtype": self.dtype_hint,
                "total_rows": self.total_rows_seen,
                "non_null_count": 0,
                "convertible_ratio": 0.0,
                "missing_ratio": 1.0,
                "zero_ratio": 0.0,
                "negative_ratio": 0.0,
                "unique_count": 0,
                "unique_count_is_approximate": True,
                "min": 0.0,
                "p25": 0.0,
                "p50": 0.0,
                "p75": 0.0,
                "p95": 0.0,
                "p99": 0.0,
                "max": 0.0,
                "mean": 0.0,
                "std": 0.0,
                "max_abs_reference": 0.0,
                "range_bucket": "all_missing",
                "magnitude_group": "all_missing",
                "quantiles_are_approximate": True,
            }

        sample_series = pd.Series(self.reservoir, dtype="float64")
        p25 = _safe_float(sample_series.quantile(0.25))
        p50 = _safe_float(sample_series.quantile(0.50))
        p75 = _safe_float(sample_series.quantile(0.75))
        p95 = _safe_float(sample_series.quantile(0.95))
        p99 = _safe_float(sample_series.quantile(0.99))

        mean_value = self.sum_value / self.numeric_non_null_count
        variance = max((self.sum_sq_value / self.numeric_non_null_count) - (mean_value * mean_value), 0.0)
        std_value = variance ** 0.5
        min_value = _safe_float(self.min_value)
        max_value = _safe_float(self.max_value)
        max_abs_reference = max(abs(min_value), abs(p99), abs(max_value))

        unique_count = len(self.unique_values) if not self.unique_tracking_stopped else 0

        return {
            "column_name": self.column_name,
            "dtype": self.dtype_hint,
            "total_rows": self.total_rows_seen,
            "non_null_count": self.numeric_non_null_count,
            "convertible_ratio": _safe_float(self.numeric_non_null_count / max(self.total_rows_seen, 1)),
            "missing_ratio": _safe_float(1.0 - (self.numeric_non_null_count / max(self.total_rows_seen, 1))),
            "zero_ratio": _safe_float(self.zero_count / max(self.numeric_non_null_count, 1)),
            "negative_ratio": _safe_float(self.negative_count / max(self.numeric_non_null_count, 1)),
            "unique_count": int(unique_count),
            "unique_count_is_approximate": bool(self.unique_tracking_stopped),
            "min": min_value,
            "p25": p25,
            "p50": p50,
            "p75": p75,
            "p95": p95,
            "p99": p99,
            "max": max_value,
            "mean": _safe_float(mean_value),
            "std": _safe_float(std_value),
            "max_abs_reference": _safe_float(max_abs_reference),
            "range_bucket": _range_bucket(max_abs_reference, min_value),
            "magnitude_group": _magnitude_group(max_abs_reference),
            "semantic_group": _infer_semantic_group(self.column_name),
            "transform_recommendation": "",
            "grouping_rationale": "",
            "quantiles_are_approximate": True,
        }


def _group_columns(profiles: List[Dict], key: str) -> Dict[str, List[str]]:
    """Convert per-column profiles into one grouping dictionary."""
    groups: Dict[str, List[str]] = {}
    for profile in profiles:
        groups.setdefault(profile[key], []).append(profile["column_name"])

    for columns in groups.values():
        columns.sort()

    return dict(sorted(groups.items(), key=lambda item: item[0]))


def analyze_csv(
    input_csv: Path,
    output_dir: Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    reservoir_size: int = DEFAULT_RESERVOIR_SIZE,
    unique_track_limit: int = DEFAULT_UNIQUE_TRACK_LIMIT,
) -> Dict:
    """Analyze one CSV file and write numeric-only dataset statistics."""
    header_df = pd.read_csv(input_csv, nrows=0)
    column_names = header_df.columns.tolist()

    accumulators = {
        column_name: NumericColumnAccumulator(
            column_name=column_name,
            reservoir_size=reservoir_size,
            unique_track_limit=unique_track_limit,
        )
        for column_name in column_names
    }

    for chunk_df in pd.read_csv(
        input_csv,
        chunksize=chunk_size,
        dtype=str,
        low_memory=False,
    ):
        for column_name in column_names:
            accumulators[column_name].update(chunk_df[column_name])

    profiles = [accumulator.to_profile() for accumulator in accumulators.values()]

    numeric_profiles: List[Dict] = []
    text_columns_not_processed: List[Dict] = []

    for profile in profiles:
        if profile["convertible_ratio"] >= NUMERIC_CONVERSION_THRESHOLD:
            numeric_profiles.append(profile)
        else:
            text_columns_not_processed.append(
                {
                    "column_name": profile["column_name"],
                    "dtype": profile["dtype"],
                    "non_null_count": int(accumulators[profile["column_name"]].non_null_original_count),
                    "convertible_ratio": profile["convertible_ratio"],
                    "note": "Not processed because this column is treated as text or mixed text.",
                }
            )

    numeric_profiles = sorted(numeric_profiles, key=lambda item: item["column_name"].lower())
    stats_df = pd.DataFrame(numeric_profiles)

    for profile in numeric_profiles:
        profile["transform_recommendation"] = _recommend_transform(profile)
        profile["grouping_rationale"] = _grouping_rationale(profile)

    range_groups = _group_columns(numeric_profiles, "range_bucket")
    magnitude_groups = _group_columns(numeric_profiles, "magnitude_group")
    semantic_groups = _group_columns(numeric_profiles, "semantic_group")
    transform_groups = _group_columns(numeric_profiles, "transform_recommendation")
    processing_recommendations = _build_processing_recommendations(numeric_profiles)

    total_rows = profiles[0]["total_rows"] if profiles else 0
    summary = {
        "input_csv": str(input_csv),
        "row_count": int(total_rows),
        "column_count": len(column_names),
        "numeric_column_count": len(numeric_profiles),
        "text_column_count": len(text_columns_not_processed),
        "chunk_size": int(chunk_size),
        "reservoir_size_per_numeric_column": int(reservoir_size),
        "numeric_range_groups": range_groups,
        "numeric_magnitude_groups": magnitude_groups,
        "semantic_groups": semantic_groups,
        "transform_groups": transform_groups,
        "processing_recommendations": processing_recommendations,
        "text_columns_not_processed": text_columns_not_processed,
        "notes": {
            "large_csv_mode": True,
            "quantiles_are_approximate": True,
            "unique_count_may_be_approximate": True,
            "grouping_strategy": "semantic_group + observed_range + transform_recommendation",
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)

    stats_df.to_csv(output_dir / "numeric_column_stats.csv", index=False)
    with open(output_dir / "numeric_range_groups.json", "w", encoding="utf-8") as handle:
        json.dump(range_groups, handle, indent=2)
    with open(output_dir / "numeric_magnitude_groups.json", "w", encoding="utf-8") as handle:
        json.dump(magnitude_groups, handle, indent=2)
    with open(output_dir / "semantic_groups.json", "w", encoding="utf-8") as handle:
        json.dump(semantic_groups, handle, indent=2)
    with open(output_dir / "transform_groups.json", "w", encoding="utf-8") as handle:
        json.dump(transform_groups, handle, indent=2)
    with open(output_dir / "processing_recommendations.json", "w", encoding="utf-8") as handle:
        json.dump(processing_recommendations, handle, indent=2)
    with open(output_dir / "text_columns_not_processed.json", "w", encoding="utf-8") as handle:
        json.dump(text_columns_not_processed, handle, indent=2)
    with open(output_dir / "analysis_summary.json", "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)

    _write_markdown_report(
        output_path=output_dir / "analysis_report.md",
        summary=summary,
        numeric_profiles=numeric_profiles,
    )

    return summary


def _write_markdown_report(output_path: Path, summary: Dict, numeric_profiles: List[Dict]) -> None:
    """Write a human-readable analysis report."""
    lines = [
        "# Numeric Column Analysis",
        "",
        f"- Input CSV: `{summary['input_csv']}`",
        f"- Row count: `{summary['row_count']}`",
        f"- Total columns: `{summary['column_count']}`",
        f"- Numeric columns processed: `{summary['numeric_column_count']}`",
        f"- Text columns not processed: `{summary['text_column_count']}`",
        f"- Chunk size: `{summary['chunk_size']}`",
        f"- Reservoir size per numeric column: `{summary['reservoir_size_per_numeric_column']}`",
        "- Quantiles in this report are approximate because the script uses streaming samples for large CSV support.",
        "",
        "## Range Groups",
        "",
    ]

    for group_name, columns in summary["numeric_range_groups"].items():
        lines.append(f"### {group_name}")
        lines.append("")
        for column_name in columns:
            lines.append(f"- `{column_name}`")
        lines.append("")

    lines.extend(["## Semantic Groups", ""])
    for group_name, columns in summary["semantic_groups"].items():
        lines.append(f"### {group_name}")
        lines.append("")
        for column_name in columns:
            lines.append(f"- `{column_name}`")
        lines.append("")

    lines.extend(["## Transform Groups", ""])
    for group_name, columns in summary["transform_groups"].items():
        lines.append(f"### {group_name}")
        lines.append("")
        for column_name in columns:
            lines.append(f"- `{column_name}`")
        lines.append("")

    lines.extend(["## Processing Recommendations", ""])
    for transform_name, payload in summary["processing_recommendations"].items():
        lines.append(f"### {transform_name}")
        lines.append("")
        for step in payload["steps"]:
            lines.append(f"- {step}")
        lines.append("")

    lines.extend(["## Text Columns Not Processed", ""])
    if summary["text_columns_not_processed"]:
        for item in summary["text_columns_not_processed"]:
            lines.append(
                f"- `{item['column_name']}`: dtype=`{item['dtype']}`, convertible_ratio=`{item['convertible_ratio']:.4f}`"
            )
    else:
        lines.append("- None")
    lines.append("")

    lines.extend(["## Top Numeric Columns By Max Value", ""])
    for profile in sorted(
        numeric_profiles,
        key=lambda item: item["max_abs_reference"],
        reverse=True,
    )[:20]:
        lines.append(
            f"- `{profile['column_name']}`: max=`{profile['max']}`, p99≈`{profile['p99']}`, "
            f"range_bucket=`{profile['range_bucket']}`, semantic_group=`{profile['semantic_group']}`, "
            f"transform=`{profile['transform_recommendation']}`"
        )

    lines.extend(["", "## Sample Column Rationales", ""])
    for profile in numeric_profiles[:20]:
        lines.append(
            f"- `{profile['column_name']}`: {profile['grouping_rationale']}"
        )

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    """Parse args and run one CSV numeric-column analysis."""
    parser = argparse.ArgumentParser(description="Analyze numeric column ranges from one CSV file")
    parser.add_argument("--input-csv", type=Path, required=True, help="Path to the input CSV file")
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory where analysis files will be written",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=f"Rows per chunk for streaming analysis (default: {DEFAULT_CHUNK_SIZE})",
    )
    parser.add_argument(
        "--reservoir-size",
        type=int,
        default=DEFAULT_RESERVOIR_SIZE,
        help=f"Sample size per numeric column for approximate quantiles (default: {DEFAULT_RESERVOIR_SIZE})",
    )
    parser.add_argument(
        "--unique-track-limit",
        type=int,
        default=DEFAULT_UNIQUE_TRACK_LIMIT,
        help=f"Maximum exact unique values to track per numeric column (default: {DEFAULT_UNIQUE_TRACK_LIMIT})",
    )
    args = parser.parse_args()

    summary = analyze_csv(
        input_csv=args.input_csv,
        output_dir=args.output_dir,
        chunk_size=args.chunk_size,
        reservoir_size=args.reservoir_size,
        unique_track_limit=args.unique_track_limit,
    )
    print("NUMERIC COLUMN ANALYSIS COMPLETED")
    print(f"Input CSV: {summary['input_csv']}")
    print(f"Rows: {summary['row_count']}")
    print(f"Numeric columns processed: {summary['numeric_column_count']}")
    print(f"Text columns not processed: {summary['text_column_count']}")
    print(f"Chunk size: {summary['chunk_size']}")
    print(f"Saved outputs to: {args.output_dir}")


if __name__ == "__main__":
    main()
