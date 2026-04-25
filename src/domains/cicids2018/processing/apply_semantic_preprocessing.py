"""
Apply semantic-group-aware preprocessing to CICIDS2018 raw CSV data.

This script:
- normalizes the raw CICFlowMeter CSV into the domain schema
- reads the profiled transform recommendations emitted by analyze_numeric_columns.py
- applies per-group preprocessing rules
- writes a model-ready dataframe plus a transform manifest

Example:
    ./.venv/bin/python src/domains/cicids2018/processing/apply_semantic_preprocessing.py \
        --input-csv "data/raw/cicflowmeter/Processed Traffic Data for ML Algorithms/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv" \
        --profile-csv data/analysis/cicids2018/numeric_column_stats.csv \
        --output-path data/processed/cicids2018/semantic_preprocessed_sample.parquet \
        --sample-rows 50000
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd

from .config import CICIDS2018Config
from .normalizer import CICIDS2018Normalizer, _snake_case


TRANSPORT_METADATA_COLUMNS = [
    "event_id",
    "source_file",
    "row_index",
    "timestamp",
    "attack_label_raw",
    "attack_family",
    "label_binary",
    "label_known",
    "target_label",
]


def _raw_to_normalized(raw_column_name: str) -> str:
    """Map profiled raw CICFlowMeter headers into normalized schema names."""
    normalized = _snake_case(raw_column_name)
    if normalized == "label":
        return "attack_label_raw"
    return normalized


def _safe_std(value: float) -> float:
    """Prevent division by zero during z-score scaling."""
    if not np.isfinite(value) or value == 0.0:
        return 1.0
    return float(value)


def _replace_inf(series: pd.Series) -> pd.Series:
    """Standardize infinite values to NaN before downstream transforms."""
    return series.replace([np.inf, -np.inf], np.nan)


def _resolve_transform_name(profile: Dict) -> str:
    """Use stored recommendation when present, otherwise recompute from profile stats."""
    transform_name = profile.get("transform_recommendation")
    if isinstance(transform_name, str) and transform_name.strip():
        return transform_name

    semantic_group = profile["semantic_group"]
    min_value = float(profile["min"])
    max_value = float(profile["max"])
    p95 = float(profile["p95"])
    p99 = float(profile["p99"])
    unique_count = int(profile["unique_count"])
    unique_count_is_approximate = bool(profile["unique_count_is_approximate"])
    zero_ratio = float(profile["zero_ratio"])

    if semantic_group == "transport_context":
        return "bucketize_transport_context"
    if semantic_group == "signed_or_sentinel_window" or min_value < 0:
        return "treat_negative_as_sentinel_then_scale"
    if (not unique_count_is_approximate and unique_count <= 1) or min_value == max_value:
        return "drop_constant_feature"
    if unique_count <= 2 and min_value >= 0 and max_value <= 1:
        return "keep_binary_indicator"
    if semantic_group == "flag_features":
        if zero_ratio >= 0.95 or unique_count <= 3:
            return "keep_binary_indicator"
        return "clip_then_log1p_flag_count"
    if semantic_group == "directionality_ratio":
        return "clip_ratio_then_standardize"

    tail_ratio = (p99 + 1.0) / (max(p95, 0.0) + 1.0)
    extreme_ratio = (max_value + 1.0) / (max(p99, 0.0) + 1.0)
    is_heavy_tail = p99 > 100.0 or tail_ratio > 1.5 or extreme_ratio > 5.0
    if semantic_group in {"timing", "rate", "flow_volume"} and is_heavy_tail:
        return "clip_high_percentile_then_log1p_then_standardize"
    return "standardize_after_basic_cleaning"


class CICIDS2018SemanticPreprocessor:
    """Apply preprocessing rules driven by profiled transform recommendations."""

    def __init__(self, profile_csv: Path):
        self.profile_df = pd.read_csv(profile_csv)
        self.profile_df["normalized_column"] = self.profile_df["column_name"].map(_raw_to_normalized)
        self.profile_map = {
            row["normalized_column"]: row
            for row in self.profile_df.to_dict(orient="records")
        }

    def transform(self, normalized_df: pd.DataFrame) -> tuple[pd.DataFrame, Dict]:
        """Transform one normalized dataframe into a model-ready matrix."""
        output_df = normalized_df[TRANSPORT_METADATA_COLUMNS].copy()
        manifest = {
            "source_columns": [],
            "generated_features": [],
            "dropped_columns": [],
            "transform_summary": {},
        }

        self._add_transport_context(normalized_df, output_df, manifest)

        for normalized_column, profile in sorted(self.profile_map.items()):
            if normalized_column not in normalized_df.columns:
                continue
            if normalized_column in {"protocol", "dst_port"}:
                continue

            transform_name = _resolve_transform_name(profile)
            semantic_group = profile["semantic_group"]
            manifest["transform_summary"].setdefault(transform_name, []).append(normalized_column)

            if transform_name == "drop_constant_feature":
                manifest["dropped_columns"].append(normalized_column)
                continue
            if transform_name == "keep_binary_indicator":
                self._apply_binary_indicator(normalized_df, output_df, normalized_column, manifest)
                continue
            if transform_name == "clip_high_percentile_then_log1p_then_standardize":
                self._apply_clip_log_standardize(normalized_df, output_df, normalized_column, profile, manifest)
                continue
            if transform_name == "standardize_after_basic_cleaning":
                self._apply_standardize(normalized_df, output_df, normalized_column, profile, manifest)
                continue
            if transform_name == "clip_ratio_then_standardize":
                self._apply_ratio(normalized_df, output_df, normalized_column, profile, manifest)
                continue
            if transform_name == "treat_negative_as_sentinel_then_scale":
                self._apply_signed_sentinel(normalized_df, output_df, normalized_column, profile, manifest)
                continue
            if transform_name == "bucketize_transport_context":
                continue

            if semantic_group == "flag_features":
                self._apply_binary_indicator(normalized_df, output_df, normalized_column, manifest)
            else:
                self._apply_standardize(normalized_df, output_df, normalized_column, profile, manifest)

        manifest["source_columns"] = list(normalized_df.columns)
        manifest["generated_features"] = [column for column in output_df.columns if column not in TRANSPORT_METADATA_COLUMNS]
        return output_df, manifest

    def _add_transport_context(self, normalized_df: pd.DataFrame, output_df: pd.DataFrame, manifest: Dict) -> None:
        """Create coarse transport indicators instead of feeding raw IDs."""
        protocol = normalized_df["protocol"].fillna(0).astype(int)
        dst_port = normalized_df["dst_port"].fillna(-1).astype(int)

        output_df["is_tcp"] = (protocol == 6).astype(np.int8)
        output_df["is_udp"] = (protocol == 17).astype(np.int8)
        output_df["is_icmp"] = (protocol == 1).astype(np.int8)
        output_df["is_other_protocol"] = (~protocol.isin([1, 6, 17])).astype(np.int8)

        output_df["is_system_port"] = ((dst_port >= 0) & (dst_port <= 1023)).astype(np.int8)
        output_df["is_registered_port"] = ((dst_port >= 1024) & (dst_port <= 49151)).astype(np.int8)
        output_df["is_dynamic_port"] = (dst_port >= 49152).astype(np.int8)
        output_df["is_invalid_port"] = (dst_port < 0).astype(np.int8)

        manifest["transform_summary"]["bucketize_transport_context"] = ["protocol", "dst_port"]

    def _apply_binary_indicator(
        self,
        normalized_df: pd.DataFrame,
        output_df: pd.DataFrame,
        normalized_column: str,
        manifest: Dict,
    ) -> None:
        """Turn sparse counts into presence indicators."""
        source = _replace_inf(normalized_df[normalized_column]).fillna(0)
        feature_name = f"{normalized_column}_present"
        output_df[feature_name] = (source > 0).astype(np.int8)
        manifest["generated_features"].append(feature_name)

    def _apply_clip_log_standardize(
        self,
        normalized_df: pd.DataFrame,
        output_df: pd.DataFrame,
        normalized_column: str,
        profile: Dict,
        manifest: Dict,
    ) -> None:
        """Clip extreme positive tails, apply log1p, then z-score."""
        source = _replace_inf(normalized_df[normalized_column]).fillna(0.0).clip(lower=0.0)
        clip_upper = float(profile["p99"])
        if not np.isfinite(clip_upper) or clip_upper <= 0.0:
            clip_upper = float(profile["max"]) if np.isfinite(profile["max"]) else 0.0
        clipped = source.clip(upper=clip_upper)
        logged = np.log1p(clipped)
        log_mean = float(logged.mean())
        log_std = _safe_std(float(logged.std(ddof=0)))
        feature_name = f"{normalized_column}_log1p_z"
        output_df[feature_name] = ((logged - log_mean) / log_std).astype(np.float32)
        manifest["generated_features"].append(feature_name)

    def _apply_standardize(
        self,
        normalized_df: pd.DataFrame,
        output_df: pd.DataFrame,
        normalized_column: str,
        profile: Dict,
        manifest: Dict,
    ) -> None:
        """Basic cleaned z-score transform."""
        source = _replace_inf(normalized_df[normalized_column]).fillna(0.0)
        mean_value = float(profile["mean"])
        std_value = _safe_std(float(profile["std"]))
        feature_name = f"{normalized_column}_z"
        output_df[feature_name] = ((source - mean_value) / std_value).astype(np.float32)
        manifest["generated_features"].append(feature_name)

    def _apply_ratio(
        self,
        normalized_df: pd.DataFrame,
        output_df: pd.DataFrame,
        normalized_column: str,
        profile: Dict,
        manifest: Dict,
    ) -> None:
        """Clip unstable ratios then z-score."""
        source = _replace_inf(normalized_df[normalized_column]).fillna(0.0)
        clip_upper = float(profile["p99"])
        if not np.isfinite(clip_upper) or clip_upper <= 0.0:
            clip_upper = float(profile["max"]) if np.isfinite(profile["max"]) else 1.0
        clipped = source.clip(lower=0.0, upper=clip_upper)
        mean_value = float(clipped.mean())
        std_value = _safe_std(float(clipped.std(ddof=0)))
        feature_name = f"{normalized_column}_clipped_z"
        output_df[feature_name] = ((clipped - mean_value) / std_value).astype(np.float32)
        manifest["generated_features"].append(feature_name)

    def _apply_signed_sentinel(
        self,
        normalized_df: pd.DataFrame,
        output_df: pd.DataFrame,
        normalized_column: str,
        profile: Dict,
        manifest: Dict,
    ) -> None:
        """Treat negative values as invalid sentinel, add validity flag, then scale valid values."""
        source = _replace_inf(normalized_df[normalized_column]).astype(float)
        valid_mask = source >= 0
        clean = source.where(valid_mask, np.nan)
        filled = clean.fillna(0.0)
        mean_value = float(clean.mean()) if valid_mask.any() else 0.0
        std_value = _safe_std(float(clean.std(ddof=0))) if valid_mask.any() else 1.0

        indicator_name = f"{normalized_column}_valid"
        scaled_name = f"{normalized_column}_valid_z"
        output_df[indicator_name] = valid_mask.astype(np.int8)
        output_df[scaled_name] = ((filled - mean_value) / std_value).astype(np.float32)
        manifest["generated_features"].extend([indicator_name, scaled_name])


def run(
    input_csv: Path,
    profile_csv: Path,
    output_path: Path,
    sample_rows: int | None = None,
) -> Dict:
    """Run normalization plus semantic preprocessing and persist the result."""
    config = CICIDS2018Config()
    normalizer = CICIDS2018Normalizer(config)
    preprocessor = CICIDS2018SemanticPreprocessor(profile_csv)

    normalized_df = normalizer.process_file(input_csv)
    if sample_rows:
        normalized_df = normalized_df.head(sample_rows).copy()

    processed_df, manifest = preprocessor.transform(normalized_df)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    processed_df.to_parquet(output_path, index=False, compression="snappy")

    manifest_path = output_path.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return {
        "rows": int(len(processed_df)),
        "columns": int(len(processed_df.columns)),
        "output_path": str(output_path),
        "manifest_path": str(manifest_path),
        "feature_columns": [column for column in processed_df.columns if column not in TRANSPORT_METADATA_COLUMNS],
    }


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Apply semantic-group-aware CICIDS2018 preprocessing")
    parser.add_argument("--input-csv", type=Path, required=True, help="Raw CICFlowMeter CSV to preprocess")
    parser.add_argument("--profile-csv", type=Path, required=True, help="Profile CSV emitted by analyze_numeric_columns")
    parser.add_argument("--output-path", type=Path, required=True, help="Parquet file to write transformed output")
    parser.add_argument("--sample-rows", type=int, default=None, help="Optional head() limit for a fast trial run")
    args = parser.parse_args()

    summary = run(
        input_csv=args.input_csv,
        profile_csv=args.profile_csv,
        output_path=args.output_path,
        sample_rows=args.sample_rows,
    )
    print("SEMANTIC PREPROCESSING COMPLETED")
    print(f"Rows: {summary['rows']}")
    print(f"Columns: {summary['columns']}")
    print(f"Output: {summary['output_path']}")
    print(f"Manifest: {summary['manifest_path']}")


if __name__ == "__main__":
    main()
