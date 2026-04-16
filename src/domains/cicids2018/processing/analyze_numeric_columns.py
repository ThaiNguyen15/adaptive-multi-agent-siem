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

    range_groups = _group_columns(numeric_profiles, "range_bucket")
    magnitude_groups = _group_columns(numeric_profiles, "magnitude_group")

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
        "text_columns_not_processed": text_columns_not_processed,
        "notes": {
            "large_csv_mode": True,
            "quantiles_are_approximate": True,
            "unique_count_may_be_approximate": True,
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)

    stats_df.to_csv(output_dir / "numeric_column_stats.csv", index=False)
    with open(output_dir / "numeric_range_groups.json", "w", encoding="utf-8") as handle:
        json.dump(range_groups, handle, indent=2)
    with open(output_dir / "numeric_magnitude_groups.json", "w", encoding="utf-8") as handle:
        json.dump(magnitude_groups, handle, indent=2)
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
            f"- `{profile['column_name']}`: max=`{profile['max']}`, p99≈`{profile['p99']}`, range_bucket=`{profile['range_bucket']}`"
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
