"""
Derive fine-grained CICIDS2018 preprocessing groups from numeric column stats.

The goal is to split broad semantic groups into smaller processing families that
match the observed data characteristics more closely.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

import math
import pandas as pd


def _is_finite(value: float) -> bool:
    return value is not None and not pd.isna(value) and math.isfinite(float(value))


def _safe_float(value) -> float:
    if pd.isna(value):
        return float("nan")
    return float(value)


def _tail_ratio(p99: float, p95: float) -> float:
    if not _is_finite(p99):
        return float("inf")
    if not _is_finite(p95):
        return float("inf")
    return (p99 + 1.0) / (p95 + 1.0)


def _max_ratio(max_value: float, p99: float) -> float:
    if not _is_finite(max_value):
        return float("inf")
    if not _is_finite(p99):
        return float("inf")
    return (max_value + 1.0) / (p99 + 1.0)


def classify_column(row: Dict) -> tuple[str, Dict]:
    """Assign one column into a fine-grained processing family."""
    name = row["column_name"]
    semantic_group = row["semantic_group"]
    min_value = _safe_float(row["min"])
    max_value = _safe_float(row["max"])
    p50 = _safe_float(row["p50"])
    p95 = _safe_float(row["p95"])
    p99 = _safe_float(row["p99"])
    zero_ratio = _safe_float(row["zero_ratio"])
    negative_ratio = _safe_float(row["negative_ratio"])
    unique_count = int(row["unique_count"])
    unique_count_is_approximate = bool(row["unique_count_is_approximate"])

    tail = _tail_ratio(p99, p95)
    spike = _max_ratio(max_value, p99)
    center_tail_ratio = float("inf")
    if _is_finite(p95) and _is_finite(p50):
        center_tail_ratio = (p95 + 1.0) / (p50 + 1.0)

    if semantic_group == "transport_context":
        if name.lower() == "protocol":
            return "transport_protocol_category", {
                "why": "Very low-cardinality protocol code; behaves as a categorical routing context feature.",
                "best_practice": "Convert to one-hot or coarse indicators such as is_tcp and is_udp.",
            }
        return "transport_port_high_cardinality", {
            "why": "Destination port is a high-cardinality identifier with shortcut risk.",
            "best_practice": "Bucketize into coarse port families or audited service groups, not raw scaling.",
        }

    if (not unique_count_is_approximate and unique_count == 1) or min_value == max_value:
        return "constant_zero_or_constant_value", {
            "why": "The column has no usable variance in this dataset snapshot.",
            "best_practice": "Drop from training features.",
        }

    if semantic_group == "signed_or_sentinel_window" or negative_ratio > 0.0:
        return "signed_sentinel_tcp_window", {
            "why": "Negative values indicate sentinel or invalid markers rather than true signed magnitude.",
            "best_practice": "Create validity flag, mask sentinel values, then scale only valid magnitudes.",
        }

    if semantic_group == "flag_features":
        if unique_count <= 2 and min_value >= 0 and max_value <= 1:
            if zero_ratio >= 0.95:
                return "rare_binary_transport_flag", {
                    "why": "Binary transport flag with very sparse positives.",
                    "best_practice": "Keep as 0/1 indicator; no additional scaling needed.",
                }
            return "binary_transport_flag", {
                "why": "Binary transport flag with enough positives to be directly useful.",
                "best_practice": "Keep as 0/1 indicator.",
            }
        return "small_count_flag", {
            "why": "Flag-like count with limited support beyond pure binary.",
            "best_practice": "Keep presence indicator and optionally a clipped log-count view.",
        }

    if semantic_group == "directionality_ratio":
        if p99 <= 1.0 and max_value > 10.0:
            return "denominator_sensitive_ratio_spike", {
                "why": "Most rows are bounded near 0-1 but a tiny minority spikes sharply because of small denominators.",
                "best_practice": "Clip the upper tail aggressively, then standardize the clipped ratio.",
            }
        return "bounded_or_mild_ratio", {
            "why": "Ratio feature with relatively bounded support.",
            "best_practice": "Clip to a safe range if needed and standardize.",
        }

    if semantic_group == "packet_shape":
        if zero_ratio >= 0.75 and p95 <= 125.0:
            return "packet_floor_zero_inflated", {
                "why": "Many flows have a structural zero minimum, with a compact positive range when present.",
                "best_practice": "Keep the raw shape signal, optionally add a presence indicator, and standardize.",
            }
        if p95 >= 1200.0 and p99 >= 1400.0:
            return "packet_ceiling_mtu_like", {
                "why": "Upper quantiles sit near Ethernet payload ceilings, so the feature captures bounded packet-size structure.",
                "best_practice": "Standardize after basic cleaning; avoid unnecessary log compression.",
            }
        if spike > 100.0 and p99 < 5000.0:
            return "packet_shape_with_rare_header_outlier", {
                "why": "The bulk of the distribution is moderate, but a very small number of rows create extreme header-related outliers.",
                "best_practice": "Prefer clipping plus standardization if those outliers hurt training; otherwise standardize.",
            }
        if p99 <= 1000.0:
            return "moderate_packet_shape_continuous", {
                "why": "Continuous packet-size structure feature with moderate spread.",
                "best_practice": "Standardize after cleaning missing and infinite values.",
            }
        return "broad_packet_shape_continuous", {
            "why": "Packet-shape feature with a wider but still interpretable physical range.",
            "best_practice": "Standardize, with optional mild clipping if outliers destabilize the model.",
        }

    if semantic_group == "rate":
        if not _is_finite(max_value):
            return "rate_with_infinite_risk", {
                "why": "Per-second rate can explode to infinity when duration is tiny or malformed.",
                "best_practice": "Replace inf with NaN, clip high percentiles, apply log1p, then standardize.",
            }
        return "extreme_positive_rate", {
            "why": "Rate feature is strongly right-skewed with extreme upper tail.",
            "best_practice": "Clip the high tail, apply log1p, and standardize.",
        }

    if semantic_group == "timing":
        if zero_ratio >= 0.85 and center_tail_ratio > 1000.0:
            return "zero_inflated_extreme_timing", {
                "why": "Most rows are zero or near-zero, but nonzero rows jump to very large values.",
                "best_practice": "Clip, apply log1p, and standardize; optionally add a nonzero indicator.",
            }
        if center_tail_ratio > 10000.0 and p99 >= 1e7:
            return "saturated_timeout_like_timing", {
                "why": "Median timing is tiny while upper percentiles cluster near a hard cap or timeout ceiling.",
                "best_practice": "Treat as heavy-tailed timing: clip near p99, log1p, and standardize.",
            }
        if tail > 2.0 or spike > 5.0:
            return "burst_gap_heavy_tail_timing", {
                "why": "Inter-arrival timing has a strong burst-versus-gap pattern with a heavy right tail.",
                "best_practice": "Clip, apply log1p, and standardize.",
            }
        return "moderate_timing_continuous", {
            "why": "Timing feature is continuous but less pathological than the extreme-tail timing families.",
            "best_practice": "Standardize, adding clipping if later diagnostics show instability.",
        }

    if semantic_group == "flow_volume":
        if zero_ratio == 0.0 and p50 <= 3.0 and spike > 100.0:
            return "always_positive_count_with_rare_huge_tail", {
                "why": "Every row has a positive count, but a small minority of flows are orders of magnitude larger.",
                "best_practice": "Clip the upper tail, apply log1p, and standardize.",
            }
        if zero_ratio >= 0.25 and spike > 100.0:
            return "zero_moderate_with_extreme_volume_tail", {
                "why": "Many rows are zero or small, while a tiny minority explodes to very large bytes or packet totals.",
                "best_practice": "Clip, apply log1p, and standardize; optional nonzero indicator can help.",
            }
        if p99 <= 50.0 and max_value >= 1000.0:
            return "small_count_with_rare_large_flow", {
                "why": "The normal operating range is tiny, but rare very large flows produce a long tail.",
                "best_practice": "Keep a clipped raw or log1p view; avoid raw unbounded scale.",
            }
        return "general_positive_volume", {
            "why": "Positive traffic magnitude feature with enough skew to benefit from compression.",
            "best_practice": "Clip high values, apply log1p, and standardize.",
        }

    return "other_numeric_needs_manual_review", {
        "why": "The column did not match a stronger fine-grained family safely.",
        "best_practice": "Inspect the raw semantics and training impact manually.",
    }


def build_groups(stats_df: pd.DataFrame) -> tuple[Dict[str, List[str]], Dict[str, Dict], List[Dict]]:
    """Build fine-grained groups and per-column decisions."""
    rows = stats_df.to_dict(orient="records")
    group_map: Dict[str, List[str]] = {}
    group_notes: Dict[str, Dict] = {}
    enriched_rows: List[Dict] = []

    for row in rows:
        group_name, note = classify_column(row)
        row["fine_grained_group"] = group_name
        row["fine_grained_why"] = note["why"]
        row["fine_grained_best_practice"] = note["best_practice"]
        enriched_rows.append(row)

        group_map.setdefault(group_name, []).append(row["column_name"])
        group_notes[group_name] = {
            "why": note["why"],
            "best_practice": note["best_practice"],
        }

    for columns in group_map.values():
        columns.sort()

    group_map = dict(sorted(group_map.items(), key=lambda item: item[0]))
    group_notes = dict(sorted(group_notes.items(), key=lambda item: item[0]))
    return group_map, group_notes, enriched_rows


def write_markdown(output_path: Path, groups: Dict[str, List[str]], notes: Dict[str, Dict], rows: List[Dict]) -> None:
    """Write a human-readable explanation of the fine-grained groups."""
    by_column = {row["column_name"]: row for row in rows}

    lines = [
        "# Fine-Grained CICIDS2018 Processing Groups",
        "",
        "This report splits the broad semantic groups into smaller families that",
        "match the observed data shape more closely.",
        "",
    ]

    for group_name, columns in groups.items():
        lines.append(f"## {group_name}")
        lines.append("")
        lines.append(f"- Why: {notes[group_name]['why']}")
        lines.append(f"- Best practice: {notes[group_name]['best_practice']}")
        lines.append("")
        lines.append("| Column | Semantic Group | zero_ratio | p50 | p95 | p99 | max |")
        lines.append("|---|---|---:|---:|---:|---:|---:|")
        for column in columns:
            row = by_column[column]
            lines.append(
                f"| `{column}` | `{row['semantic_group']}` | {row['zero_ratio']:.4f} | "
                f"{row['p50']} | {row['p95']} | {row['p99']} | {row['max']} |"
            )
        lines.append("")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Derive fine-grained CICIDS2018 groups from stats CSV")
    parser.add_argument("--stats-csv", type=Path, required=True, help="numeric_column_stats.csv path")
    parser.add_argument("--output-dir", type=Path, required=True, help="directory for group outputs")
    args = parser.parse_args()

    stats_df = pd.read_csv(args.stats_csv)
    groups, notes, enriched_rows = build_groups(stats_df)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    with open(args.output_dir / "fine_grained_groups.json", "w", encoding="utf-8") as handle:
        json.dump(groups, handle, indent=2)
    with open(args.output_dir / "fine_grained_group_notes.json", "w", encoding="utf-8") as handle:
        json.dump(notes, handle, indent=2)
    pd.DataFrame(enriched_rows).to_csv(args.output_dir / "numeric_column_stats_fine_groups.csv", index=False)
    write_markdown(
        output_path=args.output_dir / "fine_grained_groups.md",
        groups=groups,
        notes=notes,
        rows=enriched_rows,
    )

    print("FINE-GRAINED GROUPING COMPLETED")
    print(f"Groups: {len(groups)}")
    print(f"Output dir: {args.output_dir}")


if __name__ == "__main__":
    main()
