"""
Audit processed API traffic static-view columns.

Example:
    python -m src.scripts.audit_api_static_view \
        --processed-dir data/processed/api_traffic_quality_v2
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


DYNAMIC_PREFIXES = (
    "response_",
    "suspicious_request_got_",
)
DYNAMIC_COLUMNS = {
    "status",
    "status_code",
    "response_text",
    "sql_request_got_2xx",
    "traversal_request_got_2xx",
    "xss_request_got_2xx",
    "log4j_request_got_2xx",
    "rce_request_got_2xx",
    "log_forging_request_got_2xx",
    "auth_or_cookie_request_got_2xx",
}


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def dynamic_columns(columns: list[str]) -> list[str]:
    return sorted(
        column
        for column in columns
        if column in DYNAMIC_COLUMNS or any(column.startswith(prefix) for prefix in DYNAMIC_PREFIXES)
    )


def parquet_columns(processed_dir: Path, split: str) -> list[str]:
    split_dir = processed_dir / "splits" / split
    shard_paths = sorted(split_dir.glob("shard_*.parquet"))
    if not shard_paths:
        return []
    import pandas as pd

    return list(pd.read_parquet(shard_paths[0]).columns)


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit API processed static-view columns")
    parser.add_argument("--processed-dir", type=Path, required=True)
    parser.add_argument("--split", default="train")
    parser.add_argument(
        "--allow-response-context",
        action="store_true",
        help="Treat response/status/impact columns as expected for misconfiguration training",
    )
    args = parser.parse_args()

    config = load_json(args.processed_dir / "config.json")
    manifest = load_json(args.processed_dir / "feature_manifest.json")
    print(f"processed_dir: {args.processed_dir}")
    print(f"feature_mode: {config.get('feature_mode')}")
    print(f"static_view: {config.get('static_view')}")
    print(f"default_training_blocks: {manifest.get('default_training_blocks')}")

    feature_blocks = manifest.get("feature_blocks", {})
    request_static = feature_blocks.get("request_static", [])
    response_static = feature_blocks.get("response_impact_static", [])
    print(f"request_static columns: {len(request_static)}")
    print(f"response_impact_static columns: {len(response_static)}")
    print(f"dynamic columns in request_static: {dynamic_columns(request_static) or '-'}")

    focus_blocks = [
        key for key in feature_blocks if key.endswith("_focus")
    ]
    print(f"attack focus blocks: {', '.join(sorted(focus_blocks)) or '-'}")

    try:
        columns = parquet_columns(args.processed_dir, args.split)
    except ModuleNotFoundError as exc:
        print(f"parquet schema skipped: missing dependency {exc.name}")
        return

    if not columns:
        print(f"split columns: no shard found for split={args.split}")
        return

    leaked = [] if args.allow_response_context else dynamic_columns(columns)
    print(f"{args.split} split columns: {len(columns)}")
    print(f"dynamic columns in split: {dynamic_columns(columns) or '-'}")
    print(f"response context allowed: {args.allow_response_context}")
    print("status: OK" if not leaked else "status: DYNAMIC_COLUMNS_PRESENT")


if __name__ == "__main__":
    main()
