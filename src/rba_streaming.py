"""
Streaming Risk-Based Authentication (RBA) pipeline.

Design goals:
- process login events sequentially in chronological order
- avoid loading the full dataset into memory
- avoid dataset-wide groupby operations
- store only aggregate counts in hash tables
- compute a risk score before updating state for the current event

Expected input columns:
- user_id
- ip
- country
- device
- browser
- timestamp
"""

from __future__ import annotations

import argparse
import csv
import math
import os
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, Iterable, Iterator, Optional, TextIO

from dotenv import load_dotenv


FEATURES = ("ip", "country", "device", "browser")
UNKNOWN_VALUE = "unknown"
COLUMN_MAP = {
    "User ID": "user_id",
    "IP Address": "ip",
    "Country": "country",
    "Region": "region",
    "City": "city",
    "ASN": "asn",
    "Device Type": "device",
    "User Agent String": "user_agent",
    "OS Name and Version": "os_name",
    "Browser Name and Version": "browser_name",
    "Login Timestamp": "login_timestamp",
    "Round-Trip Time [ms]": "rtt",
    "Login Successful": "login_successful",
    "Is Attack IP": "is_attack_ip",
    "Is Account Takeover": "is_account_takeover",
}


load_dotenv()


def nested_counter() -> defaultdict[str, int]:
    """Create a dictionary of counts with 0 as the default value."""
    return defaultdict(int)


def feature_counter_map() -> dict[str, defaultdict[str, int]]:
    """Create the per-feature counter structure."""
    return {feature: nested_counter() for feature in FEATURES}


@dataclass(slots=True)
class Event:
    """Normalized login event."""

    user_id: str
    ip: str
    country: str
    device: str
    browser: str
    timestamp: Optional[datetime]


@dataclass(slots=True)
class UserState:
    """Per-user aggregate state stored in memory."""

    total_events: int = 0
    feature_counts: dict[str, defaultdict[str, int]] = field(default_factory=feature_counter_map)
    recent_events: Optional[Deque[tuple[Optional[datetime], dict[str, str]]]] = None


@dataclass(slots=True)
class GlobalState:
    """Global aggregate state stored in memory."""

    total_events: int = 0
    feature_counts: dict[str, defaultdict[str, int]] = field(default_factory=feature_counter_map)


class RBAProcessor:
    """
    Stateful streaming RBA processor.

    The risk score is calculated as:
        risk = product(P(feature) / P(feature | user))

    To keep the score numerically stable, the implementation sums logs and then
    exponentiates the result.
    """

    def __init__(
        self,
        smoothing: float = 1.0,
        anomaly_threshold: Optional[float] = None,
        user_history_limit: Optional[int] = None,
    ) -> None:
        self.smoothing = smoothing
        self.anomaly_threshold = anomaly_threshold
        self.user_history_limit = user_history_limit
        self.global_state = GlobalState()
        self.user_stats: dict[str, UserState] = {}

    def process_event(self, event: Event) -> dict[str, object]:
        """Compute the event risk, then update global and user state."""
        user_state = self.user_stats.get(event.user_id)
        risk_score = self._compute_risk(event, user_state)
        is_anomalous = (
            self.anomaly_threshold is not None and risk_score >= self.anomaly_threshold
        )

        self._update_state(event, user_state)

        return {
            "user_id": event.user_id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else "",
            "risk_score": risk_score,
            "is_anomalous": is_anomalous,
        }

    def _compute_risk(self, event: Event, user_state: Optional[UserState]) -> float:
        """
        Compute risk from historical state only.

        Cold start handling:
        - If the user has no history, return 1.0 to avoid over-penalizing the
          first login.
        """
        if user_state is None or user_state.total_events == 0:
            return 1.0

        log_risk = 0.0
        global_total = self.global_state.total_events
        user_total = user_state.total_events

        for feature in FEATURES:
            feature_value = getattr(event, feature)
            global_count = self.global_state.feature_counts[feature][feature_value]
            user_count = user_state.feature_counts[feature][feature_value]

            global_probability = (global_count + self.smoothing) / (
                global_total + (2.0 * self.smoothing)
            )
            user_probability = (user_count + self.smoothing) / (
                user_total + (2.0 * self.smoothing)
            )

            log_risk += math.log(global_probability / user_probability)

        return math.exp(log_risk)

    def _update_state(self, event: Event, user_state: Optional[UserState]) -> None:
        """Update counts after the event risk has been emitted."""
        if user_state is None:
            user_state = UserState()
            if self.user_history_limit is not None:
                user_state.recent_events = deque()
            self.user_stats[event.user_id] = user_state

        self.global_state.total_events += 1
        user_state.total_events += 1

        feature_snapshot: dict[str, str] = {}
        for feature in FEATURES:
            feature_value = getattr(event, feature)
            self.global_state.feature_counts[feature][feature_value] += 1
            user_state.feature_counts[feature][feature_value] += 1
            feature_snapshot[feature] = feature_value

        if self.user_history_limit is not None:
            self._append_with_limit(user_state, event.timestamp, feature_snapshot)

    def _append_with_limit(
        self,
        user_state: UserState,
        event_time: Optional[datetime],
        feature_snapshot: dict[str, str],
    ) -> None:
        """
        Keep only the last N user events by decrementing old aggregate counts.

        This still avoids storing full history for all users indefinitely. When
        enabled, the processor retains at most N feature snapshots per user.
        """
        assert user_state.recent_events is not None

        user_state.recent_events.append((event_time, feature_snapshot))
        if len(user_state.recent_events) <= self.user_history_limit:
            return

        _, expired_snapshot = user_state.recent_events.popleft()
        user_state.total_events -= 1
        for feature, value in expired_snapshot.items():
            feature_counts = user_state.feature_counts[feature]
            feature_counts[value] -= 1
            if feature_counts[value] <= 0:
                del feature_counts[value]


def parse_timestamp(value: str) -> Optional[datetime]:
    """Parse common timestamp formats into timezone-aware UTC datetimes."""
    raw = (value or "").strip()
    if not raw:
        return None

    if raw.isdigit():
        numeric = int(raw)
        abs_numeric = abs(numeric)
        if abs_numeric >= 10**17:
            seconds = numeric / 1_000_000_000
        elif abs_numeric >= 10**14:
            seconds = numeric / 1_000_000
        elif abs_numeric >= 10**11:
            seconds = numeric / 1_000
        else:
            seconds = numeric
        return datetime.fromtimestamp(seconds, tz=timezone.utc)

    normalized = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_value(value: Optional[str], fallback: str = UNKNOWN_VALUE) -> str:
    """Convert missing values into stable categorical tokens."""
    text = (value or "").strip()
    return text if text else fallback


def remap_row_columns(row: dict[str, str]) -> dict[str, str]:
    """Rename source columns into internal names without copying unused history."""
    normalized_row: dict[str, str] = {}
    for source_name, value in row.items():
        target_name = COLUMN_MAP.get(source_name, source_name)
        normalized_row[target_name] = value
    return normalized_row


def normalize_row(row: dict[str, str]) -> Event:
    """Map one CSV row into the internal event representation."""
    normalized = remap_row_columns(row)
    return Event(
        user_id=normalize_value(normalized.get("user_id"), fallback="unknown_user"),
        ip=normalize_value(normalized.get("ip"), fallback="unknown_ip"),
        country=normalize_value(normalized.get("country"), fallback="unknown_country"),
        device=normalize_value(normalized.get("device"), fallback="unknown_device"),
        browser=normalize_value(
            normalized.get("browser")
            or normalized.get("browser_name")
            or normalized.get("user_agent"),
            fallback="unknown_browser",
        ),
        timestamp=parse_timestamp(
            normalized.get("timestamp") or normalized.get("login_timestamp", "")
        ),
    )


def iter_login_events(input_path: Path) -> Iterator[Event]:
    """Yield login events one row at a time from a CSV file."""
    with input_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        normalized_fieldnames = {
            COLUMN_MAP.get(fieldname, fieldname) for fieldname in (reader.fieldnames or [])
        }
        required_columns = {"user_id", "ip", "country", "device"}
        missing_columns = required_columns.difference(normalized_fieldnames)
        if missing_columns:
            missing = ", ".join(sorted(missing_columns))
            raise KeyError(f"Missing required CSV columns: {missing}")
        if not (
            {"browser", "browser_name", "user_agent"} & normalized_fieldnames
        ):
            raise KeyError(
                "Missing browser column after normalization. Expected one of: "
                "browser, browser_name, user_agent"
            )
        if not (
            {"timestamp", "login_timestamp"} & normalized_fieldnames
        ):
            raise KeyError(
                "Missing timestamp column after normalization. Expected one of: "
                "timestamp, login_timestamp"
            )

        for row in reader:
            yield normalize_row(row)


def write_results(
    events: Iterable[Event],
    processor: RBAProcessor,
    output_handle: TextIO,
) -> None:
    """Stream risk scores to CSV output as each event is processed."""
    writer = csv.DictWriter(
        output_handle,
        fieldnames=["user_id", "timestamp", "risk_score", "is_anomalous"],
    )
    writer.writeheader()

    for event in events:
        result = processor.process_event(event)
        writer.writerow(result)


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(
        description="Sequential streaming Risk-Based Authentication pipeline."
    )
    parser.add_argument(
        "input_csv",
        nargs="?",
        type=Path,
        help="Path to the input login CSV. Defaults to INPUT_FILE from .env.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Optional output CSV path. Defaults to OUTPUT_FILE from .env or stdout.",
    )
    parser.add_argument(
        "--smoothing",
        type=float,
        default=1.0,
        help="Laplace smoothing factor for probability estimates.",
    )
    parser.add_argument(
        "--anomaly-threshold",
        type=float,
        default=None,
        help="Flag events with risk_score >= threshold.",
    )
    parser.add_argument(
        "--user-history-limit",
        type=int,
        default=None,
        help="Optional cap on per-user event history used to maintain counts.",
    )
    return parser


def resolve_io_paths(args: argparse.Namespace) -> tuple[Path, Optional[Path]]:
    """Resolve CLI or environment-based input and output paths."""
    input_path = args.input_csv or (
        Path(os.environ["INPUT_FILE"]) if os.getenv("INPUT_FILE") else None
    )
    if input_path is None:
        raise ValueError("Input CSV is required. Pass input_csv or set INPUT_FILE in .env.")

    output_path = args.output
    if output_path is None and os.getenv("OUTPUT_FILE"):
        output_path = Path(os.environ["OUTPUT_FILE"])

    return input_path, output_path


def main() -> None:
    """Run the streaming pipeline from the command line."""
    parser = build_argument_parser()
    args = parser.parse_args()
    input_path, output_path = resolve_io_paths(args)

    processor = RBAProcessor(
        smoothing=args.smoothing,
        anomaly_threshold=args.anomaly_threshold,
        user_history_limit=args.user_history_limit,
    )
    events = iter_login_events(input_path)

    if output_path is None:
        import sys

        write_results(events, processor, sys.stdout)
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        write_results(events, processor, handle)


if __name__ == "__main__":
    main()
