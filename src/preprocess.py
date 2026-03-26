"""
Why chunk processing?
- The RBA dataset is very large, so reading it in chunks avoids loading the
  full file into memory and keeps the script usable in Google Colab.

Why parallel chunk processing?
- We still read the file chunk by chunk for memory efficiency, but we can
  preprocess multiple chunks at the same time to reduce total runtime.

Why transform raw features into behavior features?
- In Risk-Based Authentication (RBA), we care less about raw values like the
  exact IP or device string and more about how familiar or unusual they are
  for a user's behavior.

Why use parquet instead of CSV?
- Parquet is usually smaller on disk, faster to read later, and preserves data
  types better than CSV for downstream machine learning workflows.
"""

import os
from collections import Counter, deque
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv


load_dotenv()


def get_config() -> tuple[str, Path, int, int, int]:
    """Read preprocessing settings from the .env file."""
    input_file = os.getenv("INPUT_FILE", "/content/drive/MyDrive/rba-dataset.csv")
    output_dir = Path(os.getenv("OUTPUT_DIR", "/content/drive/MyDrive/rba_features/"))
    chunk_size = int(os.getenv("CHUNK_SIZE", "200000"))
    max_workers = int(os.getenv("MAX_WORKERS", "2"))
    history_window_days = int(os.getenv("HISTORY_WINDOW_DAYS", "180"))
    return input_file, output_dir, chunk_size, max_workers, history_window_days


def normalize_columns(chunk: pd.DataFrame) -> pd.DataFrame:
    """Rename known dataset columns into simple internal names."""
    column_map = {
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
    return chunk.rename(columns=column_map)


def iter_user_aligned_chunks(input_file: str, chunk_size: int):
    """
    Read the CSV in row chunks, but avoid splitting a contiguous user block.

    This preserves all consecutive rows for the same user_id in the same
    processed chunk. If the source file is sorted or grouped by user_id, each
    user will stay in a single chunk.
    """
    carryover = pd.DataFrame()

    for raw_chunk in pd.read_csv(input_file, chunksize=chunk_size):
        chunk = normalize_columns(raw_chunk)

        if "user_id" not in chunk.columns:
            raise KeyError(
                'Missing required column "user_id" after normalization. '
                f"Available columns: {list(chunk.columns)}"
            )

        if not carryover.empty:
            chunk = pd.concat([carryover, chunk], ignore_index=True)
            carryover = pd.DataFrame()

        chunk = chunk.dropna(subset=["user_id"])
        if chunk.empty:
            continue

        last_user_id = chunk["user_id"].iloc[-1]
        different_user_positions = chunk.index[chunk["user_id"] != last_user_id]

        if different_user_positions.empty:
            carryover = chunk
            continue

        split_index = int(different_user_positions[-1]) + 1
        yield chunk.iloc[:split_index].reset_index(drop=True)
        carryover = chunk.iloc[split_index:].reset_index(drop=True)

    if not carryover.empty:
        yield carryover.reset_index(drop=True)


def to_binary(series: pd.Series, default: int = 0) -> pd.Series:
    """Convert booleans, numbers, and true/false strings into 0/1 integers."""
    normalized = series.astype(str).str.strip().str.lower().map(
        {"true": 1, "false": 0, "1": 1, "0": 0, "yes": 1, "no": 0}
    )
    numeric = pd.to_numeric(series, errors="coerce")
    return normalized.fillna(numeric).fillna(default).astype(int)


def parse_login_timestamp(series: pd.Series) -> pd.Series:
    """Infer timestamp unit and convert login timestamps to UTC datetimes."""
    numeric = pd.to_numeric(series, errors="coerce")
    if numeric.notna().any():
        max_abs = numeric.abs().max()
        if max_abs >= 10**17:
            unit = "ns"
        elif max_abs >= 10**14:
            unit = "us"
        elif max_abs >= 10**11:
            unit = "ms"
        else:
            unit = "s"
        return pd.to_datetime(numeric, unit=unit, errors="coerce", utc=True)

    return pd.to_datetime(series, errors="coerce", utc=True)


def build_behavior_features(user_history: pd.DataFrame, history_window: pd.Timedelta) -> pd.DataFrame:
    """
    Build RBA-style history features from earlier successful logins only.

    The implementation follows the paper's practical guidance more closely than
    the original chunk-level counts:
    - compare each attempt against earlier logins of the same user
    - use time order inside each user history
    - keep only recent history by default (six months)
    - avoid using attack intelligence as a direct input feature
    """
    tracked_features = [
        "ip",
        "country",
        "region",
        "city",
        "asn",
        "user_agent",
        "browser_name",
        "os_name",
        "device",
    ]
    history_counts = {feature: Counter() for feature in tracked_features}
    success_events = deque()
    success_rtt_sum = 0.0
    success_rtt_sum_sq = 0.0
    last_success_ts = pd.NaT
    rows = []

    def evict_old_history(current_ts: pd.Timestamp) -> tuple[float, float]:
        nonlocal success_rtt_sum, success_rtt_sum_sq, last_success_ts

        if pd.isna(current_ts):
            return success_rtt_sum, success_rtt_sum_sq

        cutoff = current_ts - history_window
        while success_events and success_events[0]["ts"] < cutoff:
            event = success_events.popleft()
            for feature in tracked_features:
                value = event[feature]
                history_counts[feature][value] -= 1
                if history_counts[feature][value] <= 0:
                    del history_counts[feature][value]

            if pd.notna(event["rtt"]):
                success_rtt_sum -= event["rtt"]
                success_rtt_sum_sq -= event["rtt"] ** 2

        last_success_ts = success_events[-1]["ts"] if success_events else pd.NaT
        return success_rtt_sum, success_rtt_sum_sq

    for row in user_history.itertuples(index=False):
        current_ts = row.login_ts
        evict_old_history(current_ts)
        history_size = len(success_events)

        feature_row = {
            "user_id": row.user_id,
            "history_size": history_size,
            "login_successful": row.login_successful,
            "is_attack_ip": row.is_attack_ip,
            "is_account_takeover": row.is_account_takeover,
        }

        for feature in tracked_features:
            value = getattr(row, feature)
            prev_count = history_counts[feature].get(value, 0)
            feature_row[f"{feature}_prev_count"] = prev_count
            feature_row[f"{feature}_known"] = int(prev_count > 0)
            feature_row[f"{feature}_match_rate"] = prev_count / history_size if history_size else 0.0

        if history_size and pd.notna(current_ts) and pd.notna(last_success_ts):
            delta = current_ts - last_success_ts
            feature_row["time_since_last_success_hours"] = delta.total_seconds() / 3600.0
        else:
            feature_row["time_since_last_success_hours"] = -1.0

        if history_size >= 2 and pd.notna(row.rtt):
            rtt_mean = success_rtt_sum / history_size
            variance = max((success_rtt_sum_sq / history_size) - (rtt_mean**2), 0.0)
            rtt_std = variance**0.5
            if rtt_std > 0:
                feature_row["rtt_anomaly"] = (row.rtt - rtt_mean) / rtt_std
            else:
                feature_row["rtt_anomaly"] = 0.0
        else:
            feature_row["rtt_anomaly"] = 0.0

        # Backward-compatible aliases for existing downstream code.
        feature_row["ip_familiarity"] = feature_row["ip_prev_count"]
        feature_row["device_familiarity"] = feature_row["device_prev_count"]

        rows.append(feature_row)

        if row.login_successful:
            event = {"ts": current_ts, "rtt": row.rtt}
            for feature in tracked_features:
                value = getattr(row, feature)
                history_counts[feature][value] += 1
                event[feature] = value
            success_events.append(event)

            if pd.notna(row.rtt):
                success_rtt_sum += row.rtt
                success_rtt_sum_sq += row.rtt**2

            if pd.notna(current_ts):
                last_success_ts = current_ts

    return pd.DataFrame(rows)


def preprocess_chunk(chunk: pd.DataFrame, history_window_days: int) -> pd.DataFrame:
    """Convert one raw chunk into history-aware behavior features."""
    chunk = normalize_columns(chunk.copy())

    # Use fallback columns when the dataset does not contain the derived fields.
    if "device" not in chunk.columns and "user_agent" in chunk.columns:
        chunk["device"] = chunk["user_agent"]
    if "browser_name" not in chunk.columns and "user_agent" in chunk.columns:
        chunk["browser_name"] = chunk["user_agent"]
    if "os_name" not in chunk.columns and "user_agent" in chunk.columns:
        chunk["os_name"] = chunk["user_agent"]

    # Keep only the columns we need for feature creation and final output.
    required_columns = ["user_id", "ip", "device", "user_agent", "rtt"]
    missing_columns = [column for column in required_columns if column not in chunk.columns]
    if missing_columns:
        raise KeyError(
            "Missing required columns after normalization: "
            f"{missing_columns}. Available columns: {list(chunk.columns)}"
        )

    # Drop rows without a user_id because user-based behavior cannot be computed.
    chunk = chunk.dropna(subset=["user_id"])
    if chunk.empty:
        return pd.DataFrame(
            columns=[
                "user_id",
                "history_size",
                "ip_prev_count",
                "ip_known",
                "ip_match_rate",
                "country_prev_count",
                "country_known",
                "country_match_rate",
                "region_prev_count",
                "region_known",
                "region_match_rate",
                "city_prev_count",
                "city_known",
                "city_match_rate",
                "asn_prev_count",
                "asn_known",
                "asn_match_rate",
                "user_agent_prev_count",
                "user_agent_known",
                "user_agent_match_rate",
                "browser_name_prev_count",
                "browser_name_known",
                "browser_name_match_rate",
                "os_name_prev_count",
                "os_name_known",
                "os_name_match_rate",
                "device_prev_count",
                "device_known",
                "device_match_rate",
                "time_since_last_success_hours",
                "rtt_anomaly",
                "ip_familiarity",
                "device_familiarity",
                "login_successful",
                "is_attack_ip",
                "is_account_takeover",
            ]
        )

    optional_defaults = {
        "country": "unknown_country",
        "region": "unknown_region",
        "city": "unknown_city",
        "asn": "unknown_asn",
        "browser_name": "unknown_browser",
        "os_name": "unknown_os",
        "login_timestamp": pd.NA,
        "login_successful": 1,
        "is_attack_ip": 0,
        "is_account_takeover": 0,
    }
    for column, default_value in optional_defaults.items():
        if column not in chunk.columns:
            chunk[column] = default_value

    # Fill missing categorical values with placeholders so history counts still work.
    chunk["ip"] = chunk["ip"].fillna("unknown_ip").astype(str)
    chunk["country"] = chunk["country"].fillna("unknown_country").astype(str)
    chunk["region"] = chunk["region"].fillna("unknown_region").astype(str)
    chunk["city"] = chunk["city"].fillna("unknown_city").astype(str)
    chunk["asn"] = chunk["asn"].fillna("unknown_asn").astype(str)
    chunk["device"] = chunk["device"].fillna("unknown_device").astype(str)
    chunk["user_agent"] = chunk["user_agent"].fillna("unknown_user_agent").astype(str)
    chunk["browser_name"] = chunk["browser_name"].fillna("unknown_browser").astype(str)
    chunk["os_name"] = chunk["os_name"].fillna("unknown_os").astype(str)

    # Convert RTT to numeric and safely handle invalid values.
    chunk["rtt"] = pd.to_numeric(chunk["rtt"], errors="coerce")
    chunk["login_ts"] = parse_login_timestamp(chunk["login_timestamp"])

    # Convert labels/status fields to clean binary integers.
    chunk["login_successful"] = to_binary(chunk["login_successful"], default=1)
    chunk["is_attack_ip"] = to_binary(chunk["is_attack_ip"], default=0)
    chunk["is_account_takeover"] = to_binary(chunk["is_account_takeover"], default=0)

    # Preserve chronological order inside each user before building history features.
    chunk = chunk.sort_values(["user_id", "login_ts"], kind="stable").reset_index(drop=True)

    history_window = pd.Timedelta(days=history_window_days)
    processed_users = [
        build_behavior_features(user_history, history_window)
        for _, user_history in chunk.groupby("user_id", sort=False)
    ]
    processed_chunk = pd.concat(processed_users, ignore_index=True)

    output_columns = [
        "user_id",
        "history_size",
        "ip_prev_count",
        "ip_known",
        "ip_match_rate",
        "country_prev_count",
        "country_known",
        "country_match_rate",
        "region_prev_count",
        "region_known",
        "region_match_rate",
        "city_prev_count",
        "city_known",
        "city_match_rate",
        "asn_prev_count",
        "asn_known",
        "asn_match_rate",
        "user_agent_prev_count",
        "user_agent_known",
        "user_agent_match_rate",
        "browser_name_prev_count",
        "browser_name_known",
        "browser_name_match_rate",
        "os_name_prev_count",
        "os_name_known",
        "os_name_match_rate",
        "device_prev_count",
        "device_known",
        "device_match_rate",
        "time_since_last_success_hours",
        "rtt_anomaly",
        "ip_familiarity",
        "device_familiarity",
        "login_successful",
        "is_attack_ip",
        "is_account_takeover",
    ]
    return processed_chunk[output_columns]


def process_and_save_chunk(chunk_index: int, chunk: pd.DataFrame, output_dir: str, history_window_days: int) -> str:
    """Preprocess one chunk and save it as a parquet file."""
    processed_chunk = preprocess_chunk(chunk, history_window_days)
    output_file = Path(output_dir) / f"part_{chunk_index}.parquet"
    processed_chunk.to_parquet(output_file, index=False)
    return f"Saved chunk {chunk_index} to {output_file} ({len(processed_chunk)} rows)"


def flush_completed_tasks(pending_tasks: dict) -> dict:
    """Print completed task results and keep unfinished tasks."""
    done, not_done = wait(pending_tasks, return_when=FIRST_COMPLETED)

    for future in done:
        chunk_index = pending_tasks[future]
        print(future.result())
        print(f"Finished chunk {chunk_index}.")

    return {future: pending_tasks[future] for future in not_done}


def main() -> None:
    input_file, output_dir, chunk_size, max_workers, history_window_days = get_config()

    # Create the output folder if it does not exist.
    output_dir.mkdir(parents=True, exist_ok=True)

    # Keep only a small number of chunks in memory while workers process them.
    max_pending_tasks = max_workers * 2
    pending_tasks = {}

    # Read the dataset chunk by chunk, but process several chunks in parallel.
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        for chunk_index, chunk in enumerate(iter_user_aligned_chunks(input_file, chunk_size)):
            print(f"Submitting chunk {chunk_index} with {len(chunk)} user-aligned rows...")

            future = executor.submit(
                process_and_save_chunk,
                chunk_index,
                chunk,
                str(output_dir),
                history_window_days,
            )
            pending_tasks[future] = chunk_index

            if len(pending_tasks) >= max_pending_tasks:
                pending_tasks = flush_completed_tasks(pending_tasks)

        while pending_tasks:
            pending_tasks = flush_completed_tasks(pending_tasks)

    print("Preprocessing complete.")


if __name__ == "__main__":
    main()
