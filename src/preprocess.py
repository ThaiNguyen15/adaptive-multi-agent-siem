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
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv


load_dotenv()


def get_config() -> tuple[str, Path, int, int]:
    """Read preprocessing settings from the .env file."""
    input_file = os.getenv("INPUT_FILE", "/content/drive/MyDrive/rba-dataset.csv")
    output_dir = Path(os.getenv("OUTPUT_DIR", "/content/drive/MyDrive/rba_features/"))
    chunk_size = int(os.getenv("CHUNK_SIZE", "200000"))
    max_workers = int(os.getenv("MAX_WORKERS", "2"))
    return input_file, output_dir, chunk_size, max_workers


def normalize_columns(chunk: pd.DataFrame) -> pd.DataFrame:
    """Rename known dataset columns into simple internal names."""
    column_map = {
        "User ID": "user_id",
        "IP Address": "ip",
        "Device Type": "device",
        "User Agent String": "user_agent",
        "Round-Trip Time [ms]": "rtt",
        "Is Attack IP": "is_attack_ip",
    }
    return chunk.rename(columns=column_map)


def preprocess_chunk(chunk: pd.DataFrame) -> pd.DataFrame:
    """Convert one raw chunk into simple behavior-based features."""
    chunk = normalize_columns(chunk.copy())

    # Use a fallback device column when the dataset does not contain "device".
    if "device" not in chunk.columns and "user_agent" in chunk.columns:
        chunk["device"] = chunk["user_agent"]

    # Keep only the columns we need for feature creation and final output.
    required_columns = ["user_id", "ip", "device", "rtt", "is_attack_ip"]
    missing_columns = [column for column in required_columns if column not in chunk.columns]
    if missing_columns:
        raise KeyError(
            "Missing required columns after normalization: "
            f"{missing_columns}. Available columns: {list(chunk.columns)}"
        )

    chunk = chunk[required_columns]

    # Drop rows without a user_id because user-based behavior cannot be computed.
    chunk = chunk.dropna(subset=["user_id"])

    # Fill missing IP/device values with a placeholder so frequency counts still work.
    chunk["ip"] = chunk["ip"].fillna("unknown_ip").astype(str)
    chunk["device"] = chunk["device"].fillna("unknown_device").astype(str)

    # Convert RTT to numeric and safely handle invalid values.
    chunk["rtt"] = pd.to_numeric(chunk["rtt"], errors="coerce")

    # Fill missing attack labels with 0 and cast to integer for consistency.
    chunk["is_attack_ip"] = pd.to_numeric(chunk["is_attack_ip"], errors="coerce").fillna(0).astype(int)

    # Count how often each IP appears for the same user inside this chunk.
    chunk["ip_familiarity"] = chunk.groupby(["user_id", "ip"])["ip"].transform("size")

    # Count how often each device appears for the same user inside this chunk.
    chunk["device_familiarity"] = chunk.groupby(["user_id", "device"])["device"].transform("size")

    # Compute chunk-level RTT mean and standard deviation for a simple z-score.
    rtt_mean = chunk["rtt"].mean()
    rtt_std = chunk["rtt"].std()

    # If std is missing or zero, set anomaly score to 0 to avoid division issues.
    if pd.isna(rtt_std) or rtt_std == 0:
        chunk["rtt_anomaly"] = 0.0
    else:
        chunk["rtt_anomaly"] = (chunk["rtt"] - rtt_mean) / rtt_std
        chunk["rtt_anomaly"] = chunk["rtt_anomaly"].fillna(0.0)

    # Keep only the final model-ready behavior features.
    return chunk[["user_id", "ip_familiarity", "device_familiarity", "rtt_anomaly", "is_attack_ip"]]


def process_and_save_chunk(chunk_index: int, chunk: pd.DataFrame, output_dir: str) -> str:
    """Preprocess one chunk and save it as a parquet file."""
    processed_chunk = preprocess_chunk(chunk)
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
    input_file, output_dir, chunk_size, max_workers = get_config()

    # Create the output folder if it does not exist.
    output_dir.mkdir(parents=True, exist_ok=True)

    # Keep only a small number of chunks in memory while workers process them.
    max_pending_tasks = max_workers * 2
    pending_tasks = {}

    # Read the dataset chunk by chunk, but process several chunks in parallel.
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        for chunk_index, chunk in enumerate(pd.read_csv(input_file, chunksize=chunk_size)):
            print(f"Submitting chunk {chunk_index} with chunk size {chunk_size}...")

            future = executor.submit(process_and_save_chunk, chunk_index, chunk, str(output_dir))
            pending_tasks[future] = chunk_index

            if len(pending_tasks) >= max_pending_tasks:
                pending_tasks = flush_completed_tasks(pending_tasks)

        while pending_tasks:
            pending_tasks = flush_completed_tasks(pending_tasks)

    print("Preprocessing complete.")


if __name__ == "__main__":
    main()
